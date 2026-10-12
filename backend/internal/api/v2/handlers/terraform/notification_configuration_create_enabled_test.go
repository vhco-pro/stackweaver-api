// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A notification configuration created with `enabled: false` must be stored disabled, one created
// with true must be enabled, and one created without the attribute must be disabled: the Terraform
// Enterprise API documents the create attribute's default as false, go-tfe refuses to send a
// create without it, and the tfe provider's own default is false. The three create routes
// (workspace, project, team) share one code path and are all covered.
//
// The defect this test was written against: NotificationConfiguration.Enabled carried
// `gorm:"default:true"`, and GORM substitutes a literal default for a zero value in the INSERT
// (and writes it back into the struct), so a false sent on create was stored and answered as
// true, and the configuration delivered.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestNotificationConfigurationCreate_Enabled

//go:build integration

package terraform

import (
	"net/http"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

func TestNotificationConfigurationCreate_EnabledIsStoredAsSent(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.OrganizationMember{},
		&models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{}, &models.TeamProjectAccess{},
		&models.TeamWorkspaceAccess{}, &models.Project{}, &models.Workspace{}, &models.NotificationConfiguration{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "ncenabled-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "ncenabled-" + sfx, Email: "ncenabled-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "ncenabled-proj-" + sfx}
	workspace := &models.Workspace{ID: "ws-nc" + uuid.NewString()[:14], ProjectID: project.ID, Name: "ncenabled-ws-" + sfx}
	// Workspace permissions resolve through project access, which the owners team does not get
	// by name alone; admin on the project grants workspace write.
	adminAccess := "admin"
	seed := []any{
		org, owner, ownersTeam, project, workspace,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: ownersTeam.ID, ProjectID: project.ID, Access: &adminAccess},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	var configIDs []string
	t.Cleanup(func() {
		// Row-scoped only: exactly the configurations the cases below created, by id.
		if len(configIDs) > 0 {
			db.Where("id IN ?", configIDs).Delete(&models.NotificationConfiguration{})
		}
		db.Where("id = ?", workspace.ID).Delete(&models.Workspace{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamProjectAccess{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", ownersTeam.ID).Delete(&models.Team{})
		db.Where("id = ?", project.ID).Delete(&models.Project{})
		db.Where("organization_id = ?", org.ID).Delete(&models.OrganizationMember{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
		db.Where("id = ?", owner.ID).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	h := NewNotificationConfigurationHandlerV2(
		repository.NewNotificationConfigurationRepository(db),
		repository.NewWorkspaceRepository(db),
		projectRepo,
		orgRepo,
		teamRepo,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo),
		nil, // cryptoService - only reached when a token is sent
		nil, // notifier - only reached by the verify action
	)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", owner.ID)
		c.Next()
	})
	router.POST("/api/v2/workspaces/:id/notification-configurations", h.Create)
	router.POST("/api/v2/projects/:id/notification-configurations", h.CreateForProject)
	router.POST("/api/v2/teams/:id/notification-configurations", h.CreateForTeam)
	router.GET("/api/v2/notification-configurations/:id", h.Read)

	routes := []struct {
		scope string
		path  string
	}{
		{"workspace", "/api/v2/workspaces/" + workspace.ID + "/notification-configurations"},
		{"project", "/api/v2/projects/" + project.ID.String() + "/notification-configurations"},
		{"team", "/api/v2/teams/" + ownersTeam.ID.String() + "/notification-configurations"},
	}
	sent := func(v bool) *bool { return &v }
	cases := []struct {
		name    string
		enabled *bool // nil leaves the attribute out
		want    bool
	}{
		{"explicit false", sent(false), false},
		{"explicit true", sent(true), true},
		{"absent", nil, false},
	}
	for _, route := range routes {
		for _, tc := range cases {
			t.Run(route.scope+"/"+tc.name, func(t *testing.T) {
				attrs := map[string]any{
					"name":             "ncenabled-" + uuid.NewString()[:8],
					"destination-type": "generic",
					"url":              "https://example.com/hook",
					"triggers":         []string{"run:completed"},
				}
				if tc.enabled != nil {
					attrs["enabled"] = *tc.enabled
				}
				code, id, created := createEnabledRequest(t, router, http.MethodPost, route.path, "notification-configurations", attrs)
				if code != http.StatusCreated {
					t.Fatalf("create = %d, want 201", code)
				}
				configIDs = append(configIDs, id)
				if got, ok := created["enabled"].(bool); !ok || got != tc.want {
					t.Errorf("create response: enabled = %v, want %t", created["enabled"], tc.want)
				}

				code, _, read := createEnabledRequest(t, router, http.MethodGet,
					"/api/v2/notification-configurations/"+id, "notification-configurations", nil)
				if code != http.StatusOK {
					t.Fatalf("read = %d, want 200", code)
				}
				if got, ok := read["enabled"].(bool); !ok || got != tc.want {
					t.Errorf("read back: enabled = %v, want %t", read["enabled"], tc.want)
				}
			})
		}
	}
}
