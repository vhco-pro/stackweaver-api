// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Who may create a configuration version in a workspace: a caller who may create runs there, the
// same runs and workspace write permissions RunHandlerV2.Create checks. A run created without a
// configuration version plans the workspace's latest one, so creating one is creating what a run
// plans. A caller without those permissions is refused and no row is written.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run 'TestConfigurationVersionCreate'

//go:build integration

package terraform

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestConfigurationVersionCreate_RequiresRunPermissions(t *testing.T) {
	f := setupRunCreateScope(t)
	sfx := uuid.NewString()[:8]

	// A reader: a team with read access to the workspace's project. A bystander: a member of the
	// organization with no team access to the project.
	reader := &models.User{ID: uuid.New(), ZitadelSubject: "cvperm-r-" + sfx, Email: "cvperm-r-" + sfx + "@test.local"}
	bystander := &models.User{ID: uuid.New(), ZitadelSubject: "cvperm-b-" + sfx, Email: "cvperm-b-" + sfx + "@test.local"}
	readers := &models.Team{ID: uuid.New(), OrganizationID: f.orgA, Name: "cvperm-readers-" + sfx}
	readAccess := "read"
	for _, row := range []any{
		reader, bystander, readers,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.orgA, UserID: reader.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.orgA, UserID: bystander.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: readers.ID, UserID: reader.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: readers.ID, ProjectID: f.projectA, Access: &readAccess},
	} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}
	t.Cleanup(func() {
		// Registered after the shared fixture's cleanup, so it runs first; scoped to these rows.
		f.db.Where("team_id = ?", readers.ID).Delete(&models.TeamProjectAccess{})
		f.db.Where("team_id = ?", readers.ID).Delete(&models.TeamMember{})
		f.db.Where("id = ?", readers.ID).Delete(&models.Team{})
		f.db.Where("user_id IN ?", []uuid.UUID{reader.ID, bystander.ID}).Delete(&models.OrganizationMember{})
		f.db.Where("id IN ?", []uuid.UUID{reader.ID, bystander.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(f.db)
	cvRepo := repository.NewConfigurationVersionRepository(f.db)
	h := NewConfigurationVersionHandlerV2(
		cvRepo, repository.NewWorkspaceRepository(f.db),
		auth.NewService(repository.NewUserRepository(f.db)), nil,
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)),
	)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if id, err := uuid.Parse(c.GetHeader("X-Test-User")); err == nil {
			c.Set("user_id", id)
		}
		c.Next()
	})
	router.POST("/api/v2/workspaces/:id/configuration-versions", h.Create)

	versions := func() int64 {
		t.Helper()
		var n int64
		if err := f.db.Model(&models.ConfigurationVersion{}).Where("workspace_id = ?", f.workspace).Count(&n).Error; err != nil {
			t.Fatalf("counting configuration versions: %v", err)
		}
		return n
	}
	create := func(user uuid.UUID) *httptest.ResponseRecorder {
		body := []byte(`{"data":{"type":"configuration-versions","attributes":{"auto-queue-runs":false}}}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v2/workspaces/"+f.workspace+"/configuration-versions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/vnd.api+json")
		req.Header.Set("X-Test-User", user.String())
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	for _, tc := range []struct {
		name string
		user uuid.UUID
	}{
		{"reader", reader.ID},
		{"bystander", bystander.ID},
	} {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			before := versions()
			if w := create(tc.user); w.Code != http.StatusForbidden {
				t.Fatalf("%s creating a configuration version: got %d, want 403\nbody: %s", tc.name, w.Code, w.Body.String())
			}
			if after := versions(); after != before {
				t.Fatalf("a refused create still wrote a configuration version: %d -> %d", before, after)
			}
		})
	}

	t.Run("admin creates", func(t *testing.T) {
		before := versions()
		if w := create(f.ownerID); w.Code != http.StatusCreated {
			t.Fatalf("admin creating a configuration version: got %d, want 201\nbody: %s", w.Code, w.Body.String())
		}
		if after := versions(); after != before+1 {
			t.Fatalf("admin create: configuration versions %d -> %d, want one more", before, after)
		}
	})
}
