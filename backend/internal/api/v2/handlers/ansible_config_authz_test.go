// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The Ansible configuration reads as a signed-in session reaches them. A session is not held by
// the org wall, so the handler's own check is the only one it meets: a member of another
// organization and a member without Ansible access must both be refused. The caller is put in
// the context the way the auth middleware puts a verified JWT's user, with no token kind.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration
// +build integration

package handlers

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestAuthzAnsibleConfig_SessionReads(t *testing.T) {
	db := setupAuthzTestDB(t)
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "acfg-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "acfg-b-" + sfx}
	project := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "acfg-" + sfx}
	users := map[string]*models.User{}
	for _, name := range []string{"member", "reader", "outsider"} {
		users[name] = &models.User{ID: uuid.New(), ZitadelSubject: "acfg-" + name + "-" + sfx, Email: "acfg-" + name + "-" + sfx + "@test.local"}
	}
	memberTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "acfg-members-" + sfx}
	readerTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "acfg-readers-" + sfx}
	outsiderTeam := &models.Team{ID: uuid.New(), OrganizationID: orgB.ID, Name: "owners"}
	orgConfig := &models.AnsibleConfig{ID: uuid.New(), OrganizationID: &orgA.ID, ConfigContent: "[defaults]\nforks=10\n", CreatedByID: users["reader"].ID, UpdatedByID: users["reader"].ID}
	projectConfig := &models.AnsibleConfig{ID: uuid.New(), ProjectID: &project.ID, ConfigContent: "[defaults]\nforks=5\n", CreatedByID: users["reader"].ID, UpdatedByID: users["reader"].ID}

	rows := []any{orgA, orgB, project, memberTeam, readerTeam, outsiderTeam}
	for _, u := range users {
		rows = append(rows, u)
	}
	rows = append(rows,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: users["member"].ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: users["reader"].ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: users["outsider"].ID},
		&models.TeamMember{ID: uuid.New(), TeamID: memberTeam.ID, UserID: users["member"].ID},
		&models.TeamMember{ID: uuid.New(), TeamID: readerTeam.ID, UserID: users["reader"].ID},
		&models.TeamMember{ID: uuid.New(), TeamID: outsiderTeam.ID, UserID: users["outsider"].ID},
		&models.TeamOrganizationAccess{ID: uuid.New(), TeamID: readerTeam.ID, ReadAnsible: true},
		orgConfig, projectConfig,
	)
	// Registered before seeding, so a seed that fails part way is still removed.
	teamIDs := []uuid.UUID{memberTeam.ID, readerTeam.ID, outsiderTeam.ID}
	t.Cleanup(func() {
		db.Where("id IN ?", []uuid.UUID{orgConfig.ID, projectConfig.ID}).Delete(&models.AnsibleConfig{})
		db.Where("team_id IN ?", teamIDs).Delete(&models.TeamOrganizationAccess{})
		db.Where("team_id IN ?", teamIDs).Delete(&models.TeamMember{})
		db.Where("id IN ?", teamIDs).Delete(&models.Team{})
		db.Where("id = ?", project.ID).Delete(&models.Project{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		for _, u := range users {
			db.Where("id = ?", u.ID).Delete(&models.User{})
		}
	})
	for _, row := range rows {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	orgRepo := repository.NewOrganizationRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	h := NewAnsibleConfigHandler(
		repository.NewAnsibleConfigRepository(db), orgRepo, projectRepo,
		rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo), db,
	)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(testUserAuth())
	router.GET("/api/v2/organizations/:name/ansible-config", h.GetByOrganization)
	router.GET("/api/v2/organizations/:name/ansible-config/effective", h.GetEffective)
	router.GET("/api/v2/projects/:id/ansible-config", h.GetByProject)

	paths := []string{
		"/api/v2/organizations/" + orgA.Name + "/ansible-config",
		"/api/v2/organizations/" + orgA.Name + "/ansible-config/effective?project_id=" + project.ID.String(),
		"/api/v2/projects/" + project.ID.String() + "/ansible-config",
	}
	for _, tc := range []struct {
		caller uuid.UUID
		name   string
		want   int
	}{
		{users["outsider"].ID, "a member of another organization", http.StatusForbidden},
		{users["member"].ID, "a member without Ansible access", http.StatusForbidden},
		{uuid.Nil, "anonymous", http.StatusUnauthorized},
		{users["reader"].ID, "a member with Ansible read", http.StatusOK},
	} {
		for _, path := range paths {
			t.Run(tc.name+" "+path, func(t *testing.T) {
				rec := authzRequest(t, router, http.MethodGet, path, tc.caller, nil)
				if rec.Code != tc.want {
					t.Errorf("GET %s = %d, want %d.\nbody: %s", path, rec.Code, tc.want, rec.Body.String())
				}
			})
		}
	}
}
