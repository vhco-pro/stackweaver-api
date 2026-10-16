// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Force-unlocking a workspace removes a lock someone else holds, so it requires admin access on
// the workspace, which is what TFE requires for POST /workspaces/:id/actions/force-unlock. Lock
// and unlock need only the lock permission, which plan and write access also carry.
//
// A signed-in session is not held by the org wall, so the handler's own check is the only one a
// session meets. These cases drive the real handler, the real rbac.Service and real Postgres as
// a session would reach them: the caller is put in the context the way the auth middleware puts
// a verified JWT's user, with no token kind.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration
// +build integration

package terraform

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

type forceUnlockFixture struct {
	db          *gorm.DB
	router      *gin.Engine
	workspaceID string
	locker      uuid.UUID
	users       map[string]uuid.UUID
	org         *models.Organization
	projectID   uuid.UUID
	rbac        *rbac.Service
	orgRepo     *repository.OrganizationRepository
}

func setupForceUnlockFixture(t *testing.T) *forceUnlockFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "fu-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "fu-b-" + sfx}
	project := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "fu-" + sfx}
	workspace := &models.Workspace{ID: "ws-fu" + sfx + "00000", ProjectID: project.ID, Name: "fu-" + sfx}

	// One team per role, so each user holds exactly the access its name says.
	roles := []struct {
		name, org         string
		projectAccess     string // "" = none
		workspaceAccess   string // "" = none
		owners, manageAll bool
	}{
		{name: "owner", org: "a", owners: true},
		{name: "manage-all", org: "a", manageAll: true},
		{name: "project-admin", org: "a", projectAccess: "admin"},
		{name: "project-maintain", org: "a", projectAccess: "maintain"},
		{name: "workspace-admin", org: "a", workspaceAccess: "admin"},
		{name: "project-write", org: "a", projectAccess: "write"},
		{name: "workspace-write", org: "a", workspaceAccess: "write"},
		{name: "project-read", org: "a", projectAccess: "read"},
		{name: "outsider", org: "b", owners: true},
	}

	var rows []any
	rows = append(rows, orgA, orgB, project, workspace)
	users := map[string]uuid.UUID{}
	var userIDs, teamIDs []uuid.UUID
	for _, r := range roles {
		org := orgA
		if r.org == "b" {
			org = orgB
		}
		user := &models.User{ID: uuid.New(), ZitadelSubject: "fu-" + r.name + "-" + sfx, Email: "fu-" + r.name + "-" + sfx + "@test.local"}
		teamName := "fu-" + r.name + "-" + sfx
		if r.owners {
			teamName = "owners"
		}
		team := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: teamName}
		rows = append(rows, user, team,
			&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: user.ID},
			&models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: user.ID},
		)
		if r.manageAll {
			rows = append(rows, &models.TeamOrganizationAccess{ID: uuid.New(), TeamID: team.ID, ManageWorkspaces: true})
		}
		if r.projectAccess != "" {
			level := r.projectAccess
			rows = append(rows, &models.TeamProjectAccess{ID: uuid.New(), TeamID: team.ID, ProjectID: project.ID, Access: &level})
		}
		if r.workspaceAccess != "" {
			level := r.workspaceAccess
			rows = append(rows, &models.TeamWorkspaceAccess{ID: uuid.New(), TeamID: team.ID, WorkspaceID: workspace.ID, Access: &level})
		}
		users[r.name] = user.ID
		userIDs = append(userIDs, user.ID)
		teamIDs = append(teamIDs, team.ID)
	}
	for _, row := range rows {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	t.Cleanup(func() {
		db.Where("workspace_id = ?", workspace.ID).Delete(&models.TeamWorkspaceAccess{})
		db.Where("id = ?", workspace.ID).Delete(&models.Workspace{})
		db.Where("team_id IN ?", teamIDs).Delete(&models.TeamProjectAccess{})
		db.Where("team_id IN ?", teamIDs).Delete(&models.TeamOrganizationAccess{})
		db.Where("team_id IN ?", teamIDs).Delete(&models.TeamMember{})
		db.Where("id IN ?", teamIDs).Delete(&models.Team{})
		db.Where("id = ?", project.ID).Delete(&models.Project{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", userIDs).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	h := NewWorkspaceHandlerV2(
		repository.NewWorkspaceRepository(db), projectRepo, orgRepo,
		repository.NewVCSConnectionRepository(db), teamRepo,
		nil, repository.NewRunRepository(db),
		auth.NewService(repository.NewUserRepository(db)),
		nil,
		rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo),
		nil, db,
	)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if v := c.GetHeader("X-Test-User"); v != "" {
			if id, err := uuid.Parse(v); err == nil {
				c.Set("user_id", id)
			}
		}
		c.Next()
	})
	router.POST("/api/v2/workspaces/:id/actions/force-unlock", h.ForceUnlock)
	router.POST("/api/v2/workspaces/:id/actions/unlock", h.Unlock)
	router.GET("/api/v2/workspaces/:id", h.GetByID)
	router.GET("/api/v2/organizations/:name/workspaces", h.ListByOrganization)

	return &forceUnlockFixture{
		db: db, router: router, workspaceID: workspace.ID, locker: users["project-write"], users: users,
		org: orgA, projectID: project.ID, rbac: rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo), orgRepo: orgRepo,
	}
}

// lock puts the workspace under a lock held by another user than any caller below.
func (f *forceUnlockFixture) lock(t *testing.T) {
	t.Helper()
	now := time.Now()
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.workspaceID).
		Updates(map[string]any{"locked": true, "locked_by": f.locker, "locked_at": now, "locked_reason": "held"}).Error; err != nil {
		t.Fatalf("lock workspace: %v", err)
	}
}

func (f *forceUnlockFixture) locked(t *testing.T) bool {
	t.Helper()
	var ws models.Workspace
	if err := f.db.Where("id = ?", f.workspaceID).First(&ws).Error; err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	return ws.Locked
}

func (f *forceUnlockFixture) forceUnlock(t *testing.T, workspaceID string, asUser uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v2/workspaces/"+workspaceID+"/actions/force-unlock", nil)
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func TestForceUnlockAuthz_SessionCallers(t *testing.T) {
	f := setupForceUnlockFixture(t)

	refused := []struct {
		caller string
		want   int
	}{
		{"project-read", http.StatusForbidden},
		// Write access carries the lock permission, which is enough to lock and unlock but not
		// to remove a lock someone else holds.
		{"project-write", http.StatusForbidden},
		{"workspace-write", http.StatusForbidden},
		{"outsider", http.StatusForbidden},
		{"anonymous", http.StatusUnauthorized},
	}
	for _, tc := range refused {
		t.Run(tc.caller+" is refused", func(t *testing.T) {
			f.lock(t)
			rec := f.forceUnlock(t, f.workspaceID, f.users[tc.caller])
			if rec.Code != tc.want {
				t.Errorf("force-unlock as %s = %d, want %d.\nbody: %s", tc.caller, rec.Code, tc.want, rec.Body.String())
			}
			if !f.locked(t) {
				t.Errorf("force-unlock as %s removed the lock", tc.caller)
			}
		})
	}

	for _, caller := range []string{"owner", "manage-all", "project-admin", "project-maintain", "workspace-admin"} {
		t.Run(caller+" force-unlocks", func(t *testing.T) {
			f.lock(t)
			rec := f.forceUnlock(t, f.workspaceID, f.users[caller])
			if rec.Code != http.StatusOK {
				t.Fatalf("force-unlock as %s = %d, want 200.\nbody: %s", caller, rec.Code, rec.Body.String())
			}
			if f.locked(t) {
				t.Errorf("force-unlock as %s answered 200 and left the lock", caller)
			}
		})
	}

	// An outsider learns nothing about the lock: an unlocked workspace is refused the same way.
	t.Run("outsider is refused before the lock state is read", func(t *testing.T) {
		f.lock(t)
		if rec := f.forceUnlock(t, f.workspaceID, f.users["owner"]); rec.Code != http.StatusOK {
			t.Fatalf("unlock for the setup = %d", rec.Code)
		}
		if rec := f.forceUnlock(t, f.workspaceID, f.users["outsider"]); rec.Code != http.StatusForbidden {
			t.Errorf("outsider on an unlocked workspace = %d, want 403.\nbody: %s", rec.Code, rec.Body.String())
		}
	})
}
