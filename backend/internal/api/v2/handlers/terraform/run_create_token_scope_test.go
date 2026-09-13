// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// #806: POST /api/v2/runs is classified agnostic() in the org wall because the target
// workspace arrives in the request body, where the wall - which reads path params -
// cannot see it. The agnostic branch calls c.Next() immediately, so nothing about the
// token was checked, and RunHandlerV2.Create authorized purely through
// rbacService.CheckResourcePermission on the KEY OWNER's user id.
//
// The consequence: an org-A-bound API key created runs in an org-B workspace whenever
// its human owner happened to hold run permissions in B. This test pins the boundary at
// the handler, which is the half the middleware unit tests cannot reach - it proves the
// guard is actually wired into Create, and wired BEFORE the RBAC check rather than after.

//go:build integration

package terraform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type runCreateScopeFixture struct {
	router    *gin.Engine
	runRepo   *repository.RunRepository
	orgA      uuid.UUID // holds the workspace
	orgB      uuid.UUID // the token is bound here
	ownerID   uuid.UUID // admin in org A, member of org B
	workspace string    // lives in org A
}

// setupRunCreateScope seeds the exact shape the escalation needs: one user who is
// legitimately privileged in org A, and a token bound to org B. Under the old code the
// owner's org-A permissions carried the org-B token straight through.
func setupRunCreateScope(t *testing.T) *runCreateScopeFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.OrganizationMember{},
		&models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{}, &models.TeamProjectAccess{},
		&models.Project{}, &models.Workspace{}, &models.Run{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "runscope-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "runscope-b-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "runscope-" + sfx, Email: "runscope-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "projA-" + sfx}
	wsA := &models.Workspace{ID: "ws-" + sfx + "0000000", ProjectID: projA.ID, Name: "wsA"}

	adminAccess := "admin" // grants Runs + WorkspaceWrite on the project's workspaces
	seed := []interface{}{
		orgA, orgB, owner, ownersTeam, projA, wsA,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: ownersTeam.ID, ProjectID: projA.ID, Access: &adminAccess},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		// Row-scoped only: TEST_DATABASE_URL points at the live dev database.
		db.Where("workspace_id = ?", wsA.ID).Delete(&models.Run{})
		db.Where("id = ?", wsA.ID).Delete(&models.Workspace{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamProjectAccess{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", ownersTeam.ID).Delete(&models.Team{})
		db.Where("id = ?", projA.ID).Delete(&models.Project{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id = ?", owner.ID).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	runRepo := repository.NewRunRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))

	h := NewRunHandlerV2(
		runRepo, repository.NewWorkspaceRepository(db), orgRepo, authService,
		nil, repository.NewConfigurationVersionRepository(db), nil, nil, nil, nil, rbacService, nil, nil, nil, nil, nil,
		middleware.NewDBOrgResolver(db),
	)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		// Seed the context the way AuthMiddleware does for an api-key request.
		c.Set("user_id", owner.ID)
		if kind := c.GetHeader("X-Test-Token-Kind"); kind != "" {
			c.Set("token_kind", kind)
		}
		if bound := c.GetHeader("X-Test-Token-Org"); bound != "" {
			if id, err := uuid.Parse(bound); err == nil {
				c.Set("token_org_id", id)
			}
		}
		c.Next()
	})
	router.POST("/api/v2/runs", h.Create)

	return &runCreateScopeFixture{
		router: router, runRepo: runRepo,
		orgA: orgA.ID, orgB: orgB.ID, ownerID: owner.ID, workspace: wsA.ID,
	}
}

func (f *runCreateScopeFixture) postRun(t *testing.T, tokenKind string, boundOrg *uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"type":       "runs",
			"attributes": map[string]any{"message": "scope test"},
			"relationships": map[string]any{
				"workspace": map[string]any{
					"data": map[string]any{"type": "workspaces", "id": f.workspace},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v2/runs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	if tokenKind != "" {
		req.Header.Set("X-Test-Token-Kind", tokenKind)
	}
	if boundOrg != nil {
		req.Header.Set("X-Test-Token-Org", boundOrg.String())
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

// The regression test for #806.
func TestRunCreate_OrgBoundTokenCannotReachAnotherOrg(t *testing.T) {
	f := setupRunCreateScope(t)

	_, before, err := f.runRepo.ListByWorkspace(f.workspace, 100, 0)
	if err != nil {
		t.Fatalf("count runs before: %v", err)
	}

	w := f.postRun(t, models.APIKeyKindOrg, &f.orgB)

	if w.Code != http.StatusForbidden {
		t.Fatalf("org-B-bound token creating a run in an org-A workspace: got %d, want 403.\nbody: %s",
			w.Code, w.Body.String())
	}

	// A 403 that still wrote the row would be no fix at all.
	_, after, err := f.runRepo.ListByWorkspace(f.workspace, 100, 0)
	if err != nil {
		t.Fatalf("count runs after: %v", err)
	}
	if after != before {
		t.Fatalf("denied request still created a run: %d -> %d", before, after)
	}
}

// The guard must not break the legitimate path: a token bound to the workspace's own
// org still gets past it and on to the normal RBAC check. The request may still fail
// further down (this fixture wires no storage or VCS), so the assertion is precisely
// "not blocked by the org guard".
func TestRunCreate_OrgBoundTokenAllowedInItsOwnOrg(t *testing.T) {
	f := setupRunCreateScope(t)

	w := f.postRun(t, models.APIKeyKindOrg, &f.orgA)

	if w.Code == http.StatusForbidden {
		t.Fatalf("org-A-bound token creating a run in an org-A workspace was blocked: got 403.\nbody: %s",
			w.Body.String())
	}
}

// A browser/JWT session carries no token_kind, so the guard must not govern it - the
// handler's existing RBAC remains its only gate, exactly as before.
func TestRunCreate_JWTIdentityUnaffected(t *testing.T) {
	f := setupRunCreateScope(t)

	w := f.postRun(t, "", nil)

	if w.Code == http.StatusForbidden {
		t.Fatalf("JWT identity with admin access was blocked by the token guard: got 403.\nbody: %s",
			w.Body.String())
	}
}
