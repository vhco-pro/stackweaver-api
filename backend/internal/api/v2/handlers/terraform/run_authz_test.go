// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-010 run control-plane authorization matrix. The run action/read endpoints
// (Get/GetPlan/GetLogs/GetApply/GetPlanLogs/GetApplyLogs/Cancel/Discard/ForceCancel/
// ForceExecute) performed NO RBAC check, so any authenticated user — including JWT
// identities, which bypass the org wall — could read another tenant's plan/apply
// logs or cancel/discard/force-execute their runs by run id. These tests drive the
// real handler + real rbac.Service + real Postgres and assert cross-tenant and
// unauthenticated callers are denied while a legitimate org member is allowed.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is
// strictly row-scoped (the DB may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestRunAuthz

//go:build integration
// +build integration

package terraform

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type runAuthzFixture struct {
	router   *gin.Engine
	runID    string
	owner    *models.User // org A owners team
	outsider *models.User // org B only
}

func setupRunAuthzFixture(t *testing.T) *runAuthzFixture {
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

	orgA := &models.Organization{ID: uuid.New(), Name: "runauthz-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "runauthz-b-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "run-own-" + sfx, Email: "run-own-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "run-out-" + sfx, Email: "run-out-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "projA-" + sfx}
	wsA := &models.Workspace{ID: "ws-" + sfx + "0000000", ProjectID: projA.ID, Name: "wsA"}
	runA := &models.Run{ID: "run-" + sfx + "0000000", WorkspaceID: wsA.ID, Status: models.RunStatusPlanned, Operation: models.RunOperationPlanAndApply}

	adminAccess := "admin" // grants RunRead/RunWrite/Runs on the project's workspaces
	seed := []interface{}{
		orgA, orgB, owner, outsider, ownersTeam, projA, wsA, runA,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: ownersTeam.ID, ProjectID: projA.ID, Access: &adminAccess},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		db.Where("id = ?", runA.ID).Delete(&models.Run{})
		db.Where("id = ?", wsA.ID).Delete(&models.Workspace{})
		db.Where("id = ?", projA.ID).Delete(&models.Project{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamProjectAccess{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", ownersTeam.ID).Delete(&models.Team{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{owner.ID, outsider.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	// Only the repos authorizeRun + Get's formatter touch are wired; the rest are nil
	// because the denial paths return at the gate and the owner-allow path only formats.
	h := NewRunHandlerV2(
		repository.NewRunRepository(db), repository.NewWorkspaceRepository(db), orgRepo, authService,
		nil, repository.NewConfigurationVersionRepository(db), nil, nil, nil, nil, rbacService, nil, nil, nil,
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
	router.GET("/runs/:id", h.Get)
	router.GET("/runs/:id/plan", h.GetPlan)
	router.GET("/runs/:id/logs", h.GetLogs)
	router.POST("/runs/:id/actions/cancel", h.Cancel)
	router.POST("/runs/:id/actions/discard", h.Discard)
	router.POST("/runs/:id/actions/force-execute", h.ForceExecute)

	return &runAuthzFixture{router: router, runID: runA.ID, owner: owner, outsider: outsider}
}

func runAuthzReq(t *testing.T, f *runAuthzFixture, method, path string, asUser uuid.UUID) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec.Code
}

// TestRunAuthz_CrossTenantDenied is the core AUD-010 assertion: an org-B outsider
// must not reach any org-A run endpoint, and anonymous callers get 401.
func TestRunAuthz_CrossTenantDenied(t *testing.T) {
	f := setupRunAuthzFixture(t)
	base := "/runs/" + f.runID

	reads := []struct{ m, p string }{
		{http.MethodGet, base},
		{http.MethodGet, base + "/plan"},
		{http.MethodGet, base + "/logs"},
	}
	actions := []struct{ m, p string }{
		{http.MethodPost, base + "/actions/cancel"},
		{http.MethodPost, base + "/actions/discard"},
		{http.MethodPost, base + "/actions/force-execute"},
	}

	for _, e := range append(append([]struct{ m, p string }{}, reads...), actions...) {
		t.Run("outsider "+e.p, func(t *testing.T) {
			if code := runAuthzReq(t, f, e.m, e.p, f.outsider.ID); code != http.StatusForbidden {
				t.Fatalf("outsider %s %s = %d, want 403", e.m, e.p, code)
			}
		})
		t.Run("anon "+e.p, func(t *testing.T) {
			if code := runAuthzReq(t, f, e.m, e.p, uuid.Nil); code != http.StatusUnauthorized {
				t.Fatalf("anon %s %s = %d, want 401", e.m, e.p, code)
			}
		})
	}
}

// TestRunAuthz_OwnerAllowedRead confirms a legitimate org member (owners team) still
// reads their own run — the gate must not break the happy path.
func TestRunAuthz_OwnerAllowedRead(t *testing.T) {
	f := setupRunAuthzFixture(t)
	if code := runAuthzReq(t, f, http.MethodGet, "/runs/"+f.runID, f.owner.ID); code != http.StatusOK {
		t.Fatalf("owner GET run = %d, want 200", code)
	}
}
