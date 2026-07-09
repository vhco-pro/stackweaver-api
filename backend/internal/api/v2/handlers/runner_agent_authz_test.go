// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-001 runner control-plane authorization tests. Two layers:
//   - the RunnerAuth middleware (JWT/anon/non-runner-token rejected; runner token resolves);
//   - the per-handler org/pool/assignment binding helpers (authorizeRunnerForRun /
//     authorizeRunnerForAnsibleJob), which are what stop a runner in org B from pulling
//     org A's decrypted artifacts or overwriting its state.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRunnerAuthz

//go:build integration
// +build integration

package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

func setupRunnerAuthzDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupAuthzTestDB(t) // shared helper in authz_matrix_test.go
	if err := db.AutoMigrate(
		&models.Organization{}, &models.Project{}, &models.Workspace{},
		&models.Run{}, &models.Runner{}, &models.AgentPool{},
		&models.User{}, &models.APIKey{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// runnerAuthzFixture is two orgs, each with an agent pool + a runner, plus a run in
// org A assigned to runner A1. Runner A2 shares org A but is a different runner;
// runner B1 is in org B.
type runnerAuthzFixture struct {
	db        *gorm.DB
	orgA      uuid.UUID
	poolA     uuid.UUID
	poolB     uuid.UUID
	runnerA1  *models.Runner
	runnerA2  *models.Runner
	runnerB1  *models.Runner
	runAID    string // run in org A / poolA, assigned to runnerA1
	unassigned string // run in org A / poolA, no runner assigned yet
}

func setupRunnerAuthzFixture(t *testing.T) *runnerAuthzFixture {
	t.Helper()
	db := setupRunnerAuthzDB(t)
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "runauthz-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "runauthz-b-" + sfx}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "projA-" + sfx}
	poolA := &models.AgentPool{ID: uuid.New(), OrganizationID: orgA.ID, Name: "poolA-" + sfx}
	poolB := &models.AgentPool{ID: uuid.New(), OrganizationID: orgB.ID, Name: "poolB-" + sfx}
	wsA := &models.Workspace{ID: "ws-" + sfx + "0000000", ProjectID: projA.ID, Name: "wsA", AgentPoolID: &poolA.ID}

	runnerA1 := &models.Runner{ID: uuid.New(), OrganizationID: orgA.ID, AgentPoolID: poolA.ID, Name: "a1-" + sfx}
	runnerA2 := &models.Runner{ID: uuid.New(), OrganizationID: orgA.ID, AgentPoolID: poolA.ID, Name: "a2-" + sfx}
	runnerB1 := &models.Runner{ID: uuid.New(), OrganizationID: orgB.ID, AgentPoolID: poolB.ID, Name: "b1-" + sfx}

	runA := &models.Run{ID: "run-" + sfx + "0000000", WorkspaceID: wsA.ID, AgentPoolID: &poolA.ID, RunnerID: &runnerA1.ID, Status: models.RunStatusPlanning}
	runUnassigned := &models.Run{ID: "run-" + sfx + "1111111", WorkspaceID: wsA.ID, AgentPoolID: &poolA.ID, Status: models.RunStatusPending}

	for _, obj := range []interface{}{orgA, orgB, projA, poolA, poolB, wsA, runnerA1, runnerA2, runnerB1, runA, runUnassigned} {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		db.Where("id IN ?", []string{runA.ID, runUnassigned.ID}).Delete(&models.Run{})
		db.Where("id = ?", wsA.ID).Delete(&models.Workspace{})
		db.Where("id IN ?", []uuid.UUID{runnerA1.ID, runnerA2.ID, runnerB1.ID}).Delete(&models.Runner{})
		db.Where("id IN ?", []uuid.UUID{poolA.ID, poolB.ID}).Delete(&models.AgentPool{})
		db.Where("id = ?", projA.ID).Delete(&models.Project{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
	})

	return &runnerAuthzFixture{
		db: db, orgA: orgA.ID, poolA: poolA.ID, poolB: poolB.ID,
		runnerA1: runnerA1, runnerA2: runnerA2, runnerB1: runnerB1,
		runAID: runA.ID, unassigned: runUnassigned.ID,
	}
}

// ctxWithRunner builds a gin context as if RunnerAuth had resolved the given runner.
func ctxWithRunner(runner *models.Runner) (*gin.Context, *httptest.ResponseRecorder) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if runner != nil {
		c.Set(middleware.CallingRunnerKey, runner)
	}
	return c, rec
}

// TestRunnerAuthz_AuthorizeRun is the core AUD-001 matrix: only a runner in the run's
// org+pool (and, once assigned, the assignee) may touch a run.
func TestRunnerAuthz_AuthorizeRun(t *testing.T) {
	f := setupRunnerAuthzFixture(t)
	h := &RunnerAgentHandler{db: f.db}

	var assignedRun models.Run
	if err := f.db.First(&assignedRun, "id = ?", f.runAID).Error; err != nil {
		t.Fatalf("load run: %v", err)
	}
	var unassignedRun models.Run
	if err := f.db.First(&unassignedRun, "id = ?", f.unassigned).Error; err != nil {
		t.Fatalf("load unassigned run: %v", err)
	}

	cases := []struct {
		name            string
		runner          *models.Runner
		run             *models.Run
		requireAssigned bool
		want            bool
	}{
		// The crown-jewel denial: a runner in org B must never touch org A's run.
		{"cross-org runner denied (artifacts)", f.runnerB1, &assignedRun, false, false},
		// Same org, same pool, but not the assignee — denied once the run is claimed.
		{"non-assignee same-org runner denied", f.runnerA2, &assignedRun, false, false},
		// The assigned runner is allowed.
		{"assigned runner allowed", f.runnerA1, &assignedRun, false, true},
		{"assigned runner allowed (requireAssigned)", f.runnerA1, &assignedRun, true, true},
		// Unassigned run: any org-A pool-A runner may fetch artifacts (offer stage)...
		{"same-pool runner may fetch unassigned artifacts", f.runnerA2, &unassignedRun, false, true},
		// ...but requireAssigned (post-start ops) rejects an unassigned run.
		{"unassigned run rejected when assignment required", f.runnerA2, &unassignedRun, true, false},
		// Cross-org on the unassigned run is still denied (org check precedes pool).
		{"cross-org runner denied on unassigned run", f.runnerB1, &unassignedRun, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := ctxWithRunner(tc.runner)
			got := h.authorizeRunnerForRun(c, tc.run, tc.requireAssigned)
			if got != tc.want {
				t.Fatalf("authorizeRunnerForRun = %v, want %v (status %d, body %s)", got, tc.want, rec.Code, rec.Body.String())
			}
			if !got && rec.Code != http.StatusForbidden && rec.Code != http.StatusInternalServerError {
				t.Errorf("denied path should write 403, got %d", rec.Code)
			}
		})
	}
}

// TestRunnerAuthz_Middleware proves the gate that keeps JWT/browser sessions and
// non-runner tokens off the control plane entirely.
func TestRunnerAuthz_Middleware(t *testing.T) {
	f := setupRunnerAuthzFixture(t)

	apiKeyRepo := repository.NewAPIKeyRepository(f.db)
	orgRepo := repository.NewOrganizationRepository(f.db)
	teamRepo := repository.NewTeamRepository(f.db)
	projectRepo := repository.NewProjectRepository(f.db)
	apiKeySvc := apikey.NewService(apiKeyRepo, orgRepo, projectRepo, teamRepo)
	runnerRepo := repository.NewRunnerRepository(f.db)

	// A user to own the tokens.
	user := &models.User{ID: uuid.New(), ZitadelSubject: "runauthz-" + uuid.NewString()[:8], Email: "runauthz-" + uuid.NewString()[:8] + "@test.local"}
	if err := f.db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("user_id = ?", user.ID).Delete(&models.APIKey{}) // FK: keys before user
		f.db.Where("id = ?", user.ID).Delete(&models.User{})
	})

	// A valid runner token for runnerA1, and a non-runner org token.
	_, runnerTokenRaw, err := apiKeySvc.CreateRunnerToken(user.ID, f.runnerA1.ID, f.orgA, "test-runner-token")
	if err != nil {
		t.Fatalf("mint runner token: %v", err)
	}

	gin.SetMode(gin.TestMode)

	// Build a router that mimics production: auth sets context keys, then RunnerAuth.
	build := func(authSetter gin.HandlerFunc) *gin.Engine {
		r := gin.New()
		r.Use(authSetter)
		r.Use(middleware.RunnerAuth(runnerRepo))
		r.GET("/probe", func(c *gin.Context) {
			runner, ok := callingRunner(c)
			if !ok {
				c.JSON(http.StatusInternalServerError, gin.H{"err": "no runner"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"runner_id": runner.ID.String()})
		})
		return r
	}

	// JWT identity → blocked outright.
	jwtRouter := build(func(c *gin.Context) { c.Set("auth_method", "jwt"); c.Set("user_id", user.ID); c.Next() })
	// Anonymous (no auth_method) → blocked.
	anonRouter := build(func(c *gin.Context) { c.Next() })
	// Valid runner token → resolves.
	runnerKey, _ := apiKeySvc.VerifyAPIKey(runnerTokenRaw)
	runnerRouter := build(func(c *gin.Context) {
		c.Set("auth_method", "api_key")
		c.Set("api_key", runnerKey)
		c.Next()
	})
	// An org-scoped (non-runner) key → 403, not a runner token.
	orgKey := &models.APIKey{Scopes: models.StringArray{"org:" + f.orgA.String() + ":runner:register"}, OrganizationID: &f.orgA}
	orgRouter := build(func(c *gin.Context) {
		c.Set("auth_method", "api_key")
		c.Set("api_key", orgKey)
		c.Next()
	})

	cases := []struct {
		name   string
		router *gin.Engine
		want   int
	}{
		{"jwt identity blocked", jwtRouter, http.StatusUnauthorized},
		{"anonymous blocked", anonRouter, http.StatusUnauthorized},
		{"non-runner org token forbidden", orgRouter, http.StatusForbidden},
		{"valid runner token resolves", runnerRouter, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/probe", nil)
			tc.router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
