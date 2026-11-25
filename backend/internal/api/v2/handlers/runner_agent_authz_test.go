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
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/dbtest/testschema"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
)

func setupRunnerAuthzDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupAuthzTestDB(t) // shared helper in authz_matrix_test.go
	if err := testschema.Ensure(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// runnerAuthzFixture is two orgs, each with an agent pool + a runner, plus a run in
// org A assigned to runner A1. Runner A2 shares org A but is a different runner;
// runner B1 is in org B.
type runnerAuthzFixture struct {
	db         *gorm.DB
	orgA       uuid.UUID
	poolA      uuid.UUID
	poolB      uuid.UUID
	runnerA1   *models.Runner
	runnerA2   *models.Runner
	runnerB1   *models.Runner
	runAID     string // run in org A / poolA, assigned to runnerA1
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

	runnerA1 := &models.Runner{ID: uuid.New(), OrganizationID: new(orgA.ID), AgentPoolID: new(poolA.ID), Name: "a1-" + sfx}
	runnerA2 := &models.Runner{ID: uuid.New(), OrganizationID: new(orgA.ID), AgentPoolID: new(poolA.ID), Name: "a2-" + sfx}
	runnerB1 := &models.Runner{ID: uuid.New(), OrganizationID: new(orgB.ID), AgentPoolID: new(poolB.ID), Name: "b1-" + sfx}

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
		// Same org, same pool, but not the assignee - denied once the run is claimed.
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
	_, runnerTokenRaw, err := apiKeySvc.CreateRunnerToken(user.ID, f.runnerA1.ID, f.orgA, f.poolA, "test-runner-token")
	if err != nil {
		t.Fatalf("mint runner token: %v", err)
	}

	gin.SetMode(gin.TestMode)

	// Build a router that mimics production: auth sets context keys, then RunnerAuth.
	build := func(authSetter gin.HandlerFunc) *gin.Engine {
		r := gin.New()
		r.Use(authSetter)
		r.Use(middleware.RunnerAuth(runnerRepo, &middleware.LauncherTrust{Permissions: rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo)}))
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

	// A signed-in person (browser session) → blocked outright. This was a JWT identity until the
	// browser moved to the session cookie (backend-for-frontend-session-plan.md); either way it is a
	// person, not a runner.
	jwtRouter := build(func(c *gin.Context) { c.Set("auth_method", "session"); c.Set("user_id", user.ID); c.Next() })
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

	// The same runner token with its org binding removed, and with another org's binding: both
	// must be refused, never waved through.
	unboundKey := *runnerKey
	unboundKey.OrganizationID = nil
	unboundRouter := build(func(c *gin.Context) {
		c.Set("auth_method", "api_key")
		c.Set("api_key", &unboundKey)
		c.Next()
	})
	otherOrg := uuid.New()
	mismatchKey := *runnerKey
	mismatchKey.OrganizationID = &otherOrg
	mismatchRouter := build(func(c *gin.Context) {
		c.Set("auth_method", "api_key")
		c.Set("api_key", &mismatchKey)
		c.Next()
	})

	// A key a member minted for themselves that names runner A1: an organization key of A1's
	// organization, so the organization match alone would accept it. A launcher token carries
	// launcher scopes only; anything else beside them means it was not minted at registration.
	selfMinted := &models.APIKey{
		Kind: models.APIKeyKindOrg,
		Scopes: models.StringArray{
			"org:" + f.orgA.String() + ":read",
			"runner:" + f.runnerA1.ID.String() + ":heartbeat",
			"runner:" + f.runnerA1.ID.String() + ":jobs",
		},
		OrganizationID: &f.orgA,
	}
	selfMintedRouter := build(func(c *gin.Context) {
		c.Set("auth_method", "api_key")
		c.Set("api_key", selfMinted)
		c.Next()
	})

	// Launcher tokens issued before registration checked agent pool permission carry no pool. Such
	// a token stands only while its owner may manage the organization's agent pools: user is not
	// even a member of org A, poolAdmin owns it.
	poolAdmin := &models.User{ID: uuid.New(), ZitadelSubject: "runauthz-adm-" + uuid.NewString()[:8], Email: "runauthz-adm-" + uuid.NewString()[:8] + "@test.local"}
	owners := &models.Team{ID: uuid.New(), OrganizationID: f.orgA, Name: "owners"}
	for _, row := range []any{
		poolAdmin, owners,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.orgA, UserID: poolAdmin.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: owners.ID, UserID: poolAdmin.ID},
	} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	t.Cleanup(func() {
		f.db.Where("team_id = ?", owners.ID).Delete(&models.TeamMember{})
		f.db.Where("id = ?", owners.ID).Delete(&models.Team{})
		f.db.Where("user_id = ?", poolAdmin.ID).Delete(&models.OrganizationMember{})
		f.db.Where("id = ?", poolAdmin.ID).Delete(&models.User{})
	})
	if runnerKey.AgentPoolID == nil || *runnerKey.AgentPoolID != f.poolA {
		t.Fatalf("a launcher token carries pool %v, want %s", runnerKey.AgentPoolID, f.poolA)
	}
	unmarked := *runnerKey
	unmarked.AgentPoolID = nil
	unmarkedRouter := build(func(c *gin.Context) {
		c.Set("auth_method", "api_key")
		c.Set("api_key", &unmarked)
		c.Next()
	})
	unmarkedAdmin := *runnerKey
	unmarkedAdmin.AgentPoolID = nil
	unmarkedAdmin.UserID = &poolAdmin.ID
	unmarkedAdminRouter := build(func(c *gin.Context) {
		c.Set("auth_method", "api_key")
		c.Set("api_key", &unmarkedAdmin)
		c.Next()
	})

	// Job tokens carry their launcher's pool too. A customer job token minted before that mark cannot
	// be traced to the credential that minted it, so it is refused even when its launcher's own token
	// is marked, as runner A1's is.
	jobRouter := func(runner *models.Runner, marked bool) *gin.Engine {
		key, _, err := apiKeySvc.CreateJobToken(f.orgA, runner.AgentPoolID, apikey.JobPrincipal{Kind: models.JobTypeTofuRun, JobID: "run-" + uuid.NewString()[:8], RunnerID: runner.ID, Attempt: 1}, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("mint job token: %v", err)
		}
		t.Cleanup(func() { f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })
		if key.AgentPoolID == nil || *key.AgentPoolID != *runner.AgentPoolID {
			t.Fatalf("a job token carries pool %v, want %s", key.AgentPoolID, *runner.AgentPoolID)
		}
		if !marked {
			key.AgentPoolID = nil
		}
		return build(func(c *gin.Context) {
			c.Set("auth_method", "api_key")
			c.Set("api_key", key)
			c.Next()
		})
	}

	cases := []struct {
		name   string
		router *gin.Engine
		want   int
	}{
		{"unmarked job token forbidden", jobRouter(f.runnerA2, false), http.StatusForbidden},
		{"unmarked job token forbidden though its launcher's token is marked", jobRouter(f.runnerA1, false), http.StatusForbidden},
		{"marked job token resolves", jobRouter(f.runnerA2, true), http.StatusOK},
		{"unmarked token whose owner may not manage agent pools forbidden", unmarkedRouter, http.StatusForbidden},
		{"unmarked token whose owner may manage agent pools resolves", unmarkedAdminRouter, http.StatusOK},
		{"key with launcher and other scopes forbidden", selfMintedRouter, http.StatusForbidden},
		{"runner token without an org forbidden", unboundRouter, http.StatusForbidden},
		{"runner token for another org forbidden", mismatchRouter, http.StatusForbidden},
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

	// The refusal of an unmarked job token is coded job-token-revoked, so the executor holding it
	// stops instead of retrying while its job keeps running.
	rec := httptest.NewRecorder()
	jobRouter(f.runnerA2, false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/probe", nil))
	if !strings.Contains(rec.Body.String(), runnercontract.ErrorCodeJobTokenRevoked) {
		t.Errorf("unmarked job token refusal = %s, want error code %s", rec.Body.String(), runnercontract.ErrorCodeJobTokenRevoked)
	}
}

// TestRunnerAuthz_PoollessRunRefused pins that an OpenTofu run with no pool is refused like a
// pool-less Ansible job (#933, D1, D9): every run reaching a runner carries a pool, the hosted one
// by default, so a run without one is no runner's business.
func TestRunnerAuthz_PoollessRunRefused(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _ := f.attemptRouter()
	ws := &models.Workspace{ProjectID: f.projectA, Name: "poolless-ws-" + uuid.NewString()[:8]}
	if err := f.db.Create(ws).Error; err != nil {
		t.Fatal(err)
	}
	run := &models.Run{WorkspaceID: ws.ID, Status: models.RunStatusPending, Operation: models.RunOperationPlanOnly}
	if err := f.db.Create(run).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("id = ?", run.ID).Delete(&models.Run{})
		f.db.Where("id = ?", ws.ID).Delete(&models.Workspace{})
	})
	if rec := runnerDo(t, r, "a1", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/status", nil); rec.Code != http.StatusForbidden {
		t.Errorf("status of a pool-less run: %d, want 403", rec.Code)
	}
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+run.ID+"/start", map[string]any{"runner_id": f.runnerA1.ID.String()}); rec.Code != http.StatusForbidden {
		t.Errorf("claiming a pool-less run: %d, want 403", rec.Code)
	}
}

// TestRunnerAuthz_HeartbeatRenewsTheRunnerToken pins that a runner token expires unless its runner
// keeps heartbeating (#933, D1): it is minted with RunnerTokenTTL and a heartbeat renews it once
// half of that has passed.
func TestRunnerAuthz_HeartbeatRenewsTheRunnerToken(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.credentialRouter()
	sfx := uuid.NewString()[:8]
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "renewal-" + sfx, Email: "renewal-" + sfx + "@test.local"}
	if err := f.db.Create(owner).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", owner.ID).Delete(&models.User{}) })
	key, _, err := svc.CreateRunnerToken(owner.ID, f.runnerA1.ID, f.orgA, f.poolA, "renewal-"+sfx)
	if err == nil {
		t.Cleanup(func() { f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })
	}
	if err != nil {
		t.Fatalf("minting a runner token: %v", err)
	}
	if key.ExpiresAt == nil || time.Until(*key.ExpiresAt) < apikey.RunnerTokenTTL-time.Minute {
		t.Fatalf("a new runner token expires at %v, want about %s from now", key.ExpiresAt, apikey.RunnerTokenTTL)
	}

	// Most of its life has passed.
	soon := time.Now().Add(time.Hour)
	if err := f.db.Model(&models.APIKey{}).Where("id = ?", key.ID).Update("expires_at", soon).Error; err != nil {
		t.Fatal(err)
	}
	key.ExpiresAt = &soon
	f.keys["renew"] = key

	if rec := runnerDo(t, r, "renew", http.MethodPost, "/api/v2/runner/heartbeat", map[string]any{"runner_id": f.runnerA1.ID.String(), "status": "online"}); rec.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d (%s)", rec.Code, rec.Body.String())
	}
	var stored models.APIKey
	if err := f.db.First(&stored, "id = ?", key.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.ExpiresAt == nil || time.Until(*stored.ExpiresAt) < apikey.RunnerTokenTTL-time.Minute {
		t.Errorf("after the heartbeat the token expires at %v, want it renewed to about %s from now", stored.ExpiresAt, apikey.RunnerTokenTTL)
	}
}
