// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the operator hooks (#933, D11, AC18, AC78): a just-in-time registration
// token, minted by a key bound to its pool, registers one launcher once; a remote drain reaches
// the launcher through its heartbeat; the pool's queue depth breaks the pending work down by
// engine and reports the headroom its launchers have left.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run 'TestJITToken|TestDrain|TestQueueDepth_'

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

// operatorRouter mounts the pool routes and registration behind the same stand-in for
// AuthMiddleware registerRouter uses.
func (f *agentPrepFixture) operatorRouter() *gin.Engine {
	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	pools := &AgentPoolHandlerV2{poolRepo: repository.NewAgentPoolRepository(f.db), apiKeyService: svc, runnerRepo: repository.NewRunnerRepository(f.db)}
	runners := &RunnerAgentHandler{db: f.db, runnerRepo: repository.NewRunnerRepository(f.db), poolRepo: repository.NewAgentPoolRepository(f.db), apiKeyService: svc}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		key := f.keys[c.GetHeader("X-Test-Key")]
		if key == nil {
			c.Next()
			return
		}
		c.Set("auth_method", "api_key")
		c.Set("api_key", key)
		c.Set("api_key_id", key.ID)
		c.Set("api_key_scopes", []string(key.Scopes))
		c.Set("token_kind", key.Kind)
		if key.UserID != nil {
			c.Set("user_id", *key.UserID)
		}
		c.Next()
	})
	r.POST("/api/v2/agent-pools/:id/jit-token", pools.JITToken)
	r.GET("/api/v2/agent-pools/:id/queue-depth", pools.QueueDepth)
	r.POST("/api/v2/runner/register", runners.Register)
	return r
}

// agentToken stores a pool-bound agent token owned by owner.
func (f *agentPrepFixture) agentToken(t *testing.T, owner uuid.UUID, org, pool uuid.UUID) *models.APIKey {
	t.Helper()
	k := &models.APIKey{
		ID: uuid.New(), Name: "operator-" + uuid.NewString()[:6], Kind: models.APIKeyKindOrg, KeyHash: "x", KeyPrefix: "tfe-op",
		Scopes: models.StringArray{"org:" + org.String() + ":runner:register"}, OrganizationID: &org, AgentPoolID: &pool, IsAgentToken: true, UserID: &owner,
	}
	if err := f.db.Create(k).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", k.ID).Delete(&models.APIKey{}) })
	return k
}

func (f *agentPrepFixture) operatorOwner(t *testing.T) uuid.UUID {
	t.Helper()
	sfx := uuid.NewString()[:8]
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "operator-" + sfx, Email: "operator-" + sfx + "@test.local"}
	if err := f.db.Create(owner).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", owner.ID).Delete(&models.User{}) })
	return owner.ID
}

// mintJIT mints a JIT token for pool with the key named by header and returns the stored key.
func (f *agentPrepFixture) mintJIT(t *testing.T, r *gin.Engine, header string, pool uuid.UUID) (*models.APIKey, int) {
	t.Helper()
	rec := runnerDo(t, r, header, http.MethodPost, "/api/v2/agent-pools/"+pool.String()+"/jit-token", map[string]any{"data": map[string]any{"type": "agent-jit-tokens"}})
	if rec.Code != http.StatusCreated {
		return nil, rec.Code
	}
	var doc struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				Token     string    `json:"token"`
				ExpiresAt time.Time `json:"expires-at"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Data.Attributes.Token == "" || time.Until(doc.Data.Attributes.ExpiresAt) <= 0 || time.Until(doc.Data.Attributes.ExpiresAt) > time.Hour {
		t.Fatalf("JIT token = %+v, want a token expiring within the hour", doc.Data.Attributes)
	}
	var key models.APIKey
	if err := f.db.First(&key, "id = ?", doc.Data.ID).Error; err != nil {
		t.Fatalf("the JIT token is not stored as a key: %v", err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })
	if !key.IsJITToken || !key.IsAgentToken || key.AgentPoolID == nil || *key.AgentPoolID != pool {
		t.Fatalf("stored JIT key = %+v, want a single-use agent token bound to the pool", key)
	}
	return &key, rec.Code
}

func TestJITToken_RegistersOneLauncherOnceIntoItsPool(t *testing.T) {
	f := setupAgentPrepFixture(t)
	owner := f.operatorOwner(t)
	r := f.operatorRouter()
	f.keys["agent"] = f.agentToken(t, owner, f.orgA, f.poolA)
	f.keys["other-pool"] = f.agentToken(t, owner, f.orgA, *f.runnerA3.AgentPoolID)

	if _, code := f.mintJIT(t, r, "other-pool", f.poolA); code != http.StatusForbidden {
		t.Errorf("another pool's agent token minting for pool A = %d, want 403", code)
	}
	if _, code := f.mintJIT(t, r, "a1", f.poolA); code != http.StatusForbidden {
		t.Errorf("a runner token minting = %d, want 403", code)
	}

	jit, _ := f.mintJIT(t, r, "agent", f.poolA)
	f.keys["jit"] = jit
	name := "jit-" + uuid.NewString()[:8]
	t.Cleanup(func() {
		var runner models.Runner
		if f.db.First(&runner, "name = ?", name).Error == nil {
			f.db.Where("scopes::text LIKE ?", "%runner:"+runner.ID.String()+":%").Delete(&models.APIKey{})
			f.db.Where("id = ?", runner.ID).Delete(&models.Runner{})
		}
	})

	// Naming another pool is refused and does not use the token up.
	if rec := runnerDo(t, r, "jit", http.MethodPost, "/api/v2/runner/register", map[string]any{"agent_pool_id": f.runnerA3.AgentPoolID.String(), "name": name, "tofu_version": "1.9.0"}); rec.Code != http.StatusForbidden {
		t.Errorf("a JIT token registering into another pool = %d, want 403", rec.Code)
	}
	if rec := runnerDo(t, r, "jit", http.MethodPost, "/api/v2/runner/register", map[string]any{"agent_pool_id": f.poolA.String(), "name": name, "tofu_version": "1.9.0"}); rec.Code != http.StatusCreated {
		t.Fatalf("a JIT token registering = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := runnerDo(t, r, "jit", http.MethodPost, "/api/v2/runner/register", map[string]any{"agent_pool_id": f.poolA.String(), "name": name + "-again", "tofu_version": "1.9.0"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("a JIT token registering a second time = %d, want 401", rec.Code)
	}
	var used models.APIKey
	f.db.First(&used, "id = ?", jit.ID)
	if used.ExpiresAt == nil || used.ExpiresAt.After(time.Now()) {
		t.Errorf("the used JIT token stays valid until %v", used.ExpiresAt)
	}

	// A JIT token is not one of the pool's listed agent tokens.
	tokens, err := repository.NewAPIKeyRepository(f.db).ListAgentTokens(f.poolA)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range tokens {
		if k.ID == jit.ID {
			t.Error("the JIT token is listed among the pool's agent tokens")
		}
	}
}

func TestDrain_RemoteDrainReachesTheLauncher(t *testing.T) {
	f := setupAgentPrepFixture(t)
	h := &RunnerAgentHandler{db: f.db, runnerRepo: repository.NewRunnerRepository(f.db), ansibleJobRepo: repository.NewAnsibleJobRepository(f.db)}
	r := f.router(func(authed *gin.RouterGroup) {
		authed.POST("/drain", middleware.RequireRunnerToken(), h.Drain)
		authed.POST("/heartbeat", middleware.RequireRunnerToken(), h.Heartbeat)
	})
	t.Cleanup(func() {
		f.db.Model(&models.Runner{}).Where("id IN ?", []uuid.UUID{f.runnerA1.ID, f.runnerA2.ID}).Update("drain_requested_at", nil)
	})
	f.seedJob(t, nil, nil)

	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/drain", runnercontract.DrainRequest{RunnerID: f.runnerA2.ID.String()}); rec.Code != http.StatusForbidden {
		t.Errorf("a runner draining another runner = %d, want 403", rec.Code)
	}
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/drain", runnercontract.DrainRequest{RunnerID: f.runnerA1.ID.String()}); rec.Code != http.StatusAccepted {
		t.Fatalf("drain = %d (%s)", rec.Code, rec.Body.String())
	}
	beat := func(key string, runner *models.Runner) runnercontract.HeartbeatResponse {
		rec := runnerDo(t, r, key, http.MethodPost, "/api/v2/runner/heartbeat", runnercontract.HeartbeatRequest{RunnerID: runner.ID.String(), Status: "online"})
		var resp runnercontract.HeartbeatResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp
	}
	if resp := beat("a1", f.runnerA1); !resp.Drain || len(resp.PendingJobs) != 0 {
		t.Errorf("the drained runner's heartbeat = drain %v with %d offers, want drain and no offers", resp.Drain, len(resp.PendingJobs))
	}
	if resp := beat("a2", f.runnerA2); resp.Drain {
		t.Error("another runner of the pool was asked to drain")
	}
}

func TestQueueDepth_ByEngineWithHeadroom(t *testing.T) {
	f := setupAgentPrepFixture(t)
	owner := f.operatorOwner(t)
	f.keys["agent"] = f.agentToken(t, owner, f.orgA, f.poolA)
	r := f.operatorRouter()
	// Pool A: two launchers of capacity 3 and 2, one job in flight; one pending Ansible job, one
	// pending inventory sync (Ansible) and one pending playbook snapshot (any engine).
	if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA1.ID).Update("max_concurrent_jobs", 3).Error; err != nil {
		t.Fatal(err)
	}
	f.seedJob(t, nil, f.runnerA1) // in flight on a1
	if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA2.ID).Update("max_concurrent_jobs", 2).Error; err != nil {
		t.Fatal(err)
	}
	job := f.seedJob(t, nil, nil)
	now := time.Now()
	f.db.Model(&models.AnsibleJob{}).Where("id = ?", job.ID).Update("queued_at", now)
	for _, kind := range []string{models.WorkItemInventoryFileSync, models.WorkItemPlaybookSnapshot} {
		item := &models.WorkItem{ID: "wi-" + uuid.NewString()[:16], OrganizationID: f.orgA, Kind: kind, Status: models.WorkItemStatusPending, AgentPoolID: &f.poolA, QueuedAt: &now}
		if err := f.db.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}

	rec := runnerDo(t, r, "agent", http.MethodGet, "/api/v2/agent-pools/"+f.poolA.String()+"/queue-depth", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("queue depth = %d %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Data struct {
			Attributes QueueDepthAttributes `json:"attributes"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	a := doc.Data.Attributes
	if a.PendingAnsibleJobs != 1 || a.PendingWorkItems != 2 {
		t.Errorf("by kind = %+v", a)
	}
	if a.PendingByEngine.Tofu != 0 || a.PendingByEngine.Ansible != 2 || a.PendingByEngine.Any != 1 {
		t.Errorf("by engine = %+v, want ansible 2 (the job and the inventory sync), any 1 (the snapshot)", a.PendingByEngine)
	}
	if a.Capacity != 5 || a.InFlight != 1 || a.Headroom != 4 {
		t.Errorf("capacity %d, in flight %d, headroom %d; want 5, 1, 4", a.Capacity, a.InFlight, a.Headroom)
	}
}
