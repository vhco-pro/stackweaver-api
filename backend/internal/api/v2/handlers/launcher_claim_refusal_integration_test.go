// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A file sync whose effective binding changes between request and claim (#1113, D2, D3; AC-19),
// and an attempt whose pool's restriction changes after its token was issued (AC-23), driven
// through the production launcher: launcher.New runs against an httptest server serving the
// real runner routes on the slot database. The test only queues work and reads state; it never
// asks for a job token or reports a failure itself.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/executor"
	"github.com/michielvha/stackweaver/backend/internal/launcher"
	"github.com/michielvha/stackweaver/backend/internal/launcher/driver"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

// tokenResponses records the status of every job token response the launcher API sent, by job.
type tokenResponses struct {
	mu       sync.Mutex
	statuses map[string][]int
}

func (r *tokenResponses) of(jobID string) []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.statuses[jobID]...)
}

// launcherAPI serves the runner routes a launcher calls, authenticating its bearer tokens as the
// API does: the registration key by its fixed value, every other token against the database. It
// records the status of each job token response.
func (f *workItemRunnerFixture) launcherAPI(t *testing.T) (*httptest.Server, *tokenResponses) {
	t.Helper()
	// An agent token of pool A, the key an operator registers a launcher of the pool with.
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "claim-refusal-" + uuid.NewString(), Email: "claim-refusal-" + uuid.NewString()[:8] + "@example.test", Name: "claim refusal"}
	if err := f.db.Create(owner).Error; err != nil {
		t.Fatal(err)
	}
	regKey, regRaw, err := f.svc.CreateAgentToken(owner.ID, f.poolA, f.orgA, "launcher claim refusal test")
	if err != nil {
		t.Fatal(err)
	}
	f.registration = regRaw
	t.Cleanup(func() {
		// The registration key and every runner key a registration issued in the owner's name.
		f.db.Where("id = ? OR user_id = ?", regKey.ID, owner.ID).Delete(&models.APIKey{})
		f.db.Where("id = ?", owner.ID).Delete(&models.User{})
	})
	// authenticate sets what the API's API key authentication sets (auth.Service).
	authenticate := func(c *gin.Context, key *models.APIKey) {
		if key.UserID != nil {
			c.Set("user_id", *key.UserID)
		}
		c.Set("auth_method", "api_key")
		c.Set("api_key_id", key.ID)
		c.Set("api_key_scopes", []string(key.Scopes))
		c.Set("api_key", key)
		c.Set("token_kind", key.Kind)
		if key.OrganizationID != nil {
			c.Set("token_org_id", *key.OrganizationID)
		}
	}
	r := gin.New()
	r.Use(gin.CustomRecovery(func(c *gin.Context, err any) {
		t.Errorf("launcher API handler panicked: %v", err)
		c.AbortWithStatus(500)
	}))
	r.Use(func(c *gin.Context) {
		raw := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if raw != "" {
			if key, err := f.svc.VerifyAPIKey(raw); err == nil {
				authenticate(c, key)
			}
		}
		c.Next()
	})
	tokens := &tokenResponses{statuses: map[string][]int{}}
	r.Use(func(c *gin.Context) {
		c.Next()
		if strings.HasSuffix(c.Request.URL.Path, "/token") {
			tokens.mu.Lock()
			tokens.statuses[c.Param("id")] = append(tokens.statuses[c.Param("id")], c.Writer.Status())
			tokens.mu.Unlock()
		}
	})
	h := f.h
	h.poolRepo = repository.NewAgentPoolRepository(f.db)
	h.rbacService = rbac.NewServiceWithTeams(repository.NewOrganizationRepository(f.db), repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db))
	// Registration bootstraps the runner identity on the registration key, outside RunnerAuth, as
	// the API's routes mount it.
	r.POST("/api/v2/runner/register", h.Register)
	authed := r.Group("/api/v2/runner")
	authed.Use(middleware.RunnerAuth(repository.NewRunnerRepository(f.db), nil))
	authed.POST("/heartbeat", middleware.RequireRunnerToken(), h.Heartbeat)
	authed.POST("/deregister", middleware.RequireRunnerToken(), h.Deregister)
	authed.POST("/jobs/:id/start", middleware.RequireRunnerToken(), h.JobStart)
	authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
	authed.GET("/jobs/:id/status", h.GetJobStatus)
	authed.POST("/jobs/:id/output", h.JobOutput)
	authed.POST("/jobs/:id/complete", h.JobComplete)
	authed.GET("/jobs/:id/artifacts", middleware.JobData(), h.GetJobArtifacts)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		f.db.Where("agent_pool_id = ? AND name LIKE ?", f.poolA, "claim-refusal-%").Delete(&models.Runner{})
	})
	return srv, tokens
}

// kubernetesNamed is the in-process driver registered under the Kubernetes driver's name, so the
// launcher is one the API may issue an identity to while its placement stays a fake (#1113, D3).
type kubernetesNamed struct{ *driver.InProcess }

func (kubernetesNamed) Name() string { return driver.NameKubernetes }

// runLauncher starts the production launcher on pool A, registered as a non-strict Kubernetes
// launcher, with an in-process placement whose executor reports each job it is handed on placed.
func (f *workItemRunnerFixture) runLauncher(t *testing.T, srv *httptest.Server, placed chan<- string) {
	t.Helper()
	f.runLauncherWith(t, srv, func(_ context.Context, inv driver.Invocation) int {
		placed <- inv.JobID
		return 0
	})
}

// runLauncherWith starts the production launcher on pool A, registered as a non-strict Kubernetes
// launcher, with an in-process placement that runs exec as each job's executor.
func (f *workItemRunnerFixture) runLauncherWith(t *testing.T, srv *httptest.Server, exec driver.ExecutorFunc) {
	t.Helper()
	images := map[string]string{"tofu": "platform:1", "ansible": "platform:1"}
	cfg := launcher.Config{
		ServerURL: srv.URL, RegistrationToken: f.registration, PoolID: f.poolA.String(),
		Name: "claim-refusal-" + uuid.NewString()[:6], Engines: []string{"ansible"}, Capacity: 1, JobImages: images,
		HeartbeatWait: time.Second, IdleBeat: 50 * time.Millisecond, StatusInterval: 50 * time.Millisecond,
		DrainGrace: 2 * time.Second, KillGrace: 100 * time.Millisecond,
	}
	d := &driver.InProcess{JobImages: images, Executors: map[string]driver.ExecutorFunc{"ansible": exec}}
	l := launcher.New(cfg, kubernetesNamed{d})
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = l.Run(ctx)
	}()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the launcher did not stop")
		}
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestLauncherClaim_BindingChangedBeforeTheClaim(t *testing.T) {
	f := setupWorkItemRunner(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	// The project now selects a binding of another pool, which pool A does not offer.
	elsewhere := f.otherPoolBinding(t)
	f.selectOnProject(t, elsewhere.ID)

	srv, tokens := f.launcherAPI(t)
	placed := make(chan string, 4)
	f.runLauncher(t, srv, placed)

	waitFor(t, "the work item to fail", func() bool { return f.reload(t, item.ID).Status == models.WorkItemStatusFailed })
	got := f.reload(t, item.ID)
	// The Kubernetes launcher could take a binding, so the refusal is the queued pool's offer check.
	if !strings.HasPrefix(got.ErrorMessage, "the launcher could not obtain a job token:") ||
		!strings.Contains(got.ErrorMessage, "belongs to another pool than the one the job runs on") || !strings.Contains(got.ErrorMessage, elsewhere.Name) {
		t.Errorf("work item error = %q, want the token refusal naming %s as not offered by the queued pool", got.ErrorMessage, elsewhere.Name)
	}
	if statuses := tokens.of(item.ID); len(statuses) == 0 || statuses[0] != http.StatusConflict {
		t.Errorf("job token responses = %v, want 409", statuses)
	}
	var stored models.AnsibleInventory
	if err := f.db.First(&stored, "id = ?", inv.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.LastSyncStatus != "failed" || !strings.Contains(stored.LastSyncError, "could not obtain a job token") {
		t.Errorf("inventory last sync = %q %q, want the failure", stored.LastSyncStatus, stored.LastSyncError)
	}
	var history models.AnsibleInventorySync
	if err := f.db.Where("inventory_id = ?", inv.ID).Order("created_at DESC").First(&history).Error; err != nil {
		t.Errorf("reading the sync history: %v, want a failed row", err)
	} else if history.Status != models.InventorySyncStatusFailed {
		t.Errorf("sync history = %s, want failed", history.Status)
	}
	select {
	case job := <-placed:
		t.Errorf("job %s was placed after its token was refused", job)
	default:
	}

	// The next request queues on the binding's pool, which lets the project use it.
	if err := f.db.Exec("INSERT INTO agent_pool_allowed_projects (agent_pool_id, project_id) VALUES (?, ?) ON CONFLICT DO NOTHING", elsewhere.AgentPoolID, f.projectA).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Exec("DELETE FROM agent_pool_allowed_projects WHERE agent_pool_id = ?", elsewhere.AgentPoolID)
	})
	next, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if next.AgentPoolID == nil || *next.AgentPoolID != elsewhere.AgentPoolID {
		t.Errorf("the next sync queued on %v, want the binding's pool %s", next.AgentPoolID, elsewhere.AgentPoolID)
	}
}

func TestLauncherClaim_ClearedSelectionRunsWithNoIdentity(t *testing.T) {
	f := setupWorkItemRunner(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	f.selectOnProject(t, nil)

	srv, _ := f.launcherAPI(t)
	placed := make(chan string, 4)
	f.runLauncher(t, srv, placed)
	select {
	case job := <-placed:
		if job != item.ID {
			t.Errorf("placed %s, want %s", job, item.ID)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the sync with a cleared selection was never placed")
	}
	got := f.reload(t, item.ID).Placement
	if got.Identity == nil || got.Identity.BindingID != nil || got.Identity.Mechanism != models.PlacementMechanismPlatform {
		t.Errorf("decision = %+v, want the platform identity on the queued pool", got.Identity)
	}
}

// The executor of an attempt issued before its pool's restriction changed still fetches its
// artifacts, and one whose inventory moved project after the first token gets 409 and no clone
// inputs (#1113, D2; AC-23). The launcher claims the sync and is issued its token; then the pool
// stops letting the inventory's project use it, or the inventory moves to another project; then
// the placed executor asks for its artifacts with the token the launcher handed it.
func TestLauncherClaim_ArtifactsAfterTheTokenWasIssued(t *testing.T) {
	for _, change := range []string{"restriction changed", "inventory moved"} {
		t.Run(change, func(t *testing.T) {
			f := setupWorkItemRunner(t)
			b := f.binding(t, f.poolA, "files")
			f.selectOnProject(t, b.ID)
			inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
			item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
			if err != nil {
				t.Fatal(err)
			}

			type fetch struct {
				art runnercontract.WorkItemArtifacts
				err error
			}
			placed, proceed, fetched := make(chan string, 1), make(chan struct{}), make(chan fetch, 1)
			srv, tokens := f.launcherAPI(t)
			f.runLauncherWith(t, srv, func(ctx context.Context, call driver.Invocation) int {
				placed <- call.JobID
				select {
				case <-proceed:
				case <-ctx.Done():
					return 1
				}
				var art runnercontract.WorkItemArtifacts
				err := executor.NewClient(call.ServerURL, call.Token, call.RunnerID).Artifacts(ctx, call.JobID, &art, func() int { return art.ContractVersion })
				fetched <- fetch{art: art, err: err}
				return 0
			})
			select {
			case job := <-placed:
				if job != item.ID {
					t.Fatalf("placed %s, want %s", job, item.ID)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("the sync was never placed")
			}
			if statuses := tokens.of(item.ID); len(statuses) != 1 || statuses[0] != http.StatusOK {
				t.Fatalf("job token responses = %v, want one 200 before placement", statuses)
			}
			if got := f.reload(t, item.ID).Placement; got.Identity == nil || got.Identity.BindingID == nil || *got.Identity.BindingID != b.ID {
				t.Fatalf("decision = %+v, want binding %s", got.Identity, b.ID)
			}

			switch change {
			case "restriction changed":
				// Pool A stops letting project A use it; a new request is refused by then.
				if err := f.db.Exec("DELETE FROM agent_pool_allowed_projects WHERE agent_pool_id = ? AND project_id = ?", f.poolA, f.projectA).Error; err != nil {
					t.Fatal(err)
				}
				if _, err := f.items.RequestInventorySync(t.Context(), inv, "manual"); !errors.Is(err, ansible.ErrPoolNotAllowed) {
					t.Fatalf("a new request after the restriction changed = %v, want ErrPoolNotAllowed", err)
				}
			case "inventory moved":
				moved := &models.Project{ID: uuid.New(), OrganizationID: f.orgA, Name: "claim-moved-" + uuid.NewString()[:8]}
				if err := f.db.Create(moved).Error; err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("project_id", f.projectA)
					f.db.Where("id = ?", moved.ID).Delete(&models.Project{})
				})
				if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("project_id", moved.ID).Error; err != nil {
					t.Fatal(err)
				}
			}

			close(proceed)
			var got fetch
			select {
			case got = <-fetched:
			case <-time.After(30 * time.Second):
				t.Fatal("the executor's artifacts request never returned")
			}
			if change == "restriction changed" {
				if got.err != nil {
					t.Fatalf("the executor's artifacts request: %v", got.err)
				}
				if got.art.Clone == nil || got.art.InventoryPath != "hosts.yml" || got.art.JobID != item.ID {
					t.Errorf("artifacts = %+v, want the inventory's clone inputs", got.art)
				}
				return
			}
			var se *executor.StatusError
			if !errors.As(got.err, &se) || se.Code != http.StatusConflict || got.art.Clone != nil {
				t.Errorf("artifacts after the move = %v, clone %+v; want 409 and no clone inputs", got.err, got.art.Clone)
			}
		})
	}
}
