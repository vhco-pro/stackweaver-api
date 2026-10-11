// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for POST /api/v2/runner/jobs/:id/events, the channel a self-hosted
// Ansible agent uses to record the job events the platform runner writes straight to
// the database (Galaxy install progress, the playbook source banner).
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Every row is
// created under a unique name and removed by primary key, so a run against a database
// that holds real data leaves it untouched. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRunnerJobEvents

//go:build integration

package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// agentPrepFixture is the tenant graph the runner playbook-preparation endpoints bind
// against: organization A with a project, an inventory, a VCS connection and two agent
// pools, and organization B with one pool. Runners: a1 and a2 share pool A, a3 sits in
// organization A's other pool, b1 belongs to organization B.
type agentPrepFixture struct {
	db        *gorm.DB
	orgA      uuid.UUID
	projectA  uuid.UUID
	poolA     uuid.UUID
	inventory uuid.UUID
	vcsConn   uuid.UUID
	runnerA1  *models.Runner
	runnerA2  *models.Runner
	runnerA3  *models.Runner
	runnerB1  *models.Runner
	// keys maps the X-Test-Key header value to the API key the request authenticates
	// with: one runner-scoped token per runner plus "org", an org-scoped registration key.
	keys map[string]*models.APIKey
}

func runnerTokenFor(r *models.Runner) *models.APIKey {
	return &models.APIKey{
		Scopes:         models.StringArray{"runner:" + r.ID.String() + ":heartbeat", "runner:" + r.ID.String() + ":jobs"},
		OrganizationID: &r.OrganizationID,
	}
}

func setupAgentPrepFixture(t *testing.T) *agentPrepFixture {
	t.Helper()
	db := setupAuthzTestDB(t) // shared helper in authz_matrix_test.go; migrates the full model set
	gin.SetMode(gin.TestMode)
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "agentprep-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "agentprep-b-" + sfx}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "agentprep-proj-" + sfx}
	poolA := &models.AgentPool{ID: uuid.New(), OrganizationID: orgA.ID, Name: "agentprep-pool-a-" + sfx}
	poolA2 := &models.AgentPool{ID: uuid.New(), OrganizationID: orgA.ID, Name: "agentprep-pool-a2-" + sfx}
	poolB := &models.AgentPool{ID: uuid.New(), OrganizationID: orgB.ID, Name: "agentprep-pool-b-" + sfx}
	inv := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: orgA.ID, Name: "agentprep-inv-" + sfx, Type: models.InventoryTypeStatic}
	// GitLab is the provider whose token and clone URL need no network: the token is
	// the stored one and the URL is built from it.
	conn := &models.VCSConnection{ID: uuid.New(), OrganizationID: orgA.ID, Provider: models.VCSProviderGitLab, AccessToken: "glpat-" + sfx, AccountName: "agentprep-" + sfx}

	runner := func(org, pool uuid.UUID, name string) *models.Runner {
		return &models.Runner{ID: uuid.New(), OrganizationID: org, AgentPoolID: pool, Name: name + "-" + sfx, Status: models.RunnerStatusOnline, AnsibleVersion: "2.16.0", MaxConcurrentJobs: 1}
	}
	a1 := runner(orgA.ID, poolA.ID, "agentprep-a1")
	a2 := runner(orgA.ID, poolA.ID, "agentprep-a2")
	a3 := runner(orgA.ID, poolA2.ID, "agentprep-a3")
	b1 := runner(orgB.ID, poolB.ID, "agentprep-b1")

	for _, obj := range []any{orgA, orgB, projA, poolA, poolA2, poolB, inv, conn, a1, a2, a3, b1} {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seeding %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		db.Where("id IN ?", []uuid.UUID{a1.ID, a2.ID, a3.ID, b1.ID}).Delete(&models.Runner{})
		db.Where("id = ?", conn.ID).Delete(&models.VCSConnection{})
		db.Where("id = ?", inv.ID).Delete(&models.AnsibleInventory{})
		db.Where("id IN ?", []uuid.UUID{poolA.ID, poolA2.ID, poolB.ID}).Delete(&models.AgentPool{})
		db.Where("id = ?", projA.ID).Delete(&models.Project{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
	})

	return &agentPrepFixture{
		db: db, orgA: orgA.ID, projectA: projA.ID, poolA: poolA.ID, inventory: inv.ID, vcsConn: conn.ID,
		runnerA1: a1, runnerA2: a2, runnerA3: a3, runnerB1: b1,
		keys: map[string]*models.APIKey{
			"a1": runnerTokenFor(a1), "a2": runnerTokenFor(a2), "a3": runnerTokenFor(a3), "b1": runnerTokenFor(b1),
			"org": {Scopes: models.StringArray{"org:" + orgA.ID.String() + ":runner:register"}, OrganizationID: &orgA.ID},
		},
	}
}

// seedJob inserts a job in organization A's pool A. playbookID may be nil (ad hoc
// shape); assignee, when set, is the runner the job is reserved by.
func (f *agentPrepFixture) seedJob(t *testing.T, playbookID *uuid.UUID, assignee *models.Runner) *models.AnsibleJob {
	t.Helper()
	job := &models.AnsibleJob{
		ID:          uuid.New(),
		ProjectID:   f.projectA,
		PlaybookID:  playbookID,
		InventoryID: f.inventory,
		Status:      models.AnsibleJobStatusPending,
		AgentPoolID: &f.poolA,
	}
	if assignee != nil {
		job.RunnerID = &assignee.ID
		job.Status = models.AnsibleJobStatusRunning
	}
	if err := f.db.Create(job).Error; err != nil {
		t.Fatalf("seeding job: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("job_id = ?", job.ID).Delete(&models.AnsibleJobEvent{})
		f.db.Where("id = ?", job.ID).Delete(&models.AnsibleJob{})
	})
	return job
}

// router builds the production middleware chain for the runner control plane: a
// stand-in for AuthMiddleware (the X-Test-Key header selects the API key), the real
// RunnerAuth, then the routes register adds.
func (f *agentPrepFixture) router(register func(authed *gin.RouterGroup)) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if key := f.keys[c.GetHeader("X-Test-Key")]; key != nil {
			c.Set("auth_method", "api_key")
			c.Set("api_key", key)
		}
		c.Next()
	})
	authed := r.Group("/api/v2/runner")
	authed.Use(middleware.RunnerAuth(repository.NewRunnerRepository(f.db)))
	register(authed)
	return r
}

func (f *agentPrepFixture) eventsRouter() *gin.Engine {
	h := &RunnerAgentHandler{db: f.db, ansibleJobRepo: repository.NewAnsibleJobRepository(f.db)}
	return f.router(func(authed *gin.RouterGroup) {
		authed.POST("/jobs/:id/events", middleware.MaxBodyBytes(1<<20), h.JobEvents)
	})
}

func postJobEvent(t *testing.T, r *gin.Engine, key string, jobID uuid.UUID, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encoding request body: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runner/jobs/"+jobID.String()+"/events", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Key", key)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func (f *agentPrepFixture) jobEvents(t *testing.T, jobID uuid.UUID) []models.AnsibleJobEvent {
	t.Helper()
	var events []models.AnsibleJobEvent
	if err := f.db.Where("job_id = ?", jobID).Order("counter ASC").Find(&events).Error; err != nil {
		t.Fatalf("loading job events: %v", err)
	}
	return events
}

func TestRunnerJobEvents_StoresEventWithNextCounter(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := f.eventsRouter()
	job := f.seedJob(t, nil, f.runnerA1)

	// An event already streamed for the job: the posted events must continue its
	// sequence so they interleave correctly with the playbook's own output.
	prior := &models.AnsibleJobEvent{JobID: job.ID, Event: "runner_output", Stdout: "earlier line"}
	if err := repository.NewAnsibleJobRepository(f.db).CreateEventNextCounter(prior); err != nil {
		t.Fatalf("seeding prior event: %v", err)
	}

	posts := []JobEventRequest{
		{Event: "galaxy_cache_seeded", Task: "Galaxy cache reused", Stdout: "Seeded the Galaxy staging directory from the project's warm cache (collections)\n"},
		{Event: "galaxy_install", Task: "Installing Galaxy Requirements", Stdout: "Installing collections/roles from requirements.yml\n"},
		{Event: "galaxy_install_failed", Task: "Galaxy Installation Failed", Stderr: "ERROR! could not resolve\n", Failed: true},
		{Event: "galaxy_install_complete", Task: "Galaxy Requirements Installed", Stdout: "Nothing to do.\n"},
		{Event: "playbook_source", Task: "Playbook source", Stdout: "Source: cached snapshot\n"},
	}
	for _, p := range posts {
		if rec := postJobEvent(t, r, "a1", job.ID, p); rec.Code != http.StatusOK {
			t.Fatalf("POST %s: status = %d, want 200 (body %s)", p.Event, rec.Code, rec.Body.String())
		}
	}

	events := f.jobEvents(t, job.ID)
	if len(events) != len(posts)+1 {
		t.Fatalf("stored %d events, want %d", len(events), len(posts)+1)
	}
	for i, want := range posts {
		got := events[i+1]
		if got.Event != want.Event || got.Task != want.Task || got.Stdout != want.Stdout || got.Stderr != want.Stderr || got.Failed != want.Failed {
			t.Errorf("event %d = {event:%q task:%q stdout:%q stderr:%q failed:%v}, want %+v", i, got.Event, got.Task, got.Stdout, got.Stderr, got.Failed, want)
		}
		if wantCounter := prior.Counter + i + 1; got.Counter != wantCounter {
			t.Errorf("event %d counter = %d, want %d (the job's next counter)", i, got.Counter, wantCounter)
		}
		if got.Timestamp.IsZero() {
			t.Errorf("event %d has no timestamp", i)
		}
	}
}

func TestRunnerJobEvents_RejectsEventOutsideAllowlist(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := f.eventsRouter()
	job := f.seedJob(t, nil, f.runnerA1)

	// These are the rows that drive host counters and the task tree; an agent must not
	// be able to forge them through the control-event channel.
	for _, event := range []string{"runner_on_ok", "runner_on_failed", "v2_playbook_on_stats", "runner_output", "something_else", ""} {
		t.Run("event="+event, func(t *testing.T) {
			rec := postJobEvent(t, r, "a1", job.ID, map[string]any{"event": event, "stdout": "forged"})
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
		})
	}
	if events := f.jobEvents(t, job.ID); len(events) != 0 {
		t.Errorf("stored %d events after only rejected posts, want none", len(events))
	}
}

func TestRunnerJobEvents_OnlyTheAssignedRunnerMayPost(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := f.eventsRouter()
	assigned := f.seedJob(t, nil, f.runnerA1)
	unassigned := f.seedJob(t, nil, nil)
	body := JobEventRequest{Event: "galaxy_install", Stdout: "Installing\n"}

	tests := []struct {
		name string
		key  string
		job  *models.AnsibleJob
		want int
	}{
		{"assigned runner", "a1", assigned, http.StatusOK},
		{"same pool, not the assignee", "a2", assigned, http.StatusForbidden},
		{"same organization, another pool", "a3", assigned, http.StatusForbidden},
		{"another organization", "b1", assigned, http.StatusForbidden},
		{"job not yet assigned to anyone", "a1", unassigned, http.StatusForbidden},
		{"org-scoped key that is not a runner token", "org", assigned, http.StatusForbidden},
		{"no API key", "", assigned, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := postJobEvent(t, r, tt.key, tt.job.ID, body)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
	if events := f.jobEvents(t, assigned.ID); len(events) != 1 {
		t.Errorf("assigned job has %d events, want exactly the assignee's one", len(events))
	}
	if events := f.jobEvents(t, unassigned.ID); len(events) != 0 {
		t.Errorf("unassigned job has %d events, want none", len(events))
	}
}

func TestRunnerJobEvents_RejectsOversizedBody(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := f.eventsRouter()
	job := f.seedJob(t, nil, f.runnerA1)

	rec := postJobEvent(t, r, "a1", job.ID, JobEventRequest{Event: "galaxy_install_complete", Stdout: strings.Repeat("x", 1<<20+1)})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413 for a body over the 1 MiB cap (body %.120s)", rec.Code, rec.Body.String())
	}
	if events := f.jobEvents(t, job.ID); len(events) != 0 {
		t.Errorf("stored %d events from an oversized post, want none", len(events))
	}
}
