// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the hosted runner identity (#933, D9, AC53, AC53a): one hosted runner with
// one token and one heartbeat serves the hosted pools of two organizations and of a pool created
// after it started; a job token stays bound to its job's organization; a hosted runner token is
// refused on a customer pool's job and a customer runner token on a hosted pool's; and RunnerAuth
// refuses a token whose kind does not fit its runner.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestHostedRunner

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

type hostedRunnerFixture struct {
	*agentPrepFixture
	group  string
	runner *models.Runner
	r      *gin.Engine
	svc    *apikey.Service
}

func setupHostedRunnerFixture(t *testing.T) *hostedRunnerFixture {
	t.Helper()
	f := setupAgentPrepFixture(t)
	sfx := uuid.NewString()[:8]
	group := "test-" + sfx
	runner := &models.Runner{ID: uuid.New(), Kind: models.RunnerKindHosted, HostedGroup: group, Name: "hosted-mo-" + sfx, Status: models.RunnerStatusOnline, MaxConcurrentJobs: 4, RunnerType: models.RunnerTypeTofu}
	if err := f.db.Create(runner).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", runner.ID).Delete(&models.Runner{}) })
	f.keys["hosted"] = &models.APIKey{ID: uuid.New(), Kind: models.APIKeyKindHosted, Scopes: models.StringArray{"runner:" + runner.ID.String() + ":heartbeat", "runner:" + runner.ID.String() + ":jobs"}}
	// A customer-kind token naming the hosted runner, and a hosted-kind token naming a customer one.
	f.keys["hosted-as-org"] = &models.APIKey{ID: uuid.New(), Kind: models.APIKeyKindOrg, OrganizationID: &f.orgA, Scopes: models.StringArray{"runner:" + runner.ID.String() + ":heartbeat"}}
	f.keys["customer-as-hosted"] = &models.APIKey{ID: uuid.New(), Kind: models.APIKeyKindHosted, Scopes: models.StringArray{"runner:" + f.runnerA1.ID.String() + ":heartbeat"}}

	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	h := &RunnerAgentHandler{
		db: f.db, apiKeyService: svc, runnerRepo: repository.NewRunnerRepository(f.db),
		jobExecRepo: repository.NewRunnerJobExecutionRepository(f.db), ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
	}
	r := f.router(func(authed *gin.RouterGroup) {
		authed.POST("/heartbeat", middleware.RequireRunnerToken(), h.Heartbeat)
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.GET("/jobs/:id/status", h.GetJobStatus)
	})
	return &hostedRunnerFixture{agentPrepFixture: f, group: group, runner: runner, r: r, svc: svc}
}

// hostedOrgRun makes an organization with a hosted pool of the fixture's group and one pending
// run on it.
func (f *hostedRunnerFixture) hostedOrgRun(t *testing.T, name string) (orgID uuid.UUID, runID string) {
	t.Helper()
	sfx := uuid.NewString()[:8]
	org := &models.Organization{ID: uuid.New(), Name: "hosted-mo-" + name + "-" + sfx}
	pool := models.NewHostedPool(org.ID)
	pool.PlacementGroup = f.group
	proj := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "hosted-mo-proj-" + sfx}
	ws := &models.Workspace{ProjectID: proj.ID, Name: "hosted-mo-ws-" + sfx, ExecutionMode: "remote"}
	for _, obj := range []any{org, pool, proj, ws} {
		if err := f.db.Create(obj).Error; err != nil {
			t.Fatal(err)
		}
	}
	run := &models.Run{WorkspaceID: ws.ID, Status: models.RunStatusPending, Operation: models.RunOperationPlanOnly, AgentPoolID: &pool.ID}
	if err := f.db.Create(run).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("id = ?", run.ID).Delete(&models.Run{})
		f.db.Where("id = ?", ws.ID).Delete(&models.Workspace{})
		f.db.Where("id = ?", proj.ID).Delete(&models.Project{})
		f.db.Where("id = ?", pool.ID).Delete(&models.AgentPool{})
		f.db.Where("id = ?", org.ID).Delete(&models.Organization{})
	})
	return org.ID, run.ID
}

func (f *hostedRunnerFixture) offers(t *testing.T, key string) []string {
	t.Helper()
	rec := runnerDo(t, f.r, key, http.MethodPost, "/api/v2/runner/heartbeat", runnercontract.HeartbeatRequest{RunnerID: f.runner.ID.String(), Status: "online"})
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat as %s: %d (%s)", key, rec.Code, rec.Body.String())
	}
	var resp runnercontract.HeartbeatResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	ids := make([]string, 0, len(resp.PendingJobs))
	for _, o := range resp.PendingJobs {
		ids = append(ids, o.JobID)
	}
	return ids
}

func TestHostedRunner_ServesEveryOrganizationOfItsGroup(t *testing.T) {
	f := setupHostedRunnerFixture(t)
	_, runA := f.hostedOrgRun(t, "a")
	orgB, runB := f.hostedOrgRun(t, "b")

	got := f.offers(t, "hosted")
	if len(got) != 2 || !slices.Contains(got, runA) || !slices.Contains(got, runB) {
		t.Fatalf("one heartbeat offered %v, want both organizations' runs", got)
	}
	// A hosted pool created after the runner started is served on its next poll.
	_, runC := f.hostedOrgRun(t, "c")
	if got := f.offers(t, "hosted"); !slices.Contains(got, runC) {
		t.Errorf("the next heartbeat offered %v, want the new organization's run %s", got, runC)
	}

	// Job tokens are bound to their job's organization.
	code, tokB := f.mintJobToken(t, f.r, f.svc, "hosted", runB, "jobB")
	if code != http.StatusOK {
		t.Fatalf("job token for org B's run: %d", code)
	}
	if k := f.keys["jobB"]; k.OrganizationID == nil || *k.OrganizationID != orgB {
		t.Errorf("org B's job token is bound to %v", k.OrganizationID)
	}
	_ = tokB
	if rec := runnerDo(t, f.r, "jobB", http.MethodGet, "/api/v2/runner/jobs/"+runA+"/status", nil); rec.Code != http.StatusForbidden {
		t.Errorf("org B's job token on org A's run = %d, want 403", rec.Code)
	}
	if rec := runnerDo(t, f.r, "jobB", http.MethodGet, "/api/v2/runner/jobs/"+runB+"/status", nil); rec.Code != http.StatusOK {
		t.Errorf("org B's job token on its own run = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

func TestHostedRunner_RefusedAcrossTheHostedBoundary(t *testing.T) {
	f := setupHostedRunnerFixture(t)
	_, hostedRun := f.hostedOrgRun(t, "x")
	f.offers(t, "hosted") // reserves the hosted run for the hosted runner

	// A customer runner's token on the hosted pool's run, and the hosted runner's token on a
	// customer pool's run.
	if rec := runnerDo(t, f.r, "a1", http.MethodGet, "/api/v2/runner/jobs/"+hostedRun+"/status", nil); rec.Code != http.StatusForbidden {
		t.Errorf("a customer runner token on a hosted run = %d, want 403", rec.Code)
	}
	customerRun := f.seedRun(t, f.runnerA1)
	if rec := runnerDo(t, f.r, "hosted", http.MethodGet, "/api/v2/runner/jobs/"+customerRun.ID+"/status", nil); rec.Code != http.StatusForbidden {
		t.Errorf("the hosted runner token on a customer pool's run = %d, want 403", rec.Code)
	}

	// A token whose kind does not fit its runner is refused by RunnerAuth itself.
	for _, key := range []string{"hosted-as-org", "customer-as-hosted"} {
		rec := runnerDo(t, f.r, key, http.MethodPost, "/api/v2/runner/heartbeat", runnercontract.HeartbeatRequest{RunnerID: uuid.NewString(), Status: "online"})
		if rec.Code != http.StatusForbidden {
			t.Errorf("heartbeat with %s = %d, want 403", key, rec.Code)
		}
	}
}
