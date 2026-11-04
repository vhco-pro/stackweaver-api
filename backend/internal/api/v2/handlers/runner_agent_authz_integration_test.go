// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for which credential reaches which runner route (#933, D1, AC3): once a runner
// has declared the job-token capability, its runner token no longer reaches a job's data; only the
// job token the executor holds does. A runner that has not declared it (an agent built before the
// job token) keeps the runner-token path for the deprecation window (D14).
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRunnerToken

//go:build integration

package handlers

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// credentialRouter mounts the routes the way SetupV2Routes does, with the job-data guard on the
// routes that carry a job's data.
func (f *agentPrepFixture) credentialRouter() (*gin.Engine, *apikey.Service) {
	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	playbookRepo := repository.NewAnsiblePlaybookRepository(f.db)
	registry := vcs.NewProviderRegistry(nil, nil, nil, nil)
	h := &RunnerAgentHandler{
		db:             f.db,
		runnerRepo:     repository.NewRunnerRepository(f.db),
		jobExecRepo:    repository.NewRunnerJobExecutionRepository(f.db),
		apiKeyService:  svc,
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
		playbookRepo:   playbookRepo,
		vcsRegistry:    registry,
		storageClient:  newSnapshotStore(),
		syncRequester:  ansible.NewPlaybookSnapshotRequester(ansible.NewWorkItemService(f.db, nil), playbookRepo),
	}
	return f.router(func(authed *gin.RouterGroup) {
		authed.POST("/heartbeat", middleware.RequireRunnerToken(), h.Heartbeat)
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.GET("/jobs/:id/status", h.GetJobStatus)
		authed.GET("/jobs/:id/artifacts", middleware.JobData(), h.GetJobArtifacts)
		authed.GET("/jobs/:id/playbook-snapshot", middleware.JobData(), h.GetPlaybookSnapshot)
		authed.POST("/jobs/:id/complete", middleware.JobData(), h.JobComplete)
		authed.POST("/jobs/:id/state", middleware.JobData(), h.UploadState)
	}), svc
}

func (f *agentPrepFixture) declareCapabilities(t *testing.T, r *models.Runner, caps ...string) {
	t.Helper()
	if err := f.db.Model(&models.Runner{}).Where("id = ?", r.ID).Update("capabilities", models.RunnerLabels(caps)).Error; err != nil {
		t.Fatalf("declaring capabilities: %v", err)
	}
}

func TestRunnerToken_RefusedOnJobDataOnceJobTokensAreDeclared(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.credentialRouter()
	f.declareCapabilities(t, f.runnerA1, runnercontract.CapabilityJobToken, runnercontract.CapabilityPlaybookSnapshot)

	job := f.seedJob(t, nil, f.runnerA1)
	id := job.ID.String()
	complete := map[string]any{"runner_id": f.runnerA1.ID.String(), "status": "completed"}

	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/v2/runner/jobs/" + id + "/artifacts", nil},
		{http.MethodGet, "/api/v2/runner/jobs/" + id + "/playbook-snapshot", nil},
		{http.MethodPost, "/api/v2/runner/jobs/" + id + "/complete", complete},
		{http.MethodPost, "/api/v2/runner/jobs/" + id + "/state", map[string]any{"runner_id": f.runnerA1.ID.String(), "state": "e30="}},
	} {
		if rec := runnerDo(t, r, "a1", tc.method, tc.path, tc.body); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with the runner token: status %d, want 403 (%s)", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}

	// The runner token still does what is the launcher's: heartbeat, status, minting.
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/heartbeat", map[string]any{"runner_id": f.runnerA1.ID.String(), "status": "online"}); rec.Code != http.StatusOK {
		t.Errorf("heartbeat with the runner token: status %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec := runnerDo(t, r, "a1", http.MethodGet, "/api/v2/runner/jobs/"+id+"/status", nil); rec.Code != http.StatusOK {
		t.Errorf("status with the runner token: status %d, want 200", rec.Code)
	}
	if code, _ := f.mintJobToken(t, r, svc, "a1", id, "job"); code != http.StatusOK {
		t.Fatalf("minting with the runner token: status %d, want 200", code)
	}

	// The job token reaches the job's data.
	if rec := runnerDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+id+"/artifacts", nil); rec.Code != http.StatusOK {
		t.Errorf("artifacts with the job token: status %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

func TestRunnerToken_OldAgentKeepsTheRunnerTokenPath(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _ := f.credentialRouter()
	// a1 declares nothing: an agent built before the job token.
	job := f.seedJob(t, nil, f.runnerA1)
	if rec := runnerDo(t, r, "a1", http.MethodGet, "/api/v2/runner/jobs/"+job.ID.String()+"/artifacts", nil); rec.Code != http.StatusOK {
		t.Errorf("artifacts for an agent without the job-token capability: status %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}
