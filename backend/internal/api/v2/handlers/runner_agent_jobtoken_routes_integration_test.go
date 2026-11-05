// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the job token on every job-data route (#933, D1, AC2): a job token reaches
// its own job's artifacts, state, plan and completion and nothing of another job's, and once its
// job is terminal it reaches nothing at all, answering the code an executor stops on.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Rows are created under unique
// names and removed by primary key. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run 'TestJobToken_(AnotherJob|Terminal)'

//go:build integration

package handlers

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// jobDataRouter mounts every route that carries one job's data, behind the guards SetupV2Routes
// gives them, plus the token route the launcher mints with.
func (f *agentPrepFixture) jobDataRouter(t *testing.T) (*gin.Engine, *apikey.Service) {
	t.Helper()
	cs, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	playbookRepo := repository.NewAnsiblePlaybookRepository(f.db)
	h := &RunnerAgentHandler{
		db:             f.db,
		runnerRepo:     repository.NewRunnerRepository(f.db),
		jobExecRepo:    repository.NewRunnerJobExecutionRepository(f.db),
		apiKeyService:  svc,
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
		playbookRepo:   playbookRepo,
		vcsRegistry:    vcs.NewProviderRegistry(nil, nil, nil, nil),
		storageClient:  newSnapshotStore(),
		cryptoService:  cs,
		syncRequester:  ansible.NewPlaybookSnapshotRequester(ansible.NewWorkItemService(f.db, nil), playbookRepo),
	}
	f.jobDataStore = h.storageClient.(*snapshotStore)
	return f.router(func(authed *gin.RouterGroup) {
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.POST("/jobs/:id/output", h.JobOutput)
		authed.GET("/jobs/:id/status", h.GetJobStatus)
		authed.GET("/jobs/:id/artifacts", middleware.JobData(), h.GetJobArtifacts)
		authed.POST("/jobs/:id/complete", middleware.JobData(), h.JobComplete)
		authed.POST("/jobs/:id/state", middleware.JobData(), h.UploadState)
		authed.POST("/jobs/:id/plan", middleware.JobData(), h.UploadPlan)
		authed.GET("/jobs/:id/plan", middleware.JobData(), h.DownloadPlan)
	}), svc
}

// stateUpload is a minimal state file in the JSON form an executor posts.
func (f *agentPrepFixture) stateUpload() map[string]any {
	state := `{"version":4,"serial":1,"lineage":"jobtoken-routes","outputs":{},"resources":[]}`
	return map[string]any{"runner_id": f.runnerA1.ID.String(), "state": base64.StdEncoding.EncodeToString([]byte(state))}
}

// jobDataCall is one request to a job-data route.
type jobDataCall struct {
	method, path string
	body         any  // JSON body, or nil
	raw          bool // the body is the plan file, posted as octet-stream
}

func (f *agentPrepFixture) doJobData(t *testing.T, r *gin.Engine, key string, call jobDataCall) (int, string, string) {
	t.Helper()
	if call.raw {
		rec := rawPost(t, r, key, call.path, []byte("PK\x03\x04 a saved plan"))
		return rec.Code, errorCode(t, rec.Body.Bytes()), rec.Body.String()
	}
	rec := runnerDo(t, r, key, call.method, call.path, call.body)
	return rec.Code, errorCode(t, rec.Body.Bytes()), rec.Body.String()
}

// runDataCalls are the job-data routes of an OpenTofu run.
func (f *agentPrepFixture) runDataCalls(runID string) []jobDataCall {
	base := "/api/v2/runner/jobs/" + runID
	return []jobDataCall{
		{method: http.MethodGet, path: base + "/artifacts"},
		{method: http.MethodPost, path: base + "/state", body: f.stateUpload()},
		{method: http.MethodPost, path: base + "/plan", raw: true},
		{method: http.MethodGet, path: base + "/plan"},
		{method: http.MethodPost, path: base + "/complete", body: map[string]any{"runner_id": f.runnerA1.ID.String(), "status": "completed"}},
	}
}

func TestJobToken_AnotherJobRefusedOnStateAndPlan(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.jobDataRouter(t)

	mine := f.seedRun(t, f.runnerA1)
	sibling := f.seedRun(t, f.runnerA1) // same runner, same pool, a different run
	if code, _ := f.mintJobToken(t, r, svc, "a1", mine.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}

	base := "/api/v2/runner/jobs/" + sibling.ID
	for _, call := range []jobDataCall{
		{method: http.MethodPost, path: base + "/state", body: f.stateUpload()},
		{method: http.MethodPost, path: base + "/plan", raw: true},
		{method: http.MethodGet, path: base + "/plan"},
	} {
		if code, _, body := f.doJobData(t, r, "job", call); code != http.StatusForbidden {
			t.Errorf("%s %s with another run's job token: status %d, want 403 (%s)", call.method, call.path, code, body)
		}
	}

	// Nothing of the sibling changed: no state version, no saved plan.
	var versions int64
	if err := f.db.Model(&models.StateVersion{}).Where("run_id = ?", sibling.ID).Count(&versions).Error; err != nil {
		t.Fatal(err)
	}
	if versions != 0 {
		t.Errorf("the sibling run has %d state versions after refused uploads, want 0", versions)
	}

	// The token still reaches its own run's plan route, so the refusals above are about the job.
	if code, _, body := f.doJobData(t, r, "job", jobDataCall{method: http.MethodPost, path: "/api/v2/runner/jobs/" + mine.ID + "/plan", raw: true}); code != http.StatusOK {
		t.Errorf("POST plan of its own run: status %d, want 200 (%s)", code, body)
	}
}

// A job deleted while it runs answers its executor's and its launcher's status poll 404, whose token
// is still valid: the row is gone, not the token (#1005). The executor reads that as the end of the
// job (TestStatusPollStopRule), as it does a cancel.
func TestJobToken_ADeletedJobAnswersItsStatusPoll404(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.jobDataRouter(t)

	job := f.seedJob(t, nil, f.runnerA1)
	if code, _ := f.mintJobToken(t, r, svc, "a1", job.ID.String(), "ansible"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	path := "/api/v2/runner/jobs/" + job.ID.String() + "/status"
	if code, _, body := f.doJobData(t, r, "ansible", jobDataCall{method: http.MethodGet, path: path}); code != http.StatusOK {
		t.Fatalf("status of a running job: %d (%s)", code, body)
	}
	if err := repository.NewAnsibleJobRepository(f.db).Delete(job.ID); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ansible", "a1"} {
		if code, _, body := f.doJobData(t, r, key, jobDataCall{method: http.MethodGet, path: path}); code != http.StatusNotFound {
			t.Errorf("status of a deleted job with %s: %d, want 404 (%s)", key, code, body)
		}
	}
}

func TestJobToken_TerminalRefusedOnEveryDataRoute(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.jobDataRouter(t)

	for _, status := range finishedRunStatuses {
		t.Run("run "+string(status), func(t *testing.T) {
			run := f.seedRun(t, f.runnerA1)
			name := "run-job-" + string(status)
			if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, name); code != http.StatusOK {
				t.Fatalf("mint: %d", code)
			}
			if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Update("status", status).Error; err != nil {
				t.Fatal(err)
			}
			for _, call := range f.runDataCalls(run.ID) {
				// A canceled run's own executor may still upload the state of what its interrupted
				// apply changed and report its completion (TestJobToken_CanceledRunAcceptsTheFinalReport).
				if status == models.RunStatusCancelled && (strings.HasSuffix(call.path, "/state") || strings.HasSuffix(call.path, "/complete")) {
					continue
				}
				code, ecode, body := f.doJobData(t, r, name, call)
				if code != http.StatusForbidden || ecode != runnercontract.ErrorCodeJobTerminal {
					t.Errorf("%s %s after the run turned %s: status %d code %q, want 403 %s (%s)", call.method, call.path, status, code, ecode, runnercontract.ErrorCodeJobTerminal, body)
				}
			}
		})
	}

	for _, status := range finishedAnsibleJobStatuses {
		t.Run("ansible job "+string(status), func(t *testing.T) {
			job := f.seedJob(t, nil, f.runnerA1)
			// Completion looks the job's execution record up before it authorizes anything.
			if err := f.db.Create(&models.RunnerJobExecution{RunnerID: f.runnerA1.ID, JobType: models.JobTypeAnsibleJob, JobID: job.ID, Status: models.JobExecutionStatusRunning}).Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.db.Where("job_id = ?", job.ID).Delete(&models.RunnerJobExecution{}) })
			name := "ansible-job-" + string(status)
			if code, _ := f.mintJobToken(t, r, svc, "a1", job.ID.String(), name); code != http.StatusOK {
				t.Fatalf("mint: %d", code)
			}
			if err := f.db.Model(&models.AnsibleJob{}).Where("id = ?", job.ID).Update("status", status).Error; err != nil {
				t.Fatal(err)
			}
			base := "/api/v2/runner/jobs/" + job.ID.String()
			for _, call := range []jobDataCall{
				{method: http.MethodGet, path: base + "/artifacts"},
				{method: http.MethodPost, path: base + "/complete", body: map[string]any{"runner_id": f.runnerA1.ID.String(), "status": "completed"}},
			} {
				code, ecode, body := f.doJobData(t, r, name, call)
				if code != http.StatusForbidden || ecode != runnercontract.ErrorCodeJobTerminal {
					t.Errorf("%s %s after the job turned %s: status %d code %q, want 403 %s (%s)", call.method, call.path, status, code, ecode, runnercontract.ErrorCodeJobTerminal, body)
				}
			}
			// The refused completion left the terminal status alone.
			var reloaded models.AnsibleJob
			if err := f.db.First(&reloaded, "id = ?", job.ID).Error; err != nil {
				t.Fatal(err)
			}
			if reloaded.Status != status {
				t.Errorf("status after a refused completion = %s, want %s", reloaded.Status, status)
			}
		})
	}
}
