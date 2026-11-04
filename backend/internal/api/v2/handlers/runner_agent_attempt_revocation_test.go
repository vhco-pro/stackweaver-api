// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for attempt revocation (#933, D3, AC67, AC2): a job token belongs to one attempt
// of one job. Once a later attempt exists, or the job is terminal, the token is refused on every
// route with the code an executor stops on, and completion and re-claim revoke the job's tokens.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAttempt

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
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// errorCode returns the JSON:API error code of a refusal, or "".
func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var doc struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || len(doc.Errors) == 0 {
		return ""
	}
	return doc.Errors[0].Code
}

// seedRun inserts a run in organization A's pool A, on a workspace in project A, claimed by
// assignee and executing its plan phase.
func (f *agentPrepFixture) seedRun(t *testing.T, assignee *models.Runner) *models.Run {
	t.Helper()
	ws := &models.Workspace{ProjectID: f.projectA, Name: "agentprep-ws-" + uuid.NewString()[:8], ExecutionMode: "agent", AgentPoolID: &f.poolA}
	if err := f.db.Create(ws).Error; err != nil {
		t.Fatalf("seeding workspace: %v", err)
	}
	run := &models.Run{WorkspaceID: ws.ID, Status: models.RunStatusPlanning, Operation: models.RunOperationPlanOnly, AgentPoolID: &f.poolA, RunnerID: &assignee.ID, Attempt: 1}
	if err := f.db.Create(run).Error; err != nil {
		t.Fatalf("seeding run: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("id = ?", run.ID).Delete(&models.Run{})
		f.db.Where("id = ?", ws.ID).Delete(&models.Workspace{})
	})
	return run
}

func (f *agentPrepFixture) attemptRouter() (*gin.Engine, *apikey.Service) {
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
		authed.POST("/jobs/:id/start", middleware.RequireRunnerToken(), h.JobStart)
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.GET("/jobs/:id/status", h.GetJobStatus)
		authed.GET("/jobs/:id/artifacts", middleware.JobData(), h.GetJobArtifacts)
		authed.POST("/jobs/:id/complete", middleware.JobData(), h.JobComplete)
	}), svc
}

// jobTokenRows counts the live job tokens of a job: the ones that still verify. A revoked token is
// expired, not deleted, so its executor is answered job-token-revoked (AC67, AC72).
func (f *agentPrepFixture) jobTokenRows(t *testing.T, kind models.JobType, jobID string) int64 {
	t.Helper()
	var n int64
	if err := f.db.Model(&models.APIKey{}).Where("kind = ? AND scopes::text LIKE ? AND (expires_at IS NULL OR expires_at > ?)", models.APIKeyKindJob, "%\"job:"+string(kind)+":"+jobID+":%", time.Now().UTC()).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAttempt_StaleTokenRefusedOnEveryRoute(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.attemptRouter()

	for _, tc := range []struct {
		name string
		id   string
	}{
		{
			name: "ansible job",
			id: func() string {
				j := f.seedJob(t, nil, f.runnerA1)
				return j.ID.String()
			}(),
		},
		{name: "opentofu run", id: f.seedRun(t, f.runnerA1).ID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, tok := f.mintJobToken(t, r, svc, "a1", tc.id, "job"); code != http.StatusOK || tok.Attempt != 1 {
				t.Fatalf("mint: status %d, attempt %d", code, tok.Attempt)
			}
			if rec := runnerDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+tc.id+"/status", nil); rec.Code != http.StatusOK {
				t.Fatalf("status before the re-dispatch: %d (%s)", rec.Code, rec.Body.String())
			}

			// A later attempt exists: the launcher was lost and the job re-dispatched.
			table := "ansible_jobs"
			if tc.name == "opentofu run" {
				table = "runs"
			}
			if err := f.db.Table(table).Where("id = ?", tc.id).Update("attempt", 2).Error; err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{"/status", "/artifacts"} {
				rec := runnerDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+tc.id+p, nil)
				if rec.Code != http.StatusForbidden || errorCode(t, rec.Body.Bytes()) != runnercontract.ErrorCodeJobTokenRevoked {
					t.Errorf("GET %s with the attempt-1 token: status %d code %q, want 403 %s", p, rec.Code, errorCode(t, rec.Body.Bytes()), runnercontract.ErrorCodeJobTokenRevoked)
				}
			}
		})
	}
}

func TestAttempt_TerminalJobAnswersJobTerminal(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.attemptRouter()
	run := f.seedRun(t, f.runnerA1)
	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Update("status", models.RunStatusCancelled).Error; err != nil {
		t.Fatal(err)
	}
	rec := runnerDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/status", nil)
	if rec.Code != http.StatusForbidden || errorCode(t, rec.Body.Bytes()) != runnercontract.ErrorCodeJobTerminal {
		t.Errorf("status of a canceled run with its job token: %d %q, want 403 %s", rec.Code, errorCode(t, rec.Body.Bytes()), runnercontract.ErrorCodeJobTerminal)
	}
	// The runner token is still told the status, which is how an older agent learns of a cancel.
	if rec := runnerDo(t, r, "a1", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/status", nil); rec.Code != http.StatusOK {
		t.Errorf("status with the runner token: %d, want 200", rec.Code)
	}
	// And a finished run serves no artifacts to anyone.
	if rec := runnerDo(t, r, "a1", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/artifacts", nil); rec.Code != http.StatusForbidden {
		t.Errorf("artifacts of a finished run with the runner token: %d, want 403", rec.Code)
	}
}

func TestAttempt_CompletionRevokesTheJobsTokens(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.attemptRouter()
	job := f.seedJob(t, nil, f.runnerA1)
	if err := f.db.Create(&models.RunnerJobExecution{RunnerID: f.runnerA1.ID, JobType: models.JobTypeAnsibleJob, JobID: job.ID, Status: models.JobExecutionStatusRunning}).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("job_id = ?", job.ID).Delete(&models.RunnerJobExecution{}) })
	if code, _ := f.mintJobToken(t, r, svc, "a1", job.ID.String(), "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	if n := f.jobTokenRows(t, models.JobTypeAnsibleJob, job.ID.String()); n != 1 {
		t.Fatalf("stored job tokens after mint = %d, want 1", n)
	}
	rec := runnerDo(t, r, "job", http.MethodPost, "/api/v2/runner/jobs/"+job.ID.String()+"/complete", map[string]any{"runner_id": f.runnerA1.ID.String(), "status": "completed"})
	if rec.Code != http.StatusOK {
		t.Fatalf("complete with the job token: %d (%s)", rec.Code, rec.Body.String())
	}
	if n := f.jobTokenRows(t, models.JobTypeAnsibleJob, job.ID.String()); n != 0 {
		t.Errorf("stored job tokens after completion = %d, want 0", n)
	}
}

func TestAttempt_ReclaimRevokesEarlierTokens(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.attemptRouter()
	job := f.seedJob(t, nil, f.runnerA1)
	if code, _ := f.mintJobToken(t, r, svc, "a1", job.ID.String(), "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	// The job is put back for a re-dispatch, and a2 claims it.
	if err := f.db.Model(&models.AnsibleJob{}).Where("id = ?", job.ID).Updates(map[string]any{"status": models.AnsibleJobStatusPending, "runner_id": nil}).Error; err != nil {
		t.Fatal(err)
	}
	if rec := runnerDo(t, r, "a2", http.MethodPost, "/api/v2/runner/jobs/"+job.ID.String()+"/start", map[string]any{"runner_id": f.runnerA2.ID.String()}); rec.Code != http.StatusOK {
		t.Fatalf("re-claim: %d (%s)", rec.Code, rec.Body.String())
	}
	if n := f.jobTokenRows(t, models.JobTypeAnsibleJob, job.ID.String()); n != 0 {
		t.Errorf("stored tokens of the earlier attempt after the re-claim = %d, want 0", n)
	}
	var reloaded models.AnsibleJob
	if err := f.db.First(&reloaded, "id = ?", job.ID).Error; err != nil {
		t.Fatal(err)
	}
	if reloaded.Attempt < 1 {
		t.Errorf("attempt after the re-claim = %d, want it incremented", reloaded.Attempt)
	}
}
