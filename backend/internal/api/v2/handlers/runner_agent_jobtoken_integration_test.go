// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the job token (#933, D1, AC2): the launcher mints one per claimed job with
// its runner token, and the executor reaches that one job's data with it and nothing else.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Rows are created under unique
// names and removed by primary key. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestJobToken

//go:build integration

package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// jobTokenRouter wires the job-token route and the job-data routes the way SetupV2Routes does.
func (f *agentPrepFixture) jobTokenRouter() (*gin.Engine, *apikey.Service) {
	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	playbookRepo := repository.NewAnsiblePlaybookRepository(f.db)
	registry := vcs.NewProviderRegistry(nil, nil, nil, nil)
	h := &RunnerAgentHandler{
		db:             f.db,
		apiKeyService:  svc,
		jobExecRepo:    repository.NewRunnerJobExecutionRepository(f.db),
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
		playbookRepo:   playbookRepo,
		vcsRegistry:    registry,
		storageClient:  newSnapshotStore(),
		syncRequester:  ansible.NewPlaybookSnapshotRequester(ansible.NewWorkItemService(f.db, nil), playbookRepo),
	}
	return f.router(func(authed *gin.RouterGroup) {
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.GET("/jobs/:id/artifacts", h.GetJobArtifacts)
		authed.GET("/jobs/:id/status", h.GetJobStatus)
		authed.POST("/jobs/:id/complete", h.JobComplete)
	}), svc
}

// mintJobToken mints a job token for jobID as the runner behind runnerKey, and registers the key
// it returns under name so later requests can present it.
func (f *agentPrepFixture) mintJobToken(t *testing.T, r *gin.Engine, svc *apikey.Service, runnerKey, jobID, name string) (int, runnercontract.JobToken) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runner/jobs/"+jobID+"/token", nil)
	req.Header.Set("X-Test-Key", runnerKey)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var tok runnercontract.JobToken
	if rec.Code != http.StatusOK {
		return rec.Code, tok
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatalf("decoding job token: %v (%s)", err, rec.Body.String())
	}
	key, err := svc.VerifyAPIKey(tok.Token)
	if err != nil {
		t.Fatalf("the minted job token does not verify: %v", err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })
	f.keys[name] = key
	return rec.Code, tok
}

func runnerDo(t *testing.T, r *gin.Engine, key, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Key", key)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestJobToken_MintedOnlyForAClaimedJob(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.jobTokenRouter()

	unclaimed := f.seedJob(t, nil, nil)
	if code, _ := f.mintJobToken(t, r, svc, "a1", unclaimed.ID.String(), "x"); code != http.StatusForbidden {
		t.Errorf("minting for an unclaimed job: status %d, want 403", code)
	}
	otherRunners := f.seedJob(t, nil, f.runnerA2)
	if code, _ := f.mintJobToken(t, r, svc, "a1", otherRunners.ID.String(), "x"); code != http.StatusForbidden {
		t.Errorf("minting for a job another runner holds: status %d, want 403", code)
	}

	mine := f.seedJob(t, nil, f.runnerA1)
	code, tok := f.mintJobToken(t, r, svc, "a1", mine.ID.String(), "job")
	if code != http.StatusOK {
		t.Fatalf("minting for the runner's own claimed job: status %d, want 200", code)
	}
	if tok.JobID != mine.ID.String() || tok.ContractVersion != runnercontract.Version || tok.Attempt < 1 {
		t.Errorf("token response = %+v", tok)
	}
	if !tok.ExpiresAt.After(time.Now()) {
		t.Errorf("expires_at %s is not in the future", tok.ExpiresAt)
	}
	key := f.keys["job"]
	if key.Kind != models.APIKeyKindJob || key.UserID != nil || key.OrganizationID == nil || *key.OrganizationID != f.orgA {
		t.Errorf("minted key: kind %q owner %v org %v, want an ownerless job key bound to organization A", key.Kind, key.UserID, key.OrganizationID)
	}

	// A job token cannot mint further tokens.
	if code, _ := f.mintJobToken(t, r, svc, "job", mine.ID.String(), "x"); code != http.StatusForbidden {
		t.Errorf("minting with a job token: status %d, want 403", code)
	}
}

func TestJobToken_ReachesOnlyItsOwnJob(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.jobTokenRouter()

	mine := f.seedJob(t, nil, f.runnerA1)
	sibling := f.seedJob(t, nil, f.runnerA1) // same runner, a different job
	if code, _ := f.mintJobToken(t, r, svc, "a1", mine.ID.String(), "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}

	if rec := runnerDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+mine.ID.String()+"/artifacts", nil); rec.Code != http.StatusOK {
		t.Errorf("own job's artifacts: status %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec := runnerDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+mine.ID.String()+"/status", nil); rec.Code != http.StatusOK {
		t.Errorf("own job's status: status %d, want 200", rec.Code)
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v2/runner/jobs/" + sibling.ID.String() + "/artifacts"},
		{http.MethodGet, "/api/v2/runner/jobs/" + sibling.ID.String() + "/status"},
		{http.MethodPost, "/api/v2/runner/jobs/" + sibling.ID.String() + "/complete"},
	} {
		body := any(nil)
		if tc.method == http.MethodPost {
			body = map[string]any{"runner_id": f.runnerA1.ID.String(), "status": "completed"}
		}
		if rec := runnerDo(t, r, "job", tc.method, tc.path, body); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with another job's token: status %d, want 403", tc.method, tc.path, rec.Code)
		}
	}
}

func TestJobToken_RefusedOnceTheJobIsTerminal(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.jobTokenRouter()

	job := f.seedJob(t, nil, f.runnerA1)
	if code, _ := f.mintJobToken(t, r, svc, "a1", job.ID.String(), "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	if err := f.db.Model(&models.AnsibleJob{}).Where("id = ?", job.ID).Update("status", models.AnsibleJobStatusCanceled).Error; err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/artifacts", "/status"} {
		if rec := runnerDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+job.ID.String()+p, nil); rec.Code != http.StatusForbidden {
			t.Errorf("GET %s after the job turned terminal: status %d, want 403", p, rec.Code)
		}
	}
}
