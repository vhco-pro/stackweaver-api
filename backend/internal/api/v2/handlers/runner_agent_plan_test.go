// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the saved-plan round trip (#933, D2, AC6, AC73): the plan job uploads
// plan.out, the API stores it sealed at runs/<id>/plan.out, and the apply job's artifacts point at
// the download route, which returns the plaintext to that job's token only.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestSavedPlan

//go:build integration

package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

func (f *agentPrepFixture) planRouter(t *testing.T, store *snapshotStore) (*gin.Engine, *apikey.Service, *crypto.CryptoService) {
	t.Helper()
	cs, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	h := &RunnerAgentHandler{
		db:             f.db,
		runnerRepo:     repository.NewRunnerRepository(f.db),
		apiKeyService:  svc,
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
		storageClient:  store,
		cryptoService:  cs,
	}
	return f.router(func(authed *gin.RouterGroup) {
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.POST("/jobs/:id/plan", middleware.JobData(), h.UploadPlan)
		authed.GET("/jobs/:id/plan", middleware.JobData(), h.DownloadPlan)
		authed.GET("/jobs/:id/artifacts", middleware.JobData(), h.GetJobArtifacts)
	}), svc, cs
}

func rawPost(t *testing.T, r *gin.Engine, key, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Test-Key", key)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestSavedPlan_RoundTrip(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc, cs := f.planRouter(t, store)
	run := f.seedRun(t, f.runnerA1)
	plan := []byte("PK\x03\x04 a saved plan with a sensitive value: hunter2")

	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "plan-job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	if rec := rawPost(t, r, "plan-job", "/api/v2/runner/jobs/"+run.ID+"/plan", plan); rec.Code != http.StatusOK {
		t.Fatalf("upload: %d (%s)", rec.Code, rec.Body.String())
	}

	raw, err := store.Get(t.Context(), "runs/"+run.ID+"/plan.out")
	if err != nil {
		t.Fatalf("no object at runs/<id>/plan.out: %v", err)
	}
	if bytes.Contains(raw, []byte("hunter2")) || bytes.Equal(raw, plan) {
		t.Fatal("the stored plan is readable as plaintext")
	}
	if opened, err := cs.DecryptAtRest(raw, nil); err != nil || !bytes.Equal(opened, plan) {
		t.Fatalf("the stored plan does not open with the at-rest helper: %v", err)
	}

	// The apply phase: a new claim, a new attempt, a new token.
	if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Updates(map[string]any{"status": models.RunStatusApplying, "attempt": 2}).Error; err != nil {
		t.Fatal(err)
	}
	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "apply-job"); code != http.StatusOK {
		t.Fatalf("mint for the apply: %d", code)
	}
	rec := runnerDo(t, r, "apply-job", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/artifacts", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply artifacts: %d (%s)", rec.Code, rec.Body.String())
	}
	var arts runnercontract.TofuArtifacts
	if err := json.Unmarshal(rec.Body.Bytes(), &arts); err != nil {
		t.Fatal(err)
	}
	if arts.Plan == nil || arts.Plan.Path != "/api/v2/runner/jobs/"+run.ID+"/plan" {
		t.Fatalf("apply artifacts plan descriptor = %+v", arts.Plan)
	}

	got := runnerDo(t, r, "apply-job", http.MethodGet, arts.Plan.Path, nil)
	if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), plan) {
		t.Fatalf("download: %d, %d bytes, want the plan back", got.Code, got.Body.Len())
	}
	// The plan job's token belongs to an earlier attempt and reads nothing.
	if stale := runnerDo(t, r, "plan-job", http.MethodGet, arts.Plan.Path, nil); stale.Code != http.StatusForbidden {
		t.Errorf("download with the plan attempt's token: %d, want 403", stale.Code)
	}
}

func TestSavedPlan_UploadOnlyWhilePlanning(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc, _ := f.planRouter(t, newSnapshotStore())
	run := f.seedRun(t, f.runnerA1)
	if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Update("status", models.RunStatusApplying).Error; err != nil {
		t.Fatal(err)
	}
	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	if rec := rawPost(t, r, "job", "/api/v2/runner/jobs/"+run.ID+"/plan", []byte("x")); rec.Code != http.StatusConflict {
		t.Errorf("uploading a plan during the apply: %d, want 409", rec.Code)
	}
}
