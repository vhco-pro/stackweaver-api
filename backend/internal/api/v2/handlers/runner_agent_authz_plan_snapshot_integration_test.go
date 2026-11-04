// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the runner token on the saved-plan and snapshot routes (#933, D1, AC3):
// once a runner has declared the job-token capability, its runner token reaches neither a run's
// saved plan, in either direction, nor a work item's snapshot upload. Only the job token its
// executor holds does.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRunnerToken_RefusedOnPlanAndSnapshot

//go:build integration

package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

func TestRunnerToken_RefusedOnPlanAndSnapshot(t *testing.T) {
	t.Run("saved plan", func(t *testing.T) {
		f := setupAgentPrepFixture(t)
		store := newSnapshotStore()
		r, svc, _ := f.planRouter(t, store)
		f.declareCapabilities(t, f.runnerA1, runnercontract.CapabilityJobToken)
		run := f.seedRun(t, f.runnerA1)
		path := "/api/v2/runner/jobs/" + run.ID + "/plan"

		if rec := rawPost(t, r, "a1", path, []byte("PK\x03\x04 plan")); rec.Code != http.StatusForbidden {
			t.Errorf("POST plan with the runner token: status %d, want 403 (%s)", rec.Code, rec.Body.String())
		}
		if _, err := store.Get(t.Context(), planFileKey(run.ID)); err == nil {
			t.Error("a refused upload stored a plan")
		}

		// The job token stores it, and the runner token still cannot read it back.
		if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job"); code != http.StatusOK {
			t.Fatalf("mint: %d", code)
		}
		if rec := rawPost(t, r, "job", path, []byte("PK\x03\x04 plan")); rec.Code != http.StatusOK {
			t.Fatalf("POST plan with the job token: status %d, want 200 (%s)", rec.Code, rec.Body.String())
		}
		if rec := runnerDo(t, r, "a1", http.MethodGet, path, nil); rec.Code != http.StatusForbidden {
			t.Errorf("GET plan with the runner token: status %d, want 403 (%d bytes)", rec.Code, rec.Body.Len())
		}
		if rec := runnerDo(t, r, "job", http.MethodGet, path, nil); rec.Code != http.StatusOK {
			t.Errorf("GET plan with the job token: status %d, want 200 (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("snapshot", func(t *testing.T) {
		f := setupWorkItemRunner(t) // a1 and a2 declare the job-token capability
		pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached})
		item, err := f.items.RequestPlaybookSnapshot(t.Context(), pb, "manual")
		if err != nil {
			t.Fatal(err)
		}
		f.onPool(t, item)
		f.claim(t, "a1", item.ID, "wi")

		upload := func(key string) *httptest.ResponseRecorder {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/snapshot", bytes.NewReader([]byte("tarball")))
			req.Header.Set("X-Test-Key", key)
			rec := httptest.NewRecorder()
			f.r.ServeHTTP(rec, req)
			return rec
		}
		if rec := upload("a1"); rec.Code != http.StatusForbidden {
			t.Errorf("POST snapshot with the runner token: status %d, want 403 (%s)", rec.Code, rec.Body.String())
		}
		if _, err := f.store.Get(t.Context(), ansible.PlaybookSnapshotKey(pb.ID)); err == nil {
			t.Error("a refused upload stored a snapshot")
		}
		if rec := upload("wi"); rec.Code != http.StatusOK {
			t.Errorf("POST snapshot with the job token: status %d, want 200 (%s)", rec.Code, rec.Body.String())
		}
	})
}
