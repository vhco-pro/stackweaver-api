// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the final report of a canceled run: cancelling an apply interrupts
// OpenTofu, which saves the state of what it already changed, and the executor then uploads that
// state, its last output and its completion. Those three are accepted for the canceled run's own
// attempt, as TFE persists the state of an interrupted apply; the run stays canceled, its log ends
// with a cancel marker, and every other job-data route stays closed.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Rows are created under unique
// names and removed by primary key. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run 'TestJobToken_CanceledRun'

//go:build integration

package handlers

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

// seedApplyingRun is a plan-and-apply run in its apply phase on a1, as the apply job's claim leaves it.
func (f *agentPrepFixture) seedApplyingRun(t *testing.T) *models.Run {
	t.Helper()
	run := f.seedRun(t, f.runnerA1)
	if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Updates(map[string]any{
		"status": models.RunStatusApplying, "operation": models.RunOperationPlanAndApply, "plan_completed_at": time.Now(),
	}).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("run_id = ?", run.ID).Delete(&models.StateVersion{}) })
	return run
}

// cancelAsTheAPIDoes moves the run to canceled the way RunHandlerV2.Cancel does.
func (f *agentPrepFixture) cancelAsTheAPIDoes(t *testing.T, runID string) {
	t.Helper()
	ok, err := repository.NewRunRepository(f.db).TransitionStatus(runID, []models.RunStatus{models.RunStatusApplying, models.RunStatusPlanning}, models.RunStatusCancelled, map[string]any{"completed_at": time.Now()})
	if err != nil || !ok {
		t.Fatalf("cancel: %v, %v", ok, err)
	}
}

func TestJobToken_CanceledRunAcceptsTheFinalReport(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.jobDataRouter(t)
	store := f.jobDataStore

	run := f.seedApplyingRun(t)
	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	f.cancelAsTheAPIDoes(t, run.ID)
	base := "/api/v2/runner/jobs/" + run.ID

	// The interrupted apply's last output, the state OpenTofu saved, and the completion.
	interrupt := "Interrupt received.\nPlease wait for OpenTofu to exit or data loss may occur.\n"
	for _, call := range []jobDataCall{
		{method: http.MethodPost, path: base + "/output", body: map[string]any{"runner_id": f.runnerA1.ID.String(), "output": interrupt, "stream": "apply"}},
		{method: http.MethodPost, path: base + "/state", body: f.stateUpload()},
		{method: http.MethodPost, path: base + "/complete", body: map[string]any{"runner_id": f.runnerA1.ID.String(), "status": "canceled", "exit_code": 1}},
	} {
		if code, ecode, body := f.doJobData(t, r, "job", call); code != http.StatusOK {
			t.Errorf("%s %s after the run was canceled: status %d code %q, want 200 (%s)", call.method, call.path, code, ecode, body)
		}
	}

	var reloaded models.Run
	if err := f.db.First(&reloaded, "id = ?", run.ID).Error; err != nil {
		t.Fatal(err)
	}
	if reloaded.Status != models.RunStatusCancelled {
		t.Errorf("status after the final report = %s, want %s", reloaded.Status, models.RunStatusCancelled)
	}
	var versions int64
	if err := f.db.Model(&models.StateVersion{}).Where("run_id = ?", run.ID).Count(&versions).Error; err != nil {
		t.Fatal(err)
	}
	if versions != 1 {
		t.Errorf("state versions of the canceled run = %d, want 1: the interrupted apply's state is kept", versions)
	}
	log := storedText(t, store, "runs/"+run.ID+"/logs/apply.log")
	if !strings.Contains(log, "Interrupt received.") {
		t.Errorf("the apply log lost the interrupted apply's output:\n%s", log)
	}
	if !strings.Contains(log, cancelMarker) {
		t.Errorf("the apply log has no cancel marker %q:\n%s", cancelMarker, log)
	}

	// The completion revoked the job's tokens, so the report is accepted once: the middleware answers
	// a revoked token job-token-revoked (TestAuthenticate_RevokedJobTokenAnswersJobTokenRevoked). The test harness maps its
	// keys directly, so the revocation is read from the tokens themselves.
	if n := f.jobTokenRows(t, models.JobTypeTofuRun, run.ID); n != 0 {
		t.Errorf("live job tokens after the completion of the canceled run = %d, want 0", n)
	}
}

// Cancelling opens the final report and nothing else: the run's artifacts and saved plan stay
// closed, and a run that ended any other way accepts no report at all.
func TestJobToken_CanceledRunOpensOnlyTheFinalReport(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.jobDataRouter(t)

	run := f.seedApplyingRun(t)
	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	f.cancelAsTheAPIDoes(t, run.ID)
	base := "/api/v2/runner/jobs/" + run.ID
	for _, call := range []jobDataCall{
		{method: http.MethodGet, path: base + "/artifacts"},
		{method: http.MethodPost, path: base + "/plan", raw: true},
		{method: http.MethodGet, path: base + "/plan"},
	} {
		if code, ecode, body := f.doJobData(t, r, "job", call); code != http.StatusForbidden || ecode != runnercontract.ErrorCodeJobTerminal {
			t.Errorf("%s %s of a canceled run: status %d code %q, want 403 %s (%s)", call.method, call.path, code, ecode, runnercontract.ErrorCodeJobTerminal, body)
		}
	}

	// Another runner's token, or a later attempt's, is still refused on the report routes.
	other := f.seedApplyingRun(t)
	if code, _ := f.mintJobToken(t, r, svc, "a1", other.ID, "stale"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	if err := f.db.Model(&models.Run{}).Where("id = ?", other.ID).Update("attempt", 2).Error; err != nil {
		t.Fatal(err)
	}
	f.cancelAsTheAPIDoes(t, other.ID)
	if code, ecode, body := f.doJobData(t, r, "stale", jobDataCall{method: http.MethodPost, path: "/api/v2/runner/jobs/" + other.ID + "/state", body: f.stateUpload()}); code != http.StatusForbidden || ecode != runnercontract.ErrorCodeJobTokenRevoked {
		t.Errorf("POST state of a canceled run with an earlier attempt's token: status %d code %q, want 403 %s (%s)", code, ecode, runnercontract.ErrorCodeJobTokenRevoked, body)
	}
}

// storedText reads an object of the test store as text.
func storedText(t *testing.T, store *snapshotStore, key string) string {
	t.Helper()
	rc, err := store.GetStream(t.Context(), key)
	if err != nil {
		t.Fatalf("reading %s: %v", key, err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
