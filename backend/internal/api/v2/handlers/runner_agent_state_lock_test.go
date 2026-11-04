// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the workspace state lock on the runner control plane (#933, D2, AC7): the
// API takes the lock at the claim, so a run holds it on every driver, a second run on the same
// workspace is not started while it is held and stays pending to be offered again, and completion
// releases it. The executor never holds the lock, so a vanished one wedges nothing beyond the TTL.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestStateLock

//go:build integration

package handlers

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func (f *agentPrepFixture) seedApplyRun(t *testing.T, ws *models.Workspace) *models.Run {
	t.Helper()
	run := &models.Run{WorkspaceID: ws.ID, Status: models.RunStatusPending, Operation: models.RunOperationPlanAndApply, AgentPoolID: &f.poolA}
	if err := f.db.Create(run).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", run.ID).Delete(&models.Run{}) })
	return run
}

func (f *agentPrepFixture) workspaceLock(t *testing.T, wsID string) *models.StateLock {
	t.Helper()
	var lock models.StateLock
	if err := f.db.Where("workspace_id = ? AND expires_at > ?", wsID, time.Now()).First(&lock).Error; err != nil {
		return nil
	}
	return &lock
}

func TestStateLock_HeldFromClaimToCompletion(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _ := f.attemptRouter()
	ws := &models.Workspace{ProjectID: f.projectA, Name: "lock-ws-" + uuid.NewString()[:8], ExecutionMode: "agent", AgentPoolID: &f.poolA, RunTimeout: 900}
	if err := f.db.Create(ws).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("workspace_id = ?", ws.ID).Delete(&models.StateLock{})
		f.db.Where("id = ?", ws.ID).Delete(&models.Workspace{})
	})
	first := f.seedApplyRun(t, ws)
	second := f.seedApplyRun(t, ws)

	start := func(key string, runner *models.Runner, runID string) int {
		return runnerDo(t, r, key, http.MethodPost, "/api/v2/runner/jobs/"+runID+"/start", map[string]any{"runner_id": runner.ID.String()}).Code
	}

	if code := start("a1", f.runnerA1, first.ID); code != http.StatusOK {
		t.Fatalf("claiming the first run: %d", code)
	}
	lock := f.workspaceLock(t, ws.ID)
	if lock == nil || lock.LockedBy == nil || *lock.LockedBy != first.ID {
		t.Fatalf("after the claim the workspace lock is %+v, want it held by %s", lock, first.ID)
	}
	if ttl := time.Until(lock.ExpiresAt); ttl < 14*time.Minute || ttl > 16*time.Minute {
		t.Errorf("lock TTL = %s, want the run's resolved timeout (900s)", ttl)
	}

	// The second run waits: refused, and left pending and undispatched to be offered again.
	if code := start("a2", f.runnerA2, second.ID); code != http.StatusConflict {
		t.Fatalf("claiming the second run while the lock is held: %d, want 409", code)
	}
	var reloaded models.Run
	if err := f.db.First(&reloaded, "id = ?", second.ID).Error; err != nil {
		t.Fatal(err)
	}
	if reloaded.Status != models.RunStatusPending || reloaded.DispatchedAt != nil || reloaded.RunnerID != nil {
		t.Fatalf("the waiting run is %s dispatched=%v runner=%v, want pending, undispatched and unassigned", reloaded.Status, reloaded.DispatchedAt, reloaded.RunnerID)
	}

	// Completion releases the lock, and the second run starts.
	done := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+first.ID+"/complete", map[string]any{"runner_id": f.runnerA1.ID.String(), "status": "failed", "error_message": "test"})
	if done.Code != http.StatusOK {
		t.Fatalf("completing the first run: %d (%s)", done.Code, done.Body.String())
	}
	if lock := f.workspaceLock(t, ws.ID); lock != nil {
		t.Fatalf("after completion the workspace is still locked by %v", lock.LockedBy)
	}
	if code := start("a2", f.runnerA2, second.ID); code != http.StatusOK {
		t.Fatalf("claiming the second run after the release: %d", code)
	}
}
