// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Starting a run's phase keeps the claim it made (#933, D2, D3, AC9): the run stays claimed for
// dispatch and assigned to the runner that started it, on the plan and on the apply phase. The
// defect this was written against, found by the live pass of a lost launcher: JobStart claimed
// the run, then saved the row it had loaded before the claim, which wrote dispatched_at back to
// NULL. A started run then looked unstarted: the stale-reservation release took its runner away
// (every later call of its executor was refused) and the lost-launcher outcome never saw it.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration

package handlers

import (
	"net/http"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

func TestJobStart_KeepsTheDispatchClaim(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _ := f.attemptRouter()
	for name, status := range map[string]models.RunStatus{"plan": models.RunStatusPending, "apply": models.RunStatusApplying} {
		t.Run(name, func(t *testing.T) {
			run := f.seedRun(t, f.runnerA1)
			if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).
				Updates(map[string]any{"status": status, "runner_id": nil, "operation": models.RunOperationPlanAndApply}).Error; err != nil {
				t.Fatal(err)
			}
			rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+run.ID+"/start", runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String()})
			if rec.Code != http.StatusOK {
				t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
			}
			var got models.Run
			if err := f.db.First(&got, "id = ?", run.ID).Error; err != nil {
				t.Fatal(err)
			}
			if got.DispatchedAt == nil {
				t.Error("the started run is no longer claimed for dispatch")
			}
			if got.RunnerID == nil || *got.RunnerID != f.runnerA1.ID {
				t.Errorf("the started run is assigned to %v, want a1", got.RunnerID)
			}
		})
	}
}
