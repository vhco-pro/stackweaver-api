// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

// TestPlanFinishedStatus pins the status a run takes when its plan job completes, against the TFE
// run states: a plan-only run, and a plan-and-apply or destroy run whose plan has no changes, end
// at planned_and_finished (a final state); a plan with changes rests at planned for confirmation,
// or applies at once under auto-apply; a post-plan task stage runs first in every case.
func TestPlanFinishedStatus(t *testing.T) {
	cases := []struct {
		name       string
		op         models.RunOperation
		hasChanges bool
		postPlan   bool
		autoApply  bool
		want       models.RunStatus
	}{
		{"plan-only with changes", models.RunOperationPlanOnly, true, false, false, models.RunStatusPlannedAndFinished},
		{"plan-only without changes", models.RunOperationPlanOnly, false, false, false, models.RunStatusPlannedAndFinished},
		{"plan-only ignores auto-apply", models.RunOperationPlanOnly, true, false, true, models.RunStatusPlannedAndFinished},
		{"apply run with changes waits for confirmation", models.RunOperationPlanAndApply, true, false, false, models.RunStatusPlanned},
		{"apply run with changes and auto-apply applies", models.RunOperationPlanAndApply, true, false, true, models.RunStatusApplying},
		{"apply run without changes is finished", models.RunOperationPlanAndApply, false, false, false, models.RunStatusPlannedAndFinished},
		{"apply run without changes is finished under auto-apply", models.RunOperationPlanAndApply, false, false, true, models.RunStatusPlannedAndFinished},
		{"destroy with resources waits for confirmation", models.RunOperationDestroy, true, false, false, models.RunStatusPlanned},
		{"destroy with nothing to destroy is finished", models.RunOperationDestroy, false, false, false, models.RunStatusPlannedAndFinished},
		{"post-plan stage runs first with changes", models.RunOperationPlanAndApply, true, true, false, models.RunStatusPostPlanRunning},
		{"post-plan stage runs first without changes", models.RunOperationPlanAndApply, false, true, false, models.RunStatusPostPlanRunning},
		{"post-plan stage runs first for plan-only", models.RunOperationPlanOnly, false, true, false, models.RunStatusPostPlanRunning},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := planFinishedStatus(tc.op, tc.hasChanges, tc.postPlan, tc.autoApply); got != tc.want {
				t.Errorf("planFinishedStatus(%s, changes=%v, postPlan=%v, autoApply=%v) = %s, want %s",
					tc.op, tc.hasChanges, tc.postPlan, tc.autoApply, got, tc.want)
			}
		})
	}
}
