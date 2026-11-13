// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// changingPlan is the plan document of a run that adds one resource.
func changingPlan() models.PlanOutput {
	return models.PlanOutput{
		"resource_changes": []interface{}{
			map[string]interface{}{
				"address": "null_resource.a",
				"change":  map[string]interface{}{"actions": []interface{}{"create"}},
			},
		},
	}
}

// noopPlan is the plan document of a run with nothing to change.
func noopPlan() models.PlanOutput {
	return models.PlanOutput{
		"resource_changes": []interface{}{
			map[string]interface{}{
				"address": "null_resource.a",
				"change":  map[string]interface{}{"actions": []interface{}{"no-op"}},
			},
		},
	}
}

// Every status a run can hold once its plan has finished. TFE's has-changes is the plan's, so it
// keeps answering after the plan: tfe_workspace_run reads it at the plan's terminal status, which
// is post_plan_completed when a post-plan task stage exists, and an applied run keeps its answer.
var statusesAfterPlan = []models.RunStatus{
	models.RunStatusPlanned,
	models.RunStatusPlannedAndFinished,
	models.RunStatusPostPlanRunning,
	models.RunStatusPostPlanCompleted,
	models.RunStatusPreApplyRunning,
	models.RunStatusPreApplyCompleted,
	models.RunStatusApplying,
	models.RunStatusPostApplyRunning,
	models.RunStatusPostApplyCompleted,
	models.RunStatusApplied,
	models.RunStatusErrored,
	models.RunStatusCancelled,
	models.RunStatusForceCanceled,
	models.RunStatusDiscarded,
}

// Statuses before the plan has finished: there is no plan to answer from yet.
var statusesBeforePlan = []models.RunStatus{
	models.RunStatusPending,
	models.RunStatusPrePlanRunning,
	models.RunStatusPrePlanCompleted,
	models.RunStatusPlanning,
}

var planOperations = []models.RunOperation{
	models.RunOperationPlanOnly,
	models.RunOperationPlanAndApply,
	models.RunOperationDestroy,
}

func runHasChangesAttr(t *testing.T, run *models.Run) bool {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	return formatRunResponse(run, c, nil, nil).Attributes.HasChanges
}

func TestRunHasChanges_FollowsThePlanAfterThePlanFinishes(t *testing.T) {
	for _, op := range planOperations {
		for _, status := range statusesAfterPlan {
			run := &models.Run{ID: "run-hc", WorkspaceID: "ws-hc", Operation: op, Status: status, CreatedAt: time.Now(), PlanOutput: changingPlan()}
			if !runHasChangesAttr(t, run) {
				t.Errorf("%s run at %s with a changing plan: has-changes = false, want true", op, status)
			}
			run.PlanOutput = noopPlan()
			if runHasChangesAttr(t, run) {
				t.Errorf("%s run at %s with a no-op plan: has-changes = true, want false", op, status)
			}
		}
	}
}

func TestRunHasChanges_FalseBeforeThePlanFinishes(t *testing.T) {
	for _, op := range planOperations {
		for _, status := range statusesBeforePlan {
			run := &models.Run{ID: "run-hc", WorkspaceID: "ws-hc", Operation: op, Status: status, CreatedAt: time.Now(), PlanOutput: changingPlan()}
			if runHasChangesAttr(t, run) {
				t.Errorf("%s run at %s: has-changes = true, want false before the plan finishes", op, status)
			}
		}
	}
}

// The workspace list answers has-changes for its latest-run summary from the plan half PostgreSQL
// evaluates (#808). For every operation and status it must agree with the run resource.
func TestRunHasChanges_WorkspaceListAgreesWithTheRunResource(t *testing.T) {
	statuses := append(append([]models.RunStatus{}, statusesAfterPlan...), statusesBeforePlan...)
	for _, op := range planOperations {
		for _, status := range statuses {
			for name, plan := range map[string]models.PlanOutput{"changing": changingPlan(), "no-op": noopPlan(), "absent": nil} {
				run := &models.Run{ID: "run-hc", WorkspaceID: "ws-hc", Operation: op, Status: status, CreatedAt: time.Now(), PlanOutput: plan}
				summary := &repository.LatestRunSummary{
					ID: run.ID, WorkspaceID: run.WorkspaceID, Operation: op, Status: status,
					PlanIndicatesChanges: plan.IndicatesChanges(),
				}
				listed := formatRunForInclusion(summary).Attributes.HasChanges
				if resource := runHasChangesAttr(t, run); listed != resource {
					t.Errorf("%s run at %s with a %s plan: workspace list has-changes = %v, run resource = %v", op, status, name, listed, resource)
				}
			}
		}
	}
}
