// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
)

// The run lifecycle as the TFE runs API reports it: which actions a run in each status takes, and
// the status and timestamps of its plan and apply. The action endpoints check the same status
// lists the run resource advertises in `actions`, so a client that acts on `is-cancelable`,
// `is-discardable` or `is-confirmable` is never refused. See
// docs/internal/analysis/tfe-run-lifecycle-audit.md.

// cancelableRunStatuses are the statuses a run is canceled from: queued, planning, applying, or
// waiting on its run tasks. TFE reports a queued run as cancelable as well as discardable.
var cancelableRunStatuses = []models.RunStatus{
	models.RunStatusPending,
	models.RunStatusPrePlanRunning,
	models.RunStatusPrePlanCompleted,
	models.RunStatusPlanning,
	models.RunStatusPostPlanRunning,
	models.RunStatusPreApplyRunning,
	models.RunStatusApplying,
	models.RunStatusPostApplyRunning,
}

// discardableRunStatuses are the statuses a run is discarded from: waiting to start, or waiting for
// a confirmation of its plan (including while its post-plan tasks run or await an override).
var discardableRunStatuses = []models.RunStatus{
	models.RunStatusPending,
	models.RunStatusPrePlanCompleted,
	models.RunStatusPlanned,
	models.RunStatusPostPlanRunning,
	models.RunStatusPostPlanCompleted,
}

// confirmableRunStatuses are the statuses a plan-and-apply or destroy run waits for its
// confirmation in: `planned`, or `post_plan_completed` when a post-plan task stage exists.
var confirmableRunStatuses = []models.RunStatus{
	models.RunStatusPlanned,
	models.RunStatusPostPlanCompleted,
}

// runIsConfirmable reports whether the apply action is accepted for the run.
func runIsConfirmable(run *models.Run) bool {
	return runHasApplyPhase(run.Operation) && slices.Contains(confirmableRunStatuses, run.Status)
}

// runActions is the run's `actions` block. A run's cancel is immediate, so there is never a
// cancel in progress to force, and is-force-cancelable is always false.
func runActions(run *models.Run) RunActions {
	return RunActions{
		IsCancelable:  slices.Contains(cancelableRunStatuses, run.Status),
		IsConfirmable: runIsConfirmable(run),
		IsDiscardable: slices.Contains(discardableRunStatuses, run.Status),
	}
}

// runCanceled reports whether the run ended by a cancel, forceful or not.
func runCanceled(status models.RunStatus) bool {
	return status == models.RunStatusCancelled || status == models.RunStatusForceCanceled
}

// runStatusTimestamps is the run's `status-timestamps`: a key for each status the run has entered,
// named after the status. plan-queueable-at is the run's creation, the first key every run has.
func runStatusTimestamps(run *models.Run) RunStatusTimestamps {
	ts := RunStatusTimestamps{PlanQueueableAt: jsonapi.FormatTime(run.CreatedAt)}
	if run.StartedAt != nil {
		ts.PlanningAt = jsonapi.FormatTime(*run.StartedAt)
	}
	if run.PlanCompletedAt != nil {
		ts.PlannedAt = jsonapi.FormatTime(*run.PlanCompletedAt)
	}
	if run.ApplyStartedAt != nil && runHasApplyPhase(run.Operation) {
		ts.ApplyingAt = jsonapi.FormatTime(*run.ApplyStartedAt)
	}
	if run.CompletedAt == nil {
		return ts
	}
	ended := jsonapi.FormatTime(*run.CompletedAt)
	switch run.Status { //nolint:exhaustive // only final statuses carry an end timestamp
	case models.RunStatusApplied:
		ts.AppliedAt = ended
	case models.RunStatusPlannedAndFinished:
		ts.PlannedAndFinishedAt = ended
		if ts.PlannedAt == "" {
			ts.PlannedAt = ended
		}
	case models.RunStatusErrored:
		ts.ErroredAt = ended
	case models.RunStatusCancelled:
		ts.CanceledAt = ended
	case models.RunStatusForceCanceled:
		ts.ForceCanceledAt = ended
	case models.RunStatusDiscarded:
		ts.DiscardedAt = ended
	}
	return ts
}

// Plan and apply resource statuses (TFE plans and applies APIs).
const (
	phasePending     = "pending"
	phaseRunning     = "running"
	phaseFinished    = "finished"
	phaseErrored     = "errored"
	phaseCanceled    = "canceled"
	phaseUnreachable = "unreachable"
)

// planPhase is the status and status-timestamps of the run's plan. Once the plan has finished it
// stays finished, through the confirmation, the apply and whatever ends the run; before that it is
// pending, running, or ended the way the run did. A plan that never started because the run was
// discarded while queued is unreachable.
func planPhase(run *models.Run) (string, PhaseStatusTimestamps) {
	ts := PhaseStatusTimestamps{
		PendingAt: jsonapi.FormatTime(run.CreatedAt),
		QueuedAt:  jsonapi.FormatTime(run.CreatedAt),
	}
	if run.StartedAt != nil {
		ts.StartedAt = jsonapi.FormatTime(*run.StartedAt)
	}
	if run.PlanCompletedAt != nil {
		ts.FinishedAt = jsonapi.FormatTime(*run.PlanCompletedAt)
		return phaseFinished, ts
	}
	ended := ""
	if run.CompletedAt != nil {
		ended = jsonapi.FormatTime(*run.CompletedAt)
	}
	switch run.Status { //nolint:exhaustive // every other status is before the plan finished
	case models.RunStatusPlanning:
		return phaseRunning, ts
	case models.RunStatusErrored:
		ts.ErroredAt = ended
		return phaseErrored, ts
	case models.RunStatusCancelled:
		ts.CanceledAt = ended
		return phaseCanceled, ts
	case models.RunStatusForceCanceled:
		ts.ForceCanceledAt = ended
		return phaseCanceled, ts
	case models.RunStatusDiscarded:
		return phaseUnreachable, ts
	case models.RunStatusPlannedAndFinished, models.RunStatusPlanned, models.RunStatusPostPlanRunning,
		models.RunStatusPostPlanCompleted, models.RunStatusPreApplyRunning, models.RunStatusPreApplyCompleted,
		models.RunStatusApplying, models.RunStatusPostApplyRunning, models.RunStatusPostApplyCompleted,
		models.RunStatusApplied:
		// The plan finished (a row stored without its plan completion time).
		if ended != "" {
			ts.FinishedAt = ended
		}
		return phaseFinished, ts
	}
	return phasePending, ts
}

// applyPhase is the status and status-timestamps of the run's apply. An apply that will never run
// - a plan-only run, a plan with nothing to apply, a discarded run, or a run that errored or was
// canceled before its apply started - is unreachable, a final state.
func applyPhase(run *models.Run) (string, PhaseStatusTimestamps) {
	var ts PhaseStatusTimestamps
	if !runHasApplyPhase(run.Operation) {
		return phaseUnreachable, ts
	}
	if run.ApplyStartedAt != nil {
		ts.QueuedAt = jsonapi.FormatTime(*run.ApplyStartedAt)
		ts.StartedAt = ts.QueuedAt
	}
	ended := ""
	if run.CompletedAt != nil {
		ended = jsonapi.FormatTime(*run.CompletedAt)
	}
	started := run.ApplyStartedAt != nil
	switch run.Status { //nolint:exhaustive // every other status is before the apply
	case models.RunStatusApplying:
		return phaseRunning, ts
	case models.RunStatusPostApplyRunning, models.RunStatusPostApplyCompleted:
		// The apply itself finished; only its post-apply tasks are still running.
		return phaseFinished, ts
	case models.RunStatusApplied:
		ts.FinishedAt = ended
		return phaseFinished, ts
	case models.RunStatusPlannedAndFinished, models.RunStatusDiscarded:
		return phaseUnreachable, ts
	case models.RunStatusErrored:
		if !started {
			return phaseUnreachable, ts
		}
		ts.ErroredAt = ended
		return phaseErrored, ts
	case models.RunStatusCancelled, models.RunStatusForceCanceled:
		if !started {
			return phaseUnreachable, ts
		}
		if run.Status == models.RunStatusForceCanceled {
			ts.ForceCanceledAt = ended
		} else {
			ts.CanceledAt = ended
		}
		return phaseCanceled, ts
	}
	return phasePending, ts
}

// RunEventAttributes is the attribute block of a TFE run event (go-tfe RunEvent).
type RunEventAttributes struct {
	Action      string `json:"action"`
	CreatedAt   string `json:"created-at"`
	Description string `json:"description,omitempty"`
}

// ListRunEvents serves GET /api/v2/runs/:id/run-events, TFE's list of a run's lifecycle events.
// Stackweaver records no run events, so the list is empty. The Terraform CLI's `cloud` block
// reads it before every plan to print the warnings TFE raises while creating a run (changed policy
// or task enforcement, ignored policy sets), none of which Stackweaver raises, and it stops the
// operation when the list cannot be read.
func (h *RunHandlerV2) ListRunEvents(c *gin.Context) {
	if _, ok := h.authorizeRun(c, c.Param("id"), "read"); !ok {
		return
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, []jsonapi.Resource[RunEventAttributes]{}, jsonapi.NewFullPageMeta(0))
}
