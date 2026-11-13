// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"testing"
	"time"

	"github.com/michielvha/stackweaver/core/models"
)

// The run lifecycle as the TFE runs API reports it. Each case is a run as a status leaves it, and
// the expectations come from the TFE run states and actions (see
// docs/internal/analysis/tfe-run-lifecycle-audit.md).

var (
	tCreated  = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	tStarted  = tCreated.Add(10 * time.Second)
	tPlanned  = tCreated.Add(30 * time.Second)
	tApplying = tCreated.Add(60 * time.Second)
	tEnded    = tCreated.Add(90 * time.Second)
)

func ptrTime(t time.Time) *time.Time { return &t }

func TestRunActions(t *testing.T) {
	cases := []struct {
		status                         models.RunStatus
		op                             models.RunOperation
		cancel, confirm, discard, keep bool
	}{
		{models.RunStatusPending, models.RunOperationPlanAndApply, true, false, true, false},
		{models.RunStatusPrePlanRunning, models.RunOperationPlanAndApply, true, false, false, false},
		{models.RunStatusPrePlanCompleted, models.RunOperationPlanAndApply, true, false, true, false},
		{models.RunStatusPlanning, models.RunOperationPlanAndApply, true, false, false, false},
		{models.RunStatusPlanned, models.RunOperationPlanAndApply, false, true, true, false},
		{models.RunStatusPlanned, models.RunOperationDestroy, false, true, true, false},
		{models.RunStatusPostPlanRunning, models.RunOperationPlanAndApply, true, false, true, false},
		{models.RunStatusPostPlanCompleted, models.RunOperationPlanAndApply, false, true, true, false},
		{models.RunStatusPreApplyRunning, models.RunOperationPlanAndApply, true, false, false, false},
		{models.RunStatusApplying, models.RunOperationPlanAndApply, true, false, false, false},
		{models.RunStatusPostApplyRunning, models.RunOperationPlanAndApply, true, false, false, false},
		{models.RunStatusApplied, models.RunOperationPlanAndApply, false, false, false, false},
		{models.RunStatusPlannedAndFinished, models.RunOperationPlanAndApply, false, false, false, false},
		{models.RunStatusPlannedAndFinished, models.RunOperationPlanOnly, false, false, false, false},
		{models.RunStatusErrored, models.RunOperationPlanAndApply, false, false, false, false},
		{models.RunStatusCancelled, models.RunOperationPlanAndApply, false, false, false, false},
		{models.RunStatusDiscarded, models.RunOperationPlanAndApply, false, false, false, false},
		{models.RunStatusForceCanceled, models.RunOperationPlanAndApply, false, false, false, false},
	}
	for _, tc := range cases {
		got := runActions(&models.Run{Status: tc.status, Operation: tc.op})
		if got.IsCancelable != tc.cancel || got.IsConfirmable != tc.confirm || got.IsDiscardable != tc.discard || got.IsForceCancelable != tc.keep {
			t.Errorf("%s %s: actions %+v, want cancelable=%v confirmable=%v discardable=%v force-cancelable=%v",
				tc.op, tc.status, got, tc.cancel, tc.confirm, tc.discard, tc.keep)
		}
	}
}

func TestRunStatusTimestamps(t *testing.T) {
	cases := []struct {
		name string
		run  models.Run
		want RunStatusTimestamps
	}{
		{
			name: "pending: only plan-queueable-at",
			run:  models.Run{Status: models.RunStatusPending, Operation: models.RunOperationPlanAndApply, CreatedAt: tCreated},
			want: RunStatusTimestamps{PlanQueueableAt: "2026-11-09T10:00:00Z"},
		},
		{
			name: "planned_and_finished keeps the plan's timestamps and records its end",
			run: models.Run{
				Status: models.RunStatusPlannedAndFinished, Operation: models.RunOperationPlanAndApply,
				CreatedAt: tCreated, StartedAt: ptrTime(tStarted), PlanCompletedAt: ptrTime(tPlanned), CompletedAt: ptrTime(tPlanned),
			},
			want: RunStatusTimestamps{
				PlanQueueableAt: "2026-11-09T10:00:00Z", PlanningAt: "2026-11-09T10:00:10Z",
				PlannedAt: "2026-11-09T10:00:30Z", PlannedAndFinishedAt: "2026-11-09T10:00:30Z",
			},
		},
		{
			name: "applied destroy records applying-at and applied-at",
			run: models.Run{
				Status: models.RunStatusApplied, Operation: models.RunOperationDestroy, CreatedAt: tCreated,
				StartedAt: ptrTime(tStarted), PlanCompletedAt: ptrTime(tPlanned), ApplyStartedAt: ptrTime(tApplying), CompletedAt: ptrTime(tEnded),
			},
			want: RunStatusTimestamps{
				PlanQueueableAt: "2026-11-09T10:00:00Z", PlanningAt: "2026-11-09T10:00:10Z", PlannedAt: "2026-11-09T10:00:30Z",
				ApplyingAt: "2026-11-09T10:01:00Z", AppliedAt: "2026-11-09T10:01:30Z",
			},
		},
		{
			name: "errored records errored-at",
			run:  models.Run{Status: models.RunStatusErrored, Operation: models.RunOperationPlanAndApply, CreatedAt: tCreated, StartedAt: ptrTime(tStarted), CompletedAt: ptrTime(tEnded)},
			want: RunStatusTimestamps{PlanQueueableAt: "2026-11-09T10:00:00Z", PlanningAt: "2026-11-09T10:00:10Z", ErroredAt: "2026-11-09T10:01:30Z"},
		},
		{
			name: "canceled records canceled-at",
			run:  models.Run{Status: models.RunStatusCancelled, Operation: models.RunOperationPlanAndApply, CreatedAt: tCreated, CompletedAt: ptrTime(tEnded)},
			want: RunStatusTimestamps{PlanQueueableAt: "2026-11-09T10:00:00Z", CanceledAt: "2026-11-09T10:01:30Z"},
		},
		{
			name: "discarded records discarded-at",
			run:  models.Run{Status: models.RunStatusDiscarded, Operation: models.RunOperationPlanAndApply, CreatedAt: tCreated, StartedAt: ptrTime(tStarted), PlanCompletedAt: ptrTime(tPlanned), CompletedAt: ptrTime(tEnded)},
			want: RunStatusTimestamps{PlanQueueableAt: "2026-11-09T10:00:00Z", PlanningAt: "2026-11-09T10:00:10Z", PlannedAt: "2026-11-09T10:00:30Z", DiscardedAt: "2026-11-09T10:01:30Z"},
		},
	}
	for _, tc := range cases {
		if got := runStatusTimestamps(&tc.run); got != tc.want {
			t.Errorf("%s:\n got  %+v\n want %+v", tc.name, got, tc.want)
		}
	}
}

func TestPlanAndApplyPhases(t *testing.T) {
	planned := func(status models.RunStatus, op models.RunOperation) models.Run {
		return models.Run{Status: status, Operation: op, CreatedAt: tCreated, StartedAt: ptrTime(tStarted), PlanCompletedAt: ptrTime(tPlanned)}
	}
	cases := []struct {
		name      string
		run       models.Run
		plan      string
		apply     string
		planStart string
	}{
		{"pending", models.Run{Status: models.RunStatusPending, Operation: models.RunOperationPlanAndApply, CreatedAt: tCreated}, "pending", "pending", ""},
		{"planning", models.Run{Status: models.RunStatusPlanning, Operation: models.RunOperationPlanAndApply, CreatedAt: tCreated, StartedAt: ptrTime(tStarted)}, "running", "pending", "2026-11-09T10:00:10Z"},
		{"planned waits for the apply", planned(models.RunStatusPlanned, models.RunOperationPlanAndApply), "finished", "pending", "2026-11-09T10:00:10Z"},
		{"plan stays finished while the run applies", func() models.Run {
			r := planned(models.RunStatusApplying, models.RunOperationPlanAndApply)
			r.ApplyStartedAt = ptrTime(tApplying)
			return r
		}(), "finished", "running", "2026-11-09T10:00:10Z"},
		{"applied keeps the plan's own start", func() models.Run {
			r := planned(models.RunStatusApplied, models.RunOperationPlanAndApply)
			r.ApplyStartedAt, r.CompletedAt = ptrTime(tApplying), ptrTime(tEnded)
			return r
		}(), "finished", "finished", "2026-11-09T10:00:10Z"},
		{"no changes: the apply is unreachable", planned(models.RunStatusPlannedAndFinished, models.RunOperationPlanAndApply), "finished", "unreachable", "2026-11-09T10:00:10Z"},
		{"plan-only: the apply is unreachable", planned(models.RunStatusPlannedAndFinished, models.RunOperationPlanOnly), "finished", "unreachable", "2026-11-09T10:00:10Z"},
		{"discarded at planned: the apply is unreachable", planned(models.RunStatusDiscarded, models.RunOperationPlanAndApply), "finished", "unreachable", "2026-11-09T10:00:10Z"},
		{"errored plan: the apply is unreachable", models.Run{Status: models.RunStatusErrored, Operation: models.RunOperationPlanAndApply, CreatedAt: tCreated, StartedAt: ptrTime(tStarted), CompletedAt: ptrTime(tEnded)}, "errored", "unreachable", "2026-11-09T10:00:10Z"},
		{"errored apply", func() models.Run {
			r := planned(models.RunStatusErrored, models.RunOperationPlanAndApply)
			r.ApplyStartedAt, r.CompletedAt = ptrTime(tApplying), ptrTime(tEnded)
			return r
		}(), "finished", "errored", "2026-11-09T10:00:10Z"},
		{"canceled while queued", models.Run{Status: models.RunStatusCancelled, Operation: models.RunOperationPlanAndApply, CreatedAt: tCreated, CompletedAt: ptrTime(tEnded)}, "canceled", "unreachable", ""},
		{"canceled mid-apply", func() models.Run {
			r := planned(models.RunStatusCancelled, models.RunOperationPlanAndApply)
			r.ApplyStartedAt, r.CompletedAt = ptrTime(tApplying), ptrTime(tEnded)
			return r
		}(), "finished", "canceled", "2026-11-09T10:00:10Z"},
		{"discarded while queued: nothing ran", models.Run{Status: models.RunStatusDiscarded, Operation: models.RunOperationPlanAndApply, CreatedAt: tCreated, CompletedAt: ptrTime(tEnded)}, "unreachable", "unreachable", ""},
	}
	for _, tc := range cases {
		plan, planTS := planPhase(&tc.run)
		apply, _ := applyPhase(&tc.run)
		if plan != tc.plan || apply != tc.apply || planTS.StartedAt != tc.planStart {
			t.Errorf("%s: plan %s (started %q), apply %s; want plan %s (started %q), apply %s",
				tc.name, plan, planTS.StartedAt, apply, tc.plan, tc.planStart, tc.apply)
		}
	}
}

// Every TFE run has a plan and an apply relationship, whatever its operation: the Terraform CLI
// streams a destroy's apply logs through the apply relationship.
func TestFormatRunResponse_PlanAndApplyRelationships(t *testing.T) {
	for _, op := range []models.RunOperation{models.RunOperationPlanAndApply, models.RunOperationPlanOnly, models.RunOperationDestroy} {
		res := formatRunResponse(&models.Run{ID: "run-1", WorkspaceID: "ws-1", Operation: op, Status: models.RunStatusPending}, nil, nil, nil)
		rels, ok := res.Relationships.(RunRelationships)
		if !ok || rels.Plan == nil || rels.Apply == nil {
			t.Errorf("%s run: relationships %+v; want both plan and apply", op, res.Relationships)
		}
	}
}

// The run attributes go-tfe reads beside the status: the message the run was queued with, its
// auto-apply intent, canceled-at once canceled (null until then), and refresh.
func TestFormatRunResponse_Attributes(t *testing.T) {
	run := &models.Run{ID: "run-1", WorkspaceID: "ws-1", Operation: models.RunOperationPlanAndApply, Status: models.RunStatusPending, Message: "queued by e2e", AutoApply: true}
	attrs := formatRunResponse(run, nil, nil, nil).Attributes
	if attrs.Message != "queued by e2e" || !attrs.AutoApply || !attrs.Refresh || attrs.RefreshOnly || attrs.AllowEmptyApply || attrs.CanceledAt != nil {
		t.Errorf("pending run attributes: message %q auto-apply %v refresh %v refresh-only %v allow-empty-apply %v canceled-at %v",
			attrs.Message, attrs.AutoApply, attrs.Refresh, attrs.RefreshOnly, attrs.AllowEmptyApply, attrs.CanceledAt)
	}
	run.Status, run.CompletedAt = models.RunStatusCancelled, ptrTime(tEnded)
	if got := formatRunResponse(run, nil, nil, nil).Attributes.CanceledAt; got == nil || *got != "2026-11-09T10:01:30Z" {
		t.Errorf("canceled run canceled-at = %v, want 2026-11-09T10:01:30Z", got)
	}
}

// A speculative configuration version (the one `terraform plan` uploads) makes a speculative
// plan-only run unless the caller says otherwise: TFE's plan-only defaults "from configuration
// version".
func TestSpeculativeRunOperation(t *testing.T) {
	speculative := &models.ConfigurationVersion{Speculative: true}
	f, tr := false, true
	cases := []struct {
		name string
		op   models.RunOperation
		attr RunCreateAttributes
		cv   *models.ConfigurationVersion
		want models.RunOperation
	}{
		{"speculative configuration plans only", models.RunOperationPlanAndApply, RunCreateAttributes{}, speculative, models.RunOperationPlanOnly},
		{"an explicit plan-only false is kept", models.RunOperationPlanAndApply, RunCreateAttributes{PlanOnly: &f}, speculative, models.RunOperationPlanAndApply},
		{"an explicit plan-only true is kept", models.RunOperationPlanOnly, RunCreateAttributes{PlanOnly: &tr}, speculative, models.RunOperationPlanOnly},
		{"a destroy keeps its operation", models.RunOperationDestroy, RunCreateAttributes{IsDestroy: &tr}, speculative, models.RunOperationDestroy},
		{"a normal configuration applies", models.RunOperationPlanAndApply, RunCreateAttributes{}, &models.ConfigurationVersion{}, models.RunOperationPlanAndApply},
	}
	for _, tc := range cases {
		got, applyable := speculativeRunOperation(tc.op, &tc.attr, tc.cv)
		if got != tc.want || applyable != (tc.want != models.RunOperationPlanOnly) {
			t.Errorf("%s: %s (applyable %v), want %s", tc.name, got, applyable, tc.want)
		}
	}
}
