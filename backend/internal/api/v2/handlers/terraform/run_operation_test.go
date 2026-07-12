// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Unit tests for resolveRunOperation — the run-create operation/apply-intent mapping. The key
// compatibility contract: a normal go-tfe run (RunCreateOptions with auto-apply present, plan-only
// false, is-destroy false — e.g. tfe_workspace_run) must resolve to an APPLYABLE plan-and-apply run,
// not a non-applyable plan-only. Also covers plan-only, is-destroy, the per-run auto-apply intent, the
// frontend/legacy operation + auto-apply-after-plan fallbacks, and the removed plan/apply operations.

package terraform

import (
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

func boolPtr(b bool) *bool { return &b }

// gotfe builds a request as the stock hashicorp/tfe provider's go-tfe client serializes
// RunCreateOptions: is-destroy, plan-only and auto-apply are all sent as JSON:API attributes; there is
// no top-level operation and no auto-apply-after-plan.
func gotfe(isDestroy, planOnly, autoApply bool) *CreateRunRequestV2 {
	req := &CreateRunRequestV2{}
	req.Data.Attributes.IsDestroy = boolPtr(isDestroy)
	req.Data.Attributes.PlanOnly = boolPtr(planOnly)
	req.Data.Attributes.AutoApply = boolPtr(autoApply)
	return req
}

func TestResolveRunOperation(t *testing.T) {
	tests := []struct {
		name       string
		req        *CreateRunRequestV2
		wantOp     models.RunOperation
		wantAfter  bool // autoApplyAfterPlan
		wantPerRun bool // perRunAutoApply
		wantLegacy bool
	}{
		// --- go-tfe wire (the compat contract) ---
		{
			name:       "go-tfe apply-and-wait: auto-apply=false is an APPLYABLE plan-and-apply, not plan-only",
			req:        gotfe(false, false, false),
			wantOp:     models.RunOperationPlanAndApply,
			wantPerRun: false,
		},
		{
			name:       "go-tfe fire-and-forget: auto-apply=true is plan-and-apply + per-run auto-apply",
			req:        gotfe(false, false, true),
			wantOp:     models.RunOperationPlanAndApply,
			wantPerRun: true,
		},
		{
			name:   "go-tfe plan-only: speculative, cannot be applied",
			req:    gotfe(false, true, false),
			wantOp: models.RunOperationPlanOnly,
		},
		{
			name:       "go-tfe destroy: is-destroy wins over auto-apply=false",
			req:        gotfe(true, false, false),
			wantOp:     models.RunOperationDestroy,
			wantPerRun: false,
		},
		{
			name:       "go-tfe destroy fire-and-forget: is-destroy + auto-apply=true",
			req:        gotfe(true, false, true),
			wantOp:     models.RunOperationDestroy,
			wantPerRun: true,
		},
		// --- frontend / legacy fallbacks (unchanged behavior) ---
		{
			name:   "frontend plan-and-apply operation",
			req:    &CreateRunRequestV2{Operation: "plan-and-apply"},
			wantOp: models.RunOperationPlanAndApply,
		},
		{
			name:   "frontend plan-only operation",
			req:    &CreateRunRequestV2{Operation: "plan-only"},
			wantOp: models.RunOperationPlanOnly,
		},
		{
			name:   "frontend destroy operation",
			req:    &CreateRunRequestV2{Operation: "destroy"},
			wantOp: models.RunOperationDestroy,
		},
		{
			name:   "no hints at all defaults to plan-only (speculative)",
			req:    &CreateRunRequestV2{},
			wantOp: models.RunOperationPlanOnly,
		},
		{
			name:       "legacy plan operation is rejected",
			req:        &CreateRunRequestV2{Operation: "plan"},
			wantLegacy: true,
		},
		{
			name:       "legacy apply operation is rejected",
			req:        &CreateRunRequestV2{Operation: "apply"},
			wantLegacy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, after, perRun, legacy := resolveRunOperation(tt.req)
			if legacy != tt.wantLegacy {
				t.Fatalf("legacyOperation = %v, want %v", legacy, tt.wantLegacy)
			}
			if tt.wantLegacy {
				return // operation is unspecified when the caller must be rejected
			}
			if op != tt.wantOp {
				t.Errorf("operation = %q, want %q", op, tt.wantOp)
			}
			if perRun != tt.wantPerRun {
				t.Errorf("perRunAutoApply = %v, want %v", perRun, tt.wantPerRun)
			}
			if after != tt.wantAfter {
				t.Errorf("autoApplyAfterPlan = %v, want %v", after, tt.wantAfter)
			}
		})
	}
}

// TestResolveRunOperation_AutoApplyAfterPlanFallback covers the frontend "Plan and Apply" toggle, which
// sends auto-apply-after-plan (not the go-tfe auto-apply attribute) and no operation.
func TestResolveRunOperation_AutoApplyAfterPlanFallback(t *testing.T) {
	req := &CreateRunRequestV2{}
	req.Data.Attributes.AutoApplyAfterPlan = boolPtr(true)
	op, after, perRun, legacy := resolveRunOperation(req)
	if legacy {
		t.Fatal("unexpected legacyOperation")
	}
	if op != models.RunOperationPlanAndApply {
		t.Errorf("operation = %q, want plan-and-apply", op)
	}
	if !after {
		t.Error("autoApplyAfterPlan = false, want true")
	}
	if perRun {
		t.Error("perRunAutoApply = true, want false (auto-apply-after-plan is not a per-run auto-apply)")
	}

	// auto-apply-after-plan=false with no other hints stays plan-only (the frontend "Plan only" toggle).
	req2 := &CreateRunRequestV2{}
	req2.Data.Attributes.AutoApplyAfterPlan = boolPtr(false)
	if op, _, _, _ := resolveRunOperation(req2); op != models.RunOperationPlanOnly {
		t.Errorf("operation = %q, want plan-only", op)
	}
}
