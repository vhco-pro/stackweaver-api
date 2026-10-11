// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Unit tests for resolveRunOperation - the run-create intent mapping.
//
// The compatibility contract is go-tfe's RunCreateOptions and nothing else: is-destroy, plan-only
// and auto-apply are the only intent attributes on the wire, and a run created with none of them
// is an APPLYABLE plan-and-apply run that waits at `planned`, exactly as on Terraform Enterprise.
//
// Why this file was rewritten (#844). It used to pin three more inputs: a top-level `operation`
// key (six rows), the top-level and attribute forms of `auto-apply-after-plan`, and a dedicated
// rejection of the long-removed "plan" and "apply" operation values. All of them were
// Stackweaver-only: go-tfe sends none, and the endpoint now accepts none. Two old expectations
// are deliberately inverted here rather than dropped:
//
//   - "no hints at all defaults to plan-only" is now "no attribute is an applyable run". The old
//     default made a bare go-tfe body (RunCreateOptions{Workspace}) a plan that could never be
//     applied; TFE's default is the opposite and speculative runs opt in with plan-only.
//   - "auto-apply-after-plan decides applyable versus plan-only" is now "auto-apply-after-plan is
//     ignored", like any attribute the request struct does not declare.
//
// Every case decodes a JSON body rather than building the struct, so the test also proves which
// attribute NAMES the endpoint reads.

package terraform

import (
	"encoding/json"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

// decodeRunAttributes unmarshals a run-create document and returns its attributes.
func decodeRunAttributes(t *testing.T, attributes string) *RunCreateAttributes {
	t.Helper()
	body := `{"data":{"type":"runs","attributes":` + attributes + `}}`
	var req CreateRunRequestV2
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("unmarshal %s: %v", body, err)
	}
	if req.Data == nil {
		t.Fatalf("document %s decoded without data", body)
	}
	return &req.Data.Attributes
}

func TestResolveRunOperation(t *testing.T) {
	tests := []struct {
		name       string
		attributes string
		wantOp     models.RunOperation
		wantPerRun bool // perRunAutoApply: apply without a manual confirmation
	}{
		{
			// go-tfe marshals RunCreateOptions{Workspace} with no intent attribute at all.
			name:       "no attribute is an applyable run that waits for confirmation",
			attributes: `{}`,
			wantOp:     models.RunOperationPlanAndApply,
		},
		{
			name:       "auto-apply false is an applyable run that waits for confirmation",
			attributes: `{"auto-apply":false}`,
			wantOp:     models.RunOperationPlanAndApply,
		},
		{
			name:       "auto-apply true is an applyable run that applies without confirmation",
			attributes: `{"auto-apply":true}`,
			wantOp:     models.RunOperationPlanAndApply,
			wantPerRun: true,
		},
		{
			name:       "plan-only is a speculative run",
			attributes: `{"plan-only":true}`,
			wantOp:     models.RunOperationPlanOnly,
		},
		{
			name:       "plan-only false is not speculative",
			attributes: `{"plan-only":false}`,
			wantOp:     models.RunOperationPlanAndApply,
		},
		{
			// The per-run intent is reported as sent, but nothing acts on it: both finalize paths
			// (the runner and the agent handler) only auto-apply plan-and-apply and destroy runs.
			name:       "plan-only wins over auto-apply",
			attributes: `{"plan-only":true,"auto-apply":true}`,
			wantOp:     models.RunOperationPlanOnly,
			wantPerRun: true,
		},
		{
			name:       "is-destroy is a destroy run that waits for confirmation",
			attributes: `{"is-destroy":true}`,
			wantOp:     models.RunOperationDestroy,
		},
		{
			name:       "is-destroy with auto-apply false still waits",
			attributes: `{"is-destroy":true,"auto-apply":false}`,
			wantOp:     models.RunOperationDestroy,
		},
		{
			name:       "is-destroy with auto-apply true destroys without confirmation",
			attributes: `{"is-destroy":true,"auto-apply":true}`,
			wantOp:     models.RunOperationDestroy,
			wantPerRun: true,
		},
		{
			name:       "is-destroy wins over plan-only",
			attributes: `{"is-destroy":true,"plan-only":true}`,
			wantOp:     models.RunOperationDestroy,
		},
		{
			// Exactly what go-tfe sends for tfe_workspace_run: every intent attribute present.
			name:       "go-tfe apply-and-wait with all three attributes present",
			attributes: `{"is-destroy":false,"plan-only":false,"auto-apply":false,"message":"x"}`,
			wantOp:     models.RunOperationPlanAndApply,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, perRun := resolveRunOperation(decodeRunAttributes(t, tt.attributes))
			if op != tt.wantOp {
				t.Errorf("operation = %q, want %q", op, tt.wantOp)
			}
			if perRun != tt.wantPerRun {
				t.Errorf("perRunAutoApply = %v, want %v", perRun, tt.wantPerRun)
			}
		})
	}
}

// TestResolveRunOperation_AutoApplyAfterPlanIsIgnored replaces the fallback test for the retired
// `auto-apply-after-plan` attribute. It used to turn a run with no other hint into an applyable
// one (true) or a plan-only one (false). It now changes nothing in either direction: the run
// resolves from is-destroy, plan-only and auto-apply alone.
func TestResolveRunOperation_AutoApplyAfterPlanIsIgnored(t *testing.T) {
	tests := []struct {
		name       string
		attributes string
		wantOp     models.RunOperation
		wantPerRun bool
	}{
		{
			// Was plan-only: false used to mean "the Plan only toggle".
			name:       "false does not make the run speculative",
			attributes: `{"auto-apply-after-plan":false}`,
			wantOp:     models.RunOperationPlanAndApply,
		},
		{
			name:       "true does not auto-apply",
			attributes: `{"auto-apply-after-plan":true}`,
			wantOp:     models.RunOperationPlanAndApply,
		},
		{
			name:       "true does not make a plan-only run applyable",
			attributes: `{"auto-apply-after-plan":true,"plan-only":true}`,
			wantOp:     models.RunOperationPlanOnly,
		},
		{
			name:       "false does not cancel auto-apply",
			attributes: `{"auto-apply-after-plan":false,"auto-apply":true}`,
			wantOp:     models.RunOperationPlanAndApply,
			wantPerRun: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, perRun := resolveRunOperation(decodeRunAttributes(t, tt.attributes))
			if op != tt.wantOp {
				t.Errorf("operation = %q, want %q", op, tt.wantOp)
			}
			if perRun != tt.wantPerRun {
				t.Errorf("perRunAutoApply = %v, want %v", perRun, tt.wantPerRun)
			}
		})
	}
}
