// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Regression guard for #107: destroy-run apply logs were unreachable.
//
// Destroy runs use the same two-phase plan/apply flow as plan-and-apply, and both the
// platform runner and agent mode store their output under the "apply" phase. GetApply
// already admitted destroy, but GetApplyLogs rejected any operation other than
// plan-and-apply with a 400 - so the logs existed in storage and the frontend requested
// them (useRunPolling calls getApplyLogs when operation === 'destroy'), but the endpoint
// refused to serve them. The two gates are now one predicate so they cannot drift apart
// again.

package terraform

import (
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

func TestRunHasApplyPhase(t *testing.T) {
	tests := []struct {
		name string
		op   models.RunOperation
		want bool
	}{
		{
			name: "plan-and-apply has an apply phase",
			op:   models.RunOperationPlanAndApply,
			want: true,
		},
		{
			// The #107 case: this returned false before the fix, which made
			// GetApplyLogs 400 on every destroy run.
			name: "destroy has an apply phase (two-phase flow, output stored under apply)",
			op:   models.RunOperationDestroy,
			want: true,
		},
		{
			name: "plan-only has no apply phase",
			op:   models.RunOperationPlanOnly,
			want: false,
		},
		{
			name: "empty operation has no apply phase",
			op:   models.RunOperation(""),
			want: false,
		},
		{
			name: "unknown operation has no apply phase",
			op:   models.RunOperation("refresh-only"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runHasApplyPhase(tt.op); got != tt.want {
				t.Errorf("runHasApplyPhase(%q) = %v, want %v", tt.op, got, tt.want)
			}
		})
	}
}
