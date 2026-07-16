// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

var (
	wsPool   = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	projPool = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	orgPool  = uuid.MustParse("33333333-3333-3333-3333-333333333333")
)

// ws builds a workspace sitting in a project sitting in an org, so the whole inheritance chain can be
// exercised.
func ws(wsMode string, wsAgentPool *uuid.UUID, projMode string, projPoolID *uuid.UUID, projOverwritten bool, orgMode string, orgPoolID *uuid.UUID) *models.Workspace {
	return &models.Workspace{
		ExecutionMode: wsMode,
		AgentPoolID:   wsAgentPool,
		Project: models.Project{
			DefaultExecutionMode: projMode,
			DefaultAgentPoolID:   projPoolID,
			SettingsOverwritten:  projOverwritten,
			Organization: models.Organization{
				DefaultExecutionMode: orgMode,
				DefaultAgentPoolID:   orgPoolID,
			},
		},
	}
}

// TestResolveEffectiveAgentPool pins TFE's execution-settings chain: workspace -> project -> org, most
// specific level that expresses a preference wins.
func TestResolveEffectiveAgentPool(t *testing.T) {
	tests := []struct {
		name string
		in   *models.Workspace
		want *uuid.UUID
	}{
		// --- the organization level (new: tfe_organization_default_settings) ---
		{
			"org default applies when neither workspace nor project overwrote",
			ws("remote", nil, "remote", nil, false, "agent", &orgPool),
			&orgPool,
		},
		{
			"org default applies to a workspace with an unset execution mode",
			ws("", nil, "remote", nil, false, "agent", &orgPool),
			&orgPool,
		},
		{
			"org default in remote mode yields no pool",
			ws("remote", nil, "remote", nil, false, "remote", nil),
			nil,
		},
		{
			"org set to agent but with no pool cannot dispatch: no pool",
			ws("remote", nil, "remote", nil, false, "agent", nil),
			nil,
		},

		// --- precedence between levels ---
		{
			"project beats org",
			ws("remote", nil, "agent", &projPool, true, "agent", &orgPool),
			&projPool,
		},
		{
			"workspace beats both",
			ws("agent", &wsPool, "agent", &projPool, true, "agent", &orgPool),
			&wsPool,
		},
		{
			"a project that overwrote with a non-agent mode does NOT inherit the org agent default",
			ws("remote", nil, "local", nil, true, "agent", &orgPool),
			nil,
		},

		// --- pre-existing project-level behaviour that must not regress ---
		{
			"remote workspace still inherits its project's agent pool",
			ws("remote", nil, "agent", &projPool, true, "remote", nil),
			&projPool,
		},
		{
			"a project agent default overrides a stale pool on a remote workspace",
			ws("remote", &wsPool, "agent", &projPool, true, "remote", nil),
			&projPool,
		},
		{
			"a local workspace keeps its own pool and ignores the levels above",
			ws("local", &wsPool, "agent", &projPool, true, "agent", &orgPool),
			&wsPool,
		},
		{
			"nothing anywhere: no pool",
			ws("remote", nil, "remote", nil, false, "remote", nil),
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveEffectiveAgentPool(tt.in)
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("got pool %s, want none", got)
			case tt.want != nil && got == nil:
				t.Fatalf("got no pool, want %s", tt.want)
			case tt.want != nil && *got != *tt.want:
				t.Fatalf("got pool %s, want %s", got, tt.want)
			}
		})
	}
}
