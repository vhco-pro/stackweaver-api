// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Unit tests for applyProjectSettings — the tfe_project_settings mapping (default execution mode +
// default agent pool + setting-overwrites) onto a Project. Covers the branches that do not touch the
// agent-pool repository (validation, mode transitions, overwrite clearing, and the agent-requires-pool
// rule). The pool-lookup branch is exercised end-to-end by the runtime harness.

package handlers

import (
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

func strPtr(s string) *string { return &s }
func bPtr(b bool) *bool       { return &b }

func TestApplyProjectSettings(t *testing.T) {
	h := &ProjectHandlerV2{} // agentPoolRepo unused by these cases (no default-agent-pool-id set)

	t.Run("invalid execution mode is rejected", func(t *testing.T) {
		p := &models.Project{DefaultExecutionMode: "remote"}
		if _, ok := h.applyProjectSettings(p, projectSettingsAttrs{DefaultExecutionMode: strPtr("bogus")}); ok {
			t.Fatal("expected invalid mode to be rejected")
		}
	})

	t.Run("agent mode without a pool is rejected", func(t *testing.T) {
		p := &models.Project{DefaultExecutionMode: "remote"}
		if _, ok := h.applyProjectSettings(p, projectSettingsAttrs{DefaultExecutionMode: strPtr("agent")}); ok {
			t.Fatal("expected agent mode without a pool to be rejected")
		}
	})

	t.Run("local mode clears any stale pool", func(t *testing.T) {
		id := models.Project{}.ID // zero uuid, only need a non-nil pointer
		p := &models.Project{DefaultExecutionMode: "agent", DefaultAgentPoolID: &id}
		if _, ok := h.applyProjectSettings(p, projectSettingsAttrs{DefaultExecutionMode: strPtr("local")}); !ok {
			t.Fatal("local mode should be accepted")
		}
		if p.DefaultExecutionMode != "local" || p.DefaultAgentPoolID != nil {
			t.Fatalf("expected local + nil pool, got %s / %v", p.DefaultExecutionMode, p.DefaultAgentPoolID)
		}
	})

	t.Run("explicit mode marks the project as overwriting", func(t *testing.T) {
		p := &models.Project{DefaultExecutionMode: "remote"}
		if _, ok := h.applyProjectSettings(p, projectSettingsAttrs{DefaultExecutionMode: strPtr("local")}); !ok {
			t.Fatal("local mode should be accepted")
		}
		if !p.SettingsOverwritten {
			t.Fatal("SettingsOverwritten should be true after an explicit mode is set")
		}
	})

	t.Run("setting-overwrites execution-mode=false reverts to remote and clears overwrite", func(t *testing.T) {
		id := models.Project{}.ID
		p := &models.Project{DefaultExecutionMode: "agent", DefaultAgentPoolID: &id, SettingsOverwritten: true}
		if _, ok := h.applyProjectSettings(p, projectSettingsAttrs{
			SettingOverwrites: &projectSettingOverwritesReq{DefaultExecutionMode: bPtr(false)},
		}); !ok {
			t.Fatal("clearing execution-mode overwrite should be accepted")
		}
		if p.DefaultExecutionMode != "remote" || p.DefaultAgentPoolID != nil || p.SettingsOverwritten {
			t.Fatalf("expected remote + nil pool + not-overwritten, got %s / %v / %v", p.DefaultExecutionMode, p.DefaultAgentPoolID, p.SettingsOverwritten)
		}
	})

	t.Run("remote mode is a no-op-safe default", func(t *testing.T) {
		p := &models.Project{DefaultExecutionMode: "remote"}
		if _, ok := h.applyProjectSettings(p, projectSettingsAttrs{DefaultExecutionMode: strPtr("remote")}); !ok {
			t.Fatal("remote mode should be accepted")
		}
		if p.DefaultExecutionMode != "remote" {
			t.Fatalf("expected remote, got %s", p.DefaultExecutionMode)
		}
	})
}
