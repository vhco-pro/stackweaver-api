// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

// TestFormatRunTaskGlobalConfigurationAlwaysPresent pins the go-tfe decode quirk: the
// global-configuration attribute sub-object must ALWAYS be emitted with a boolean `enabled`
// (go-tfe parses it only then), or tfe_organization_run_task_global_settings and its data source
// break on every task that never enabled global settings.
func TestFormatRunTaskGlobalConfigurationAlwaysPresent(t *testing.T) {
	doc := formatRunTask(&models.RunTask{ID: "task-abc", Name: "t", URL: "https://x.example", Category: "task"}, "acme", nil)
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, `"global-configuration":{"enabled":false`) {
		t.Fatalf("global-configuration must always be present with a boolean enabled (map key order is sorted, enabled first); got %s", s)
	}
	if !strings.Contains(s, `"stages":[]`) {
		t.Fatalf("global-configuration stages must be an array, never null; got %s", s)
	}
}

// TestFormatRunTaskNeverEchoesHMACKey: hmac-key is write-only, exactly like TFE.
func TestFormatRunTaskNeverEchoesHMACKey(t *testing.T) {
	doc := formatRunTask(&models.RunTask{ID: "task-abc", Name: "t", URL: "https://x.example", HMACKey: "encrypted-secret"}, "acme", nil)
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "hmac") || strings.Contains(string(body), "secret") {
		t.Fatalf("hmac-key must never appear in a task document; got %s", body)
	}
}

// TestFormatWorkspaceTaskEmitsBothStageAndStages: the provider stores BOTH the deprecated singular
// `stage` (= stages[0]) and `stages`; dropping either breaks its round-trip.
func TestFormatWorkspaceTaskEmitsBothStageAndStages(t *testing.T) {
	doc := formatWorkspaceTask(&models.WorkspaceTask{
		ID: "wstask-abc", WorkspaceID: "ws-1", TaskID: "task-1",
		EnforcementLevel: "mandatory", Stages: models.StringArray{"pre_apply", "post_apply"},
	})
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, `"stage":"pre_apply"`) {
		t.Fatalf("singular stage must equal stages[0]; got %s", s)
	}
	if !strings.Contains(s, `"stages":["pre_apply","post_apply"]`) {
		t.Fatalf("stages array must be emitted verbatim; got %s", s)
	}
}

// The pagination boundary cases this file used to test now live in
// internal/api/v2/jsonapi/pagination_test.go, alongside the single implementation those nine
// per-handler variants were converged onto (#756). They are not lost, they moved.

func TestRunTaskValidators(t *testing.T) {
	if !validTaskStages([]string{"pre_plan", "post_apply"}) {
		t.Fatal("valid stages rejected")
	}
	if validTaskStages([]string{"post_plan", "post_plan"}) {
		t.Fatal("duplicate stages must be rejected")
	}
	if validTaskStages([]string{"plan"}) {
		t.Fatal("unknown stage must be rejected")
	}
	if !validEnforcementLevel("advisory") || !validEnforcementLevel("mandatory") || validEnforcementLevel("blocking") {
		t.Fatal("enforcement level validation wrong")
	}
	if validTaskURL("ftp://x") || validTaskURL("not a url") || !validTaskURL("https://tasks.example.com/hook") {
		t.Fatal("url validation wrong")
	}
}

// TestNormalizeStages pins the deprecated-stage normalization: stages wins over stage; a singular
// stage becomes a one-element list; absent input keeps the fallback.
func TestNormalizeStages(t *testing.T) {
	pre := "pre_plan"
	if got := normalizeStages(workspaceTaskAttributes{Stages: []string{"post_plan"}, Stage: &pre}, nil); len(got) != 1 || got[0] != "post_plan" {
		t.Fatalf("stages must win over stage, got %v", got)
	}
	if got := normalizeStages(workspaceTaskAttributes{Stage: &pre}, nil); len(got) != 1 || got[0] != "pre_plan" {
		t.Fatalf("singular stage must normalize, got %v", got)
	}
	if got := normalizeStages(workspaceTaskAttributes{}, []string{"post_plan"}); len(got) != 1 || got[0] != "post_plan" {
		t.Fatalf("fallback must apply, got %v", got)
	}
	if got := normalizeStages(workspaceTaskAttributes{Stages: []string{}}, []string{"post_plan"}); got != nil {
		t.Fatalf("empty stages array must be invalid, got %v", got)
	}
}
