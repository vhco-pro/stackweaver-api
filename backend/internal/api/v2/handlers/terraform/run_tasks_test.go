// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
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

// TestFullPaginationMeta: go-tfe's Pagination consumes all five fields and the run-task data
// sources page on next-page being null at the end.
func TestFullPaginationMeta(t *testing.T) {
	meta := fullPaginationMeta(2, 20, 45)
	p := meta["pagination"].(gin.H)
	if p["current-page"] != 2 || p["total-count"] != int64(45) || p["total-pages"] != 3 {
		t.Fatalf("unexpected meta: %+v", p)
	}
	if p["prev-page"] != 1 || p["next-page"] != 3 {
		t.Fatalf("prev/next wrong: %+v", p)
	}
	last := fullPaginationMeta(3, 20, 45)["pagination"].(gin.H)
	if last["next-page"] != nil {
		t.Fatalf("next-page must be null on the last page: %+v", last)
	}
	empty := fullPaginationMeta(1, 20, 0)["pagination"].(gin.H)
	if empty["total-pages"] != 1 || empty["prev-page"] != nil || empty["next-page"] != nil {
		t.Fatalf("empty list meta wrong: %+v", empty)
	}
}

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
