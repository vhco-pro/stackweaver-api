// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/settings"
)

// The effective-settings reads (#933, D0, AC32) report, for every multi-level setting of a workspace,
// a job template or an inventory source, the resolved value and the level it came from.

func level(s EffectiveSettingsAttributes, get func(EffectiveSettingsAttributes) *string) string {
	if l := get(s); l != nil {
		return *l
	}
	return ""
}

func TestWorkspaceEffectiveSettings(t *testing.T) {
	pool := uuid.New()
	ws := &models.Workspace{
		ExecutionMode: "remote",
		RunTimeout:    0,
		Project: models.Project{
			DefaultExecutionMode: "agent", DefaultAgentPoolID: &pool, SettingsOverwritten: true,
			RunTimeout:   1200,
			Organization: models.Organization{DefaultTofuVersion: "1.8.0", RunTimeout: 1800},
		},
	}
	got := workspaceEffectiveSettings(ws, 7200, "1.13.1")

	if got.ExecutionMode == nil || got.ExecutionMode.Value != "agent" || level(got, func(s EffectiveSettingsAttributes) *string { return s.ExecutionMode.Level }) != "project" {
		t.Fatalf("execution-mode = %+v", got.ExecutionMode)
	}
	if got.AgentPoolID == nil || got.AgentPoolID.Value == nil || *got.AgentPoolID.Value != pool.String() {
		t.Fatalf("agent-pool-id = %+v", got.AgentPoolID)
	}
	if got.TofuVersion == nil || got.TofuVersion.Value != "1.8.0" || *got.TofuVersion.Level != "organization" {
		t.Fatalf("tofu-version = %+v", got.TofuVersion)
	}
	if got.RunTimeout == nil || got.RunTimeout.Value != 1200 || *got.RunTimeout.Level != "project" {
		t.Fatalf("run-timeout = %+v", got.RunTimeout)
	}
}

// A workspace whose levels set no version reads the installation default at the deployment level.
// It used to read empty with a null level; #1069 (D2) gave the version a deployment level.
func TestWorkspaceEffectiveSettingsInstallationVersion(t *testing.T) {
	got := workspaceEffectiveSettings(&models.Workspace{}, 7200, "1.13.1")
	if got.TofuVersion == nil || got.TofuVersion.Value != "1.13.1" || got.TofuVersion.Level == nil || *got.TofuVersion.Level != "deployment" {
		t.Fatalf("an unset version must read as the installation default from deployment, got %+v", got.TofuVersion)
	}
	if got.RunTimeout.Value != 7200 || *got.RunTimeout.Level != "deployment" {
		t.Fatalf("run-timeout = %+v", got.RunTimeout)
	}
	if got.AgentPoolID.Value != nil || *got.ExecutionMode.Level != "deployment" || got.ExecutionMode.Value != "remote" {
		t.Fatalf("execution = %+v / %+v", got.ExecutionMode, got.AgentPoolID)
	}
}

func TestJobTemplateEffectiveSettings(t *testing.T) {
	tplPool := uuid.New()
	project := &models.Project{RunTimeout: 0, Organization: models.Organization{RunTimeout: 1800}}
	got := jobTemplateEffectiveSettings(&models.AnsibleJobTemplate{AgentPoolID: &tplPool, TimeoutSeconds: 0}, project, 7200)
	if got.AgentPoolID == nil || *got.AgentPoolID.Value != tplPool.String() || *got.AgentPoolID.Level != "job-template" {
		t.Fatalf("agent-pool-id = %+v", got.AgentPoolID)
	}
	if got.RunTimeout.Value != 1800 || *got.RunTimeout.Level != "organization" {
		t.Fatalf("run-timeout = %+v", got.RunTimeout)
	}
	if got.TofuVersion != nil || got.ExecutionMode != nil {
		t.Fatal("a job template has no OpenTofu settings")
	}
}

func TestInventorySourceEffectiveSettings(t *testing.T) {
	org := &models.Organization{RunTimeout: 0}
	// An org-scoped inventory has no project level.
	got := inventorySourceEffectiveSettings(&models.AnsibleInventorySource{}, nil, org, 3600)
	if got.RunTimeout.Value != 3600 || *got.RunTimeout.Level != "deployment" {
		t.Fatalf("run-timeout = %+v", got.RunTimeout)
	}
	got = inventorySourceEffectiveSettings(&models.AnsibleInventorySource{}, &models.Project{RunTimeout: 900}, org, 3600)
	if got.RunTimeout.Value != 900 || *got.RunTimeout.Level != "project" {
		t.Fatalf("run-timeout = %+v", got.RunTimeout)
	}
	// The source's own sync timeout (`sync-timeout`, TimeoutSeconds) is its launching level, as it
	// is for the sync itself (WorkItemService.RequestSourceSync).
	got = inventorySourceEffectiveSettings(&models.AnsibleInventorySource{TimeoutSeconds: 600}, &models.Project{RunTimeout: 900}, org, 3600)
	if got.RunTimeout.Value != 600 || *got.RunTimeout.Level != "inventory-source" {
		t.Fatalf("run-timeout with the source's own sync timeout = %+v, want 600 from inventory-source", got.RunTimeout)
	}
}

// TestEffectiveSettingsDeploymentDefaults pins the deployment default each launching object falls
// back to: a workspace and a job template the run timeout default, an inventory source sync_timeout,
// which is what its syncs are limited by.
func TestEffectiveSettingsDeploymentDefaults(t *testing.T) {
	t.Setenv(settings.EnvRunTimeoutDefault, "5000")
	t.Setenv(settings.EnvSyncTimeout, "1500")
	h := NewEffectiveSettingsHandlerV2(nil, nil, nil, nil, nil, nil, nil, nil)
	if got := workspaceEffectiveSettings(&models.Workspace{}, h.deploymentTimeout, "1.13.1").RunTimeout; got.Value != 5000 || *got.Level != "deployment" {
		t.Errorf("workspace run-timeout = %+v, want 5000 from deployment", got)
	}
	project := &models.Project{}
	if got := jobTemplateEffectiveSettings(&models.AnsibleJobTemplate{}, project, h.deploymentTimeout).RunTimeout; got.Value != 5000 || *got.Level != "deployment" {
		t.Errorf("job template run-timeout = %+v, want 5000 from deployment", got)
	}
	if got := inventorySourceEffectiveSettings(&models.AnsibleInventorySource{}, nil, &models.Organization{}, h.syncTimeout).RunTimeout; got.Value != 1500 || *got.Level != "deployment" {
		t.Errorf("inventory source run-timeout = %+v, want sync_timeout 1500 from deployment", got)
	}
}

// TestEffectiveSettingsWireShape pins the JSON:API attribute names the UI and the provider read.
func TestEffectiveSettingsWireShape(t *testing.T) {
	b, err := json.Marshal(effectiveSettingsResource("ws-abc", workspaceEffectiveSettings(&models.Workspace{}, 7200, "1.13.1")))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ID         string                     `json:"id"`
		Type       string                     `json:"type"`
		Attributes map[string]json.RawMessage `json:"attributes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Type != "effective-settings" || doc.ID != "ws-abc" {
		t.Fatalf("type/id = %s/%s", doc.Type, doc.ID)
	}
	for _, k := range []string{"execution-mode", "agent-pool-id", "tofu-version", "run-timeout", "run-image-id", "identity-binding-id"} {
		if _, ok := doc.Attributes[k]; !ok {
			t.Errorf("missing attribute %q in %s", k, b)
		}
	}
}
