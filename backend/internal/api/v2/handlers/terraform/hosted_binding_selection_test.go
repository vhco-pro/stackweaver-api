// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The hosted binding on a workspace (#1113, D3; AC-06, AC-09): a workspace on hosted capacity may
// select it, one on an agent pool may not, a run of a hosted workspace selecting it is created
// through the run repository's identity bindings, and once the configuration no longer names it a
// run is refused at creation with 422 naming the binding.
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestHostedBindingSelection

//go:build integration

package terraform

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func configureHostedBinding(t *testing.T, name string) uuid.UUID {
	t.Helper()
	repository.SetHostedBinding(&repository.HostedBindingConfig{
		Name: name, Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "stackweaver-hosted-identity",
		Annotations: map[string]string{"azure.workload.identity/client-id": "11111111-2222-3333-4444-555555555555"},
	})
	t.Cleanup(func() { repository.SetHostedBinding(nil) })
	return models.HostedIdentityBindingID(name)
}

func TestHostedBindingSelection_Workspace(t *testing.T) {
	f := setupWorkspacePools(t)
	hosted := configureHostedBinding(t, "hosted-workload-identity")
	t.Cleanup(func() {
		f.db.Model(&models.Workspace{}).Where("project_id = ?", f.projectID).Update("identity_binding_id", nil)
	})

	name := "wshosted-" + uuid.NewString()[:8]
	rec := f.send(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/workspaces", map[string]any{
		"name": name, "execution-mode": "remote", "identity-binding-id": hosted.String(),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("a hosted workspace selecting the hosted binding = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
	var ws models.Workspace
	if err := f.db.First(&ws, "project_id = ? AND name = ?", f.projectID, name).Error; err != nil {
		t.Fatal(err)
	}
	if ws.IdentityBindingID == nil || *ws.IdentityBindingID != hosted {
		t.Errorf("stored binding = %v, want the hosted binding %s", ws.IdentityBindingID, hosted)
	}
	// On an agent pool it is refused.
	if rec := f.send(t, http.MethodPatch, "/api/v2/workspaces/"+ws.ID, map[string]any{"execution-mode": "agent", "agent-pool-id": f.own.ID.String()}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("moving a workspace selecting the hosted binding to an agent pool = %d, want 422 (%s)", rec.Code, rec.Body.String())
	}
}

func TestHostedBindingSelection_RunCreation(t *testing.T) {
	f := setupRunCreateScope(t)
	hosted := configureHostedBinding(t, "hosted-workload-identity")
	t.Cleanup(func() {
		f.db.Where("workspace_id = ?", f.workspace).Delete(&models.Run{})
		f.db.Model(&models.Workspace{}).Where("id = ?", f.workspace).Update("identity_binding_id", nil)
	})
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.workspace).Updates(map[string]any{
		"execution_mode": "remote", "agent_pool_id": nil, "identity_binding_id": hosted,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if rec := f.postRun(t, "", nil); rec.Code != http.StatusCreated {
		t.Fatalf("a run of a hosted workspace selecting the hosted binding = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}

	// Renamed: the old ID no longer exists, and a new run is refused at creation.
	f.db.Where("workspace_id = ?", f.workspace).Delete(&models.Run{})
	configureHostedBinding(t, "renamed-identity")
	rec := f.postRun(t, "", nil)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), hosted.String()) || !strings.Contains(rec.Body.String(), "no longer exists") {
		t.Errorf("a run selecting an old hosted ID = %d %s, want 422 naming the binding as no longer existing", rec.Code, rec.Body.String())
	}

	// Disabled: no hosted binding is configured, and a new run is refused at creation the same way.
	repository.SetHostedBinding(nil)
	rec = f.postRun(t, "", nil)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), hosted.String()) || !strings.Contains(rec.Body.String(), "no longer exists") {
		t.Errorf("a run selecting the hosted ID after a disable = %d %s, want 422 naming the binding as no longer existing", rec.Code, rec.Body.String())
	}
}
