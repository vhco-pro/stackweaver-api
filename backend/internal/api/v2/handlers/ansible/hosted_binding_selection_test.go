// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The hosted binding on Ansible objects (#1113, D3, AC-09): a job template, an inventory source and
// a VCS inventory on hosted capacity may select it, and a job template on an agent pool may not.
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestHostedBindingSelection

//go:build integration

package ansible

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestHostedBindingSelection_AnsibleObjects(t *testing.T) {
	f := setupInventoryIdentity(t)
	repository.SetHostedBinding(&repository.HostedBindingConfig{
		Name: "hosted-workload-identity", Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "stackweaver-hosted-identity",
		Annotations: map[string]string{"azure.workload.identity/client-id": "11111111-2222-3333-4444-555555555555"},
	})
	t.Cleanup(func() { repository.SetHostedBinding(nil) })
	hosted := models.HostedIdentityBindingID("hosted-workload-identity").String()
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgID, Name: "hbsel-" + uuid.NewString()[:6], OrganizationScoped: true}
	if err := f.db.Create(pool).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Model(&models.AnsibleJobTemplate{}).Where("id = ?", f.template).Updates(map[string]any{"identity_binding_id": nil, "agent_pool_id": nil})
		f.db.Model(&models.AnsibleInventorySource{}).Where("id = ?", f.source).Update("identity_binding_id", nil)
		f.db.Where("id = ?", pool.ID).Delete(&models.AgentPool{})
	})
	template := "/api/v2/ansible/job-templates/" + f.template.String()

	if code, body := f.call(t, http.MethodPatch, template, neighbourDocument(t, "ansible-job-templates", map[string]any{"identity-binding-id": hosted}, nil, nil)); code != http.StatusOK {
		t.Errorf("a hosted job template selecting the hosted binding = %d, want 200 (%s)", code, body)
	}
	if code, body := f.call(t, http.MethodPatch, template, neighbourDocument(t, "ansible-job-templates", map[string]any{}, map[string]string{"agent-pool": pool.ID.String()}, nil)); code != http.StatusUnprocessableEntity {
		t.Errorf("moving a template selecting the hosted binding to an agent pool = %d, want 422 (%s)", code, body)
	}
	if code, body := f.call(t, http.MethodPatch, "/api/v2/ansible/inventory-sources/"+f.source.String(),
		neighbourDocument(t, "ansible-inventory-sources", map[string]any{"identity-binding-id": hosted}, nil, nil)); code != http.StatusOK {
		t.Errorf("an inventory source selecting the hosted binding = %d, want 200 (%s)", code, body)
	}
	if code, body := f.patch(t, f.vcs, hosted); code != http.StatusOK {
		t.Errorf("a VCS inventory selecting the hosted binding = %d, want 200 (%s)", code, body)
	}
	for table, id := range map[string]any{"ansible_job_templates": f.template, "ansible_inventory_sources": f.source, "ansible_inventories": f.vcs} {
		var got *string
		if err := f.db.Table(table).Select("identity_binding_id::text").Where("id = ?", id).Scan(&got).Error; err != nil {
			t.Fatal(err)
		}
		if got == nil || *got != hosted {
			t.Errorf("%s stored %v, want the hosted binding %s", table, got, hosted)
		}
	}
}
