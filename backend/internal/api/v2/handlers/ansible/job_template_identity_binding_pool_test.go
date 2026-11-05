// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A job template keeps only an identity binding the pool its jobs run on offers (#933, D8, AC44):
// saving one of another pool, or moving the template to a pool that does not offer its binding,
// answers 422 at the save rather than refusing every job of it later.
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run 'TestJobTemplateIdentityBinding'

//go:build integration

package ansible

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func TestJobTemplateIdentityBinding_MustBeOfferedByItsPool(t *testing.T) {
	f := setupNeighbourScope(t)
	if err := f.db.AutoMigrate(&models.IdentityBinding{}); err != nil {
		t.Fatal(err)
	}
	var project models.Project
	if err := f.db.First(&project, "id = ?", f.projectID).Error; err != nil {
		t.Fatal(err)
	}
	sfx := uuid.NewString()[:6]
	poolA := &models.AgentPool{ID: uuid.New(), OrganizationID: project.OrganizationID, Name: "tbind-a-" + sfx, OrganizationScoped: true}
	poolB := &models.AgentPool{ID: uuid.New(), OrganizationID: project.OrganizationID, Name: "tbind-b-" + sfx, OrganizationScoped: true}
	offered := &models.IdentityBinding{ID: uuid.New(), OrganizationID: project.OrganizationID, AgentPoolID: poolA.ID, Name: "deploy-" + sfx, Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-deploy"}
	foreign := &models.IdentityBinding{ID: uuid.New(), OrganizationID: project.OrganizationID, AgentPoolID: poolB.ID, Name: "elsewhere-" + sfx, Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-elsewhere"}
	for _, row := range []any{poolA, poolB, offered, foreign} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	// Registered after the fixture's own cleanup, so it runs first: the templates let go of the
	// bindings and pools before those are removed.
	t.Cleanup(func() {
		f.db.Model(&models.AnsibleJobTemplate{}).Where("project_id = ?", f.projectID).Updates(map[string]any{"identity_binding_id": nil, "agent_pool_id": nil})
		f.db.Where("id IN ?", []uuid.UUID{offered.ID, foreign.ID}).Delete(&models.IdentityBinding{})
		f.db.Where("id IN ?", []uuid.UUID{poolA.ID, poolB.ID}).Delete(&models.AgentPool{})
	})

	orgTemplates := "/api/v2/organizations/" + f.orgName + "/ansible/job-templates"
	template := "/api/v2/ansible/job-templates/" + f.template.String()
	create := func(binding *models.IdentityBinding) string {
		attrs := neighbourName()
		attrs["identity-binding-id"] = binding.ID.String()
		return neighbourDocument(t, "ansible-job-templates", attrs, f.own("agent-pool", poolA.ID.String()), nil)
	}

	if code, body := f.call(t, http.MethodPost, orgTemplates, create(foreign)); code != http.StatusUnprocessableEntity {
		t.Errorf("create with another pool's binding = %d, want 422 (%s)", code, body)
	}
	if code, body := f.call(t, http.MethodPost, orgTemplates, create(offered)); code != http.StatusCreated {
		t.Errorf("create with the binding its pool offers = %d, want 201 (%s)", code, body)
	}

	// The existing template moves to pool A with its binding, then may neither take pool B's
	// binding nor move to pool B while it holds pool A's.
	if code, body := f.call(t, http.MethodPatch, template, neighbourDocument(t, "ansible-job-templates",
		map[string]any{"identity-binding-id": offered.ID.String()}, map[string]string{"agent-pool": poolA.ID.String()}, nil)); code != http.StatusOK {
		t.Fatalf("update to pool A with its binding = %d, want 200 (%s)", code, body)
	}
	if code, body := f.call(t, http.MethodPatch, template, neighbourDocument(t, "ansible-job-templates",
		map[string]any{"identity-binding-id": foreign.ID.String()}, nil, nil)); code != http.StatusUnprocessableEntity {
		t.Errorf("update with another pool's binding = %d, want 422 (%s)", code, body)
	}
	if code, body := f.call(t, http.MethodPatch, template, neighbourDocument(t, "ansible-job-templates",
		map[string]any{}, map[string]string{"agent-pool": poolB.ID.String()}, nil)); code != http.StatusUnprocessableEntity {
		t.Errorf("update to a pool that does not offer its binding = %d, want 422 (%s)", code, body)
	}
	var row models.AnsibleJobTemplate
	if err := f.db.First(&row, "id = ?", f.template).Error; err != nil {
		t.Fatal(err)
	}
	if row.AgentPoolID == nil || *row.AgentPoolID != poolA.ID || row.IdentityBindingID == nil || *row.IdentityBindingID != offered.ID {
		t.Errorf("the refused updates changed the template to pool %v, binding %v", row.AgentPoolID, row.IdentityBindingID)
	}

	// An unrelated edit is not checked, and clearing the binding is always allowed.
	if code, body := f.call(t, http.MethodPatch, template, neighbourDocument(t, "ansible-job-templates",
		map[string]any{"description": "unrelated"}, nil, nil)); code != http.StatusOK {
		t.Errorf("an unrelated update = %d, want 200 (%s)", code, body)
	}
	if code, body := f.call(t, http.MethodPatch, template, neighbourDocument(t, "ansible-job-templates",
		map[string]any{"identity-binding-id": ""}, map[string]string{"agent-pool": poolB.ID.String()}, nil)); code != http.StatusOK {
		t.Errorf("moving to pool B without a binding = %d, want 200 (%s)", code, body)
	}
}
