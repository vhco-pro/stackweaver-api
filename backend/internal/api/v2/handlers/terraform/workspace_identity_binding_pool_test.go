// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for
// details.

// A workspace keeps only an identity binding the pool it runs on offers (#933, D8, AC44): saving one
// of another pool, or moving the workspace to a pool that does not offer its binding, answers 422
// at the save, through every route that writes a workspace, rather than refusing each run later.
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run 'TestWorkspaceIdentityBinding'

//go:build integration

package terraform

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func TestWorkspaceIdentityBinding_MustBeOfferedByItsPool(t *testing.T) {
	f := setupWorkspacePools(t)
	if err := f.db.AutoMigrate(&models.IdentityBinding{}); err != nil {
		t.Fatal(err)
	}
	var project models.Project
	if err := f.db.First(&project, "id = ?", f.projectID).Error; err != nil {
		t.Fatal(err)
	}
	offered := &models.IdentityBinding{ID: uuid.New(), OrganizationID: project.OrganizationID, AgentPoolID: f.own.ID, Name: "deploy-" + uuid.NewString()[:6], Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-deploy"}
	foreign := &models.IdentityBinding{ID: uuid.New(), OrganizationID: project.OrganizationID, AgentPoolID: f.own2.ID, Name: "elsewhere-" + uuid.NewString()[:6], Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-elsewhere"}
	for _, b := range []*models.IdentityBinding{offered, foreign} {
		if err := f.db.Create(b).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.db.Model(&models.Workspace{}).Where("project_id = ?", f.projectID).Update("identity_binding_id", nil)
		f.db.Where("id IN ?", []uuid.UUID{offered.ID, foreign.ID}).Delete(&models.IdentityBinding{})
	})
	agent := func(pool *models.AgentPool, binding *models.IdentityBinding) map[string]any {
		a := map[string]any{"execution-mode": "agent", "agent-pool-id": pool.ID.String()}
		if binding != nil {
			a["identity-binding-id"] = binding.ID.String()
		}
		return a
	}

	// Created with another pool's binding: refused, and nothing is stored.
	name := "wsbind-" + uuid.NewString()[:8]
	create := agent(f.own, foreign)
	create["name"] = name
	if rec := f.send(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/workspaces", create); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("create with another pool's binding = %d, want 422 (%s)", rec.Code, rec.Body.String())
	}

	// Created with the binding its pool offers.
	create = agent(f.own, offered)
	create["name"] = name
	rec := f.send(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/workspaces", create)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create with an offered binding = %d (%s)", rec.Code, rec.Body.String())
	}
	var ws models.Workspace
	if err := f.db.First(&ws, "project_id = ? AND name = ?", f.projectID, name).Error; err != nil {
		t.Fatal(err)
	}

	byName := "/api/v2/organizations/" + f.orgName + "/workspaces/" + name
	byID := "/api/v2/workspaces/" + ws.ID
	for _, path := range []string{byName, byID} {
		// Another pool's binding on this pool.
		if rec := f.send(t, http.MethodPatch, path, map[string]any{"identity-binding-id": foreign.ID.String()}); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("PATCH %s with another pool's binding = %d, want 422 (%s)", path, rec.Code, rec.Body.String())
		}
		// Moving to a pool that does not offer the workspace's binding.
		if rec := f.send(t, http.MethodPatch, path, agent(f.own2, nil)); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("PATCH %s to a pool that does not offer its binding = %d, want 422 (%s)", path, rec.Code, rec.Body.String())
		}
	}
	var kept models.Workspace
	if err := f.db.First(&kept, "id = ?", ws.ID).Error; err != nil {
		t.Fatal(err)
	}
	if kept.IdentityBindingID == nil || *kept.IdentityBindingID != offered.ID || kept.AgentPoolID == nil || *kept.AgentPoolID != f.own.ID {
		t.Errorf("a refused save changed the workspace: binding %v pool %v", kept.IdentityBindingID, kept.AgentPoolID)
	}

	// Moving pool and binding together is one consistent save; clearing the binding is always allowed.
	if rec := f.send(t, http.MethodPatch, byID, agent(f.own2, foreign)); rec.Code != http.StatusOK {
		t.Errorf("PATCH to the other pool with its own binding = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec := f.send(t, http.MethodPatch, byName, map[string]any{"identity-binding-id": ""}); rec.Code != http.StatusOK {
		t.Errorf("PATCH clearing the binding = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}
