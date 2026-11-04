// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test: a run's identity binding resolves by the level rule and only to a binding its
// pool offers (#933, D0, D8, AC44).
//
// Gated behind `integration`; cleanup is row-scoped.

//go:build integration

package terraform

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func TestRunCreate_IdentityBindingMustBeOfferedByThePool(t *testing.T) {
	f := setupRunCreateScope(t)
	if err := f.db.AutoMigrate(&models.AgentPool{}, &models.IdentityBinding{}); err != nil {
		t.Fatal(err)
	}
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA, Name: "idpool-" + uuid.NewString()[:8], OrganizationScoped: true}
	other := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA, Name: "idother-" + uuid.NewString()[:8], OrganizationScoped: true}
	offered := &models.IdentityBinding{ID: uuid.New(), OrganizationID: f.orgA, AgentPoolID: pool.ID, Name: "deploy", Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-deploy"}
	foreign := &models.IdentityBinding{ID: uuid.New(), OrganizationID: f.orgA, AgentPoolID: other.ID, Name: "elsewhere", Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-elsewhere"}
	for _, o := range []any{pool, other, offered, foreign} {
		if err := f.db.Create(o).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.db.Where("id = ?", f.workspace).Updates(map[string]any{"identity_binding_id": nil, "agent_pool_id": nil})
		f.db.Model(&models.Project{}).Where("id = ?", f.projectA).Update("identity_binding_id", nil)
		f.db.Where("id IN ?", []uuid.UUID{offered.ID, foreign.ID}).Delete(&models.IdentityBinding{})
		f.db.Where("id IN ?", []uuid.UUID{pool.ID, other.ID}).Delete(&models.AgentPool{})
	})
	setWorkspace := func(binding *uuid.UUID) {
		t.Helper()
		if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.workspace).Updates(map[string]any{
			"execution_mode": "agent", "agent_pool_id": pool.ID, "identity_binding_id": binding,
		}).Error; err != nil {
			t.Fatal(err)
		}
		f.db.Where("workspace_id = ?", f.workspace).Delete(&models.Run{})
	}

	// A binding the pool offers: the run is created.
	setWorkspace(&offered.ID)
	if rec := f.postRun(t, "", nil); rec.Code != http.StatusCreated {
		t.Fatalf("a run with an offered binding = %d %s", rec.Code, rec.Body.String())
	}

	// A binding of another pool, at the workspace: refused with the reason.
	setWorkspace(&foreign.ID)
	rec := f.postRun(t, "", nil)
	var doc struct {
		Errors []struct{ Detail string } `json:"errors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	if rec.Code != http.StatusUnprocessableEntity || len(doc.Errors) == 0 || !strings.Contains(doc.Errors[0].Detail, `identity binding "elsewhere"`) {
		t.Errorf("a run with another pool's binding = %d %s, want 422 naming the binding", rec.Code, rec.Body.String())
	}

	// The same binding inherited from the project: refused the same way, by the level rule.
	setWorkspace(nil)
	if err := f.db.Model(&models.Project{}).Where("id = ?", f.projectA).Update("identity_binding_id", foreign.ID).Error; err != nil {
		t.Fatal(err)
	}
	if rec := f.postRun(t, "", nil); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("a run inheriting another pool's binding from its project = %d, want 422", rec.Code)
	}
	if n := f.runCount(t); n != 0 {
		t.Errorf("%d runs were stored for refused creations", n)
	}
}
