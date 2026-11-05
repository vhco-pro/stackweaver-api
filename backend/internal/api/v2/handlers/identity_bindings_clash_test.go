// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for identity bindings (#933, D8, AC49a, AC49b): a create whose
// ServiceAccount another manager already holds is refused with 409 naming the manager and writes
// nothing, the same request in reference mode succeeds, and a binding the launcher reported as
// declared outside Stackweaver refuses PATCH of its Kubernetes fields and DELETE.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestIdentityBindings

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestIdentityBindings_ClashAndHandOver(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "idb-" + f.sfx, OrganizationScoped: true}
	if err := f.db.Create(pool).Error; err != nil {
		t.Fatal(err)
	}
	bindings := repository.NewIdentityBindingRepository(f.db)
	t.Cleanup(func() {
		f.db.Where("agent_pool_id = ?", pool.ID).Delete(&models.IdentityBinding{})
		f.db.Where("agent_pool_id = ?", pool.ID).Delete(&models.PoolObjectReport{})
		f.db.Where("id = ?", pool.ID).Delete(&models.AgentPool{})
	})
	// The pool's launcher reported a ServiceAccount Argo CD manages.
	if err := bindings.ReportInventory(pool.ID, []repository.ObjectReport{
		{Kind: "ServiceAccount", Namespace: "stackweaver", Name: "sw-argo", Present: true, ManagedBy: "external", ExternalManager: "Argo CD application platform"},
	}); err != nil {
		t.Fatal(err)
	}

	orgs := repository.NewOrganizationRepository(f.db)
	h := NewIdentityBindingHandler(repository.NewAgentPoolRepository(f.db), bindings, f.authSvc, rbac.NewServiceWithTeams(orgs, repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	r := platformAdminRouter()
	r.POST("/api/v2/agent-pools/:id/identity-bindings", h.Create)
	r.GET("/api/v2/agent-pools/:id/identity-bindings", h.List)
	r.GET("/api/v2/identity-bindings/:id", h.Get)
	r.PATCH("/api/v2/identity-bindings/:id", h.Update)
	r.DELETE("/api/v2/identity-bindings/:id", h.Delete)
	create := func(attrs string) (int, string) {
		rec := platformAdminCall(t, r, http.MethodPost, "/api/v2/agent-pools/"+pool.ID.String()+"/identity-bindings", browserAs(f.owner), `{"data":{"type":"identity-bindings","attributes":`+attrs+`}}`)
		return rec.Code, rec.Body.String()
	}

	// Order 1: the name is taken by Argo CD.
	code, body := create(`{"name":"deploy","mechanism":"aws-irsa","service-account":"sw-argo","annotations":{"eks.amazonaws.com/role-arn":"arn:aws:iam::1:role/deploy"}}`)
	if code != http.StatusConflict || !strings.Contains(body, "sw-argo exists in namespace stackweaver and is managed by Argo CD application platform") {
		t.Fatalf("a create over an Argo CD object = %d %s, want 409 naming the manager", code, body)
	}
	if list, _ := bindings.ListByPool(pool.ID); len(list) != 0 {
		t.Fatalf("a refused create stored %d bindings", len(list))
	}
	// Reference mode never writes the object, so it may name it.
	code, body = create(`{"name":"deploy","mechanism":"aws-irsa","service-account":"sw-argo","reference":true}`)
	if code != http.StatusCreated {
		t.Fatalf("the same binding in reference mode = %d %s", code, body)
	}
	var doc struct {
		Data struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(body), &doc)
	if doc.Data.Attributes["mechanism"] != "aws-irsa" || doc.Data.Attributes["reference"] != true {
		t.Errorf("created binding = %v", doc.Data.Attributes)
	}

	// A create-mode binding of a free name, then the launcher reports Flux took it over.
	// The client id is a real application id's form: a created account needs its mechanism's
	// annotation in that form (TestValidateBinding).
	code, body = create(`{"name":"ours","mechanism":"azure-workload-identity","service-account":"sw-ours","annotations":{"azure.workload.identity/client-id":"00000000-0000-0000-0000-000000000000"}}`)
	if code != http.StatusCreated {
		t.Fatalf("a create of a free name = %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &doc)
	ours := doc.Data.ID
	if err := bindings.ReportInventory(pool.ID, []repository.ObjectReport{
		{Kind: "ServiceAccount", Namespace: "stackweaver", Name: "sw-ours", Present: true, ManagedBy: "external", ExternalManager: "Flux Kustomization flux-system/infra"},
	}); err != nil {
		t.Fatal(err)
	}
	read := platformAdminCall(t, r, http.MethodGet, "/api/v2/identity-bindings/"+ours, browserAs(f.member), "")
	_ = json.Unmarshal(read.Body.Bytes(), &doc)
	if read.Code != http.StatusOK || doc.Data.Attributes["declared-externally"] != true || doc.Data.Attributes["external-manager"] != "Flux Kustomization flux-system/infra" {
		t.Errorf("a handed-over binding reads %d %v", read.Code, doc.Data.Attributes)
	}
	patch := platformAdminCall(t, r, http.MethodPatch, "/api/v2/identity-bindings/"+ours, browserAs(f.owner), `{"data":{"type":"identity-bindings","attributes":{"service-account":"sw-other"}}}`)
	if patch.Code != http.StatusConflict || !strings.Contains(patch.Body.String(), "declared outside Stackweaver") {
		t.Errorf("PATCH of a Kubernetes field of a declared binding = %d %s, want 409", patch.Code, patch.Body.String())
	}
	if rename := platformAdminCall(t, r, http.MethodPatch, "/api/v2/identity-bindings/"+ours, browserAs(f.owner), `{"data":{"type":"identity-bindings","attributes":{"name":"renamed"}}}`); rename.Code != http.StatusOK {
		t.Errorf("renaming a declared binding = %d %s, want 200 (the name is Stackweaver's)", rename.Code, rename.Body.String())
	}
	if del := platformAdminCall(t, r, http.MethodDelete, "/api/v2/identity-bindings/"+ours, browserAs(f.owner), ""); del.Code != http.StatusConflict {
		t.Errorf("DELETE of a declared binding = %d, want 409", del.Code)
	}
	// Validation: an unknown mechanism and a name that is not a ServiceAccount name.
	if code, _ := create(`{"name":"bad","mechanism":"ssh","service-account":"sw-bad"}`); code != http.StatusUnprocessableEntity {
		t.Errorf("an unknown mechanism = %d, want 422", code)
	}
	if code, _ := create(`{"name":"bad","mechanism":"aws-irsa","service-account":"Not_A_Name"}`); code != http.StatusUnprocessableEntity {
		t.Errorf("an invalid service account name = %d, want 422", code)
	}
	// A member reads but does not write.
	if code := platformAdminCall(t, r, http.MethodPost, "/api/v2/agent-pools/"+pool.ID.String()+"/identity-bindings", browserAs(f.member), `{"data":{"type":"identity-bindings","attributes":{"name":"m","mechanism":"aws-irsa","service-account":"sw-m"}}}`).Code; code != http.StatusForbidden {
		t.Errorf("a member creating a binding = %d, want 403", code)
	}
	if list := platformAdminCall(t, r, http.MethodGet, "/api/v2/agent-pools/"+pool.ID.String()+"/identity-bindings", browserAs(f.member), ""); list.Code != http.StatusOK {
		t.Errorf("a member listing bindings = %d, want 200", list.Code)
	}
}
