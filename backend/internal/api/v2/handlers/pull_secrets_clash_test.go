// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for a pool's registry pull Secrets (#933, D8, AC48, AC49a, AC49b): a create
// whose Secret another manager already holds is refused with 409 naming the manager and writes
// nothing, the same request in reference mode succeeds, and a Secret the launcher reported as
// declared outside Stackweaver refuses PATCH of its Kubernetes fields and DELETE.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set.

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

func TestPullSecrets_ClashAndHandOver(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "pull-" + f.sfx, OrganizationScoped: true}
	if err := f.db.Create(pool).Error; err != nil {
		t.Fatal(err)
	}
	cred := &models.AnsibleCredential{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "pull-cred-" + f.sfx, Type: models.CredentialTypeRegistry, Username: "robot"}
	if err := f.db.Create(cred).Error; err != nil {
		t.Fatal(err)
	}
	otherOrgCred := &models.AnsibleCredential{ID: uuid.New(), OrganizationID: f.orgB.ID, Name: "pull-foreign-" + f.sfx, Type: models.CredentialTypeRegistry, Username: "x"}
	if err := f.db.Create(otherOrgCred).Error; err != nil {
		t.Fatal(err)
	}
	bindings := repository.NewIdentityBindingRepository(f.db)
	pulls := repository.NewPullSecretRepository(f.db)
	t.Cleanup(func() {
		f.db.Where("agent_pool_id = ?", pool.ID).Delete(&models.PullSecret{})
		f.db.Where("agent_pool_id = ?", pool.ID).Delete(&models.PoolObjectReport{})
		f.db.Where("id IN ?", []uuid.UUID{cred.ID, otherOrgCred.ID}).Delete(&models.AnsibleCredential{})
		f.db.Where("id = ?", pool.ID).Delete(&models.AgentPool{})
	})
	if err := bindings.ReportInventory(pool.ID, []repository.ObjectReport{
		{Kind: "Secret", Namespace: "stackweaver", Name: "sw-pull-argo", Present: true, ManagedBy: "external", ExternalManager: "Argo CD application platform"},
	}); err != nil {
		t.Fatal(err)
	}

	orgs := repository.NewOrganizationRepository(f.db)
	h := NewPullSecretHandler(repository.NewAgentPoolRepository(f.db), pulls, f.db, f.authSvc, rbac.NewServiceWithTeams(orgs, repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	r := platformAdminRouter()
	r.POST("/api/v2/agent-pools/:id/pull-secrets", h.Create)
	r.GET("/api/v2/agent-pools/:id/pull-secrets", h.List)
	r.GET("/api/v2/pull-secrets/:id", h.Get)
	r.PATCH("/api/v2/pull-secrets/:id", h.Update)
	r.DELETE("/api/v2/pull-secrets/:id", h.Delete)
	create := func(attrs string) (int, string) {
		rec := platformAdminCall(t, r, http.MethodPost, "/api/v2/agent-pools/"+pool.ID.String()+"/pull-secrets", browserAs(f.owner), `{"data":{"type":"pull-secrets","attributes":`+attrs+`}}`)
		return rec.Code, rec.Body.String()
	}
	credAttr := `"registry-credential-id":"` + cred.ID.String() + `"`

	// Order 1: the Secret's name is taken by Argo CD.
	code, body := create(`{"name":"ghcr","secret-name":"sw-pull-argo","registry":"ghcr.io",` + credAttr + `}`)
	if code != http.StatusConflict || !strings.Contains(body, "sw-pull-argo exists in namespace stackweaver and is managed by Argo CD application platform") {
		t.Fatalf("a create over an Argo CD Secret = %d %s, want 409 naming the manager", code, body)
	}
	if list, _ := pulls.ListByPool(pool.ID); len(list) != 0 {
		t.Fatalf("a refused create stored %d pull Secrets", len(list))
	}
	// Reference mode never writes the Secret, so it may name it, and needs no credential.
	code, body = create(`{"name":"ghcr","secret-name":"sw-pull-argo","registry":"ghcr.io","reference":true}`)
	if code != http.StatusCreated {
		t.Fatalf("the same Secret in reference mode = %d %s", code, body)
	}
	var doc struct {
		Data struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(body), &doc)
	if doc.Data.Attributes["registry"] != "ghcr.io" || doc.Data.Attributes["reference"] != true {
		t.Errorf("created pull Secret = %v", doc.Data.Attributes)
	}

	// A create-mode Secret of a free name, then the launcher reports Flux took it over.
	code, body = create(`{"name":"internal","secret-name":"sw-pull-internal","registry":"registry.example:5000",` + credAttr + `}`)
	if code != http.StatusCreated {
		t.Fatalf("a create of a free name = %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &doc)
	ours := doc.Data.ID
	if err := bindings.ReportInventory(pool.ID, []repository.ObjectReport{
		{Kind: "Secret", Namespace: "stackweaver", Name: "sw-pull-argo", Present: true, ManagedBy: "external", ExternalManager: "Argo CD application platform"},
		{Kind: "Secret", Namespace: "stackweaver", Name: "sw-pull-internal", Present: true, ManagedBy: "external", ExternalManager: "Flux Kustomization flux-system/infra"},
	}); err != nil {
		t.Fatal(err)
	}
	read := platformAdminCall(t, r, http.MethodGet, "/api/v2/pull-secrets/"+ours, browserAs(f.member), "")
	_ = json.Unmarshal(read.Body.Bytes(), &doc)
	if read.Code != http.StatusOK || doc.Data.Attributes["declared-externally"] != true || doc.Data.Attributes["external-manager"] != "Flux Kustomization flux-system/infra" {
		t.Errorf("a handed-over pull Secret reads %d %v", read.Code, doc.Data.Attributes)
	}
	patch := platformAdminCall(t, r, http.MethodPatch, "/api/v2/pull-secrets/"+ours, browserAs(f.owner), `{"data":{"type":"pull-secrets","attributes":{"registry":"other.example"}}}`)
	if patch.Code != http.StatusConflict || !strings.Contains(patch.Body.String(), "declared outside Stackweaver") {
		t.Errorf("PATCH of a Kubernetes field of a declared pull Secret = %d %s, want 409", patch.Code, patch.Body.String())
	}
	if rename := platformAdminCall(t, r, http.MethodPatch, "/api/v2/pull-secrets/"+ours, browserAs(f.owner), `{"data":{"type":"pull-secrets","attributes":{"name":"renamed"}}}`); rename.Code != http.StatusOK {
		t.Errorf("renaming a declared pull Secret = %d %s, want 200 (the name is Stackweaver's)", rename.Code, rename.Body.String())
	}
	if del := platformAdminCall(t, r, http.MethodDelete, "/api/v2/pull-secrets/"+ours, browserAs(f.owner), ""); del.Code != http.StatusConflict {
		t.Errorf("DELETE of a declared pull Secret = %d, want 409", del.Code)
	}

	// Validation: create mode needs a registry credential of the organization, and names are
	// Kubernetes Secret names.
	if code, _ := create(`{"name":"nocred","secret-name":"sw-nocred","registry":"ghcr.io"}`); code != http.StatusUnprocessableEntity {
		t.Errorf("a create-mode Secret without a credential = %d, want 422", code)
	}
	if code, _ := create(`{"name":"foreign","secret-name":"sw-foreign","registry":"ghcr.io","registry-credential-id":"` + otherOrgCred.ID.String() + `"}`); code != http.StatusUnprocessableEntity {
		t.Errorf("a credential of another organization = %d, want 422", code)
	}
	if code, _ := create(`{"name":"bad","secret-name":"Not_A_Name","registry":"ghcr.io","reference":true}`); code != http.StatusUnprocessableEntity {
		t.Errorf("an invalid Secret name = %d, want 422", code)
	}
	// A member reads but does not write.
	if code := platformAdminCall(t, r, http.MethodPost, "/api/v2/agent-pools/"+pool.ID.String()+"/pull-secrets", browserAs(f.member), `{"data":{"type":"pull-secrets","attributes":{"name":"m","secret-name":"sw-m","registry":"ghcr.io","reference":true}}}`).Code; code != http.StatusForbidden {
		t.Errorf("a member creating a pull Secret = %d, want 403", code)
	}
	if list := platformAdminCall(t, r, http.MethodGet, "/api/v2/agent-pools/"+pool.ID.String()+"/pull-secrets", browserAs(f.member), ""); list.Code != http.StatusOK {
		t.Errorf("a member listing pull Secrets = %d, want 200", list.Code)
	}
}
