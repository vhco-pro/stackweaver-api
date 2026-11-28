// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The organization's identity binding list and the hosted binding (#1113, D3; AC-07, AC-08): one
// read lists every customer binding of the organization with its pool, then the configured hosted
// binding, each marked hosted and deployment-managed or not; the hosted binding is never
// addressable as /identity-bindings/:id; a customer reference binding still needs no annotation.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestOrganizationIdentityBindings

//go:build integration

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

type orgBindingEntry struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	Attributes    map[string]any `json:"attributes"`
	Relationships struct {
		AgentPool struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		} `json:"agent-pool"`
	} `json:"relationships"`
}

func TestOrganizationIdentityBindings(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	poolA := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "oib-a-" + f.sfx, OrganizationScoped: true}
	poolB := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "oib-b-" + f.sfx, OrganizationScoped: true}
	for _, p := range []*models.AgentPool{poolA, poolB} {
		if err := f.db.Create(p).Error; err != nil {
			t.Fatal(err)
		}
	}
	onA := &models.IdentityBinding{OrganizationID: f.orgA.ID, AgentPoolID: poolA.ID, Name: "deploy", Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-deploy", Reference: true}
	onB := &models.IdentityBinding{OrganizationID: f.orgA.ID, AgentPoolID: poolB.ID, Name: "deploy", Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-deploy-b", Reference: true}
	for _, b := range []*models.IdentityBinding{onA, onB} {
		if err := f.db.Create(b).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.db.Where("agent_pool_id IN ?", []uuid.UUID{poolA.ID, poolB.ID}).Delete(&models.IdentityBinding{})
		f.db.Where("id IN ?", []uuid.UUID{poolA.ID, poolB.ID}).Delete(&models.AgentPool{})
	})
	hostedPool, _, err := repository.HostedPoolOf(f.db, f.orgA.ID)
	if err != nil {
		t.Fatal(err)
	}

	orgs := repository.NewOrganizationRepository(f.db)
	h := NewIdentityBindingHandler(repository.NewAgentPoolRepository(f.db), repository.NewIdentityBindingRepository(f.db), f.authSvc, rbac.NewServiceWithTeams(orgs, repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	h.SetOrganizations(orgs)
	r := platformAdminRouter()
	r.GET("/api/v2/organizations/:name/identity-bindings", h.ListOrganization)
	r.POST("/api/v2/agent-pools/:id/identity-bindings", h.Create)
	r.GET("/api/v2/identity-bindings/:id", h.Get)
	r.PATCH("/api/v2/identity-bindings/:id", h.Update)
	r.DELETE("/api/v2/identity-bindings/:id", h.Delete)
	list := func() []orgBindingEntry {
		t.Helper()
		rec := platformAdminCall(t, r, http.MethodGet, "/api/v2/organizations/"+f.orgA.Name+"/identity-bindings", browserAs(f.owner), "")
		if rec.Code != http.StatusOK {
			t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
		}
		var doc struct {
			Data []orgBindingEntry `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Data
	}

	// Without a hosted binding: the two customer bindings, each with its pool.
	got := list()
	if len(got) != 2 {
		t.Fatalf("list = %d entries, want the 2 customer bindings: %+v", len(got), got)
	}
	pools := map[string]string{}
	for _, e := range got {
		pools[e.ID] = e.Relationships.AgentPool.Data.ID
		if e.Type != "identity-bindings" || e.Attributes["hosted"] != false || e.Attributes["deployment-managed"] != false {
			t.Errorf("customer entry = %+v, want hosted and deployment-managed false", e)
		}
	}
	if pools[onA.ID.String()] != poolA.ID.String() || pools[onB.ID.String()] != poolB.ID.String() {
		t.Errorf("entries name pools %v, want each binding's own", pools)
	}

	// With one: it follows, on the hosted pool.
	repository.SetHostedBinding(&repository.HostedBindingConfig{
		Name: "hosted-workload-identity", Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "stackweaver-hosted-identity",
		Annotations: map[string]string{"azure.workload.identity/client-id": "11111111-2222-3333-4444-555555555555"},
	})
	t.Cleanup(func() { repository.SetHostedBinding(nil) })
	hosted := models.HostedIdentityBindingID("hosted-workload-identity")
	got = list()
	if len(got) != 3 {
		t.Fatalf("list = %d entries, want 2 customer bindings and the hosted one", len(got))
	}
	last := got[2]
	if last.ID != hosted.String() || last.Relationships.AgentPool.Data.ID != hostedPool.String() ||
		last.Attributes["hosted"] != true || last.Attributes["deployment-managed"] != true ||
		last.Attributes["name"] != "hosted-workload-identity" || last.Attributes["mechanism"] != models.IdentityMechanismAzureWorkloadIdentity ||
		last.Attributes["service-account"] != "stackweaver-hosted-identity" || last.Attributes["reference"] != true {
		t.Errorf("hosted entry = %+v", last)
	}
	if ann, _ := last.Attributes["annotations"].(map[string]any); ann["azure.workload.identity/client-id"] != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("hosted annotations = %v", last.Attributes["annotations"])
	}

	// The hosted binding is not addressable by id.
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		body := ""
		if method == http.MethodPatch {
			body = `{"data":{"type":"identity-bindings","attributes":{"name":"taken-over"}}}`
		}
		rec := platformAdminCall(t, r, method, "/api/v2/identity-bindings/"+hosted.String(), browserAs(f.owner), body)
		unknown := platformAdminCall(t, r, method, "/api/v2/identity-bindings/"+uuid.NewString(), browserAs(f.owner), body)
		if rec.Code != unknown.Code || rec.Code != http.StatusNotFound {
			t.Errorf("%s of the hosted binding = %d, an unknown id = %d; want both 404", method, rec.Code, unknown.Code)
		}
	}

	// A customer reference binding still needs no annotation.
	rec := platformAdminCall(t, r, http.MethodPost, "/api/v2/agent-pools/"+poolA.ID.String()+"/identity-bindings", browserAs(f.owner),
		`{"data":{"type":"identity-bindings","attributes":{"name":"ref-az","mechanism":"azure-workload-identity","service-account":"sw-ref-az","reference":true}}}`)
	if rec.Code != http.StatusCreated {
		t.Errorf("customer reference binding without the annotation = %d %s, want 201", rec.Code, rec.Body.String())
	}
}

// The organization list pages, names each binding's pool, and narrows with filter[inventory] to
// the hosted binding and the bindings of pools that inventory may use (#1113, D5; AC-08, AC-14). An
// inventory of another organization, or one the caller may not read, answers 404.
func TestOrganizationIdentityBindings_PagingPoolNameAndInventoryFilter(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	projX := &models.Project{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "oibf-x-" + f.sfx}
	projY := &models.Project{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "oibf-y-" + f.sfx}
	for _, p := range []*models.Project{projX, projY} {
		if err := f.db.Create(p).Error; err != nil {
			t.Fatal(err)
		}
	}
	open := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "oibf-open-" + f.sfx, OrganizationScoped: true}
	restricted := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "oibf-restricted-" + f.sfx, AllowedProjects: []models.Project{*projX}}
	for _, p := range []*models.AgentPool{open, restricted} {
		if err := f.db.Create(p).Error; err != nil {
			t.Fatal(err)
		}
	}
	onOpen := &models.IdentityBinding{OrganizationID: f.orgA.ID, AgentPoolID: open.ID, Name: "open", Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-open", Reference: true}
	onRestricted := &models.IdentityBinding{OrganizationID: f.orgA.ID, AgentPoolID: restricted.ID, Name: "restricted", Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-restricted", Reference: true}
	for _, b := range []*models.IdentityBinding{onOpen, onRestricted} {
		if err := f.db.Create(b).Error; err != nil {
			t.Fatal(err)
		}
	}
	inX := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.orgA.ID, ProjectID: &projX.ID, Name: "oibf-inv-x-" + f.sfx, Type: models.InventoryTypeVCS}
	inY := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.orgA.ID, ProjectID: &projY.ID, Name: "oibf-inv-y-" + f.sfx, Type: models.InventoryTypeVCS}
	orgScoped := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "oibf-inv-org-" + f.sfx, Type: models.InventoryTypeVCS}
	foreign := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.orgB.ID, Name: "oibf-inv-b-" + f.sfx, Type: models.InventoryTypeVCS}
	for _, inv := range []*models.AnsibleInventory{inX, inY, orgScoped, foreign} {
		if err := f.db.Create(inv).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.db.Where("id IN ?", []uuid.UUID{inX.ID, inY.ID, orgScoped.ID, foreign.ID}).Delete(&models.AnsibleInventory{})
		f.db.Where("agent_pool_id IN ?", []uuid.UUID{open.ID, restricted.ID}).Delete(&models.IdentityBinding{})
		f.db.Exec("DELETE FROM agent_pool_allowed_projects WHERE agent_pool_id = ?", restricted.ID)
		f.db.Where("id IN ?", []uuid.UUID{open.ID, restricted.ID}).Delete(&models.AgentPool{})
		f.db.Where("id IN ?", []uuid.UUID{projX.ID, projY.ID}).Delete(&models.Project{})
	})
	repository.SetHostedBinding(&repository.HostedBindingConfig{Name: "hosted-workload-identity", Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "stackweaver-hosted-identity"})
	t.Cleanup(func() { repository.SetHostedBinding(nil) })
	hostedID := models.HostedIdentityBindingID("hosted-workload-identity").String()

	orgs := repository.NewOrganizationRepository(f.db)
	h := NewIdentityBindingHandler(repository.NewAgentPoolRepository(f.db), repository.NewIdentityBindingRepository(f.db), f.authSvc, rbac.NewServiceWithTeams(orgs, repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	h.SetOrganizations(orgs)
	r := platformAdminRouter()
	r.GET("/api/v2/organizations/:name/identity-bindings", h.ListOrganization)
	type page struct {
		Data []orgBindingEntry `json:"data"`
		Meta struct {
			Pagination struct {
				CurrentPage int `json:"current-page"`
				TotalCount  int `json:"total-count"`
				TotalPages  int `json:"total-pages"`
			} `json:"pagination"`
		} `json:"meta"`
	}
	get := func(as *models.User, query string) (int, page) {
		t.Helper()
		rec := platformAdminCall(t, r, http.MethodGet, "/api/v2/organizations/"+f.orgA.Name+"/identity-bindings"+query, browserAs(as), "")
		var p page
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
		}
		return rec.Code, p
	}
	ids := func(p page) map[string]bool {
		out := map[string]bool{}
		for _, e := range p.Data {
			out[e.ID] = true
		}
		return out
	}

	// Paging: one entry per page, three in all, with the hosted binding last.
	seen := map[string]bool{}
	for n := 1; n <= 3; n++ {
		code, p := get(f.owner, fmt.Sprintf("?page[size]=1&page[number]=%d", n))
		if code != http.StatusOK || len(p.Data) != 1 || p.Meta.Pagination.TotalCount != 3 || p.Meta.Pagination.TotalPages != 3 || p.Meta.Pagination.CurrentPage != n {
			t.Fatalf("page %d = %d, %+v", n, code, p)
		}
		seen[p.Data[0].ID] = true
		if n == 3 && p.Data[0].ID != hostedID {
			t.Errorf("last page holds %s, want the hosted binding", p.Data[0].ID)
		}
	}
	if len(seen) != 3 {
		t.Errorf("pages returned %d distinct bindings, want 3", len(seen))
	}

	// agent-pool-name names each binding's pool.
	_, all := get(f.owner, "")
	for _, e := range all.Data {
		want := map[string]string{onOpen.ID.String(): open.Name, onRestricted.ID.String(): restricted.Name}[e.ID]
		if e.ID == hostedID {
			hostedPool, _, err := repository.HostedPoolOf(f.db, f.orgA.ID)
			if err != nil {
				t.Fatal(err)
			}
			var hp models.AgentPool
			if err := f.db.First(&hp, "id = ?", hostedPool).Error; err != nil {
				t.Fatal(err)
			}
			want = hp.Name
		}
		if e.Attributes["agent-pool-name"] != want {
			t.Errorf("binding %s agent-pool-name = %v, want %q", e.ID, e.Attributes["agent-pool-name"], want)
		}
	}

	// filter[inventory]: the hosted binding and the bindings of pools the inventory may use.
	for _, tc := range []struct {
		inv  *models.AnsibleInventory
		want []string
	}{
		{inX, []string{onOpen.ID.String(), onRestricted.ID.String(), hostedID}},
		{inY, []string{onOpen.ID.String(), hostedID}},
		{orgScoped, []string{onOpen.ID.String(), hostedID}},
	} {
		code, p := get(f.owner, "?filter[inventory]="+tc.inv.ID.String())
		got := ids(p)
		if code != http.StatusOK || len(got) != len(tc.want) {
			t.Errorf("filter[inventory]=%s = %d, %v; want %v", tc.inv.Name, code, got, tc.want)
			continue
		}
		for _, w := range tc.want {
			if !got[w] {
				t.Errorf("filter[inventory]=%s lacks %s: %v", tc.inv.Name, w, got)
			}
		}
	}
	if code, _ := get(f.owner, "?filter[inventory]="+foreign.ID.String()); code != http.StatusNotFound {
		t.Errorf("filter by another organization's inventory = %d, want 404", code)
	}
	if code, _ := get(f.member, "?filter[inventory]="+inX.ID.String()); code != http.StatusNotFound {
		t.Errorf("filter by an inventory the caller may not read = %d, want 404", code)
	}
}
