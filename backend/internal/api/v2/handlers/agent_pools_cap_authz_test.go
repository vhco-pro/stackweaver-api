// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the hosted pool's cap and placement group (#933, D9, AC55, AC79): only a
// platform administrator writes them, through a browser session or a platform:admin token, under
// platformadmin.Service.Check; an organization owner and an organization-bound key get 403 naming
// the fields; 0 means unlimited; nothing else of a hosted pool is writable, and a customer pool has
// neither field.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestHostedPoolCap

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestHostedPoolCap_PlatformAdministratorOnly(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	hosted := models.NewHostedPool(f.orgA.ID)
	customer := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "own-" + f.sfx, OrganizationScoped: true}
	for _, p := range []*models.AgentPool{hosted, customer} {
		if err := f.db.Create(p).Error; err != nil {
			t.Fatal(err)
		}
		id := p.ID
		t.Cleanup(func() { f.db.Where("id = ?", id).Delete(&models.AgentPool{}) })
	}
	poolRepo := repository.NewAgentPoolRepository(f.db)
	h := NewAgentPoolHandlerV2(poolRepo, repository.NewRunnerRepository(f.db), repository.NewOrganizationRepository(f.db), f.authSvc,
		rbac.NewServiceWithTeams(repository.NewOrganizationRepository(f.db), repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	h.SetPlatformAdmin(f.admins)
	r := platformAdminRouter()
	r.PATCH("/api/v2/agent-pools/:id", h.Update)

	patch := func(as identity, pool uuid.UUID, attrs string) (int, map[string]any) {
		rec := platformAdminCall(t, r, http.MethodPatch, "/api/v2/agent-pools/"+pool.String(), as, `{"data":{"type":"agent-pools","attributes":`+attrs+`}}`)
		var doc struct {
			Data struct {
				Attributes map[string]any `json:"attributes"`
			} `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &doc)
		return rec.Code, doc.Data.Attributes
	}
	capOf := func() (*int, string) {
		var p models.AgentPool
		f.db.First(&p, "id = ?", hosted.ID)
		return p.MaxConcurrentJobs, p.PlacementGroup
	}

	// An organization owner, a member, and an organization-bound key are refused with 403.
	for name, as := range map[string]identity{
		"an organization owner":               browserAs(f.owner),
		"a member":                            browserAs(f.member),
		"an organization key":                 {user: f.owner.ID, method: "api_key", tokenKind: models.APIKeyKindOrg, scopes: []string{"org:" + f.orgA.ID.String() + ":admin"}},
		"a user token without platform:admin": {user: f.admin.ID, method: "api_key", tokenKind: models.APIKeyKindUser},
	} {
		if code, _ := patch(as, hosted.ID, `{"max-concurrent-jobs":50}`); code != http.StatusForbidden {
			t.Errorf("%s writing the cap = %d, want 403", name, code)
		}
		if code, _ := patch(as, hosted.ID, `{"placement-group":"eu-west"}`); code != http.StatusForbidden {
			t.Errorf("%s writing the group = %d, want 403", name, code)
		}
	}
	if c, g := capOf(); c != nil || g != "default" {
		t.Fatalf("a refused write changed the pool: cap %v group %s", c, g)
	}

	// A platform administrator, by session or by a platform:admin token.
	code, attrs := patch(browserAs(f.admin), hosted.ID, `{"max-concurrent-jobs":5,"placement-group":"eu-west"}`)
	if code != http.StatusOK || attrs["max-concurrent-jobs"] != float64(5) || attrs["placement-group"] != "eu-west" {
		t.Fatalf("platform administrator write = %d %v", code, attrs)
	}
	token := identity{user: f.admin.ID, method: "api_key", tokenKind: models.APIKeyKindUser, scopes: []string{"platform:admin"}}
	if code, attrs := patch(token, hosted.ID, `{"max-concurrent-jobs":0}`); code != http.StatusOK || attrs["max-concurrent-jobs"] != float64(0) {
		t.Errorf("platform:admin token setting unlimited = %d %v", code, attrs)
	}
	if c, g := capOf(); c == nil || *c != 0 || g != "eu-west" {
		t.Errorf("stored cap %v group %s, want 0 (unlimited) and eu-west", c, g)
	}

	// Nothing else of a hosted pool is writable, even by a platform administrator; a negative cap is
	// refused; a customer pool has neither field.
	if code, _ := patch(browserAs(f.admin), hosted.ID, `{"max-concurrent-jobs":3,"name":"renamed"}`); code != http.StatusUnprocessableEntity {
		t.Errorf("renaming the hosted pool with its cap = %d, want 422", code)
	}
	if code, _ := patch(browserAs(f.admin), hosted.ID, `{"max-concurrent-jobs":-1}`); code != http.StatusUnprocessableEntity {
		t.Errorf("a negative cap = %d, want 422", code)
	}
	if code, _ := patch(browserAs(f.owner), hosted.ID, `{"name":"renamed"}`); code != http.StatusNotFound {
		t.Errorf("an owner renaming the hosted pool = %d, want 404", code)
	}
	if code, _ := patch(browserAs(f.owner), customer.ID, `{"max-concurrent-jobs":3}`); code != http.StatusUnprocessableEntity {
		t.Errorf("a cap on a customer pool = %d, want 422", code)
	}
	if code, attrs := patch(browserAs(f.owner), customer.ID, `{"keep-failed-jobs-for":3600,"memory-limit":"2Gi","limits-required":true}`); code != http.StatusOK ||
		attrs["keep-failed-jobs-for"] != float64(3600) || attrs["memory-limit"] != "2Gi" || attrs["limits-required"] != true || attrs["kind"] != "customer" {
		t.Errorf("an owner setting the customer pool's settings = %d %v", code, attrs)
	}
}
