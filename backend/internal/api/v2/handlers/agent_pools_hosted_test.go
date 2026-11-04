// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the hosted pool (#933, D9, AC49, AC50): creating an organization creates
// its hosted pool in the same transaction; the TFE agent-pools routes, agent tokens and the
// workspace, project, organization and job pool settings never reach it; and no organization key
// registers a runner into it.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestHostedPool

//go:build integration

package handlers

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestHostedPool_CreatedWithTheOrganization(t *testing.T) {
	db := setupAuthzTestDB(t)
	orgRepo := repository.NewOrganizationRepository(db)
	org := &models.Organization{ID: uuid.New(), Name: "hostedpool-" + uuid.NewString()[:8]}
	if err := orgRepo.Create(org); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = orgRepo.Delete(org.ID) })

	pool, err := repository.NewAgentPoolRepository(db).GetHosted(org.ID)
	if err != nil {
		t.Fatalf("the new organization has no hosted pool: %v", err)
	}
	if pool.Name != models.HostedPoolName || !pool.OrganizationScoped || pool.Kind != models.AgentPoolKindHosted {
		t.Errorf("hosted pool = %+v", pool)
	}
}

func TestHostedPool_InvisibleToOrganizationRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthzTestDB(t)
	orgRepo := repository.NewOrganizationRepository(db)
	poolRepo := repository.NewAgentPoolRepository(db)
	org := &models.Organization{ID: uuid.New(), Name: "hostedhide-" + uuid.NewString()[:8]}
	if err := orgRepo.Create(org); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = orgRepo.Delete(org.ID) })
	hosted, err := poolRepo.GetHosted(org.ID)
	if err != nil {
		t.Fatal(err)
	}
	customer := &models.AgentPool{ID: uuid.New(), OrganizationID: org.ID, Name: "own-pool", OrganizationScoped: true}
	if err := poolRepo.Create(customer); err != nil {
		t.Fatal(err)
	}

	// The TFE listing names the customer pool only.
	pools, total, err := poolRepo.ListByOrganization(org.ID, repository.ListAgentPoolsOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(pools) != 1 || pools[0].ID != customer.ID {
		t.Errorf("listed %d pools (total %d), want only the customer pool", len(pools), total)
	}
	if _, err := poolRepo.GetByOrganizationAndName(org.ID, models.HostedPoolName); err == nil {
		t.Error("the hosted pool is found by name")
	}

	// The by-id routes answer 404 before any permission check, and change nothing.
	h := NewAgentPoolHandlerV2(poolRepo, repository.NewRunnerRepository(db), orgRepo, nil, nil)
	tokens := NewAgentTokenHandlerV2(nil, nil, nil, poolRepo)
	r := gin.New()
	r.GET("/api/v2/agent-pools/:id", h.GetByID)
	r.PATCH("/api/v2/agent-pools/:id", h.Update)
	r.DELETE("/api/v2/agent-pools/:id", h.Delete)
	r.GET("/api/v2/agent-pools/:id/agents", h.ListAgents)
	r.POST("/api/v2/agent-pools/:id/authentication-tokens", tokens.Create)
	path := "/api/v2/agent-pools/" + hosted.ID.String()
	for _, call := range []struct{ method, path string }{
		{http.MethodGet, path},
		{http.MethodPatch, path},
		{http.MethodDelete, path},
		{http.MethodGet, path + "/agents"},
		{http.MethodPost, path + "/authentication-tokens"},
	} {
		rec := runnerDo(t, r, "", call.method, call.path, map[string]any{"data": map[string]any{"type": "agent-pools", "attributes": map[string]any{"name": "renamed"}}})
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 (%s)", call.method, call.path, rec.Code, rec.Body.String())
		}
	}
	still, err := poolRepo.GetHosted(org.ID)
	if err != nil || still.Name != models.HostedPoolName {
		t.Errorf("the hosted pool was changed or deleted: %+v, %v", still, err)
	}
	if _, err := poolRepo.GetCustomerByID(hosted.ID, false); err == nil {
		t.Error("GetCustomerByID returned the hosted pool")
	}
}

// No organization key registers a runner into the hosted pool (AC65).
func TestHostedPool_RefusesCustomerRegistration(t *testing.T) {
	f := setupAgentPrepFixture(t)
	// The fixture's organization A has its hosted pool.
	var hosted models.AgentPool
	if err := f.db.First(&hosted, "organization_id = ? AND kind = ?", f.orgA, models.AgentPoolKindHosted).Error; err != nil {
		t.Fatal(err)
	}
	sfx := uuid.NewString()[:8]
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "hostedreg-" + sfx, Email: "hostedreg-" + sfx + "@test.local"}
	if err := f.db.Create(owner).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", owner.ID).Delete(&models.User{}) })
	f.keys["reg"] = &models.APIKey{ID: uuid.New(), Kind: models.APIKeyKindOrg, Scopes: models.StringArray{"org:" + f.orgA.String() + ":runner:register"}, OrganizationID: &f.orgA, UserID: &owner.ID}
	r := f.registerRouter(owner.ID)
	name := "hostedreg-" + sfx
	rec := runnerDo(t, r, "reg", http.MethodPost, "/api/v2/runner/register", map[string]any{"agent_pool_id": hosted.ID.String(), "name": name, "tofu_version": "1.9.0"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("register into the hosted pool = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	var n int64
	f.db.Model(&models.Runner{}).Where("name = ?", name).Count(&n)
	if n != 0 {
		t.Errorf("a refused registration left %d runner row(s)", n)
	}
}
