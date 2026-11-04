// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test for the read-only launcher network mode (#933, D5, AC22): the agents of a pool
// carry the driver and network mode their launcher reported at registration, and no agents route
// writes either.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestPoolAgents_NetworkModeReadOnly

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

func TestPoolAgents_NetworkModeReadOnly(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "netmode-" + f.sfx, OrganizationScoped: true}
	if err := f.db.Create(pool).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", pool.ID).Delete(&models.AgentPool{}) })
	runner := &models.Runner{
		ID: uuid.New(), Name: "netmode-launcher-" + f.sfx, OrganizationID: &f.orgA.ID, AgentPoolID: &pool.ID,
		Status: models.RunnerStatusOnline, Driver: "container", NetworkMode: "host-identity",
	}
	if err := f.db.Create(runner).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", runner.ID).Delete(&models.Runner{}) })

	orgs := repository.NewOrganizationRepository(f.db)
	h := NewAgentPoolHandlerV2(repository.NewAgentPoolRepository(f.db), repository.NewRunnerRepository(f.db), orgs, f.authSvc,
		rbac.NewServiceWithTeams(orgs, repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	r := platformAdminRouter()
	r.GET("/api/v2/agent-pools/:id/agents", h.ListAgents)

	rec := platformAdminCall(t, r, http.MethodGet, "/api/v2/agent-pools/"+pool.ID.String()+"/agents", browserAs(f.owner), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list agents = %d %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Data []struct {
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || len(doc.Data) != 1 {
		t.Fatalf("agents document = %s (%v)", rec.Body.String(), err)
	}
	attrs := doc.Data[0].Attributes
	if attrs["network-mode"] != "host-identity" || attrs["driver"] != "container" {
		t.Errorf("agent attributes = %v, want driver container and network-mode host-identity", attrs)
	}
}
