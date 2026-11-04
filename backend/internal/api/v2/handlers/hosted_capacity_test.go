// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test for the hosted-capacity read (#933, D9, D15, AC51, AC79): an organization member
// reads the hosted pool's cap, placement group, in-flight and queued counts and the hosted launchers
// online in that group; a non-member is refused.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestHostedCapacity

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

func TestHostedCapacity_ReadByMembers(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	group := "test-" + f.sfx
	capV := 3
	pool := models.NewHostedPool(f.orgA.ID)
	pool.PlacementGroup, pool.MaxConcurrentJobs = group, &capV
	proj := &models.Project{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "hostedcap-" + f.sfx}
	ws := &models.Workspace{ProjectID: proj.ID, Name: "hostedcap-ws-" + f.sfx, ExecutionMode: "remote"}
	launcher := &models.Runner{ID: uuid.New(), Kind: models.RunnerKindHosted, HostedGroup: group, Name: "hostedcap-l-" + f.sfx, Status: models.RunnerStatusOnline}
	for _, obj := range []any{pool, proj, ws, launcher} {
		if err := f.db.Create(obj).Error; err != nil {
			t.Fatal(err)
		}
	}
	var runs []string
	for i := range 3 {
		run := &models.Run{WorkspaceID: ws.ID, Status: models.RunStatusPending, Operation: models.RunOperationPlanOnly, AgentPoolID: &pool.ID}
		if i == 0 {
			run.RunnerID, run.Status = &launcher.ID, models.RunStatusPlanning
		}
		if err := f.db.Create(run).Error; err != nil {
			t.Fatal(err)
		}
		runs = append(runs, run.ID)
	}
	t.Cleanup(func() {
		f.db.Where("id IN ?", runs).Delete(&models.Run{})
		f.db.Where("id = ?", launcher.ID).Delete(&models.Runner{})
		f.db.Where("id = ?", ws.ID).Delete(&models.Workspace{})
		f.db.Where("id = ?", proj.ID).Delete(&models.Project{})
		f.db.Where("id = ?", pool.ID).Delete(&models.AgentPool{})
	})

	h := NewHostedCapacityHandler(repository.NewOrganizationRepository(f.db), repository.NewAgentPoolRepository(f.db), repository.NewRunRepository(f.db), f.authSvc,
		rbac.NewServiceWithTeams(repository.NewOrganizationRepository(f.db), repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	r := platformAdminRouter()
	r.GET("/api/v2/organizations/:name/hosted-capacity", h.Get)

	rec := platformAdminCall(t, r, http.MethodGet, "/api/v2/organizations/"+f.orgA.Name+"/hosted-capacity", browserAs(f.member), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("member read = %d (%s)", rec.Code, rec.Body.String())
	}
	var doc struct {
		Data struct {
			Type       string                   `json:"type"`
			Attributes HostedCapacityAttributes `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	want := HostedCapacityAttributes{PoolID: pool.ID.String(), MaxConcurrentJobs: 3, PlacementGroup: group, InFlight: 1, Queued: 2, LaunchersOnline: 1}
	if doc.Data.Type != "hosted-capacities" || doc.Data.Attributes != want {
		t.Errorf("hosted capacity = %s %+v, want %+v", doc.Data.Type, doc.Data.Attributes, want)
	}
	if rec := platformAdminCall(t, r, http.MethodGet, "/api/v2/organizations/"+f.orgA.Name+"/hosted-capacity", browserAs(f.plain), ""); rec.Code != http.StatusForbidden {
		t.Errorf("non-member read = %d, want 403", rec.Code)
	}
}
