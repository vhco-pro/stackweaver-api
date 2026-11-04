// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the work item reads (#933, D2, D15, AC77): GET
// /organizations/:name/work-items lists an organization's syncs and GET /work-items/:id reads one,
// both JSON:API documents with the placement record, readable by the organization's members and
// by no one else.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestWorkItems

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/placement"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestWorkItems_ReadsWithThePlacementRecord(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	pool := models.NewHostedPool(f.orgA.ID)
	if err := f.db.Create(pool).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	inventory := uuid.New()
	done := &models.WorkItem{
		OrganizationID: f.orgA.ID, Kind: models.WorkItemInventoryFileSync, InventoryID: &inventory, TriggeredBy: "webhook",
		Status: models.WorkItemStatusCompleted, AgentPoolID: &pool.ID, Attempt: 2, QueuedAt: &now, StartedAt: &now, FinishedAt: &now,
		ImageLevel: "platform", TimeoutSeconds: 3600, Commit: "abc123", Output: "Parsing hosts.yml\n",
		Placement: models.JobPlacement{Driver: "container", PlacementID: "c-1234", Image: "ghcr.io/acme/ansible:1", ImageLevel: "platform", Node: "node-a"},
	}
	waiting := &models.WorkItem{OrganizationID: f.orgA.ID, Kind: models.WorkItemPlaybookSnapshot, TriggeredBy: "manual", AgentPoolID: &pool.ID, QueuedAt: &now}
	other := &models.WorkItem{OrganizationID: f.orgB.ID, Kind: models.WorkItemPlaybookSnapshot, TriggeredBy: "manual"}
	for _, w := range []*models.WorkItem{done, waiting, other} {
		if err := f.db.Create(w).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.db.Where("id IN ?", []string{done.ID, waiting.ID, other.ID}).Delete(&models.WorkItem{})
		f.db.Where("id = ?", pool.ID).Delete(&models.AgentPool{})
	})

	orgRepo := repository.NewOrganizationRepository(f.db)
	h := NewWorkItemHandler(orgRepo, repository.NewWorkItemRepository(f.db), f.authSvc,
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	r := platformAdminRouter()
	r.GET("/api/v2/organizations/:name/work-items", h.List)
	r.GET("/api/v2/work-items/:id", h.Get)

	// The list: the organization's two work items, newest first, nothing of the other's.
	rec := platformAdminCall(t, r, http.MethodGet, "/api/v2/organizations/"+f.orgA.Name+"/work-items", browserAs(f.member), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("member list = %d (%s)", rec.Code, rec.Body.String())
	}
	var list struct {
		Data []struct {
			ID         string             `json:"id"`
			Type       string             `json:"type"`
			Attributes WorkItemAttributes `json:"attributes"`
		} `json:"data"`
		Meta struct {
			Pagination struct {
				TotalCount int `json:"total-count"`
			} `json:"pagination"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Data) != 2 || list.Meta.Pagination.TotalCount != 2 {
		t.Fatalf("listed %d work items (total %d), want the organization's 2", len(list.Data), list.Meta.Pagination.TotalCount)
	}
	for _, d := range list.Data {
		if d.Type != "work-items" || d.ID == other.ID {
			t.Errorf("listed %s %s", d.Type, d.ID)
		}
	}

	// One work item, with its placement record and output.
	rec = platformAdminCall(t, r, http.MethodGet, "/api/v2/work-items/"+done.ID, browserAs(f.member), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("member read = %d (%s)", rec.Code, rec.Body.String())
	}
	var one struct {
		Data struct {
			ID            string             `json:"id"`
			Type          string             `json:"type"`
			Attributes    WorkItemAttributes `json:"attributes"`
			Relationships map[string]struct {
				Data *struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"relationships"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil {
		t.Fatal(err)
	}
	a := one.Data.Attributes
	if one.Data.ID != done.ID || one.Data.Type != "work-items" || a.Kind != models.WorkItemInventoryFileSync || a.Status != models.WorkItemStatusCompleted ||
		a.TriggeredBy != "webhook" || a.Commit != "abc123" || a.Output != "Parsing hosts.yml\n" || a.TimeoutSeconds != 3600 {
		t.Errorf("work item = %s %+v", one.Data.ID, a)
	}
	wantPlacement := placement.Attributes{Attempt: 2, Driver: "container", PlacementID: "c-1234", Image: "ghcr.io/acme/ansible:1", ImageLevel: "platform", Node: "node-a"}
	if a.Placement != wantPlacement {
		t.Errorf("placement = %+v, want %+v", a.Placement, wantPlacement)
	}
	if rel := one.Data.Relationships["inventory"]; rel.Data == nil || rel.Data.ID != inventory.String() {
		t.Errorf("inventory relationship = %+v, want %s", rel.Data, inventory)
	}

	// No one outside the organization reads either, and another organization's item is not found.
	if rec := platformAdminCall(t, r, http.MethodGet, "/api/v2/organizations/"+f.orgA.Name+"/work-items", browserAs(f.plain), ""); rec.Code != http.StatusForbidden {
		t.Errorf("non-member list = %d, want 403", rec.Code)
	}
	if rec := platformAdminCall(t, r, http.MethodGet, "/api/v2/work-items/"+done.ID, browserAs(f.plain), ""); rec.Code != http.StatusNotFound {
		t.Errorf("non-member read = %d, want 404", rec.Code)
	}
	if rec := platformAdminCall(t, r, http.MethodGet, "/api/v2/work-items/"+other.ID, browserAs(f.member), ""); rec.Code != http.StatusNotFound {
		t.Errorf("read of another organization's work item = %d, want 404", rec.Code)
	}
}
