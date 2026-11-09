// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test for the runner_type filter on the native runners list (one-launcher spec, OD23,
// AC44): ansible returns the Ansible and the combined launchers, tofu the OpenTofu and the combined
// ones, and each item keeps the runners document shape.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRunnersList_RunnerTypeFilter

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestRunnersList_RunnerTypeFilter(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "rtype-" + f.sfx, OrganizationScoped: true}
	if err := f.db.Create(pool).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", pool.ID).Delete(&models.AgentPool{}) })
	for _, typ := range []models.RunnerType{models.RunnerTypeTofu, models.RunnerTypeAnsible, models.RunnerTypeCombined} {
		r := &models.Runner{ID: uuid.New(), Name: string(typ) + "-" + f.sfx, OrganizationID: &f.orgA.ID, AgentPoolID: &pool.ID, Kind: models.RunnerKindCustomer, RunnerType: typ, Status: models.RunnerStatusOnline}
		if err := f.db.Create(r).Error; err != nil {
			t.Fatal(err)
		}
		id := r.ID
		t.Cleanup(func() { f.db.Where("id = ?", id).Delete(&models.Runner{}) })
	}

	orgs := repository.NewOrganizationRepository(f.db)
	h := NewRunnerHandlerV2(repository.NewRunnerRepository(f.db), repository.NewRunnerJobExecutionRepository(f.db),
		repository.NewAgentPoolRepository(f.db), orgs,
		rbac.NewServiceWithTeams(orgs, repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	r := platformAdminRouter()
	r.GET("/api/v2/organizations/:name/runners", h.List)

	for _, tc := range []struct {
		filter string
		want   []string
	}{
		{"ansible", []string{"ansible-" + f.sfx, "combined-" + f.sfx}},
		{"tofu", []string{"combined-" + f.sfx, "tofu-" + f.sfx}},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			path := "/api/v2/organizations/" + f.orgA.Name + "/runners?sort=name&filter[runner_type]=" + tc.filter
			rec := platformAdminCall(t, r, http.MethodGet, path, browserAs(f.owner), "")
			if rec.Code != http.StatusOK {
				t.Fatalf("list runners = %d %s", rec.Code, rec.Body.String())
			}
			var doc struct {
				Data []struct {
					Type       string         `json:"type"`
					ID         string         `json:"id"`
					Attributes map[string]any `json:"attributes"`
				} `json:"data"`
				Meta struct {
					Pagination map[string]any `json:"pagination"`
				} `json:"meta"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				t.Fatalf("runners document = %s (%v)", rec.Body.String(), err)
			}
			var got []string
			for _, d := range doc.Data {
				if d.Type != "runners" || d.ID == "" {
					t.Errorf("item type %q id %q, want type runners with an id", d.Type, d.ID)
				}
				if _, ok := d.Attributes["runner-type"]; !ok {
					t.Errorf("item %s has no runner-type attribute: %v", d.ID, d.Attributes)
				}
				got = append(got, d.Attributes["name"].(string))
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("filter[runner_type]=%s returned %v, want %v", tc.filter, got, tc.want)
			}
			if doc.Meta.Pagination["total-count"] != float64(len(tc.want)) {
				t.Errorf("pagination = %v, want total-count %d", doc.Meta.Pagination, len(tc.want))
			}
		})
	}
}
