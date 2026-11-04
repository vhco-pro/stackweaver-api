// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test for the inventory source effective-settings read (#933, D0, AC32): a source
// with its own sync timeout reports that value from the inventory-source level, through the real
// handler over real Postgres, and a source without one inherits its project's run timeout and then
// the deployment's sync_timeout, which is the limit its syncs run under
// (WorkItemService.RequestSourceSync in core/services/ansible).
//
// The rows are the test's own and are deleted by id (the database may be live).
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestEffectiveSettings_InventorySource

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
	"github.com/michielvha/stackweaver/core/settings"
)

func TestEffectiveSettings_InventorySourceSyncTimeout(t *testing.T) {
	t.Setenv(settings.EnvSyncTimeout, "1500")
	t.Setenv(settings.EnvRunTimeoutDefault, "5000")
	f := setupPlatformAdminFixture(t)
	db := f.db

	if err := db.Model(&models.Organization{}).Where("id = ?", f.orgA.ID).Update("run_timeout", 0).Error; err != nil {
		t.Fatal(err)
	}
	project := &models.Project{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "effsrc-" + f.sfx, RunTimeout: 900}
	if err := db.Create(project).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}
	inventory := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.orgA.ID, ProjectID: &project.ID, Name: "effsrc-" + f.sfx, Type: models.InventoryTypeDynamic}
	if err := db.Create(inventory).Error; err != nil {
		t.Fatalf("create inventory: %v", err)
	}
	orgInventory := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "effsrc-org-" + f.sfx, Type: models.InventoryTypeDynamic}
	if err := db.Create(orgInventory).Error; err != nil {
		t.Fatalf("create organization inventory: %v", err)
	}
	newSource := func(inv uuid.UUID, name string, seconds int) *models.AnsibleInventorySource {
		t.Helper()
		s := &models.AnsibleInventorySource{ID: uuid.New(), InventoryID: inv, Name: name, Type: models.InventorySourceTypeAWS, TimeoutSeconds: seconds}
		if err := db.Create(s).Error; err != nil {
			t.Fatalf("create source: %v", err)
		}
		return s
	}
	own := newSource(inventory.ID, "own", 600)
	inherits := newSource(inventory.ID, "inherits", 0)
	orgScoped := newSource(orgInventory.ID, "org-scoped", 0)
	t.Cleanup(func() {
		db.Where("id IN ?", []uuid.UUID{own.ID, inherits.ID, orgScoped.ID}).Delete(&models.AnsibleInventorySource{})
		db.Where("id IN ?", []uuid.UUID{inventory.ID, orgInventory.ID}).Delete(&models.AnsibleInventory{})
		db.Where("id = ?", project.ID).Delete(&models.Project{})
	})

	orgs := repository.NewOrganizationRepository(db)
	projects := repository.NewProjectRepository(db)
	h := NewEffectiveSettingsHandlerV2(
		repository.NewWorkspaceRepository(db), repository.NewAnsibleJobTemplateRepository(db),
		repository.NewAnsibleInventorySourceRepository(db), repository.NewAnsibleInventoryRepository(db),
		projects, orgs, f.authSvc, rbac.NewServiceWithTeams(orgs, repository.NewTeamRepository(db), projects),
	)
	r := platformAdminRouter()
	r.GET("/api/v2/ansible/inventory-sources/:source_id/effective-settings", h.GetInventorySource)

	runTimeout := func(source uuid.UUID) EffectiveSetting[int] {
		t.Helper()
		rec := platformAdminCall(t, r, http.MethodGet, "/api/v2/ansible/inventory-sources/"+source.String()+"/effective-settings", browserAs(f.owner), "")
		if rec.Code != http.StatusOK {
			t.Fatalf("effective settings of %s = %d %s", source, rec.Code, rec.Body.String())
		}
		var doc struct {
			Data struct {
				Attributes struct {
					RunTimeout EffectiveSetting[int] `json:"run-timeout"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Data.Attributes.RunTimeout
	}
	levelString := func(s EffectiveSetting[int]) string {
		if s.Level == nil {
			return "<nil>"
		}
		return *s.Level
	}

	for _, tc := range []struct {
		name      string
		source    uuid.UUID
		value     int
		wantLevel string
	}{
		{"its own sync timeout", own.ID, 600, "inventory-source"},
		{"the project's run timeout when it sets none", inherits.ID, 900, "project"},
		{"sync_timeout without a project or an organization value", orgScoped.ID, 1500, "deployment"},
	} {
		got := runTimeout(tc.source)
		if got.Value != tc.value || levelString(got) != tc.wantLevel {
			t.Errorf("%s: run-timeout = {%d, %s}, want {%d, %s}", tc.name, got.Value, levelString(got), tc.value, tc.wantLevel)
		}
	}
}
