//go:build integration
// +build integration

// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package routes_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// DELETE /api/v2/organizations/:name/registry/modules must empty the registry, not one page of it.
//
// It used to load a single capped page and delete that, so an organization holding more than the
// cap kept the remainder while the response said "Deleted N module(s)" and returned 200. The
// operator's next action is then taken on the belief that the registry is empty.
//
// The cap was 1000, which is impractical to seed. The handler now drains in batches of 100, so
// seeding past *that* boundary exercises the same loop: a single-pass implementation stops after
// the first batch and leaves the rest behind, which is exactly the defect. The assertion is
// therefore "nothing is left", never "the call returned 200".
func TestDeleteAllModulesEmptiesTheWholeRegistry(t *testing.T) {
	h := setupGoldenHarness(t)

	orgName, ok := firstCol(h.db, "organizations", "name")
	if !ok {
		t.Skip("no seeded organization")
	}
	var org models.Organization
	if err := h.db.Where("name = ?", orgName).First(&org).Error; err != nil {
		t.Fatalf("load organization %s: %v", orgName, err)
	}

	// Seed past one batch. The harness runs on a throwaway database dropped in t.Cleanup.
	const seed = 105
	for i := 0; i < seed; i++ {
		m := models.Module{
			OrganizationID: org.ID,
			Name:           fmt.Sprintf("drain-probe-%03d", i),
			Provider:       "null",
			PublishedBy:    uuid.Nil,
		}
		if err := h.db.Create(&m).Error; err != nil {
			t.Fatalf("seed module %d: %v", i, err)
		}
	}

	var before int64
	h.db.Model(&models.Module{}).Where("organization_id = ?", org.ID).Count(&before)
	if before < seed {
		t.Fatalf("expected at least %d modules seeded, found %d", seed, before)
	}

	req := httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/v2/organizations/%s/registry/modules", orgName), nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE returned %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var after int64
	h.db.Model(&models.Module{}).Where("organization_id = ?", org.ID).Count(&after)
	if after != 0 {
		t.Errorf("%d of %d modules survived a call that reported success - the delete stopped at "+
			"a page boundary and told the caller the registry was emptied", after, before)
	}

	// The reported count must describe what actually happened, not the size of one page.
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err == nil {
		if msg, _ := body["message"].(string); msg != "" {
			want := fmt.Sprintf("Deleted %d module(s)", before)
			if msg != want {
				t.Errorf("response said %q, want %q", msg, want)
			}
		}
	}
}

// Deleting a module that has published versions must succeed.
//
// Both delete handlers carried the comment "cascade will delete versions". There is no cascade on
// a fresh install: AutoMigrate emits `FOREIGN KEY (module_id) REFERENCES modules(id)` with no ON
// DELETE clause, so the delete fails with a foreign-key violation and the endpoint answers 500.
// Long-lived databases migrated by an earlier schema do carry ON DELETE CASCADE, which is exactly
// why this was invisible in development while being broken for every new deployment - the
// fresh-install bug class. The harness builds its database with AutoMigrate, so it sees what a
// new deployment sees.
func TestDeleteModuleRemovesItsVersions(t *testing.T) {
	h := setupGoldenHarness(t)

	orgName, ok := firstCol(h.db, "organizations", "name")
	if !ok {
		t.Skip("no seeded organization")
	}
	var org models.Organization
	if err := h.db.Where("name = ?", orgName).First(&org).Error; err != nil {
		t.Fatalf("load organization %s: %v", orgName, err)
	}

	mod := models.Module{
		OrganizationID: org.ID,
		Name:           "cascade-probe",
		Provider:       "null",
		PublishedBy:    uuid.Nil,
	}
	if err := h.db.Create(&mod).Error; err != nil {
		t.Fatalf("seed module: %v", err)
	}
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if err := h.db.Create(&models.ModuleVersion{ModuleID: mod.ID, Version: v}).Error; err != nil {
			t.Fatalf("seed version %s: %v", v, err)
		}
	}

	req := httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/v2/organizations/%s/registry/modules/%s/%s", orgName, mod.Name, mod.Provider), nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)

	if rec.Code >= 400 {
		t.Fatalf("DELETE of a module with versions returned %d: %s - the versions were left behind "+
			"and the foreign key refused the parent row", rec.Code, rec.Body.String())
	}

	var modules, versions int64
	h.db.Model(&models.Module{}).Where("id = ?", mod.ID).Count(&modules)
	h.db.Model(&models.ModuleVersion{}).Where("module_id = ?", mod.ID).Count(&versions)
	if modules != 0 {
		t.Errorf("the module survived the delete")
	}
	if versions != 0 {
		t.Errorf("%d version(s) of the deleted module are still present - they would be orphans", versions)
	}
}
