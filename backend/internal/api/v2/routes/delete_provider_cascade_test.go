//go:build integration
// +build integration

// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package routes_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// Deleting a provider that has published versions, platforms and downloads must succeed and
// leave nothing behind.
//
// The sibling module path was broken exactly here (#772): both delete handlers assumed a database
// cascade that AutoMigrate does not create, so on a fresh install the delete failed with a
// foreign-key violation. `providers` carries the same FK shape - provider_versions references
// providers, provider_platforms references provider_versions, provider_downloads references
// provider_platforms - and none of those constraints is created with an ON DELETE clause either.
//
// ProviderRepository.Delete already removes the dependants itself, so this path was not broken.
// That is precisely why it needs a test: nothing in the schema enforces it, so the correctness
// rests entirely on that repository method continuing to do the work by hand. Deleting the
// version-cleanup from it must fail loudly, not silently pass because the seeded provider
// happened to have no versions - hence the assertions on the dependants, not just on the 204.
func TestDeleteProviderRemovesItsVersionsAndPlatforms(t *testing.T) {
	h := setupGoldenHarness(t)

	orgName, ok := firstCol(h.db, "organizations", "name")
	if !ok {
		t.Skip("no seeded organization")
	}
	var org models.Organization
	if err := h.db.Where("name = ?", orgName).First(&org).Error; err != nil {
		t.Fatalf("load organization %s: %v", orgName, err)
	}

	// A private provider is namespaced by its organization, which is the composite the delete
	// route addresses it by. The harness database is thrown away in t.Cleanup.
	provider := models.Provider{
		OrganizationID: org.ID,
		Name:           "cascade-probe",
		RegistryName:   "private",
		Namespace:      org.Name,
		PublishedBy:    uuid.Nil,
	}
	if err := h.db.Create(&provider).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}

	version := models.ProviderVersion{ProviderID: provider.ID, Version: "1.0.0", Protocols: "5.0"}
	if err := h.db.Create(&version).Error; err != nil {
		t.Fatalf("seed provider version: %v", err)
	}
	platform := models.ProviderPlatform{
		ProviderVersionID: version.ID,
		OS:                "linux",
		Arch:              "amd64",
		Filename:          "terraform-provider-cascade-probe_1.0.0_linux_amd64.zip",
		Shasum:            "0000000000000000000000000000000000000000000000000000000000000000",
	}
	if err := h.db.Create(&platform).Error; err != nil {
		t.Fatalf("seed provider platform: %v", err)
	}
	download := models.ProviderDownload{ProviderPlatformID: platform.ID, DownloadedAt: time.Now()}
	if err := h.db.Create(&download).Error; err != nil {
		t.Fatalf("seed provider download: %v", err)
	}

	path := fmt.Sprintf("/api/v2/organizations/%s/registry-providers/%s/%s/%s",
		orgName, provider.RegistryName, provider.Namespace, provider.Name)
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)

	if rec.Code >= 400 {
		t.Fatalf("DELETE %s returned %d: %s - the dependants were left behind and the foreign key "+
			"refused the parent row", path, rec.Code, rec.Body.String())
	}

	var providers, versions, platforms, downloads int64
	h.db.Model(&models.Provider{}).Where("id = ?", provider.ID).Count(&providers)
	h.db.Model(&models.ProviderVersion{}).Where("provider_id = ?", provider.ID).Count(&versions)
	h.db.Model(&models.ProviderPlatform{}).Where("provider_version_id = ?", version.ID).Count(&platforms)
	h.db.Model(&models.ProviderDownload{}).Where("provider_platform_id = ?", platform.ID).Count(&downloads)

	for _, row := range []struct {
		name  string
		count int64
	}{
		{"provider", providers},
		{"version", versions},
		{"platform", platforms},
		{"download", downloads},
	} {
		if row.count != 0 {
			t.Errorf("%d %s row(s) survived the delete - orphaned, and a later provider published "+
				"under the same name inherits them", row.count, row.name)
		}
	}
}
