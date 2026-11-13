// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Both catalogue listings carry the installation default as JSON:API meta, and every attribute of
// the TFE terraform-versions resource is unchanged (#1069, D4, AC12). The listings order with
// Postgres functions, so this runs against the database.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. It adds one enabled catalogue
// row of its own, so it holds on a database whose API never booted to seed the catalogue, and
// deletes only that row. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestTofuVersionListings_Meta

//go:build integration

package handlers

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"slices"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/settings"
	"github.com/michielvha/stackweaver/core/tofu"
)

// tfeTerraformVersionAttributes are the attributes of the admin terraform-versions resource as the
// TFE API documents them; no change here may add to them.
var tfeTerraformVersionAttributes = []string{
	"archs", "beta", "created-at", "deprecated", "deprecated-reason", "enabled", "official", "sha", "url", "usage", "version",
}

func TestTofuVersionListings_MetaNamesTheInstallationDefault(t *testing.T) {
	db, admin, routes := installationDefaultRefusalFixture(t)
	router := routes(db)
	// Both listings must list something to check its attributes; a fresh database has no catalogue
	// until the API's boot seeds it.
	row := &models.TofuVersion{Version: fmt.Sprintf("0.2.%d", 100000+rand.IntN(800000)), Enabled: true, Beta: true}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed catalogue row: %v", err)
	}
	t.Cleanup(func() { db.Where("id = ?", row.ID).Delete(&models.TofuVersion{}) })

	for _, tc := range []struct {
		name, value, want string
	}{
		{"unset", "", tofu.BundledVersion},
		{"an exact version", "1.12.0", "1.12.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(settings.EnvTofuDefaultVersion, tc.value)
			for _, path := range []string{"/api/v2/terraform-versions", "/api/v2/admin/terraform-versions"} {
				code, body := storedAsSentCall(t, router, http.MethodGet, path, admin.ID, "")
				if code != http.StatusOK {
					t.Fatalf("GET %s = %d %s", path, code, body)
				}
				var doc struct {
					Data []struct {
						Type       string                     `json:"type"`
						Attributes map[string]json.RawMessage `json:"attributes"`
					} `json:"data"`
					Meta map[string]json.RawMessage `json:"meta"`
				}
				if err := json.Unmarshal(body, &doc); err != nil {
					t.Fatal(err)
				}
				var got string
				_ = json.Unmarshal(doc.Meta["installation-default-version"], &got)
				if got != tc.want {
					t.Errorf("GET %s meta.installation-default-version = %q, want %q", path, got, tc.want)
				}
				if _, ok := doc.Meta["pagination"]; !ok {
					t.Errorf("GET %s lost meta.pagination", path)
				}
				if len(doc.Data) == 0 {
					t.Fatalf("GET %s listed no versions", path)
				}
				for _, item := range doc.Data {
					for k := range item.Attributes {
						if !slices.Contains(tfeTerraformVersionAttributes, k) {
							t.Errorf("GET %s: attribute %q is not a TFE terraform-versions attribute", path, k)
						}
					}
					if item.Type != "terraform-versions" {
						t.Errorf("GET %s: type %q", path, item.Type)
					}
				}
			}
		})
	}
}
