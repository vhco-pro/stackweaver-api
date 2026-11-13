// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// After every API start the catalogue holds the installation default, enabled, whether the version
// index answered or not (#1069, D3, AC10).
//
// tofu_versions is a global table. The installation default this test configures is a version no
// release uses, and cleanup deletes exactly the rows the seeding created, by version: the default,
// and any index or fallback version the catalogue lacked before (none, on a catalogue the API has
// seeded once).
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestSeedOfficialVersions

//go:build integration

package handlers

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"

	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/settings"
	"github.com/michielvha/stackweaver/core/tofu"
	"gorm.io/gorm"
)

func seedTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(&models.TofuVersion{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// cleanupSeededRows deletes, after the test, the candidate versions the catalogue lacks now.
func cleanupSeededRows(t *testing.T, db *gorm.DB, candidates []string) {
	t.Helper()
	var existing []string
	db.Model(&models.TofuVersion{}).Where("version IN ?", candidates).Pluck("version", &existing)
	var created []string
	for _, v := range candidates {
		if !slices.Contains(existing, v) {
			created = append(created, v)
		}
	}
	t.Cleanup(func() {
		if len(created) > 0 {
			db.Where("version IN ?", created).Delete(&models.TofuVersion{})
		}
	})
}

// stubIndex serves a version index listing only the bundled version.
func stubIndex(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"versions":[{"id":%q,"files":[]}]}`, tofu.BundledVersion)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func catalogueRow(t *testing.T, db *gorm.DB, version string) (models.TofuVersion, bool) {
	t.Helper()
	var row models.TofuVersion
	err := db.Where("version = ?", version).First(&row).Error
	return row, err == nil
}

func TestSeedOfficialVersions_HoldsTheInstallationDefaultEnabled(t *testing.T) {
	db := seedTestDB(t)
	exact := fmt.Sprintf("1.%d.7", 100000+rand.IntN(800000))
	getenv := func(key string) string {
		if key == settings.EnvTofuDefaultVersion {
			return exact
		}
		return ""
	}

	for _, tc := range []struct {
		name  string
		index string
	}{
		{"the index answers without the default", stubIndex(t)},
		{"the index is unreachable", "http://127.0.0.1:1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tofu.EnvVersionIndexURL, tc.index)
			cleanupSeededRows(t, db, append([]string{exact, tofu.BundledVersion}, models.OfficialTofuVersions...))
			db.Where("version = ?", exact).Delete(&models.TofuVersion{})

			SeedOfficialVersions(db, getenv)
			row, ok := catalogueRow(t, db, exact)
			if !ok || !row.Enabled {
				t.Fatalf("after seeding, the installation default %s is in the catalogue %t, enabled %t; want enabled", exact, ok, row.Enabled)
			}

			// A row for the default that exists disabled is enabled by the next start.
			if err := db.Model(&models.TofuVersion{}).Where("version = ?", exact).Update("enabled", false).Error; err != nil {
				t.Fatal(err)
			}
			SeedOfficialVersions(db, getenv)
			if row, _ := catalogueRow(t, db, exact); !row.Enabled {
				t.Errorf("a disabled row for the installation default stayed disabled after seeding")
			}
		})
	}

	t.Run("latest inserts nothing", func(t *testing.T) {
		t.Setenv(tofu.EnvVersionIndexURL, stubIndex(t))
		latest := fmt.Sprintf("1.%d.8", 100000+rand.IntN(800000))
		cleanupSeededRows(t, db, []string{latest, tofu.BundledVersion})
		SeedOfficialVersions(db, func(key string) string {
			if key == settings.EnvTofuDefaultVersion {
				return settings.TofuDefaultLatest
			}
			return ""
		})
		if _, ok := catalogueRow(t, db, settings.TofuDefaultLatest); ok {
			t.Error("seeding under latest inserted a row named latest")
		}
		var n int64
		db.Model(&models.TofuVersion{}).Where("version = ?", latest).Count(&n)
		if n != 0 {
			t.Errorf("seeding under latest inserted %s", latest)
		}
	})
}
