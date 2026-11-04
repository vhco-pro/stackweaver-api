// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package runner

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// A launcher is only marked lost once it has missed several heartbeats, never in the ordinary
// gap between two of them (#933, D3, decision 16, AC9, AC17). Its heartbeat is a long poll the API
// holds for up to its wait cap, and after an answer with offers the launcher claims and places each
// one before it polls again, so a live launcher's last heartbeat is often more than the cap old.
// Marking it lost then would re-dispatch its plans as a second attempt and fail its applies.
func TestMonitorKeepsALauncherBetweenHeartbeats(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dsn, &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	sfx := uuid.NewString()[:8]
	runner := func(name string, silentFor time.Duration) *models.Runner {
		beat := time.Now().Add(-silentFor)
		r := &models.Runner{ID: uuid.New(), Name: name + "-" + sfx, Kind: models.RunnerKindHosted, HostedGroup: "monitor-" + sfx, Status: models.RunnerStatusBusy, LastHeartbeatAt: &beat}
		if err := db.Create(r).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Delete(&models.Runner{}, "id = ?", r.ID) })
		return r
	}
	// Held for the full wait, then a few seconds of claims on a loaded host.
	claiming := runner("claiming", OfflineAfter/2+15*time.Second)
	gone := runner("gone", OfflineAfter+30*time.Second)

	NewMonitorService(repository.NewRunnerRepository(db)).markStaleRunners()

	var c, g models.Runner
	db.First(&c, "id = ?", claiming.ID)
	db.First(&g, "id = ?", gone.ID)
	if c.Status == models.RunnerStatusOffline {
		t.Errorf("a launcher silent for %s, inside its heartbeat gap, was marked offline", OfflineAfter/2+15*time.Second)
	}
	if g.Status != models.RunnerStatusOffline {
		t.Errorf("a launcher silent for %s is %s, want offline", OfflineAfter+30*time.Second, g.Status)
	}
}
