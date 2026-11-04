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

// TestMonitorReleasesStaleRunReservations pins that the monitor frees the OpenTofu runs a runner
// reserved but never started once the runner goes offline (#933, D2, AC9), as it already did for
// Ansible jobs, so they are offered to the pool's other runners.
func TestMonitorReleasesStaleRunReservations(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dsn, &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Organization{}, &models.Project{}, &models.AgentPool{}, &models.Workspace{}, &models.Run{}, &models.Runner{}); err != nil {
		t.Fatal(err)
	}
	sfx := uuid.NewString()[:8]
	create := func(v any) {
		t.Helper()
		if err := db.Create(v).Error; err != nil {
			t.Fatalf("seed %T: %v", v, err)
		}
	}
	org := &models.Organization{ID: uuid.New(), Name: "monrel-org-" + sfx}
	create(org)
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: org.ID, Name: "monrel-pool-" + sfx}
	create(pool)
	proj := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "monrel-proj-" + sfx}
	create(proj)
	ws := &models.Workspace{ProjectID: proj.ID, Name: "monrel-ws-" + sfx, ExecutionMode: "agent", AgentPoolID: &pool.ID}
	create(ws)
	stale := time.Now().Add(-10 * time.Minute)
	gone := &models.Runner{ID: uuid.New(), OrganizationID: new(org.ID), AgentPoolID: new(pool.ID), Name: "monrel-gone-" + sfx, Status: models.RunnerStatusOnline, LastHeartbeatAt: &stale}
	create(gone)
	reserved := &models.Run{WorkspaceID: ws.ID, Status: models.RunStatusPending, Operation: models.RunOperationPlanOnly, AgentPoolID: &pool.ID, RunnerID: &gone.ID}
	create(reserved)
	t.Cleanup(func() {
		db.Delete(&models.Run{}, "id = ?", reserved.ID)
		db.Delete(&models.Runner{}, "id = ?", gone.ID)
		db.Delete(&models.Workspace{}, "id = ?", ws.ID)
		db.Delete(&models.Project{}, "id = ?", proj.ID)
		db.Delete(&models.AgentPool{}, "id = ?", pool.ID)
		db.Delete(&models.Organization{}, "id = ?", org.ID)
	})

	NewMonitorService(repository.NewRunnerRepository(db)).markStaleRunners()

	var r models.Run
	if err := db.First(&r, "id = ?", reserved.ID).Error; err != nil {
		t.Fatal(err)
	}
	if r.RunnerID != nil {
		t.Fatalf("a stale runner's unstarted reservation is still held by %s", *r.RunnerID)
	}
	if r.Status != models.RunStatusPending {
		t.Fatalf("the released run is %s, want pending", r.Status)
	}
}
