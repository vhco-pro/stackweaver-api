// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for capacity-aware job offering. Gated behind the
// `integration` build tag; skip unless `$TEST_DATABASE_URL` is set. Run with:
//
//	go test -tags integration ./backend/internal/api/v2/handlers/ -run TestFindPendingJobs

//go:build integration
// +build integration

package handlers

import (
	"gorm.io/gorm"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// seedPendingAnsibleJob inserts a released pending job into the given pool. It
// creates the real parent graph (org → project → inventory) so the live
// foreign-key constraints are satisfied.
func seedPendingAnsibleJob(t *testing.T, h *RunnerAgentHandler, poolID uuid.UUID) uuid.UUID {
	t.Helper()
	suffix := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "captest-org-" + suffix}
	if err := h.db.Create(org).Error; err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() { h.db.Delete(&models.Organization{}, "id = ?", org.ID) })

	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "captest-proj-" + suffix}
	if err := h.db.Create(project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	t.Cleanup(func() { h.db.Delete(&models.Project{}, "id = ?", project.ID) })

	inv := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: org.ID, Name: "captest-inv-" + suffix, Type: models.InventoryTypeStatic}
	if err := h.db.Create(inv).Error; err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	t.Cleanup(func() { h.db.Delete(&models.AnsibleInventory{}, "id = ?", inv.ID) })

	now := time.Now()
	job := &models.AnsibleJob{
		ID:          uuid.New(),
		ProjectID:   project.ID,
		InventoryID: inv.ID,
		Status:      models.AnsibleJobStatusPending,
		AgentPoolID: &poolID,
		QueuedAt:    &now,
	}
	if err := h.db.Create(job).Error; err != nil {
		t.Fatalf("seed job: %v", err)
	}
	t.Cleanup(func() { h.db.Delete(&models.AnsibleJob{}, "id = ?", job.ID) })
	return job.ID
}

func migrateOfferingModels(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.AutoMigrate(
		&models.Runner{},
		&models.RunnerJobExecution{},
		&models.AnsibleJob{},
		&models.Project{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

func newOfferingHandler(db *gorm.DB) *RunnerAgentHandler {
	return &RunnerAgentHandler{
		db:             db,
		jobExecRepo:    repository.NewRunnerJobExecutionRepository(db),
		ansibleJobRepo: repository.NewAnsibleJobRepository(db),
	}
}

func newAnsibleAgent(t *testing.T, db *gorm.DB, orgID, poolID uuid.UUID, name string) *models.Runner {
	t.Helper()
	r := &models.Runner{
		ID:                uuid.New(),
		OrganizationID:    orgID,
		AgentPoolID:       poolID,
		Name:              name,
		Status:            models.RunnerStatusOnline,
		AnsibleVersion:    "2.16.0", // CanExecuteAnsible() true; no TerraformVersion → tf branch skipped
		MaxConcurrentJobs: 1,
	}
	if err := db.Create(r).Error; err != nil {
		t.Fatalf("seed runner %s: %v", name, err)
	}
	t.Cleanup(func() { db.Delete(&models.Runner{}, "id = ?", r.ID) })
	return r
}

// An idle runner with MaxConcurrentJobs=1 must be offered at most one job even
// when several pending jobs sit in its pool - the cap that stops a single
// fast-polling runner from scooping a whole batch of sibling slices.
func TestFindPendingJobs_CapacityCapsOffering(t *testing.T) {
	db := setupTestDB(t)
	migrateOfferingModels(t, db)
	h := newOfferingHandler(db)

	suffix := uuid.NewString()[:8]
	org := &models.Organization{ID: uuid.New(), Name: "captest-runner-org-" + suffix}
	if err := db.Create(org).Error; err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() { db.Delete(&models.Organization{}, "id = ?", org.ID) })

	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: org.ID, Name: "captest-pool-" + suffix}
	if err := db.Create(pool).Error; err != nil {
		t.Fatalf("seed pool: %v", err)
	}
	t.Cleanup(func() { db.Delete(&models.AgentPool{}, "id = ?", pool.ID) })

	poolID := pool.ID
	runner := &models.Runner{
		ID:                uuid.New(),
		OrganizationID:    org.ID,
		AgentPoolID:       poolID,
		Name:              "captest-runner-" + suffix,
		Status:            models.RunnerStatusOnline,
		AnsibleVersion:    "2.16.0", // makes CanExecuteAnsible() true
		MaxConcurrentJobs: 1,        // TerraformVersion left empty → terraform branch skipped
	}
	if err := db.Create(runner).Error; err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	t.Cleanup(func() { db.Delete(&models.Runner{}, "id = ?", runner.ID) })

	// Three pending jobs in the pool, but capacity is 1.
	for i := 0; i < 3; i++ {
		seedPendingAnsibleJob(t, h, poolID)
	}

	offered, err := h.findPendingJobsForRunner(runner)
	if err != nil {
		t.Fatalf("findPendingJobsForRunner: %v", err)
	}
	if len(offered) != 1 {
		t.Fatalf("expected 1 job offered (capacity=1), got %d", len(offered))
	}
	firstJobID := offered[0].JobID

	// A second poll before the job finishes must not hand out ADDITIONAL work - the
	// reservation counts against capacity, so the other two pending jobs stay unoffered.
	//
	// It does, however, re-offer the SAME held job. That is deliberate: the reserve
	// query only returns rows it newly stamped (it matches `runner_id IS NULL`), so
	// before this an offer the agent dropped was never offered again, and
	// ReleaseStaleAnsibleReservations only frees reservations held by OFFLINE runners -
	// an online agent stranded the slice forever and wedged its own capacity. Found on
	// the kind harness: 2 agents, 3 slices, one slice pending on an online runner until
	// the spec timed out. This assertion previously expected 0, which conflated "no new
	// work" with "nothing at all" and encoded the starvation as intended behaviour.
	offered, err = h.findPendingJobsForRunner(runner)
	if err != nil {
		t.Fatalf("findPendingJobsForRunner (full): %v", err)
	}
	if len(offered) != 1 {
		t.Fatalf("expected the held job to be re-offered and no new work (1), got %d", len(offered))
	}
	if offered[0].JobID != firstJobID {
		t.Fatalf("expected the SAME held job re-offered (%s), got %s - a different job means capacity was exceeded",
			firstJobID, offered[0].JobID)
	}
}

// Two idle runners polling the same pool of pending jobs must reserve DISJOINT
// jobs - the SKIP-LOCKED reservation that makes sibling slices distribute across
// agents instead of funnelling onto whichever runner wins a shared claim race.
func TestFindPendingJobs_DistributesAcrossRunners(t *testing.T) {
	db := setupTestDB(t)
	migrateOfferingModels(t, db)
	h := newOfferingHandler(db)

	suffix := uuid.NewString()[:8]
	org := &models.Organization{ID: uuid.New(), Name: "disttest-org-" + suffix}
	if err := db.Create(org).Error; err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() { db.Delete(&models.Organization{}, "id = ?", org.ID) })
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: org.ID, Name: "disttest-pool-" + suffix}
	if err := db.Create(pool).Error; err != nil {
		t.Fatalf("seed pool: %v", err)
	}
	t.Cleanup(func() { db.Delete(&models.AgentPool{}, "id = ?", pool.ID) })

	runnerA := newAnsibleAgent(t, db, org.ID, pool.ID, "dist-agent-a-"+suffix)
	runnerB := newAnsibleAgent(t, db, org.ID, pool.ID, "dist-agent-b-"+suffix)

	// Two pending jobs, two idle runners.
	for i := 0; i < 2; i++ {
		seedPendingAnsibleJob(t, h, pool.ID)
	}

	offeredA, err := h.findPendingJobsForRunner(runnerA)
	if err != nil {
		t.Fatalf("offer A: %v", err)
	}
	offeredB, err := h.findPendingJobsForRunner(runnerB)
	if err != nil {
		t.Fatalf("offer B: %v", err)
	}
	if len(offeredA) != 1 || len(offeredB) != 1 {
		t.Fatalf("each runner should reserve exactly 1 job, got A=%d B=%d", len(offeredA), len(offeredB))
	}
	if offeredA[0].JobID == offeredB[0].JobID {
		t.Fatalf("runners reserved the SAME job %s - not distributed", offeredA[0].JobID)
	}
}
