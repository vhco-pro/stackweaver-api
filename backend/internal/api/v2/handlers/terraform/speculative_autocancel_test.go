// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test for AutoCancelSupersededSpeculativeRuns (tfe_organization
// speculative_plan_management_enabled, R1): a newer commit to a branch/PR cancels only THAT
// branch/PR's pending speculative runs - never another PR's plan, never plan-and-apply runs.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestAutoCancelSupersededSpeculativeRuns

//go:build integration
// +build integration

package terraform

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestAutoCancelSupersededSpeculativeRuns(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	sfx := uuid.NewString()[:8]
	mustCreate := func(v any) {
		t.Helper()
		if err := db.Create(v).Error; err != nil {
			t.Fatalf("seed %T: %v", v, err)
		}
	}

	org := &models.Organization{ID: uuid.New(), Name: "spec-org-" + sfx}
	mustCreate(org)
	t.Cleanup(func() { db.Delete(&models.Organization{}, "id = ?", org.ID) })
	t.Cleanup(func() { db.Where("name = ?", org.Name).Delete(&models.ReservedOrganizationName{}) })
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "spec-proj-" + sfx}
	mustCreate(project)
	t.Cleanup(func() { db.Delete(&models.Project{}, "id = ?", project.ID) })
	wsID := "ws-spec" + sfx
	mustCreate(&models.Workspace{ID: wsID, ProjectID: project.ID, Name: "spec-ws-" + sfx})
	t.Cleanup(func() { db.Where("id = ?", wsID).Delete(&models.Workspace{}) })

	mkRun := func(tag, branch string, prNumber int, speculative bool, op models.RunOperation) string {
		cvID := "cv-" + tag + sfx
		mustCreate(&models.ConfigurationVersion{
			ID: cvID, WorkspaceID: wsID, Status: models.ConfigurationVersionStatusUploaded,
			Speculative: speculative, SourceBranch: branch, PRNumber: prNumber, CommitHash: "sha-" + tag + sfx,
		})
		t.Cleanup(func() { db.Where("id = ?", cvID).Delete(&models.ConfigurationVersion{}) })
		runID := "run-" + tag + sfx
		mustCreate(&models.Run{ID: runID, WorkspaceID: wsID, ConfigurationVersionID: &cvID, Status: models.RunStatusPending, Operation: op})
		t.Cleanup(func() { db.Where("id = ?", runID).Delete(&models.Run{}) })
		return runID
	}

	sameBranch := mkRun("sb", "feat-x", 7, true, models.RunOperationPlanOnly)
	otherBranch := mkRun("ob", "feat-y", 8, true, models.RunOperationPlanOnly)
	applyRun := mkRun("ap", "feat-x", 7, false, models.RunOperationPlanAndApply)

	runRepo := repository.NewRunRepository(db)
	cvRepo := repository.NewConfigurationVersionRepository(db)

	status := func(id string) models.RunStatus {
		var run models.Run
		if err := db.First(&run, "id = ?", id).Error; err != nil {
			t.Fatalf("load run %s: %v", id, err)
		}
		return run.Status
	}

	// A newer commit on feat-x supersedes only feat-x's pending speculative plan.
	AutoCancelSupersededSpeculativeRuns(runRepo, cvRepo, wsID, "feat-x", 0)
	if got := status(sameBranch); got != models.RunStatusCancelled {
		t.Errorf("same-branch speculative run = %s, want cancelled", got)
	}
	if got := status(otherBranch); got != models.RunStatusPending {
		t.Errorf("other-branch speculative run = %s, want pending (must NOT be cancelled)", got)
	}
	if got := status(applyRun); got != models.RunStatusPending {
		t.Errorf("plan-and-apply run = %s, want pending (never touched)", got)
	}

	// PR-number fallback (empty branch): supersedes PR #8's plan.
	AutoCancelSupersededSpeculativeRuns(runRepo, cvRepo, wsID, "", 8)
	if got := status(otherBranch); got != models.RunStatusCancelled {
		t.Errorf("PR-fallback: run for PR #8 = %s, want cancelled", got)
	}

	// No match criteria: must be a no-op, never a cancel-all.
	fresh := mkRun("fr", "feat-z", 9, true, models.RunOperationPlanOnly)
	AutoCancelSupersededSpeculativeRuns(runRepo, cvRepo, wsID, "", 0)
	if got := status(fresh); got != models.RunStatusPending {
		t.Errorf("no-criteria call cancelled a run (= %s), want pending", got)
	}
}
