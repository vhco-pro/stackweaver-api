// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test for issue #1062: a run's has-changes follows its plan once the plan has
// finished, and the workspace list, whose plan half PostgreSQL evaluates (#808), answers the same
// as the run resource for the same row in every status.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestRunHasChanges_WorkspaceListMatchesTheRunInPostgres

//go:build integration
// +build integration

package terraform

import (
	"os"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

func TestRunHasChanges_WorkspaceListMatchesTheRunInPostgres(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
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
	org := &models.Organization{ID: uuid.New(), Name: "hc-org-" + sfx}
	mustCreate(org)
	t.Cleanup(func() { db.Delete(&models.Organization{}, "id = ?", org.ID) })
	t.Cleanup(func() { db.Where("name = ?", org.Name).Delete(&models.ReservedOrganizationName{}) })
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "hc-proj-" + sfx}
	mustCreate(project)
	t.Cleanup(func() { db.Delete(&models.Project{}, "id = ?", project.ID) })
	wsID := "ws-hc" + sfx
	mustCreate(&models.Workspace{ID: wsID, ProjectID: project.ID, Name: "hc-ws-" + sfx})
	t.Cleanup(func() { db.Where("id = ?", wsID).Delete(&models.Workspace{}) })
	// Registered after the workspace, so it runs first: a run left by a failed iteration.
	t.Cleanup(func() { db.Where("workspace_id = ?", wsID).Delete(&models.Run{}) })

	runRepo := repository.NewRunRepository(db)
	plans := map[string]models.PlanOutput{"changing": changingPlan(), "no-op": noopPlan()}
	statuses := append(append([]models.RunStatus{}, statusesAfterPlan...), statusesBeforePlan...)

	for name, plan := range plans {
		for _, op := range planOperations {
			runID := "run-hc" + sfx
			mustCreate(&models.Run{ID: runID, WorkspaceID: wsID, Status: models.RunStatusPending, Operation: op, PlanOutput: plan})
			for _, status := range statuses {
				if err := db.Model(&models.Run{}).Where("id = ?", runID).Update("status", status).Error; err != nil {
					t.Fatalf("set status %s: %v", status, err)
				}
				run, err := runRepo.GetByID(runID)
				if err != nil {
					t.Fatalf("load run: %v", err)
				}
				latest, err := runRepo.GetLatestByWorkspaceIDs([]string{wsID})
				if err != nil {
					t.Fatalf("GetLatestByWorkspaceIDs: %v", err)
				}
				summary, ok := latest[wsID]
				if !ok || summary.ID != runID {
					t.Fatalf("latest run for %s = %+v, want %s", wsID, summary, runID)
				}

				resource := runHasChangesAttr(t, run)
				listed := formatRunForInclusion(summary).Attributes.HasChanges
				if listed != resource {
					t.Errorf("%s run at %s with a %s plan: workspace list has-changes = %v, run resource = %v", op, status, name, listed, resource)
				}
				// The run lists (runCollection) load runs without their plans and answer from
				// PostgreSQL the same way.
				flags, err := runRepo.PlanIndicatesChangesByID([]string{runID})
				if err != nil {
					t.Fatalf("PlanIndicatesChangesByID: %v", err)
				}
				if inList := flags[runID] && runReportsChanges(op, status); inList != resource {
					t.Errorf("%s run at %s with a %s plan: run list has-changes = %v, run resource = %v", op, status, name, inList, resource)
				}
				want := name == "changing" && slices.Contains(statusesAfterPlan, status)
				if resource != want {
					t.Errorf("%s run at %s with a %s plan: has-changes = %v, want %v", op, status, name, resource, want)
				}
			}
			if err := db.Where("id = ?", runID).Delete(&models.Run{}).Error; err != nil {
				t.Fatalf("delete run: %v", err)
			}
		}
	}
}
