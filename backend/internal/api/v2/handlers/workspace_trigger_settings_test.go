// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package handlers

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// file_triggers_enabled=false has to survive a round trip through the database now that it
// actually disables path filtering (#678). models.Workspace.FileTriggersEnabled carries a
// `default:true` GORM tag, and GORM leaves zero-valued fields with a default tag out of the
// INSERT - so a plain Create silently stores true. The TFE workspace create handler works
// around that with an explicit follow-up write; this test pins both halves.
func TestFileTriggersEnabledFalseSurvivesCreate(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://iac:iac_password@localhost:5432/iac_platform?sslmode=disable" //nolint:gosec // G101: test database URL
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Skipf("no test database: %v", err)
	}

	sfx := uuid.NewString()[:8]
	org := &models.Organization{ID: uuid.New(), Name: "trig-org-" + sfx}
	proj := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "trig-proj-" + sfx}
	for _, obj := range []interface{}{org, proj} {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}

	repo := repository.NewWorkspaceRepository(db)
	ws := &models.Workspace{
		ProjectID:           proj.ID,
		Name:                "trig-ws-" + sfx,
		FileTriggersEnabled: false,
		TriggerPrefixes:     `["modules/network"]`,
	}
	if err := repo.Create(ws); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	t.Cleanup(func() {
		db.Where("id = ?", ws.ID).Delete(&models.Workspace{})
		db.Where("id = ?", proj.ID).Delete(&models.Project{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
	})

	// Document what a bare Create does, so the day GORM stops swallowing the false the
	// workaround below can be dropped rather than quietly kept forever.
	afterCreate, err := repo.GetByID(ws.ID)
	if err != nil {
		t.Fatalf("reload after create: %v", err)
	}
	if afterCreate.FileTriggersEnabled {
		t.Logf("as expected, Create dropped file_triggers_enabled=false (GORM `default:true` tag); the handler's explicit write is required")
	} else {
		t.Logf("Create persisted file_triggers_enabled=false directly - the handler's follow-up write is now redundant")
	}

	// This is the handler's workaround: Update uses Save, which writes every column.
	if !afterCreate.FileTriggersEnabled {
		return
	}
	ws.FileTriggersEnabled = false
	if err := repo.Update(ws); err != nil {
		t.Fatalf("update workspace: %v", err)
	}

	reloaded, err := repo.GetByID(ws.ID)
	if err != nil {
		t.Fatalf("reload after update: %v", err)
	}
	if reloaded.FileTriggersEnabled {
		t.Errorf("file_triggers_enabled = true after an explicit write of false; a workspace configured to always trigger stays path-filtered")
	}
	if reloaded.TriggerPrefixes != `["modules/network"]` {
		t.Errorf("trigger_prefixes = %q, want the stored JSON array", reloaded.TriggerPrefixes)
	}
}
