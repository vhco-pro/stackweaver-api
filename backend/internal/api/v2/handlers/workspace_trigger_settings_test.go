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

// file_triggers_enabled=false has to survive a round trip through the database, because it is
// what disables path filtering (#678). WorkspaceRepository.Create must store the false it is
// given, with no further write.
//
// This test used to have a second half that re-assigned false and called Update, pinning a
// follow-up write in the workspace create handler. That half is gone on purpose (#867): the
// model then carried `gorm:"default:true"`, GORM substituted the default for the zero value in
// the INSERT and wrote true back into the struct, so the handler's `if !FileTriggersEnabled`
// condition could never be true and the write it guarded never ran. The tag was removed from the
// model, the unreachable write was deleted from the handler, and what is left to pin is the
// plain create.
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

	// Create must not have rewritten the caller's struct either: a substituted default shows up
	// here before it shows up in the row.
	if ws.FileTriggersEnabled {
		t.Errorf("Create changed the struct's FileTriggersEnabled from false to true")
	}

	stored, err := repo.GetByID(ws.ID)
	if err != nil {
		t.Fatalf("reload after create: %v", err)
	}
	if stored.FileTriggersEnabled {
		t.Errorf("file_triggers_enabled = true after creating with false; a workspace configured to always trigger stays path-filtered")
	}
	if stored.TriggerPrefixes != `["modules/network"]` {
		t.Errorf("trigger_prefixes = %q, want the stored JSON array", stored.TriggerPrefixes)
	}
}
