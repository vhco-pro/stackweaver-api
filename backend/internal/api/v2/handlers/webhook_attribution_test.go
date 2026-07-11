// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-124 webhook event attribution. recordWebhookEvent determined the owning org by
// "the first workspace matching this repo name" (FindByVCSRepository, Limit(1), no org
// scope). On a repo-name collision an attacker's payloads are filed into a victim org's
// webhook-event log. The fix derives the org from the validated installation instead.
// This test drives the real handler + Postgres and proves attribution follows the
// installation, not the repo name — with a control showing the old heuristic mis-attributes.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestWebhookEventAttribution

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

func TestWebhookEventAttribution(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.Organization{}, &models.Project{}, &models.Workspace{},
		&models.VCSConnection{}, &models.WebhookEvent{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	// orgA owns the GitHub App installation "111". orgB happens to have a workspace for the
	// SAME repo full_name "acme/infra" — the collision the attacker exploits.
	orgA := &models.Organization{ID: uuid.New(), Name: "wha-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "wha-b-" + sfx}
	connA := &models.VCSConnection{ID: uuid.New(), OrganizationID: orgA.ID, Provider: models.VCSProviderGitHub, InstallationID: "111-" + sfx}
	projB := &models.Project{ID: uuid.New(), OrganizationID: orgB.ID, Name: "projB-" + sfx}
	wsB := &models.Workspace{ID: "ws-" + sfx, ProjectID: projB.ID, Name: "wsB-" + sfx, VCSRepository: "acme/infra"}

	const repo = "acme/infra"
	newMarker := "new-" + sfx  // commit marker for the fixed-path event
	oldMarker := "old-" + sfx  // commit marker for the control (heuristic) event

	t.Cleanup(func() {
		db.Where("commit IN ?", []string{newMarker, oldMarker}).Delete(&models.WebhookEvent{})
		db.Where("id = ?", wsB.ID).Delete(&models.Workspace{})
		db.Where("id = ?", projB.ID).Delete(&models.Project{})
		db.Where("id = ?", connA.ID).Delete(&models.VCSConnection{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
	})
	for _, obj := range []interface{}{orgA, orgB, connA, projB, wsB} {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}

	h := &VCSAppInstallationHandlerV2{
		webhookEventRepo:  repository.NewWebhookEventRepository(db),
		workspaceRepo:     repository.NewWorkspaceRepository(db),
		vcsConnectionRepo: repository.NewVCSConnectionRepository(db),
	}

	// orgFromInstallation resolves strictly by installation id.
	if got := h.orgFromInstallation(connA.InstallationID); got == nil || *got != orgA.ID {
		t.Fatalf("orgFromInstallation(%q) = %v, want orgA %v", connA.InstallationID, got, orgA.ID)
	}
	if got := h.orgFromInstallation("999-" + sfx); got != nil {
		t.Fatalf("orgFromInstallation(unknown) = %v, want nil", got)
	}

	orgOf := func(marker string) *uuid.UUID {
		var ev models.WebhookEvent
		if err := db.Where("commit = ?", marker).First(&ev).Error; err != nil {
			t.Fatalf("load webhook event %q: %v", marker, err)
		}
		return ev.OrganizationID
	}

	// FIXED path: attribution derived from the validated installation "111" (orgA) — even
	// though the only workspace matching repo "acme/infra" belongs to orgB.
	h.recordWebhookEvent(h.orgFromInstallation(connA.InstallationID), "push", "github", repo, "main", newMarker, "ignored", "test", 200, "{}")
	if org := orgOf(newMarker); org == nil || *org != orgA.ID {
		t.Fatalf("AUD-124: event attributed to %v, want installation org orgA %v", org, orgA.ID)
	}

	// CONTROL (pre-fix behavior): with no trusted org, the repo-name heuristic mis-attributes
	// the very same delivery to orgB — the victim. This is exactly the bug the fix removes.
	h.recordWebhookEvent(nil, "push", "github", repo, "main", oldMarker, "ignored", "test", 200, "{}")
	if org := orgOf(oldMarker); org == nil || *org != orgB.ID {
		t.Fatalf("control expectation broken: heuristic attributed to %v, want orgB %v (collision victim)", org, orgB.ID)
	}
}
