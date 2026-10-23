// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a registry module create answers for a VCS connection the module may not name (#916):
// one answer, whether the connection belongs to another organization or does not exist.
//
// The defect this test was written against: the create did hold the connection to the module's
// organization, but answered 403 for a connection of another organization and 400 for an
// identifier that names nothing, so the status told a caller which connection identifiers are
// real.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRegistryModuleCreate_VCSConnection

//go:build integration

package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/storage/storagetest"
)

func TestRegistryModuleCreate_VCSConnectionOfAnotherOrganizationReadsAsNotFound(t *testing.T) {
	db := setupTestDB(t)
	if err := db.AutoMigrate(&models.VCSConnection{}, &models.Project{}, &models.TeamProjectAccess{}); err != nil {
		t.Fatalf("migrating the tables: %v", err)
	}
	org := setupTestOrg(t, db) // its cleanup removes this organization's modules, teams and members
	owner := createRegistryTestUser(t, db)
	if err := db.Create(&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: owner.ID}).Error; err != nil {
		t.Fatalf("seeding the organization member: %v", err)
	}
	makeUserOrgOwner(t, db, org, owner)

	sfx := uuid.NewString()[:8]
	otherOrg := &models.Organization{ID: uuid.New(), Name: "modconn-b-" + sfx}
	own := &models.VCSConnection{ID: uuid.New(), OrganizationID: org.ID, Provider: models.VCSProviderGitHub, AccountName: "modconn-a-" + sfx}
	other := &models.VCSConnection{ID: uuid.New(), OrganizationID: otherOrg.ID, Provider: models.VCSProviderGitHub, AccountName: "modconn-b-" + sfx}
	for _, row := range []any{otherOrg, own, other} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}
	t.Cleanup(func() {
		// Registered after setupTestOrg, so it runs first: the modules that name a connection go
		// before the connections, then the second organization, each by this run's identifiers.
		db.Exec("DELETE FROM module_versions WHERE module_id IN (SELECT id FROM modules WHERE organization_id = ?)", org.ID)
		db.Where("organization_id = ?", org.ID).Delete(&models.Module{})
		db.Where("id IN ?", []uuid.UUID{own.ID, other.ID}).Delete(&models.VCSConnection{})
		db.Where("id = ?", otherOrg.ID).Delete(&models.Organization{})
	})

	moduleRepo := repository.NewModuleRepository(db)
	moduleVersionRepo := repository.NewModuleVersionRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	vcsConnectionRepo := repository.NewVCSConnectionRepository(db)
	h := NewRegistryPublishingHandler(
		moduleRepo, moduleVersionRepo, orgRepo, vcsConnectionRepo,
		auth.NewService(repository.NewUserRepository(db)), newProviderRBAC(db),
		nil, // githubAppManager - nil skips the publish-latest-tag side effect
		registry.NewModulePublisher(moduleRepo, moduleVersionRepo, orgRepo, vcsConnectionRepo, storagetest.NewMemory()),
	)
	router := storedAsSentRouter()
	router.POST("/api/v2/organizations/:name/registry/modules", h.CreateModule)

	// The create body is flat JSON, not a JSON:API document. The name is fixed across the two
	// refused requests so that the answers can be compared byte for byte.
	create := func(t *testing.T, name, connection string) (int, []byte) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"data": map[string]any{"type": "registry-modules", "attributes": map[string]any{
			"name": name, "provider": "aws", "vcs_connection_id": connection, "vcs_repository": "modconn-" + sfx + "/" + name,
		}}})
		if err != nil {
			t.Fatalf("marshalling the request: %v", err)
		}
		return storedAsSentCall(t, router, http.MethodPost, "/api/v2/organizations/"+org.Name+"/registry/modules", owner.ID, string(raw))
	}
	modules := func(t *testing.T) int64 {
		t.Helper()
		var n int64
		if err := db.Model(&models.Module{}).Where("organization_id = ?", org.ID).Count(&n).Error; err != nil {
			t.Fatalf("counting the modules: %v", err)
		}
		return n
	}

	refused := "modconn-refused-" + sfx
	code, body := create(t, refused, other.ID.String())
	missingCode, missingBody := create(t, refused, uuid.NewString())
	if code != http.StatusBadRequest {
		t.Errorf("a connection of another organization: %d %s, want 400", code, body)
	}
	if code != missingCode || !bytes.Equal(body, missingBody) {
		t.Errorf("a connection of another organization and one that does not exist are answered differently:\n  other organization: %d %s\n  does not exist:     %d %s",
			code, body, missingCode, missingBody)
	}
	if got := modules(t); got != 0 {
		t.Errorf("the refused requests left %d module(s) behind", got)
	}

	if code, body := create(t, "modconn-own-"+sfx, own.ID.String()); code != http.StatusCreated {
		t.Errorf("a module naming its organization's connection: %d %s, want 201", code, body)
	}
}
