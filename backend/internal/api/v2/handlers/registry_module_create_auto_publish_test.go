// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A registry module created with `auto_publish_tags: false` must be stored with tag publishing
// off, and one created without the key takes the rule the create dialog applies: on for a module
// connected to a VCS repository, off for a manual one. A module stored with it off must not be
// returned by ModuleRepository.FindByVCSRepository, which is what a tag push publishes through.
//
// The defect this test was written against: Module.AutoPublishTags carried `gorm:"default:true"`,
// and GORM substitutes a literal default for a zero value in the INSERT (and writes it back into
// the struct), so every module, the manual ones the UI creates with false included, was stored as
// tag-based. There is no update route, so false could not be stored by any path.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRegistryModuleCreate_AutoPublishTags

//go:build integration

package handlers

import (
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

func TestRegistryModuleCreate_AutoPublishTagsIsStoredAsSent(t *testing.T) {
	db := setupTestDB(t)
	if err := db.AutoMigrate(&models.VCSConnection{}, &models.Project{}, &models.TeamProjectAccess{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	org := setupTestOrg(t, db) // its cleanup removes this organization's modules, teams and members
	owner := createRegistryTestUser(t, db)
	if err := db.Create(&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: owner.ID}).Error; err != nil {
		t.Fatalf("seed organization member: %v", err)
	}
	makeUserOrgOwner(t, db, org, owner)

	vcsConn := &models.VCSConnection{
		ID: uuid.New(), OrganizationID: org.ID, Provider: models.VCSProviderGitHub, AccountName: "autopub-" + uuid.NewString()[:8],
	}
	if err := db.Create(vcsConn).Error; err != nil {
		t.Fatalf("seed VCS connection: %v", err)
	}
	t.Cleanup(func() {
		// Registered after setupTestOrg, so it runs first: the modules that reference the
		// connection go before the connection does.
		db.Exec("DELETE FROM module_versions WHERE module_id IN (SELECT id FROM modules WHERE organization_id = ?)", org.ID)
		db.Where("organization_id = ?", org.ID).Delete(&models.Module{})
		db.Where("id = ?", vcsConn.ID).Delete(&models.VCSConnection{})
	})

	moduleRepo := repository.NewModuleRepository(db)
	moduleVersionRepo := repository.NewModuleVersionRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	vcsConnectionRepo := repository.NewVCSConnectionRepository(db)
	h := NewRegistryPublishingHandler(
		moduleRepo,
		moduleVersionRepo,
		orgRepo,
		vcsConnectionRepo,
		auth.NewService(repository.NewUserRepository(db)),
		newProviderRBAC(db),
		nil, // githubAppManager - nil skips the publish-latest-tag side effect
		registry.NewModulePublisher(moduleRepo, moduleVersionRepo, orgRepo, vcsConnectionRepo, storagetest.NewMemory()),
	)

	router := storedAsSentRouter()
	router.POST("/api/v2/organizations/:name/registry/modules", h.CreateModule)
	router.GET("/api/v2/organizations/:name/registry/modules/:module_name/:provider", h.GetModule)

	const attr = "auto_publish_tags"
	sent := func(v bool) *bool { return &v }
	// Each VCS-connected case gets a repository path of its own, so FindByVCSRepository can only
	// ever see that case's module.
	cases := []struct {
		name         string
		vcsConnected bool
		autoPublish  *bool // nil leaves the key out
		want         bool
	}{
		{"VCS module, explicit false", true, sent(false), false},
		{"VCS module, explicit true", true, sent(true), true},
		{"VCS module, key absent", true, nil, true},
		{"manual module, explicit false", false, sent(false), false},
		{"manual module, key absent", false, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := "autopub-" + uuid.NewString()[:8]
			repo := ""
			// The create body is a registry-modules document (#858) with snake_case attributes.
			req := map[string]any{"name": name, "provider": "aws"}
			if tc.vcsConnected {
				repo = "explicit-zero-871/" + name
				req["vcs_connection_id"] = vcsConn.ID.String()
				req["vcs_repository"] = repo
			}
			if tc.autoPublish != nil {
				req[attr] = *tc.autoPublish
			}
			raw, err := json.Marshal(map[string]any{"data": map[string]any{"type": "registry-modules", "attributes": req}})
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			path := "/api/v2/organizations/" + org.Name + "/registry/modules"
			code, body := storedAsSentCall(t, router, http.MethodPost, path, owner.ID, string(raw))
			if code != http.StatusCreated {
				t.Fatalf("create = %d, want 201 (%s)", code, body)
			}
			_, created := storedAsSentResource(t, body)
			assertStoredBool(t, "create response", created, attr, tc.want)

			code, body = storedAsSentCall(t, router, http.MethodGet, path+"/"+name+"/aws", owner.ID, "")
			if code != http.StatusOK {
				t.Fatalf("read = %d, want 200 (%s)", code, body)
			}
			_, read := storedAsSentResource(t, body)
			assertStoredBool(t, "read back", read, attr, tc.want)

			if !tc.vcsConnected {
				return
			}
			found, err := moduleRepo.FindByVCSRepository(repo)
			if err != nil {
				t.Fatalf("FindByVCSRepository(%s): %v", repo, err)
			}
			if tc.want && len(found) != 1 {
				t.Errorf("FindByVCSRepository(%s) returned %d modules, want the one with tag publishing on", repo, len(found))
			}
			if !tc.want && len(found) != 0 {
				t.Errorf("FindByVCSRepository(%s) returned %d modules, want none: tag publishing is off", repo, len(found))
			}
		})
	}
}
