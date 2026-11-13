// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The organization's default OpenTofu version under the installation default (#1069, D2): a new
// organization stores none, so its workspaces run the installation default and follow it; an
// organization or workspace that stored a version keeps it.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestOrganizationDefaultVersion

//go:build integration

package handlers

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/settings"
	"github.com/michielvha/stackweaver/core/tofu"
	"gorm.io/gorm"
)

// orgVersionFixture is a creator, the organization handler and the effective-settings read.
type orgVersionFixture struct {
	db      *gorm.DB
	creator *models.User
	sfx     string
	router  interface {
		ServeHTTP(http.ResponseWriter, *http.Request)
	}
}

func setupOrgVersionFixture(t *testing.T, orgNames ...string) *orgVersionFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	sfx := uuid.NewString()[:8]
	creator := &models.User{ID: uuid.New(), ZitadelSubject: "orgver-" + sfx, Email: "orgver-" + sfx + "@test.local"}
	if err := db.Create(creator).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { db.Where("id = ?", creator.ID).Delete(&models.User{}) })

	orgRepo := repository.NewOrganizationRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	authSvc := auth.NewService(repository.NewUserRepository(db))
	rbacSvc := rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo)
	orgH := NewOrganizationHandlerV2(orgRepo, teamRepo, projectRepo, repository.NewAgentPoolRepository(db), authSvc, nil, rbacSvc, db)
	effH := NewEffectiveSettingsHandlerV2(
		repository.NewWorkspaceRepository(db), repository.NewAnsibleJobTemplateRepository(db),
		repository.NewAnsibleInventorySourceRepository(db), repository.NewAnsibleInventoryRepository(db),
		projectRepo, orgRepo, authSvc, rbacSvc,
	)
	router := storedAsSentRouter()
	router.POST("/api/v2/organizations", orgH.Create)
	router.GET("/api/v2/organizations/:name", orgH.Get)
	router.PATCH("/api/v2/organizations/:name", orgH.Update)
	router.GET("/api/v2/workspaces/:id/effective-settings", effH.GetWorkspace)
	return &orgVersionFixture{db: db, creator: creator, sfx: sfx, router: router}
}

// createOrg creates an organization through the handler as the creator and registers its cleanup.
func (f *orgVersionFixture) createOrg(t *testing.T, name string) *models.Organization {
	t.Helper()
	t.Cleanup(func() {
		var projectIDs []uuid.UUID
		f.db.Model(&models.Project{}).Joins("JOIN organizations ON organizations.id = projects.organization_id").
			Where("organizations.name = ?", name).Pluck("projects.id", &projectIDs)
		if len(projectIDs) > 0 {
			f.db.Where("project_id IN ?", projectIDs).Delete(&models.Workspace{})
		}
		deleteOrganizationsByName(f.db, []string{name})
	})
	code, body := storedAsSentCall(t, f.router, http.MethodPost, "/api/v2/organizations", f.creator.ID,
		storedAsSentDocument(t, "organizations", map[string]any{"name": name, "email": name + "@test.local"}))
	if code != http.StatusCreated {
		t.Fatalf("create organization = %d (%s)", code, body)
	}
	var org models.Organization
	if err := f.db.First(&org, "name = ?", name).Error; err != nil {
		t.Fatal(err)
	}
	return &org
}

// workspaceIn creates a workspace in org's first project, storing version.
func (f *orgVersionFixture) workspaceIn(t *testing.T, org *models.Organization, name, version string) *models.Workspace {
	t.Helper()
	var project models.Project
	if err := f.db.Where("organization_id = ?", org.ID).Order("created_at").First(&project).Error; err != nil {
		t.Fatalf("the organization's project: %v", err)
	}
	ws := &models.Workspace{ProjectID: project.ID, Name: name, TofuVersion: version}
	if err := f.db.Create(ws).Error; err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", ws.ID).Delete(&models.Workspace{}) })
	return ws
}

// orgDefault reads default-terraform-version through GET /api/v2/organizations/:name.
func (f *orgVersionFixture) orgDefault(t *testing.T, name string) string {
	t.Helper()
	code, body := storedAsSentCall(t, f.router, http.MethodGet, "/api/v2/organizations/"+name, f.creator.ID, "")
	if code != http.StatusOK {
		t.Fatalf("read organization = %d (%s)", code, body)
	}
	_, attrs := storedAsSentResource(t, body)
	v, _ := attrs["default-terraform-version"].(string)
	return v
}

// effectiveVersion reads the workspace's tofu-version and its level.
func (f *orgVersionFixture) effectiveVersion(t *testing.T, ws *models.Workspace) (string, string) {
	t.Helper()
	code, body := storedAsSentCall(t, f.router, http.MethodGet, "/api/v2/workspaces/"+ws.ID+"/effective-settings", f.creator.ID, "")
	if code != http.StatusOK {
		t.Fatalf("effective settings = %d (%s)", code, body)
	}
	var doc struct {
		Data struct {
			Attributes struct {
				TofuVersion EffectiveSetting[string] `json:"tofu-version"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	level := ""
	if doc.Data.Attributes.TofuVersion.Level != nil {
		level = *doc.Data.Attributes.TofuVersion.Level
	}
	return doc.Data.Attributes.TofuVersion.Value, level
}

// enabledCatalogueVersion adds an enabled, stable catalogue version newer than any release, which
// the organization create handler stamped as the default before #1069, and removes it afterwards.
func enabledCatalogueVersion(t *testing.T, db *gorm.DB) string {
	t.Helper()
	v := &models.TofuVersion{Version: fmt.Sprintf("9.%d.0", 100000+rand.IntN(800000)), Enabled: true}
	if err := db.Create(v).Error; err != nil {
		t.Fatalf("create catalogue version: %v", err)
	}
	t.Cleanup(func() { db.Where("id = ?", v.ID).Delete(&models.TofuVersion{}) })
	return v.Version
}

// PATCH /api/v2/organizations/:name: null for default-terraform-version clears it, and the next GET
// reads it empty; an omitted attribute or "" keeps it; a version stores it (#1069, Q4, AC22).
func TestOrganizationDefaultVersion_PatchNullClears(t *testing.T) {
	t.Setenv(settings.EnvTofuDefaultVersion, "")
	f := setupOrgVersionFixture(t)
	for _, tc := range []struct {
		name  string
		attrs map[string]any
		want  string
	}{
		{"null clears", map[string]any{"default-terraform-version": nil}, ""},
		{"omitted keeps", map[string]any{"description": "unrelated"}, "1.12.0"},
		{"empty keeps", map[string]any{"default-terraform-version": ""}, "1.12.0"},
		{"a version stores it", map[string]any{"default-terraform-version": "1.11.0"}, "1.11.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := fmt.Sprintf("orgver-patch-%s-%d", f.sfx, rand.IntN(1000000))
			org := f.createOrg(t, name)
			if err := f.db.Model(&models.Organization{}).Where("id = ?", org.ID).Update("default_tofu_version", "1.12.0").Error; err != nil {
				t.Fatal(err)
			}
			code, body := storedAsSentCall(t, f.router, http.MethodPatch, "/api/v2/organizations/"+name, f.creator.ID,
				storedAsSentDocument(t, "organizations", tc.attrs))
			if code != http.StatusOK {
				t.Fatalf("PATCH = %d (%s)", code, body)
			}
			if got := f.orgDefault(t, name); got != tc.want {
				t.Errorf("default-terraform-version = %q, want %q", got, tc.want)
			}
			if tc.want == "" {
				ws := f.workspaceIn(t, org, "cleared", "")
				if v, level := f.effectiveVersion(t, ws); v != tofu.BundledVersion || level != "deployment" {
					t.Errorf("a workspace of the cleared organization runs %q from %q, want %q from deployment", v, level, tofu.BundledVersion)
				}
			}
		})
	}
}

// A new organization stores no default version, so a workspace in it that sets none runs the
// installation default; an organization and a workspace that stored versions keep them (AC8).
func TestOrganizationDefaultVersion_NewOrganizationInheritsTheInstallation(t *testing.T) {
	t.Setenv(settings.EnvTofuDefaultVersion, "")
	f := setupOrgVersionFixture(t)
	enabledCatalogueVersion(t, f.db)

	name := "orgver-new-" + f.sfx
	org := f.createOrg(t, name)
	if got := f.orgDefault(t, name); got != "" {
		t.Errorf("a new organization's default-terraform-version = %q, want empty (installation default)", got)
	}
	ws := f.workspaceIn(t, org, "fresh", "")
	if v, level := f.effectiveVersion(t, ws); v != tofu.BundledVersion || level != "deployment" {
		t.Errorf("a new organization's workspace runs %q from %q, want %q from deployment", v, level, tofu.BundledVersion)
	}

	// An organization and a workspace that stored versions before the change keep them.
	oldName := "orgver-old-" + f.sfx
	old := f.createOrg(t, oldName)
	if err := f.db.Model(&models.Organization{}).Where("id = ?", old.ID).Update("default_tofu_version", "1.12.0").Error; err != nil {
		t.Fatal(err)
	}
	if got := f.orgDefault(t, oldName); got != "1.12.0" {
		t.Errorf("a stored organization default reads %q, want 1.12.0", got)
	}
	inheriting := f.workspaceIn(t, old, "inherits", "")
	if v, level := f.effectiveVersion(t, inheriting); v != "1.12.0" || level != "organization" {
		t.Errorf("a workspace of the stored organization runs %q from %q, want 1.12.0 from organization", v, level)
	}
	pinned := f.workspaceIn(t, old, "pinned", "1.11.0")
	if v, level := f.effectiveVersion(t, pinned); v != "1.11.0" || level != "workspace" {
		t.Errorf("a stored workspace version runs %q from %q, want 1.11.0 from workspace", v, level)
	}
}
