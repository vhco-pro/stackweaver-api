// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// TestRegistryProtocolReadAuthz is the AUD-123 assertion: the `/v1` Terraform registry-protocol
// read/download endpoints (which carry no auth middleware) must gate PRIVATE providers and (all)
// modules on org membership while leaving PUBLIC providers anonymously reachable. Before the fix
// these handlers took no auth/rbac deps at all, so any unauthenticated caller could read and
// download any org's private registry artifacts.
func TestRegistryProtocolReadAuthz(t *testing.T) {
	db := setupTestDBForProvider(t)
	// The shared provider migrate set does not include the module models.
	if err := db.AutoMigrate(&models.Module{}, &models.ModuleVersion{}, &models.ModuleDownload{}); err != nil {
		t.Fatalf("migrate module models: %v", err)
	}

	// Declare up front and register cleanup BEFORE any seeding, so a failure mid-setup still
	// removes whatever rows were created (register-before-seed; the closure reads the vars by
	// reference). Every delete is row-scoped to this test's orgs/users — $TEST_DATABASE_URL is
	// the live dev DB, so an unscoped delete would wipe real registry data.
	var orgA, orgB *models.Organization
	var member, outsider *models.User
	t.Cleanup(func() {
		for _, o := range []*models.Organization{orgA, orgB} {
			if o == nil {
				continue
			}
			db.Exec(`DELETE FROM module_downloads WHERE module_version_id IN (
				SELECT mv.id FROM module_versions mv JOIN modules m ON m.id = mv.module_id
				WHERE m.organization_id = ?)`, o.ID)
			db.Exec("DELETE FROM module_versions WHERE module_id IN (SELECT id FROM modules WHERE organization_id = ?)", o.ID)
			db.Exec("DELETE FROM modules WHERE organization_id = ?", o.ID)
			db.Exec(`DELETE FROM provider_versions WHERE provider_id IN (SELECT id FROM providers WHERE organization_id = ?)`, o.ID)
			db.Exec("DELETE FROM providers WHERE organization_id = ?", o.ID)
			db.Exec("DELETE FROM team_members WHERE team_id IN (SELECT id FROM teams WHERE organization_id = ?)", o.ID)
			db.Exec("DELETE FROM team_organization_accesses WHERE team_id IN (SELECT id FROM teams WHERE organization_id = ?)", o.ID)
			db.Exec("DELETE FROM teams WHERE organization_id = ?", o.ID)
			db.Exec("DELETE FROM organizations WHERE id = ?", o.ID)
		}
		for _, u := range []*models.User{member, outsider} {
			if u != nil {
				db.Exec("DELETE FROM users WHERE id = ?", u.ID)
			}
		}
	})

	orgA = setupTestOrgForProvider(t, db) // owns the private provider + module
	orgB = setupTestOrgForProvider(t, db) // the outsider's org
	// Distinct ZitadelSubject per user — the shared helper leaves it empty, which collides on
	// the users' unique subject index when more than one test user exists.
	mkUser := func() *models.User {
		u := &models.User{ID: uuid.New(), Email: fmt.Sprintf("u-%s@example.com", uuid.New().String()[:8]), ZitadelSubject: uuid.New().String()}
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}
		return u
	}
	member = mkUser()   // member of A
	outsider = mkUser() // member of B only
	makeUserOrgOwner(t, db, orgA, member)
	makeUserOrgOwner(t, db, orgB, outsider)

	// Private provider in A (+ a version so an authorized read returns 200).
	privateProv := &models.Provider{ID: uuid.New(), OrganizationID: orgA.ID, Name: "secret-prov", RegistryName: "private", Namespace: orgA.Name}
	if err := db.Create(privateProv).Error; err != nil {
		t.Fatalf("create private provider: %v", err)
	}
	if err := db.Create(&models.ProviderVersion{ProviderID: privateProv.ID, Version: "1.0.0", Protocols: "5.0"}).Error; err != nil {
		t.Fatalf("create private provider version: %v", err)
	}
	// Public provider in A — must stay anonymously reachable.
	publicProv := &models.Provider{ID: uuid.New(), OrganizationID: orgA.ID, Name: "open-prov", RegistryName: "public", Namespace: orgA.Name}
	if err := db.Create(publicProv).Error; err != nil {
		t.Fatalf("create public provider: %v", err)
	}
	if err := db.Create(&models.ProviderVersion{ProviderID: publicProv.ID, Version: "1.0.0", Protocols: "5.0"}).Error; err != nil {
		t.Fatalf("create public provider version: %v", err)
	}
	// Module in A (all modules are org-private).
	mod := &models.Module{ID: uuid.New(), OrganizationID: orgA.ID, Name: "secret-mod", Provider: "aws"}
	if err := db.Create(mod).Error; err != nil {
		t.Fatalf("create module: %v", err)
	}
	if err := db.Create(&models.ModuleVersion{ModuleID: mod.ID, Version: "1.0.0", PublishedAt: time.Now()}).Error; err != nil {
		t.Fatalf("create module version: %v", err)
	}

	storageClient := registry.NewMockStorage()
	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	providerService := registry.NewProviderService(
		repository.NewProviderRepository(db), repository.NewProviderVersionRepository(db),
		repository.NewProviderPlatformRepository(db), repository.NewProviderDownloadRepository(db),
		orgRepo, storageClient)
	moduleService := registry.NewModuleService(
		repository.NewModuleRepository(db), repository.NewModuleVersionRepository(db),
		repository.NewModuleDownloadRepository(db), orgRepo, storageClient)
	provH := NewRegistryProviderHandler(providerService, repository.NewGPGKeyRepository(db), authService, orgRepo, storageClient)
	modH := NewRegistryModuleHandler(moduleService, authService, orgRepo)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	// The real /v1 groups have no auth middleware; this stub only translates a test header into
	// the same user_id context an upstream would set, so the handler's own gate does the work.
	router.Use(func(c *gin.Context) {
		if h := c.GetHeader("X-Test-User"); h != "" {
			if id, err := uuid.Parse(h); err == nil {
				c.Set("user_id", id)
			}
		}
		c.Next()
	})
	router.GET("/v1/providers/:namespace", provH.ListProviders)
	router.GET("/v1/providers/:namespace/:name", provH.GetProvider)
	router.GET("/v1/modules/:namespace/:name/:provider", modH.GetModule)

	do := func(path, user string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), "GET", path, nil)
		if user != "" {
			req.Header.Set("X-Test-User", user)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	privPath := fmt.Sprintf("/v1/providers/%s/%s", orgA.Name, privateProv.Name)
	pubPath := fmt.Sprintf("/v1/providers/%s/%s", orgA.Name, publicProv.Name)
	modPath := fmt.Sprintf("/v1/modules/%s/%s/%s", orgA.Name, mod.Name, mod.Provider)

	cases := []struct {
		name, path, user string
		want             int
	}{
		{"private provider anon -> 401", privPath, "", http.StatusUnauthorized},
		{"private provider outsider -> 404", privPath, outsider.ID.String(), http.StatusNotFound},
		{"private provider member -> 200", privPath, member.ID.String(), http.StatusOK},
		{"public provider anon -> 200", pubPath, "", http.StatusOK},
		{"module anon -> 401", modPath, "", http.StatusUnauthorized},
		{"module outsider -> 404", modPath, outsider.ID.String(), http.StatusNotFound},
		{"module member -> 200", modPath, member.ID.String(), http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := do(tc.path, tc.user)
			if w.Code != tc.want {
				t.Fatalf("%s: got %d, want %d. Body: %s", tc.name, w.Code, tc.want, w.Body.String())
			}
		})
	}

	// List filtering: a namespaced list of org A shows the public provider to everyone but the
	// private one only to a member.
	listPath := fmt.Sprintf("/v1/providers/%s", orgA.Name)
	listHasPrivate := func(user string) bool {
		w := do(listPath, user)
		if w.Code != http.StatusOK {
			t.Fatalf("list got %d: %s", w.Code, w.Body.String())
		}
		var resp struct {
			Providers []struct {
				Name string `json:"name"`
			} `json:"providers"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("parse list: %v", err)
		}
		for _, p := range resp.Providers {
			if p.Name == privateProv.Name {
				return true
			}
		}
		return false
	}
	if listHasPrivate("") {
		t.Error("anonymous list leaked the private provider")
	}
	if listHasPrivate(outsider.ID.String()) {
		t.Error("outsider list leaked the private provider")
	}
	if !listHasPrivate(member.ID.String()) {
		t.Error("member list is missing their own private provider")
	}
}
