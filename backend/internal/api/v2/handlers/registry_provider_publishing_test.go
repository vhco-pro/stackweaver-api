// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

// Integration-only tests — require a live PostgreSQL reachable at
// `$TEST_DATABASE_URL` (or the local default
// `postgres://iac:iac_password@localhost:5432/iac_platform`). Compiled
// into the test binary ONLY when the `integration` build tag is set:
//
//	go test -tags=integration ./backend/internal/api/v2/handlers/...
//
// Companion to `registry_modules_test.go`. See that file for the
// rationale on why DB-needing tests are gated rather than left to
// `t.Skipf` at runtime.

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func setupTestDBForProvider(t *testing.T) *gorm.DB {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://iac:iac_password@localhost:5432/iac_platform?sslmode=disable" //nolint:gosec // G101: test database URL, not a production credential
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Skipf("Failed to connect to test database (set TEST_DATABASE_URL or ensure local DB is running): %v", err)
	}
	if err := db.AutoMigrate(
		&models.Organization{},
		&models.User{},
		&models.Team{},
		&models.TeamMember{},
		&models.TeamOrganizationAccess{},
		&models.Project{},
		&models.Provider{},
		&models.ProviderVersion{},
		&models.ProviderPlatform{},
		&models.ProviderDownload{},
		&models.GPGKey{},
	); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}
	return db
}

// makeUserOrgOwner puts the user in the org's "owners" team so that
// CheckOrgManageProviders (owners-team shortcut) authorizes registry mutations.
// Returns the team id for cleanup.
func makeUserOrgOwner(t *testing.T, db *gorm.DB, org *models.Organization, user *models.User) uuid.UUID {
	t.Helper()
	team := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	if err := db.Create(team).Error; err != nil {
		t.Fatalf("create owners team: %v", err)
	}
	if err := db.Create(&models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: user.ID}).Error; err != nil {
		t.Fatalf("create team member: %v", err)
	}
	return team.ID
}

// newProviderRBAC builds an rbac.Service wired to the test DB.
func newProviderRBAC(db *gorm.DB) *rbac.Service {
	return rbac.NewServiceWithTeams(
		repository.NewOrganizationRepository(db),
		repository.NewTeamRepository(db),
		repository.NewProjectRepository(db),
	)
}

func setupTestOrgForProvider(t *testing.T, db *gorm.DB) *models.Organization {
	org := &models.Organization{ID: uuid.New(), Name: fmt.Sprintf("test-org-%s", uuid.New().String()[:8])}
	if err := db.Create(org).Error; err != nil {
		t.Fatalf("Failed to create test organization: %v", err)
	}
	return org
}

func setupTestUserForProvider(t *testing.T, db *gorm.DB) *models.User {
	user := &models.User{ID: uuid.New(), Email: fmt.Sprintf("test-%s@example.com", uuid.New().String()[:8])}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	return user
}

// cleanupProviderTables removes only this test's rows. Every delete is scoped to
// the test org — these tests run against $TEST_DATABASE_URL, which in dev points
// at the live app database, so an unscoped `DELETE FROM providers` would wipe real
// registry data. Deletes bottom-up through the provider → version → platform →
// download FK chain, then the org-scoped providers/gpg_keys, then the org + user.
func cleanupProviderTables(db *gorm.DB, org *models.Organization, user *models.User) {
	db.Exec(`DELETE FROM provider_downloads WHERE provider_platform_id IN (
		SELECT pp.id FROM provider_platforms pp
		JOIN provider_versions pv ON pv.id = pp.provider_version_id
		JOIN providers p ON p.id = pv.provider_id WHERE p.organization_id = ?)`, org.ID)
	db.Exec(`DELETE FROM provider_platforms WHERE provider_version_id IN (
		SELECT pv.id FROM provider_versions pv
		JOIN providers p ON p.id = pv.provider_id WHERE p.organization_id = ?)`, org.ID)
	db.Exec(`DELETE FROM provider_versions WHERE provider_id IN (
		SELECT id FROM providers WHERE organization_id = ?)`, org.ID)
	db.Exec("DELETE FROM providers WHERE organization_id = ?", org.ID)
	db.Exec("DELETE FROM gpg_keys WHERE organization_id = ?", org.ID)
	db.Exec("DELETE FROM team_members WHERE team_id IN (SELECT id FROM teams WHERE organization_id = ?)", org.ID)
	db.Exec("DELETE FROM team_organization_accesses WHERE team_id IN (SELECT id FROM teams WHERE organization_id = ?)", org.ID)
	db.Exec("DELETE FROM teams WHERE organization_id = ?", org.ID)
	db.Exec("DELETE FROM organizations WHERE id = ?", org.ID)
	db.Exec("DELETE FROM users WHERE id = ?", user.ID)
}

// TestCreateRegistryProvider exercises the go-tfe tfe_registry_provider create surface: a JSON:API
// body with a kebab-case registry-name, and a response whose attributes are kebab-case with the
// namespace defaulted to the organization for a private provider.
func TestCreateRegistryProvider(t *testing.T) {
	db := setupTestDBForProvider(t)
	org := setupTestOrgForProvider(t, db)
	user := setupTestUserForProvider(t, db)
	makeUserOrgOwner(t, db, org, user)
	defer cleanupProviderTables(db, org, user)

	providerRepo := repository.NewProviderRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	handler := NewRegistryProviderResourceHandler(providerRepo, orgRepo, authService, newProviderRBAC(db), registry.NewMockStorage())

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("user_id", user.ID); c.Next() })
	router.POST("/api/v2/organizations/:name/registry-providers", handler.CreateProvider)

	reqBody := map[string]any{
		"data": map[string]any{
			"type": "registry-providers",
			"attributes": map[string]any{
				"name":          "test-provider",
				"registry-name": "private",
			},
		},
	}
	bodyBytes, _ := json.Marshal(reqBody) //nolint:errchkjson // test helper
	req := httptest.NewRequestWithContext(context.Background(), "POST",
		fmt.Sprintf("/api/v2/organizations/%s/registry-providers", org.Name), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d. Body: %s", w.Code, w.Body.String())
	}
	var response struct {
		Data struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				Name         string `json:"name"`
				Namespace    string `json:"namespace"`
				RegistryName string `json:"registry-name"`
				CreatedAt    string `json:"created-at"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if response.Data.Type != "registry-providers" {
		t.Errorf("type = %q, want registry-providers", response.Data.Type)
	}
	if response.Data.Attributes.Name != "test-provider" {
		t.Errorf("name = %q, want test-provider", response.Data.Attributes.Name)
	}
	if response.Data.Attributes.RegistryName != "private" {
		t.Errorf("registry-name = %q, want private", response.Data.Attributes.RegistryName)
	}
	if response.Data.Attributes.Namespace != org.Name {
		t.Errorf("namespace = %q, want the org name %q (private provider)", response.Data.Attributes.Namespace, org.Name)
	}
	if response.Data.Attributes.CreatedAt == "" {
		t.Error("created-at is empty (kebab-case attribute missing)")
	}
}

// TestPublishProviderPlatform publishes a signed platform under the composite provider address and
// asserts the version records the publisher-provided SHA256SUMS + signature paths and signing key.
func TestPublishProviderPlatform(t *testing.T) {
	db := setupTestDBForProvider(t)
	org := setupTestOrgForProvider(t, db)
	user := setupTestUserForProvider(t, db)
	makeUserOrgOwner(t, db, org, user)
	defer cleanupProviderTables(db, org, user)

	provider := &models.Provider{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Name:           "test-provider",
		RegistryName:   "private",
		Namespace:      org.Name,
	}
	if err := db.Create(provider).Error; err != nil {
		t.Fatalf("Failed to create test provider: %v", err)
	}
	// A GPG key must exist for the org; the publish endpoint only checks existence (the publisher
	// signs offline, so the armor/sig contents are not verified server-side).
	gpgKey := &models.GPGKey{OrganizationID: org.ID, KeyID: "ABCD1234", ASCIIArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\ndummy\n-----END PGP PUBLIC KEY BLOCK-----", CreatedBy: user.ID}
	if err := db.Create(gpgKey).Error; err != nil {
		t.Fatalf("Failed to create test gpg key: %v", err)
	}

	handler := NewRegistryProviderPublishingHandler(
		repository.NewProviderRepository(db),
		repository.NewProviderVersionRepository(db),
		repository.NewProviderPlatformRepository(db),
		repository.NewOrganizationRepository(db),
		repository.NewGPGKeyRepository(db),
		auth.NewService(repository.NewUserRepository(db)),
		newProviderRBAC(db),
		registry.NewMockStorage(),
	)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("user_id", user.ID); c.Next() })
	router.POST("/api/v2/organizations/:name/registry-providers/:registry_name/:namespace/:provider_name/versions/:version/platforms", handler.PublishProviderPlatform)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for k, v := range map[string]string{"os": "linux", "arch": "amd64", "key_id": gpgKey.KeyID, "protocols": "5.0"} {
		if err := writer.WriteField(k, v); err != nil {
			t.Fatalf("write field: %v", err)
		}
	}
	writeFile := func(field, filename string, data []byte) {
		part, err := writer.CreateFormFile(field, filename)
		if err != nil {
			t.Fatalf("create form file %s: %v", field, err)
		}
		if _, err := io.Copy(part, bytes.NewReader(data)); err != nil {
			t.Fatalf("write file %s: %v", field, err)
		}
	}
	writeFile("file", "terraform-provider-test_1.0.0_linux_amd64.zip", []byte("dummy provider zip"))
	writeFile("shasums", "SHA256SUMS", []byte("abc123  terraform-provider-test_1.0.0_linux_amd64.zip\n"))
	writeFile("shasums_sig", "SHA256SUMS.sig", []byte("dummy detached signature bytes"))
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	url := fmt.Sprintf("/api/v2/organizations/%s/registry-providers/private/%s/%s/versions/1.0.0/platforms", org.Name, org.Name, provider.Name)
	req := httptest.NewRequestWithContext(context.Background(), "POST", url, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d. Body: %s", w.Code, w.Body.String())
	}

	var version models.ProviderVersion
	if err := db.Where("provider_id = ? AND version = ?", provider.ID, "1.0.0").First(&version).Error; err != nil {
		t.Fatalf("Version was not created: %v", err)
	}
	if version.KeyID != gpgKey.KeyID {
		t.Errorf("version key_id = %q, want %q", version.KeyID, gpgKey.KeyID)
	}
	if version.ShasumsPath == "" || version.ShasumsSigPath == "" {
		t.Errorf("version SHA256SUMS paths not recorded: %q / %q", version.ShasumsPath, version.ShasumsSigPath)
	}
	var platform models.ProviderPlatform
	if err := db.Where("provider_version_id = ? AND os = ? AND arch = ?", version.ID, "linux", "amd64").First(&platform).Error; err != nil {
		t.Errorf("Platform was not created: %v", err)
	}
	if platform.Shasum == "" {
		t.Error("platform shasum was not computed")
	}
}

// TestPublishProviderPlatform_RejectsPathInjection is the AUD-107 assertion: os/arch
// and the upload filename become object-storage path segments, so values that could
// escape the providers/<org>/… prefix must be rejected with 422 before anything is
// written.
func TestPublishProviderPlatform_RejectsPathInjection(t *testing.T) {
	db := setupTestDBForProvider(t)
	org := setupTestOrgForProvider(t, db)
	user := setupTestUserForProvider(t, db)
	makeUserOrgOwner(t, db, org, user)
	defer cleanupProviderTables(db, org, user)

	provider := &models.Provider{ID: uuid.New(), OrganizationID: org.ID, Name: "test-provider", RegistryName: "private", Namespace: org.Name}
	if err := db.Create(provider).Error; err != nil {
		t.Fatalf("create provider: %v", err)
	}
	gpgKey := &models.GPGKey{OrganizationID: org.ID, KeyID: "ABCD1234", ASCIIArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\ndummy\n-----END PGP PUBLIC KEY BLOCK-----", CreatedBy: user.ID}
	if err := db.Create(gpgKey).Error; err != nil {
		t.Fatalf("create gpg key: %v", err)
	}

	mockStore := registry.NewMockStorage()
	handler := NewRegistryProviderPublishingHandler(
		repository.NewProviderRepository(db), repository.NewProviderVersionRepository(db),
		repository.NewProviderPlatformRepository(db), repository.NewOrganizationRepository(db),
		repository.NewGPGKeyRepository(db), auth.NewService(repository.NewUserRepository(db)),
		newProviderRBAC(db), mockStore,
	)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("user_id", user.ID); c.Next() })
	router.POST("/api/v2/organizations/:name/registry-providers/:registry_name/:namespace/:provider_name/versions/:version/platforms", handler.PublishProviderPlatform)

	// os/arch come from PostForm and are NOT sanitized by the stdlib, so traversal there
	// is the real injectable vector. The multipart filename is already reduced to its base
	// by Go's mime/multipart before the handler sees it, so it can't carry separators — but
	// the handler's charset allowlist still rejects a filename with disallowed characters
	// (and embedded `..`) as defense in depth.
	cases := []struct{ name, os, arch, filename string }{
		{"arch traversal", "linux", "../../other-org", "p.zip"},
		{"os traversal", "../../etc", "amd64", "p.zip"},
		{"arch separator", "linux", "amd64/sub", "p.zip"},
		{"arch uppercase", "linux", "AMD64", "p.zip"},
		{"filename bad char", "linux", "amd64", "evil;rm.zip"},
		{"filename embedded traversal", "linux", "amd64", "evil..zip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)
			for k, v := range map[string]string{"os": tc.os, "arch": tc.arch, "key_id": gpgKey.KeyID} {
				if err := writer.WriteField(k, v); err != nil {
					t.Fatalf("write field: %v", err)
				}
			}
			part, err := writer.CreateFormFile("file", tc.filename)
			if err != nil {
				t.Fatalf("create form file: %v", err)
			}
			if _, err := io.Copy(part, bytes.NewReader([]byte("dummy"))); err != nil {
				t.Fatalf("copy: %v", err)
			}
			// shasums/shasums_sig use fixed server-side names; include them so the only
			// rejection reason is the injected os/arch/filename.
			for _, f := range []struct{ field, fn string }{{"shasums", "SHA256SUMS"}, {"shasums_sig", "SHA256SUMS.sig"}} {
				p, err := writer.CreateFormFile(f.field, f.fn)
				if err != nil {
					t.Fatalf("create %s: %v", f.field, err)
				}
				if _, err := io.Copy(p, bytes.NewReader([]byte("x"))); err != nil {
					t.Fatalf("copy %s: %v", f.field, err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("close writer: %v", err)
			}

			url := fmt.Sprintf("/api/v2/organizations/%s/registry-providers/private/%s/%s/versions/1.0.0/platforms", org.Name, org.Name, provider.Name)
			req := httptest.NewRequestWithContext(context.Background(), "POST", url, body)
			req.Header.Set("Content-Type", writer.FormDataContentType())
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("%s: got %d, want 422. Body: %s", tc.name, w.Code, w.Body.String())
			}
		})
	}

	// Nothing should have been written to storage under a traversal key.
	objs, err := mockStore.List(context.Background(), "")
	if err != nil {
		t.Fatalf("list storage: %v", err)
	}
	for _, obj := range objs {
		if strings.Contains(obj.Key, "..") || strings.Contains(obj.Key, "other-org") {
			t.Fatalf("storage key escaped the prefix: %q", obj.Key)
		}
	}
}
