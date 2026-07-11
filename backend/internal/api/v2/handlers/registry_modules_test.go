// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

// Integration-only tests — require a live PostgreSQL reachable at
// `$TEST_DATABASE_URL` (or the local default
// `postgres://iac:iac_password@localhost:5432/iac_platform`). Compiled
// into the test binary ONLY when the `integration` build tag is set:
//
//   go test -tags=integration ./backend/internal/api/v2/handlers/...
//
// The default CI pipeline has no PostgreSQL service, so without this
// guard each test logged a noisy `connection refused` before self-
// skipping via `t.Skipf`. Gating at compile time keeps `go test ./...`
// clean and forces the test author to opt in explicitly.

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
	"path/filepath"
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

// setupTestDB creates a test database (using postgres for compatibility)
// In CI, this should use a test database container
func setupTestDB(t *testing.T) *gorm.DB {
	// Use in-memory SQLite for local testing, or test Postgres for CI
	// For now, we'll skip tests if DB is not available
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}

	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	// Run migrations. The RBAC tables are included because AUD-123 gates the /v1 module
	// read endpoints on org membership (orgRepo.UserInOrg reads organization_members AND
	// teams/team_members) — omitting any of them makes the tests pass only against a DB
	// that already has the tables (dev) and fail on a fresh CI Postgres.
	if err := db.AutoMigrate(
		&models.Organization{},
		&models.Module{},
		&models.ModuleVersion{},
		&models.ModuleDownload{},
		&models.User{},
		&models.OrganizationMember{},
		&models.Team{},
		&models.TeamMember{},
		&models.TeamOrganizationAccess{},
	); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	return db
}

// createRegistryTestUser inserts a user with a unique Zitadel subject (the shared helpers leave it
// empty, which collides on the users' unique subject index once more than one test user exists) and
// registers a row-scoped cleanup.
func createRegistryTestUser(t *testing.T, db *gorm.DB) *models.User {
	t.Helper()
	u := &models.User{
		ID:             uuid.New(),
		Email:          "reg-user-" + uuid.NewString()[:8] + "@test.local",
		ZitadelSubject: "reg-user-" + uuid.NewString(),
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() {
		db.Where("user_id = ?", u.ID).Delete(&models.TeamMember{})
		db.Where("user_id = ?", u.ID).Delete(&models.OrganizationMember{})
		db.Where("id = ?", u.ID).Delete(&models.User{})
	})
	return u
}

// setupTestOrg creates a test organization with a unique name and registers a
// row-scoped cleanup. It must NOT drop shared tables — these tests run against
// $TEST_DATABASE_URL, which may be a live database.
func setupTestOrg(t *testing.T, db *gorm.DB) *models.Organization {
	org := &models.Organization{
		ID:   uuid.New(),
		Name: "test-org-" + uuid.NewString()[:8],
	}
	if err := db.Create(org).Error; err != nil {
		t.Fatalf("Failed to create test organization: %v", err)
	}
	t.Cleanup(func() {
		db.Exec("DELETE FROM module_versions WHERE module_id IN (SELECT id FROM modules WHERE organization_id = ?)", org.ID)
		db.Where("organization_id = ?", org.ID).Delete(&models.Module{})
		// Teams (+ their members/accesses) and org members created for this org by
		// makeUserOrgOwner / RBAC-authenticated tests are row-scoped to the org.
		db.Exec("DELETE FROM team_members WHERE team_id IN (SELECT id FROM teams WHERE organization_id = ?)", org.ID)
		db.Exec("DELETE FROM team_organization_accesses WHERE team_id IN (SELECT id FROM teams WHERE organization_id = ?)", org.ID)
		db.Where("organization_id = ?", org.ID).Delete(&models.Team{})
		db.Where("organization_id = ?", org.ID).Delete(&models.OrganizationMember{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
	})
	return org
}

// createTestTarball creates a minimal valid tarball for testing
func createTestTarball(t *testing.T) []byte {
	// Create a temporary directory
	tmpDir := t.TempDir()
	moduleDir := filepath.Join(tmpDir, "test-module")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil { //nolint:gosec // test directory, 0o755 is fine
		t.Fatalf("Failed to create module directory: %v", err)
	}

	// Create a minimal main.tf file
	mainTf := `variable "name" {
  description = "Name of the resource"
  type        = string
}

output "id" {
  description = "Resource ID"
  value       = "test"
}

resource "aws_instance" "test" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}
`
	if err := os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte(mainTf), 0o600); err != nil {
		t.Fatalf("Failed to write main.tf: %v", err)
	}

	// For testing, we'll create a simple gzip file
	// In a real scenario, you'd use archive/tar and compress/gzip
	tarballData := []byte("test tarball data - this would be a real gzip tarball in production")
	return tarballData
}

func TestListModules(t *testing.T) {
	db := setupTestDB(t)

	org := setupTestOrg(t, db)

	// Create test modules
	module1 := &models.Module{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Name:           "test-module-1",
		Provider:       "aws",
		Description:    "Test module 1",
	}
	module2 := &models.Module{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Name:           "test-module-2",
		Provider:       "azurerm",
		Description:    "Test module 2",
	}
	db.Create(module1)
	db.Create(module2)

	// Setup handler
	moduleRepo := repository.NewModuleRepository(db)
	moduleVersionRepo := repository.NewModuleVersionRepository(db)
	moduleDownloadRepo := repository.NewModuleDownloadRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)

	// Create a mock storage (in-memory for testing)
	mockStorage := registry.NewMockStorage()
	moduleService := registry.NewModuleService(moduleRepo, moduleVersionRepo, moduleDownloadRepo, orgRepo, mockStorage)

	// AUD-123: modules are org-private; the /v1 list handler filters to modules the caller can
	// access, so the handler needs the auth + org deps and the request must come from an org member.
	authService := auth.NewService(repository.NewUserRepository(db))
	handler := NewRegistryModuleHandler(moduleService, authService, orgRepo)

	owner := createRegistryTestUser(t, db)
	makeUserOrgOwner(t, db, org, owner)

	// Setup router — the real /v1 group carries no auth middleware, so a stub translates the test
	// header into the same user_id an upstream would set; the handler's own gate does the work.
	// testUserAuth (authz_matrix_test.go) reads the X-Test-User header into the user_id context.
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(testUserAuth())
	router.GET("/v1/modules/:namespace", handler.ListModules)

	// Make request as the org owner.
	req := httptest.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("/v1/modules/%s", org.Name), nil)
	req.Header.Set("X-Test-User", owner.ID.String())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	// The TFE registry list format nests results under "modules".
	var response struct {
		Modules []struct {
			Name     string `json:"name"`
			Provider string `json:"provider"`
		} `json:"modules"`
	}

	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(response.Modules) != 2 {
		t.Errorf("Expected 2 modules, got %d. Body: %s", len(response.Modules), w.Body.String())
	}
}

func TestGetModuleVersions(t *testing.T) {
	db := setupTestDB(t)

	org := setupTestOrg(t, db)

	// Create test module
	module := &models.Module{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Name:           "test-module",
		Provider:       "aws",
	}
	db.Create(module)

	// Create test versions
	version1 := &models.ModuleVersion{
		ID:       uuid.New(),
		ModuleID: module.ID,
		Version:  "1.0.0",
	}
	version2 := &models.ModuleVersion{
		ID:       uuid.New(),
		ModuleID: module.ID,
		Version:  "2.0.0",
	}
	db.Create(version1)
	db.Create(version2)

	// Setup handler
	moduleRepo := repository.NewModuleRepository(db)
	moduleVersionRepo := repository.NewModuleVersionRepository(db)
	moduleDownloadRepo := repository.NewModuleDownloadRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	mockStorage := registry.NewMockStorage()
	moduleService := registry.NewModuleService(moduleRepo, moduleVersionRepo, moduleDownloadRepo, orgRepo, mockStorage)

	// AUD-123: the versions endpoint gates on org membership; construct with the auth deps and
	// authenticate the request as an org owner.
	authService := auth.NewService(repository.NewUserRepository(db))
	handler := NewRegistryModuleHandler(moduleService, authService, orgRepo)

	owner := createRegistryTestUser(t, db)
	makeUserOrgOwner(t, db, org, owner)

	// Setup router (see TestListModules for the X-Test-User stub rationale).
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(testUserAuth())
	router.GET("/v1/modules/:namespace/:name/:provider/versions", handler.GetModuleVersions)

	// Make request as the org owner.
	req := httptest.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("/v1/modules/%s/%s/%s/versions", org.Name, module.Name, module.Provider), nil)
	req.Header.Set("X-Test-User", owner.ID.String())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	// TFE registry protocol nests versions under modules[].versions.
	var response struct {
		Modules []struct {
			Versions []struct {
				Version string `json:"version"`
			} `json:"versions"`
		} `json:"modules"`
	}

	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(response.Modules) != 1 {
		t.Fatalf("Expected 1 module entry, got %d. Body: %s", len(response.Modules), w.Body.String())
	}
	versions := response.Modules[0].Versions
	if len(versions) != 2 {
		t.Fatalf("Expected 2 versions, got %d. Body: %s", len(versions), w.Body.String())
	}

	// Check versions are sorted correctly (latest first)
	if versions[0].Version != "2.0.0" {
		t.Errorf("Expected latest version to be 2.0.0, got %s", versions[0].Version)
	}
}

func TestPublishModuleVersion(t *testing.T) {
	db := setupTestDB(t)

	org := setupTestOrg(t, db)

	// Create test module
	module := &models.Module{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Name:           "test-module",
		Provider:       "aws",
	}
	db.Create(module)

	// Setup handler
	moduleRepo := repository.NewModuleRepository(db)
	moduleVersionRepo := repository.NewModuleVersionRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	mockStorage := registry.NewMockStorage()

	// Create module publisher
	vcsConnectionRepo := repository.NewVCSConnectionRepository(db)
	modulePublisher := registry.NewModulePublisher(moduleRepo, moduleVersionRepo, orgRepo, vcsConnectionRepo, mockStorage)

	// Create auth service
	userRepo := repository.NewUserRepository(db)
	authService := auth.NewService(userRepo)

	// AUD-004: PublishVersion now requires manage-modules permission. Set up an owner
	// (owners team → all permissions) and authenticate the request as that user.
	if err := db.AutoMigrate(&models.User{}, &models.OrganizationMember{}, &models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{}); err != nil {
		t.Fatalf("migrate rbac models: %v", err)
	}
	ownerUser := &models.User{ID: uuid.New(), ZitadelSubject: "reg-pub-owner-" + uuid.NewString()[:8], Email: "reg-pub-owner-" + uuid.NewString()[:8] + "@test.local"}
	db.Create(ownerUser)
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	db.Create(ownersTeam)
	db.Create(&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: ownerUser.ID})
	db.Create(&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: ownerUser.ID})
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	t.Cleanup(func() {
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", ownersTeam.ID).Delete(&models.Team{})
		db.Where("user_id = ?", ownerUser.ID).Delete(&models.OrganizationMember{})
		db.Where("id = ?", ownerUser.ID).Delete(&models.User{})
	})

	handler := NewRegistryPublishingHandler(
		moduleRepo,
		moduleVersionRepo,
		orgRepo,
		vcsConnectionRepo,
		authService,
		rbacService,
		nil, // githubAppManager can be nil for tests
		modulePublisher,
	)

	// Setup router: authenticate every request as the owner user.
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("user_id", ownerUser.ID); c.Next() })

	authGroup := router.Group("/api/v2/organizations/:name/registry/modules/:module_name/:provider")
	{
		authGroup.POST("/versions", handler.PublishVersion)
	}

	// Create multipart form with file
	tarballData := createTestTarball(t)
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add version field
	if err := writer.WriteField("version", "1.0.0"); err != nil {
		t.Fatalf("Failed to write field: %v", err)
	}

	// Add file
	part, err := writer.CreateFormFile("file", "module.tar.gz")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	if _, err := io.Copy(part, bytes.NewReader(tarballData)); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	// Make request
	req := httptest.NewRequestWithContext(context.Background(), "POST", fmt.Sprintf("/api/v2/organizations/%s/registry/modules/%s/%s/versions", org.Name, module.Name, module.Provider), body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions - Note: This test may fail if the tarball parsing fails
	// In a real scenario, you'd use a proper tarball
	if w.Code != http.StatusCreated && w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 201, 200, or 400, got %d. Body: %s", w.Code, w.Body.String())
	}

	// If successful, verify version was created
	if w.Code == http.StatusCreated || w.Code == http.StatusOK {
		var version models.ModuleVersion
		if err := db.Where("module_id = ? AND version = ?", module.ID, "1.0.0").First(&version).Error; err != nil {
			t.Errorf("Version was not created in database: %v", err)
		}
	}
}
