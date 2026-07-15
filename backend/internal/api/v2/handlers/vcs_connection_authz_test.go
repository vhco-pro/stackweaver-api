// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-138 VCS-connection read authorization matrix. The repository/branch/
// file-content read endpoints (and Get metadata) performed NO membership check,
// so any authenticated caller — including JWT identities, which bypass the org
// wall — could enumerate/read another tenant's private source through the victim
// org's decrypted VCS token by connection id. These tests drive the real handler
// + real rbac.Service + real Postgres and assert cross-tenant and unauthenticated
// callers are denied while a legitimate org member is allowed.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is
// strictly row-scoped. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestVCSConnectionAuthz

//go:build integration
// +build integration

package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type vcsConnAuthzFixture struct {
	router   *gin.Engine
	connID   uuid.UUID
	member   *models.User // org A member
	outsider *models.User // org B only
}

func setupVCSConnAuthzFixture(t *testing.T) *vcsConnAuthzFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.OrganizationMember{},
		&models.Team{}, &models.TeamMember{}, &models.VCSConnection{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "vcsauthz-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "vcsauthz-b-" + sfx}
	member := &models.User{ID: uuid.New(), ZitadelSubject: "vcs-mem-" + sfx, Email: "vcs-mem-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "vcs-out-" + sfx, Email: "vcs-out-" + sfx + "@test.local"}
	conn := &models.VCSConnection{
		ID: uuid.New(), OrganizationID: orgA.ID, Provider: models.VCSProviderGitHub,
		AccessToken: "secret-token", AccountName: "acme", AccountType: "organization",
	}
	seed := []interface{}{
		orgA, orgB, member, outsider, conn,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: member.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		db.Where("id = ?", conn.ID).Delete(&models.VCSConnection{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{member.ID, outsider.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	// vcsRegistry is nil: the denial paths return at the membership gate (inside
	// getProvider / Get) before any provider is resolved, and the happy path here
	// only exercises Get (metadata), which never calls getProvider.
	h := NewVCSConnectionHandlerV2(repository.NewVCSConnectionRepository(db), orgRepo, authService, nil, rbacService)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(testUserAuth())
	router.GET("/vcs-connections/:id", h.Get)
	router.GET("/vcs-connections/:id/repositories", h.ListRepositories)

	return &vcsConnAuthzFixture{router: router, connID: conn.ID, member: member, outsider: outsider}
}

func vcsConnReq(t *testing.T, f *vcsConnAuthzFixture, path string, asUser uuid.UUID) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec.Code
}

// TestVCSConnectionAuthz_CrossTenantDenied is the core AUD-138 assertion: an
// org-B outsider must not reach org-A's connection metadata or its provider-backed
// repository listing, and anonymous callers get 401.
func TestVCSConnectionAuthz_CrossTenantDenied(t *testing.T) {
	f := setupVCSConnAuthzFixture(t)
	base := "/vcs-connections/" + f.connID.String()

	for _, p := range []string{base, base + "/repositories"} {
		t.Run("outsider "+p, func(t *testing.T) {
			if code := vcsConnReq(t, f, p, f.outsider.ID); code != http.StatusForbidden {
				t.Fatalf("outsider GET %s = %d, want 403", p, code)
			}
		})
		t.Run("anon "+p, func(t *testing.T) {
			if code := vcsConnReq(t, f, p, uuid.Nil); code != http.StatusUnauthorized {
				t.Fatalf("anon GET %s = %d, want 401", p, code)
			}
		})
	}
}

// TestVCSConnectionAuthz_MemberAllowed confirms a legitimate org member still reads
// the connection metadata — the gate must not break the happy path.
func TestVCSConnectionAuthz_MemberAllowed(t *testing.T) {
	f := setupVCSConnAuthzFixture(t)
	if code := vcsConnReq(t, f, "/vcs-connections/"+f.connID.String(), f.member.ID); code != http.StatusOK {
		t.Fatalf("member GET connection = %d, want 200", code)
	}
}
