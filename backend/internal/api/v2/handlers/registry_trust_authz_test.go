// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-103 registry trust-plane authorization matrix. The GPG-key and provider
// handlers authenticated (some not even that) but never checked org membership or
// the manage-providers role, so any authenticated user could register/enumerate/
// delete any org's GPG trust anchors and create/publish providers under any org's
// namespace. These tests drive the real handlers + real rbac.Service + real Postgres
// and assert the deny matrix: anonymous → 401, cross-tenant outsider and plain
// member (no manage role) → 403 on mutations, membership enforced on reads. The
// owner-allowed mutation paths are covered by TestCreateRegistryProvider and
// TestPublishProviderPlatform (both now owner-scoped).
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is
// strictly row-scoped (the DB may be live).

//go:build integration
// +build integration

package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

type registryTrustFixture struct {
	router   *gin.Engine
	orgAName string
	keyID    string
	provName string
	owner    *models.User // orgA owners team (manage)
	member   *models.User // orgA member, no manage role
	outsider *models.User // orgB only
}

func setupRegistryTrustAuthz(t *testing.T) *registryTrustFixture {
	t.Helper()
	db := setupTestDBForProvider(t) // shares migrations (orgs/users/teams/providers/gpg_keys)

	sfx := uuid.NewString()[:8]
	orgA := &models.Organization{ID: uuid.New(), Name: "regtrust-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "regtrust-b-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "rt-own-" + sfx, Email: "rt-own-" + sfx + "@test.local"}
	member := &models.User{ID: uuid.New(), ZitadelSubject: "rt-mem-" + sfx, Email: "rt-mem-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "rt-out-" + sfx, Email: "rt-out-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	gpgKey := &models.GPGKey{OrganizationID: orgA.ID, KeyID: "ABCD1234" + sfx, ASCIIArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\ndummy\n-----END PGP PUBLIC KEY BLOCK-----", CreatedBy: owner.ID}
	provider := &models.Provider{ID: uuid.New(), OrganizationID: orgA.ID, Name: "prov-" + sfx, RegistryName: "private", Namespace: orgA.Name}

	// Register cleanup before seeding so a partial seed failure still self-cleans.
	t.Cleanup(func() {
		db.Where("organization_id = ?", orgA.ID).Delete(&models.Provider{})
		db.Where("organization_id = ?", orgA.ID).Delete(&models.GPGKey{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", ownersTeam.ID).Delete(&models.Team{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{owner.ID, member.ID, outsider.ID}).Delete(&models.User{})
	})

	seed := []interface{}{
		orgA, orgB, owner, member, outsider, ownersTeam, gpgKey, provider,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: member.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}

	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := newProviderRBAC(db)

	gpgH := NewGPGKeyHandler(repository.NewGPGKeyRepository(db), orgRepo, authService, rbacService)
	provH := NewRegistryProviderResourceHandler(repository.NewProviderRepository(db), orgRepo, authService, rbacService, nil)
	pubH := NewRegistryProviderPublishingHandler(
		repository.NewProviderRepository(db), repository.NewProviderVersionRepository(db),
		repository.NewProviderPlatformRepository(db), orgRepo, repository.NewGPGKeyRepository(db),
		authService, rbacService, nil,
	)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if v := c.GetHeader("X-Test-User"); v != "" {
			if id, err := uuid.Parse(v); err == nil {
				c.Set("user_id", id)
			}
		}
		c.Next()
	})
	router.POST("/api/registry/:registry/v2/gpg-keys", gpgH.CreateGPGKey)
	router.GET("/api/registry/:registry/v2/gpg-keys", gpgH.ListGPGKeys)
	router.DELETE("/api/registry/:registry/v2/gpg-keys/:namespace/:key_id", gpgH.DeleteGPGKey)
	router.POST("/api/v2/organizations/:name/registry-providers", provH.CreateProvider)
	router.GET("/api/v2/organizations/:name/registry-providers", provH.ListProviders)
	router.POST("/api/v2/organizations/:name/registry-providers/:registry_name/:namespace/:provider_name/versions/:version/platforms", pubH.PublishProviderPlatform)

	return &registryTrustFixture{
		router: router, orgAName: orgA.Name, keyID: gpgKey.KeyID, provName: provider.Name,
		owner: owner, member: member, outsider: outsider,
	}
}

func rtReq(t *testing.T, f *registryTrustFixture, method, path, body string, asUser uuid.UUID) int {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec.Code
}

// TestRegistryTrustAuthz_MutationsDenied is the core AUD-103 assertion: anonymous,
// cross-tenant, and non-manage callers cannot mutate the registry trust plane.
func TestRegistryTrustAuthz_MutationsDenied(t *testing.T) {
	f := setupRegistryTrustAuthz(t)
	gpgBody := `{"data":{"type":"gpg-keys","attributes":{"namespace":"` + f.orgAName + `","ascii-armor":"x"}}}`
	provBody := `{"data":{"type":"registry-providers","attributes":{"name":"pwn","registry-name":"private"}}}`
	delKey := "/api/registry/private/v2/gpg-keys/" + f.orgAName + "/" + f.keyID
	pubPath := "/api/v2/organizations/" + f.orgAName + "/registry-providers/private/" + f.orgAName + "/" + f.provName + "/versions/1.0.0/platforms"

	muts := []struct {
		name, method, path, body string
	}{
		{"CreateGPGKey", http.MethodPost, "/api/registry/private/v2/gpg-keys", gpgBody},
		{"DeleteGPGKey", http.MethodDelete, delKey, ""},
		{"CreateProvider", http.MethodPost, "/api/v2/organizations/" + f.orgAName + "/registry-providers", provBody},
		{"PublishProvider", http.MethodPost, pubPath, ""},
	}
	for _, m := range muts {
		t.Run("anon "+m.name, func(t *testing.T) {
			if code := rtReq(t, f, m.method, m.path, m.body, uuid.Nil); code != http.StatusUnauthorized {
				t.Fatalf("anon %s = %d, want 401", m.name, code)
			}
		})
		t.Run("outsider "+m.name, func(t *testing.T) {
			if code := rtReq(t, f, m.method, m.path, m.body, f.outsider.ID); code != http.StatusForbidden {
				t.Fatalf("outsider %s = %d, want 403", m.name, code)
			}
		})
		t.Run("member "+m.name, func(t *testing.T) {
			if code := rtReq(t, f, m.method, m.path, m.body, f.member.ID); code != http.StatusForbidden {
				t.Fatalf("plain member %s = %d, want 403 (manage required)", m.name, code)
			}
		})
	}
}

// TestRegistryTrustAuthz_ReadsRequireMembership asserts reads are gated on org
// membership: a member reads, an outsider is denied provider reads, and the GPG
// list discloses keys only for orgs the caller belongs to.
func TestRegistryTrustAuthz_ReadsRequireMembership(t *testing.T) {
	f := setupRegistryTrustAuthz(t)
	listProviders := "/api/v2/organizations/" + f.orgAName + "/registry-providers"
	listGPG := "/api/registry/private/v2/gpg-keys?filter%5Bnamespace%5D=" + f.orgAName

	if code := rtReq(t, f, http.MethodGet, listProviders, "", uuid.Nil); code != http.StatusUnauthorized {
		t.Fatalf("anon ListProviders = %d, want 401", code)
	}
	if code := rtReq(t, f, http.MethodGet, listProviders, "", f.outsider.ID); code != http.StatusForbidden {
		t.Fatalf("outsider ListProviders = %d, want 403", code)
	}
	if code := rtReq(t, f, http.MethodGet, listProviders, "", f.member.ID); code != http.StatusOK {
		t.Fatalf("member ListProviders = %d, want 200", code)
	}
	// GPG list: anon denied; member allowed (its own org).
	if code := rtReq(t, f, http.MethodGet, listGPG, "", uuid.Nil); code != http.StatusUnauthorized {
		t.Fatalf("anon ListGPGKeys = %d, want 401", code)
	}
	if code := rtReq(t, f, http.MethodGet, listGPG, "", f.member.ID); code != http.StatusOK {
		t.Fatalf("member ListGPGKeys = %d, want 200", code)
	}
}
