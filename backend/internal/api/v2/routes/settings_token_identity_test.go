// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// /api/v2/settings is the account surface behind the SPA's settings pages: the signed-in
// person's profile, password, second factor, sessions and API keys. It is mounted on the root
// router by routes.SetupRoutes, outside the walled /api/v2 group, and the org wall exempts it by
// prefix as a "JWT-only surface". Nothing enforced that. AuthMiddleware resolves a `tfe-` token
// to its OWNER and the handlers then act on that owner, so a token reached the surface with its
// owner's full authority and none of its own limits.
//
// The consequence that matters: a key bound read-only to organization A could POST
// /api/v2/settings/api-keys and be handed a new key with admin scope on organization B, because
// apikey.Service.CreateAPIKey validates the requested scopes against the owner's memberships
// and never sees the key that asked. That walks straight around the single-org token model.
//
// This test drives the real router (routes.SetupRoutes through buildHarnessRouter) with real
// keys, so it proves the guard is wired onto the group rather than merely that it exists. The
// middleware's own unit test covers the half this cannot reach without a Zitadel-signed JWT:
// that an interactive caller passes untouched.

//go:build integration

package routes_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const settingsPrefix = "/api/v2/settings/"

type settingsGuardFixture struct {
	router *gin.Engine
	db     *gorm.DB
	owner  *models.User
	orgA   *models.Organization
	orgB   *models.Organization
	// tokens are the identities under test, by a name that reads well in a subtest path.
	tokens map[string]string
	// victimKeyID is a second key the owner holds, bound to org B. It is the target of the
	// delete route, so a denied request that deleted it anyway is visible.
	victimKeyID uuid.UUID
	// mintPrefix is unique to this run; every key the create route is asked for carries it.
	mintPrefix string
	bio        string
}

// setupSettingsGuard seeds the shape the escalation needs: one person who belongs to two
// organizations, holding a key that is bound read-only to the first.
func setupSettingsGuard(t *testing.T) *settingsGuardFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	// SetupV2Routes initialises the OIDC signing key and refuses an absent one.
	t.Setenv("DEV_INSECURE_KEY", "1")

	db, err := dbtest.Open(t, dbURL, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.OrganizationMember{},
		&models.Team{}, &models.TeamMember{}, &models.Project{},
		&models.APIKey{}, &models.AuditLog{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	sfx := uuid.NewString()[:8]
	f := &settingsGuardFixture{
		db:         db,
		owner:      &models.User{ID: uuid.New(), ZitadelSubject: "settingsguard-" + sfx, Email: "settingsguard-" + sfx + "@test.local", Bio: "original bio " + sfx},
		orgA:       &models.Organization{ID: uuid.New(), Name: "settingsguard-a-" + sfx},
		orgB:       &models.Organization{ID: uuid.New(), Name: "settingsguard-b-" + sfx},
		mintPrefix: "settingsguard-minted-" + sfx,
	}
	f.bio = f.owner.Bio
	seed := []any{
		f.owner, f.orgA, f.orgB,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.orgA.ID, UserID: f.owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.orgB.ID, UserID: f.owner.ID},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		// Row-scoped only: TEST_DATABASE_URL can point at a database with no backup. Every
		// statement is keyed on an id this test generated.
		db.Where("user_id = ?", f.owner.ID).Delete(&models.AuditLog{})
		db.Where("user_id = ?", f.owner.ID).Delete(&models.APIKey{})
		db.Where("user_id = ?", f.owner.ID).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{f.orgA.ID, f.orgB.ID}).Delete(&models.Organization{})
		db.Where("id = ?", f.owner.ID).Delete(&models.User{})
	})

	apiKeyService := apikey.NewService(
		repository.NewAPIKeyRepository(db),
		repository.NewOrganizationRepository(db),
		repository.NewProjectRepository(db),
		repository.NewTeamRepository(db),
	)
	_, readKeyA, err := apiKeyService.CreateAPIKey(f.owner.ID, "settingsguard-read-a-"+sfx, []string{"org:" + f.orgA.ID.String() + ":read"}, nil)
	if err != nil {
		t.Fatalf("mint the org-A read-only key: %v", err)
	}
	_, userToken, err := apiKeyService.CreateUserToken(f.owner.ID, "settingsguard-user-"+sfx, nil)
	if err != nil {
		t.Fatalf("mint the user token: %v", err)
	}
	victim, _, err := apiKeyService.CreateAPIKey(f.owner.ID, "settingsguard-victim-"+sfx, []string{"org:" + f.orgB.ID.String() + ":read"}, nil)
	if err != nil {
		t.Fatalf("mint the victim key: %v", err)
	}
	f.victimKeyID = victim.ID
	f.tokens = map[string]string{
		"org-bound read-only key": readKeyA,
		"user-bound token":        userToken,
	}

	// Real auth, as in the golden harness: `tfe-` tokens are verified against the database with
	// no Zitadel involvement, so the request runs the middleware chain production runs.
	authService := auth.NewService(repository.NewUserRepository(db))
	authService.SetAPIKeyService(apiKeyService)

	gin.SetMode(gin.TestMode)
	f.router = buildHarnessRouter(t, db, authService, identityFromEnv())
	return f
}

// settingsRoutes lists the registered settings routes, so a route added to the group later is
// covered without anyone remembering to extend this test.
func (f *settingsGuardFixture) settingsRoutes(t *testing.T) gin.RoutesInfo {
	t.Helper()
	var out gin.RoutesInfo
	for _, rt := range f.router.Routes() {
		if strings.HasPrefix(rt.Path, settingsPrefix) {
			out = append(out, rt)
		}
	}
	// The key and profile routes register unconditionally. Without them the loop below would
	// pass by asserting nothing.
	for _, want := range []string{"POST " + settingsPrefix + "api-keys", "PATCH " + settingsPrefix + "profile"} {
		found := false
		for _, rt := range out {
			if rt.Method+" "+rt.Path == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s is not registered; the settings group moved and this test no longer covers it", want)
		}
	}
	return out
}

// body returns a request body the handler would accept, so a request that got past the guard
// would go on to do its work rather than stop at validation and look denied.
func (f *settingsGuardFixture) body(t *testing.T, route, identity string) []byte {
	t.Helper()
	var v any = map[string]any{}
	switch route {
	case "POST " + settingsPrefix + "api-keys":
		v = map[string]any{
			"name":   f.mintPrefix + " " + identity,
			"scopes": []string{"org:" + f.orgB.ID.String() + ":admin"},
		}
	case "PATCH " + settingsPrefix + "profile":
		v = map[string]any{"bio": "rewritten through a token"}
	case "POST " + settingsPrefix + "2fa/verify":
		v = map[string]any{"code": "000000"}
	case "POST " + settingsPrefix + "password":
		v = map[string]any{"current_password": "not-the-password", "new_password": "not-a-password-either"}
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal body for %s: %v", route, err)
	}
	return b
}

func (f *settingsGuardFixture) do(method, path, token string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func TestSettings_TokenIdentitiesAreRefused(t *testing.T) {
	f := setupSettingsGuard(t)
	routes := f.settingsRoutes(t)

	for identity, token := range f.tokens {
		for _, rt := range routes {
			route := rt.Method + " " + rt.Path
			t.Run(identity+"/"+route, func(t *testing.T) {
				path := strings.NewReplacer(
					":id", f.victimKeyID.String(),
					":sessionId", "settingsguard-session",
				).Replace(rt.Path)

				// assertRefused lives beside the user-token tests, which share it.
				assertRefused(t, f.do(rt.Method, path, token, f.body(t, route, identity)))
			})
		}
	}

	// A 403 that still did the work would be no fix at all, so the three writes are checked
	// against the database rather than inferred from the status.
	var minted []models.APIKey
	if err := f.db.Where("user_id = ? AND name LIKE ?", f.owner.ID, f.mintPrefix+"%").Find(&minted).Error; err != nil {
		t.Fatalf("look for minted keys: %v", err)
	}
	for _, k := range minted {
		t.Errorf("a token minted key %q bound to organization %v with scopes %v", k.Name, k.OrganizationID, []string(k.Scopes))
	}

	var victims int64
	if err := f.db.Model(&models.APIKey{}).Where("id = ?", f.victimKeyID).Count(&victims).Error; err != nil {
		t.Fatalf("look for the victim key: %v", err)
	}
	if victims != 1 {
		t.Errorf("a token deleted another of its owner's keys")
	}

	var owner models.User
	if err := f.db.Where("id = ?", f.owner.ID).First(&owner).Error; err != nil {
		t.Fatalf("reload the owner: %v", err)
	}
	if owner.Bio != f.bio {
		t.Errorf("a token rewrote its owner's profile: bio is now %q", owner.Bio)
	}
}

// The guard sits behind authentication, not in front of it: a caller with no credentials is
// still told to authenticate, and is not told anything about what kind of credential would do.
func TestSettings_UnauthenticatedCallerStillGets401(t *testing.T) {
	f := setupSettingsGuard(t)

	w := f.do(http.MethodGet, settingsPrefix+"profile", "", nil)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401.\nbody: %s", w.Code, w.Body.String())
	}
}
