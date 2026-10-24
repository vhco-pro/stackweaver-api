// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The platform admin token through the router production mounts, with real tokens (#132, D5).
//
// AC13: a platform:admin user token calls the install-wide routes as its holder's session does,
// and inside organizations it is a plain user token and never more: the same answer as a token
// with no scopes from the wall (membership, user_tokens_enabled), from RBAC, from the agent-pool
// queue depth and from runner registration. AC14 (automated half): go-tfe's
// Admin.TerraformVersions client, the one tfe_terraform_version calls, manages a version with a
// platform:admin token and gets 404 for each call with a plain token of the same person. AC16
// and AC17 on the real router: an organization-bound key is refused on every admin route and on
// organization creation. AC19: the platform settings answer every token kind and refuse an
// unauthenticated request.
//
// Every row is the test's own and is deleted by id.
//
//	go test -tags integration ./internal/api/v2/routes/ -run TestPlatformAdminToken

//go:build integration

package routes_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	tfe "github.com/hashicorp/go-tfe"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type platformTokenFixture struct {
	db      *gorm.DB
	router  *gin.Engine
	keys    *apikey.Service
	orgA    *models.Organization // the member and the owner belong; the administrator does not
	orgB    *models.Organization // nobody but the owner belongs
	pool    *models.AgentPool    // in orgA
	admin   *models.User         // platform administrator, member of no organization
	member  *models.User         // developers team of orgA
	owner   *models.User         // owners team of orgA and orgB
	tokens  map[string]map[string]string
	orgKey  string // organization-bound admin key of the owner, on orgA
	created []string
}

func setupPlatformTokenFixture(t *testing.T) *platformTokenFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	t.Setenv("DEV_INSECURE_KEY", "1")
	db, err := dbtest.Open(t, dbURL, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]
	f := &platformTokenFixture{db: db, tokens: map[string]map[string]string{}}
	f.orgA = &models.Organization{ID: uuid.New(), Name: "platok-a-" + sfx, Email: "platok-a-" + sfx + "@test.local"}
	f.orgB = &models.Organization{ID: uuid.New(), Name: "platok-b-" + sfx, Email: "platok-b-" + sfx + "@test.local"}
	mk := func(role string) *models.User {
		return &models.User{ID: uuid.New(), ZitadelSubject: "platok-" + role + "-" + sfx, Email: "platok-" + role + "-" + sfx + "@test.local"}
	}
	f.admin, f.member, f.owner = mk("admin"), mk("member"), mk("owner")
	ownersA := &models.Team{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "owners"}
	ownersB := &models.Team{ID: uuid.New(), OrganizationID: f.orgB.ID, Name: "owners"}
	devs := &models.Team{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "developers"}
	f.pool = &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "platok-pool-" + sfx}
	seed := []any{
		f.orgA, f.orgB, f.admin, f.member, f.owner, ownersA, ownersB, devs, f.pool,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.orgA.ID, UserID: f.member.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.orgA.ID, UserID: f.owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.orgB.ID, UserID: f.owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersA.ID, UserID: f.owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersB.ID, UserID: f.owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: devs.ID, UserID: f.member.ID},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	users := []uuid.UUID{f.admin.ID, f.member.ID, f.owner.ID}
	teams := []uuid.UUID{ownersA.ID, ownersB.ID, devs.ID}
	t.Cleanup(func() {
		// Row-scoped only: every statement is keyed on an id or a name this test generated.
		if len(f.created) > 0 {
			var ids []uuid.UUID
			db.Model(&models.Organization{}).Where("name IN ?", f.created).Pluck("id", &ids)
			if len(ids) > 0 {
				var tids []uuid.UUID
				db.Model(&models.Team{}).Where("organization_id IN ?", ids).Pluck("id", &tids)
				db.Where("team_id IN ?", tids).Delete(&models.TeamMember{})
				db.Where("team_id IN ?", tids).Delete(&models.TeamOrganizationAccess{})
				db.Where("team_id IN ?", tids).Delete(&models.TeamProjectAccess{})
				db.Model(&models.Organization{}).Where("id IN ?", ids).Update("default_agent_pool_id", nil)
				db.Where("organization_id IN ?", ids).Delete(&models.AgentPool{})
				db.Where("organization_id IN ?", ids).Delete(&models.Team{})
				db.Where("organization_id IN ?", ids).Delete(&models.OrganizationMember{})
				db.Where("organization_id IN ?", ids).Delete(&models.Project{})
				db.Where("id IN ?", ids).Delete(&models.Organization{})
			}
			db.Where("name IN ?", f.created).Delete(&models.ReservedOrganizationName{})
		}
		db.Where("team_id IN ?", teams).Delete(&models.TeamMember{})
		db.Where("id IN ?", teams).Delete(&models.Team{})
		db.Where("id = ?", f.pool.ID).Delete(&models.AgentPool{})
		db.Where("organization_id IN ?", []uuid.UUID{f.orgA.ID, f.orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{f.orgA.ID, f.orgB.ID}).Delete(&models.Organization{})
		db.Where("resource_type = ? AND resource_id IN ?", "user", users).Delete(&models.AuditLog{})
		db.Where("user_id IN ?", users).Delete(&models.AuditLog{})
		db.Where("user_id IN ?", users).Delete(&models.APIKey{})
		db.Where("id IN ?", users).Delete(&models.User{})
	})

	userRepo := repository.NewUserRepository(db)
	if _, err := userRepo.SetPlatformAdmin(f.admin.ID, true, false); err != nil {
		t.Fatal(err)
	}
	f.keys = apikey.NewService(repository.NewAPIKeyRepository(db), repository.NewOrganizationRepository(db),
		repository.NewProjectRepository(db), repository.NewTeamRepository(db))
	for role, u := range map[string]*models.User{"admin": f.admin, "member": f.member, "owner": f.owner} {
		_, plain, err := f.keys.CreateUserToken(u.ID, "platok-plain", nil)
		if err != nil {
			t.Fatal(err)
		}
		_, platform, err := f.keys.CreateUserTokenWithScopes(u.ID, "platok-platform", nil, []string{"platform:admin"})
		if err != nil {
			t.Fatal(err)
		}
		f.tokens[role] = map[string]string{"plain": plain, "platform": platform}
	}
	if _, f.orgKey, err = f.keys.CreateAPIKey(f.owner.ID, "platok-org", []string{"org:" + f.orgA.ID.String() + ":admin"}, nil); err != nil {
		t.Fatalf("mint the organization key: %v", err)
	}

	authService := auth.NewService(userRepo)
	authService.SetAPIKeyService(f.keys)
	gin.SetMode(gin.TestMode)
	f.router = buildHarnessRouter(t, db, authService, identityFromEnv())
	return f
}

func (f *platformTokenFixture) do(method, path, token string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

// orgRequests are the organization-level requests AC13 compares, in an order that is safe to
// replay: nothing here changes what a later request sees.
func (f *platformTokenFixture) orgRequests() []struct{ method, path, body string } {
	return []struct{ method, path, body string }{
		{http.MethodGet, "/api/v2/organizations", ""},
		{http.MethodGet, "/api/v2/organizations/" + f.orgA.Name, ""},
		{http.MethodGet, "/api/v2/organizations/" + f.orgB.Name, ""},
		{http.MethodGet, "/api/v2/organizations/" + f.orgA.Name + "/teams", ""},
		{http.MethodGet, "/api/v2/organizations/" + f.orgB.Name + "/teams", ""},
		{http.MethodPatch, "/api/v2/organizations/" + f.orgA.Name, `{"data":{"type":"organizations","attributes":{"email":"` + f.orgA.Email + `"}}}`},
		{http.MethodPatch, "/api/v2/organizations/" + f.orgB.Name, `{"data":{"type":"organizations","attributes":{"email":"` + f.orgB.Email + `"}}}`},
		{http.MethodGet, "/api/v2/organizations/" + f.orgA.Name + "/agent-pools", ""},
		{http.MethodGet, "/api/v2/agent-pools/" + f.pool.ID.String() + "/queue-depth", ""},
		{http.MethodPost, "/api/v2/runner/register", `{"agent_pool_id":"` + f.pool.ID.String() + `","name":"platok-runner"}`},
	}
}

func TestPlatformAdminToken_IsAPlainUserTokenInsideOrganizations(t *testing.T) {
	f := setupPlatformTokenFixture(t)
	compare := func(t *testing.T, label string) {
		t.Helper()
		for _, role := range []string{"admin", "member", "owner"} {
			for _, rq := range f.orgRequests() {
				plain := f.do(rq.method, rq.path, f.tokens[role]["plain"], rq.body)
				platform := f.do(rq.method, rq.path, f.tokens[role]["platform"], rq.body)
				if plain.Code != platform.Code {
					t.Errorf("%s, %s: %s %s: plain user token %d, platform:admin token %d; want the same",
						label, role, rq.method, rq.path, plain.Code, platform.Code)
				}
			}
		}
	}
	compare(t, "user tokens allowed")

	// The organizations the administrator does not belong to stay closed to their token.
	for _, path := range []string{"/api/v2/organizations/" + f.orgA.Name, "/api/v2/organizations/" + f.orgB.Name} {
		if w := f.do(http.MethodGet, path, f.tokens["admin"]["platform"], ""); w.Code != http.StatusForbidden && w.Code != http.StatusNotFound {
			t.Errorf("administrator's platform:admin token reached %s: %d", path, w.Code)
		}
	}
	// Runner registration refuses it as it refuses every unrestricted key.
	if w := f.do(http.MethodPost, "/api/v2/runner/register", f.tokens["owner"]["platform"], `{"agent_pool_id":"`+f.pool.ID.String()+`","name":"platok-runner"}`); w.Code != http.StatusForbidden {
		t.Errorf("runner registration with a platform:admin token of an owner = %d, want 403", w.Code)
	}

	// user_tokens_enabled=false closes orgA to both kinds of user token alike, owners excepted.
	if err := f.db.Model(&models.Organization{}).Where("id = ?", f.orgA.ID).Update("user_tokens_enabled", false).Error; err != nil {
		t.Fatalf("disable user tokens: %v", err)
	}
	compare(t, "user tokens disabled")
	if w := f.do(http.MethodGet, "/api/v2/organizations/"+f.orgA.Name, f.tokens["member"]["platform"], ""); w.Code != http.StatusForbidden {
		t.Errorf("member's platform:admin token with user tokens disabled = %d, want 403", w.Code)
	}
}

func TestPlatformAdminToken_InstallWideRoutes(t *testing.T) {
	f := setupPlatformTokenFixture(t)
	adminPaths := []string{
		"/api/v2/admin/terraform-versions",
		"/api/v2/admin/users?filter%5Badmin%5D=true",
		"/api/v2/admin/organizations",
		"/api/v2/admin/organizations/" + f.orgA.Name,
	}
	for _, path := range adminPaths {
		if w := f.do(http.MethodGet, path, f.tokens["admin"]["platform"], ""); w.Code != http.StatusOK {
			t.Errorf("administrator's platform:admin token GET %s = %d, want 200", path, w.Code)
		}
		for label, token := range map[string]string{
			"administrator's plain token":   f.tokens["admin"]["plain"],
			"owner's platform:admin token":  f.tokens["owner"]["platform"],
			"member's platform:admin token": f.tokens["member"]["platform"],
			"organization-bound admin key":  f.orgKey,
			"owner's plain token":           f.tokens["owner"]["plain"],
		} {
			if w := f.do(http.MethodGet, path, token, ""); w.Code != http.StatusNotFound {
				t.Errorf("%s GET %s = %d, want 404", label, path, w.Code)
			}
		}
	}

	// AC17: the wall refuses organization creation to an organization-bound key; a user token
	// creates one under the default setting.
	name := "platok-new-" + uuid.NewString()[:8]
	f.created = append(f.created, name)
	body := `{"data":{"type":"organizations","attributes":{"name":"` + name + `","email":"` + name + `@test.local"}}}`
	if w := f.do(http.MethodPost, "/api/v2/organizations", f.orgKey, body); w.Code != http.StatusForbidden {
		t.Errorf("organization-bound key POST /organizations = %d, want 403", w.Code)
	}
	if w := f.do(http.MethodPost, "/api/v2/organizations", f.tokens["member"]["platform"], body); w.Code != http.StatusCreated {
		t.Errorf("user token POST /organizations = %d, want 201 (%s)", w.Code, w.Body.String())
	}

	// AC19: every token kind reads the platform settings; nobody unauthenticated does.
	for label, token := range map[string]string{"org key": f.orgKey, "plain": f.tokens["member"]["plain"], "platform": f.tokens["admin"]["platform"]} {
		if w := f.do(http.MethodGet, "/api/v2/platform/settings", token, ""); w.Code != http.StatusOK {
			t.Errorf("%s GET /platform/settings = %d, want 200", label, w.Code)
		}
	}
	if w := f.do(http.MethodGet, "/api/v2/platform/settings", "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /platform/settings = %d, want 401", w.Code)
	}
}

// AC14, automated half: go-tfe's Admin.TerraformVersions against the router.
func TestPlatformAdminToken_GoTFEAdminTerraformVersions(t *testing.T) {
	// go-tfe parses created-at with the layout "2006-01-02T15:04:05Z", so it reads only UTC
	// timestamps. The API containers run in UTC; this test process may not, so it formats in UTC
	// the way a deployment does.
	previous := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = previous })

	f := setupPlatformTokenFixture(t)
	srv := httptest.NewServer(f.router)
	t.Cleanup(srv.Close)
	client := func(t *testing.T, token string) *tfe.Client {
		t.Helper()
		c, err := tfe.NewClient(&tfe.Config{Address: srv.URL, Token: token, RetryServerErrors: false})
		if err != nil {
			t.Fatalf("go-tfe client: %v", err)
		}
		return c
	}
	ctx := context.Background()
	admin := client(t, f.tokens["admin"]["platform"])
	plain := client(t, f.tokens["admin"]["plain"])

	// A low, beta version in a range no release uses: it never becomes anyone's default.
	version := fmt.Sprintf("0.0.%d", 100000+rand.IntN(800000))
	t.Cleanup(func() { f.db.Where("version = ?", version).Delete(&models.TofuVersion{}) })

	if _, err := plain.Admin.TerraformVersions.Create(ctx, tfe.AdminTerraformVersionCreateOptions{
		Version: tfe.String(version), URL: tfe.String("https://example.invalid/tofu.zip"), Sha: tfe.String("abc"), Beta: tfe.Bool(true),
	}); !errors.Is(err, tfe.ErrResourceNotFound) {
		t.Errorf("Create with a plain token: %v, want not found", err)
	}

	created, err := admin.Admin.TerraformVersions.Create(ctx, tfe.AdminTerraformVersionCreateOptions{
		Version: tfe.String(version), URL: tfe.String("https://example.invalid/tofu.zip"), Sha: tfe.String("abc"),
		Official: tfe.Bool(false), Enabled: tfe.Bool(true), Beta: tfe.Bool(true),
	})
	if err != nil {
		t.Fatalf("Create with a platform:admin token: %v", err)
	}
	read, err := admin.Admin.TerraformVersions.Read(ctx, created.ID)
	if err != nil || read.Version != version || !read.Enabled {
		t.Fatalf("Read: %+v, %v", read, err)
	}
	updated, err := admin.Admin.TerraformVersions.Update(ctx, created.ID, tfe.AdminTerraformVersionUpdateOptions{Enabled: tfe.Bool(false)})
	if err != nil || updated.Enabled {
		t.Fatalf("Update enabled=false: %+v, %v", updated, err)
	}

	if _, err := plain.Admin.TerraformVersions.Read(ctx, created.ID); !errors.Is(err, tfe.ErrResourceNotFound) {
		t.Errorf("Read with a plain token: %v, want not found", err)
	}
	if _, err := plain.Admin.TerraformVersions.Update(ctx, created.ID, tfe.AdminTerraformVersionUpdateOptions{Enabled: tfe.Bool(true)}); !errors.Is(err, tfe.ErrResourceNotFound) {
		t.Errorf("Update with a plain token: %v, want not found", err)
	}
	if err := plain.Admin.TerraformVersions.Delete(ctx, created.ID); !errors.Is(err, tfe.ErrResourceNotFound) {
		t.Errorf("Delete with a plain token: %v, want not found", err)
	}
	if _, err := plain.Admin.TerraformVersions.List(ctx, nil); !errors.Is(err, tfe.ErrResourceNotFound) {
		t.Errorf("List with a plain token: %v, want not found", err)
	}

	if err := admin.Admin.TerraformVersions.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete with a platform:admin token: %v", err)
	}
	if _, err := admin.Admin.TerraformVersions.Read(ctx, created.ID); !errors.Is(err, tfe.ErrResourceNotFound) {
		t.Errorf("Read after delete: %v, want not found", err)
	}
}
