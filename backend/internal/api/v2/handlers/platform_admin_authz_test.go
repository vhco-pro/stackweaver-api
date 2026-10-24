// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Authorization matrix for the install-wide routes (#132, AC3, AC6, AC16): every one answers 404
// to any caller who is not a platform administrator, including a user who owns every organization
// the test creates, a member, an identity that is neither a JWT nor an API key, and everyone on an
// installation whose declared list is empty; a platform administrator gets through. The handlers
// are the real ones over real Postgres, and the identity is set on the context the way
// auth.Service sets it.
//
// The rows are the test's own and are deleted by id (the database may be live).
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestPlatformAdminAuthz

//go:build integration

package handlers

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/activity"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// platformAdminFixture holds the callers every platform administrator test needs.
type platformAdminFixture struct {
	db       *gorm.DB
	users    *repository.UserRepository
	authSvc  *auth.Service
	audit    *activity.Service
	admins   *platformadmin.Service
	admin    *models.User // granted platform administrator, member of no organization
	declared *models.User // declared platform administrator
	owner    *models.User // in the owners team of both test organizations
	member   *models.User // in a non-owner team of orgA
	plain    *models.User // no membership at all
	orgA     *models.Organization
	orgB     *models.Organization
	sfx      string
}

func setupPlatformAdminFixture(t *testing.T) *platformAdminFixture {
	t.Helper()
	db := setupAuthzTestDB(t)
	f := &platformAdminFixture{db: db, sfx: uuid.NewString()[:8]}
	f.users = repository.NewUserRepository(db)
	f.authSvc = auth.NewService(f.users)
	f.audit = activity.NewService(repository.NewAuditLogRepository(db))

	f.orgA = f.org(t, "platadm-a-"+f.sfx)
	f.orgB = f.org(t, "platadm-b-"+f.sfx)
	f.admin = f.user(t, "admin")
	f.declared = f.user(t, "declared")
	f.owner = f.user(t, "owner")
	f.member = f.user(t, "member")
	f.plain = f.user(t, "plain")
	if _, err := f.users.SetPlatformAdmin(f.admin.ID, true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.users.SetPlatformAdmin(f.declared.ID, true, true); err != nil {
		t.Fatal(err)
	}
	for _, org := range []*models.Organization{f.orgA, f.orgB} {
		f.team(t, org, "owners", f.owner)
	}
	f.team(t, f.orgA, "developers", f.member)
	f.admins = f.service(platformadmin.Config{Declared: platformadmin.NewDeclared([]string{f.declared.Email})})
	return f
}

func (f *platformAdminFixture) service(cfg platformadmin.Config) *platformadmin.Service {
	return platformadmin.NewService(f.users, f.authSvc, f.audit, cfg)
}

func (f *platformAdminFixture) org(t *testing.T, name string) *models.Organization {
	t.Helper()
	o := &models.Organization{ID: uuid.New(), Name: name, Email: name + "@test.local"}
	if err := f.db.Create(o).Error; err != nil {
		t.Fatalf("create org: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("organization_id = ?", o.ID).Delete(&models.OrganizationMember{})
		f.db.Where("id = ?", o.ID).Delete(&models.Organization{})
	})
	return o
}

func (f *platformAdminFixture) user(t *testing.T, role string) *models.User {
	t.Helper()
	u := &models.User{ID: uuid.New(), ZitadelSubject: "platadm-" + role + "-" + f.sfx, Email: "platadm-" + role + "-" + f.sfx + "@test.local", Name: "Platadm " + role}
	if err := f.db.Create(u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("resource_type = ? AND resource_id = ?", "user", u.ID).Delete(&models.AuditLog{})
		f.db.Where("user_id = ?", u.ID).Delete(&models.APIKey{})
		f.db.Where("id = ?", u.ID).Delete(&models.User{})
	})
	return u
}

func (f *platformAdminFixture) team(t *testing.T, org *models.Organization, name string, members ...*models.User) *models.Team {
	t.Helper()
	team := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: name}
	if err := f.db.Create(team).Error; err != nil {
		t.Fatalf("create team: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("team_id = ?", team.ID).Delete(&models.TeamMember{})
		f.db.Where("id = ?", team.ID).Delete(&models.Team{})
	})
	for _, m := range members {
		var existing int64
		f.db.Model(&models.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", org.ID, m.ID).Count(&existing)
		if existing == 0 {
			if err := f.db.Create(&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: m.ID}).Error; err != nil {
				t.Fatalf("create membership: %v", err)
			}
		}
		if err := f.db.Create(&models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: m.ID}).Error; err != nil {
			t.Fatalf("create team member: %v", err)
		}
	}
	return team
}

// identity is how a request is authenticated, as auth.Service would set it on the context.
type identity struct {
	user      uuid.UUID
	method    string // auth_method; "" means jwt
	tokenKind string
	scopes    []string
}

func jwtAs(u *models.User) identity { return identity{user: u.ID, method: "jwt"} }

// platformAdminRouter is a gin engine that establishes the identity of each request from the
// headers platformAdminCall sets.
func platformAdminRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		id, err := uuid.Parse(c.GetHeader("X-Test-User"))
		if err != nil {
			c.Next()
			return
		}
		c.Set("user_id", id)
		method := c.GetHeader("X-Test-Auth-Method")
		c.Set("auth_method", method)
		if method == "api_key" {
			c.Set("token_kind", c.GetHeader("X-Test-Token-Kind"))
			var scopes []string
			if s := c.GetHeader("X-Test-Scopes"); s != "" {
				scopes = strings.Split(s, ",")
			}
			c.Set("api_key_scopes", scopes)
		}
		c.Next()
	})
	return r
}

func platformAdminCall(t *testing.T, router http.Handler, method, path string, as identity, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	if as.user != uuid.Nil {
		req.Header.Set("X-Test-User", as.user.String())
		m := as.method
		if m == "" {
			m = "jwt"
		}
		req.Header.Set("X-Test-Auth-Method", m)
		req.Header.Set("X-Test-Token-Kind", as.tokenKind)
		req.Header.Set("X-Test-Scopes", strings.Join(as.scopes, ","))
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// platformRoute is one install-wide route of AC3 with a request that a platform administrator
// gets a success for.
type platformRoute struct {
	method, path, body string
	wantOK             int
}

// versionRoutes mounts the five /admin/terraform-versions routes and returns them, with a version
// row of the test's own to address.
func (f *platformAdminFixture) versionRoutes(t *testing.T, router *gin.Engine, admins *platformadmin.Service) []platformRoute {
	t.Helper()
	h := NewAdminTofuVersionsHandler(f.db, admins)
	router.GET("/api/v2/admin/terraform-versions", h.List)
	router.POST("/api/v2/admin/terraform-versions", h.Create)
	router.GET("/api/v2/admin/terraform-versions/:id", h.Read)
	router.PATCH("/api/v2/admin/terraform-versions/:id", h.Update)
	router.DELETE("/api/v2/admin/terraform-versions/:id", h.Delete)

	// A low, beta version in a range no release uses: it never becomes anyone's default.
	base := 100000 + rand.IntN(800000)
	v := &models.TofuVersion{Version: fmt.Sprintf("0.0.%d", base), Beta: true, Enabled: true}
	if err := f.db.Create(v).Error; err != nil {
		t.Fatalf("create version: %v", err)
	}
	created := fmt.Sprintf("0.0.%d", base+1)
	t.Cleanup(func() {
		f.db.Where("id = ? OR version = ?", v.ID, created).Delete(&models.TofuVersion{})
	})
	return []platformRoute{
		{http.MethodGet, "/api/v2/admin/terraform-versions", "", http.StatusOK},
		{http.MethodGet, "/api/v2/admin/terraform-versions/" + v.ID, "", http.StatusOK},
		{http.MethodPatch, "/api/v2/admin/terraform-versions/" + v.ID, `{"data":{"type":"terraform-versions","attributes":{"enabled":false}}}`, http.StatusOK},
		{http.MethodPost, "/api/v2/admin/terraform-versions", `{"data":{"type":"terraform-versions","attributes":{"version":"` + created + `","beta":true}}}`, http.StatusCreated},
		{http.MethodDelete, "/api/v2/admin/terraform-versions/" + v.ID, "", http.StatusNoContent},
	}
}

// assertAllNotFound sends every route as the caller and requires 404 with no data.
func assertAllNotFound(t *testing.T, router http.Handler, routes []platformRoute, who string, as identity) {
	t.Helper()
	for _, r := range routes {
		rec := platformAdminCall(t, router, r.method, r.path, as, r.body)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: %s %s = %d, want 404 (%s)", who, r.method, r.path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), `"data"`) {
			t.Errorf("%s: %s %s returned data on a refusal: %s", who, r.method, r.path, rec.Body.String())
		}
	}
}

// AC3: the versions catalogue is refused to everyone but a platform administrator.
func TestPlatformAdminAuthz_VersionsRefuseEveryoneElse(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	router := platformAdminRouter()
	routes := f.versionRoutes(t, router, f.admins)

	assertAllNotFound(t, router, routes, "owner of every organization", jwtAs(f.owner))
	assertAllNotFound(t, router, routes, "member", jwtAs(f.member))
	assertAllNotFound(t, router, routes, "user without memberships", jwtAs(f.plain))
	assertAllNotFound(t, router, routes, "unauthenticated", identity{})
	// A log token re-establishes a session user on run log paths only; even a platform
	// administrator's is refused here before the row is read.
	assertAllNotFound(t, router, routes, "platform administrator through a log token", identity{user: f.admin.ID, method: "log_token"})
	assertAllNotFound(t, router, routes, "platform administrator through an unknown identity", identity{user: f.admin.ID, method: "session"})
}

// AC3: a platform administrator, granted or declared, reaches every versions route.
func TestPlatformAdminAuthz_VersionsAdmitAPlatformAdministrator(t *testing.T) {
	for _, who := range []string{"granted", "declared"} {
		t.Run(who, func(t *testing.T) {
			f := setupPlatformAdminFixture(t)
			caller := f.admin
			if who == "declared" {
				caller = f.declared
			}
			router := platformAdminRouter()
			for _, r := range f.versionRoutes(t, router, f.admins) {
				rec := platformAdminCall(t, router, r.method, r.path, jwtAs(caller), r.body)
				if rec.Code != r.wantOK {
					t.Errorf("%s %s = %d, want %d (%s)", r.method, r.path, rec.Code, r.wantOK, rec.Body.String())
				}
			}
		})
	}
}

// AC6: with no declared administrator, the would-be bootstrap admin's sign-in flags nothing, and
// the routes stay 404 to them until the list is set.
func TestPlatformAdminAuthz_EmptyDeclaredListAdmitsNobody(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	empty := f.service(platformadmin.Config{})
	bootstrap := f.user(t, "bootstrap")
	if err := empty.ApplyDeclared(t.Context(), bootstrap, &auth.UserInfo{Email: bootstrap.Email, EmailVerified: true}); err != nil {
		t.Fatalf("ApplyDeclared: %v", err)
	}
	router := platformAdminRouter()
	routes := f.versionRoutes(t, router, empty)
	assertAllNotFound(t, router, routes, "bootstrap admin on an empty list", jwtAs(bootstrap))
}

// everyRoute mounts every install-wide route of AC3 and returns them in an order a platform
// administrator can replay: the grant before the revoke, the version delete last.
func (f *platformAdminFixture) everyRoute(t *testing.T, router *gin.Engine, admins *platformadmin.Service) []platformRoute {
	t.Helper()
	versions := f.versionRoutes(t, router, admins)
	f.adminUserRoutes(router, admins)
	f.adminOrganizationRoutes(router, admins)
	target := f.plain.ID.String()
	routes := []platformRoute{
		{http.MethodGet, "/api/v2/admin/users?filter%5Badmin%5D=true", "", http.StatusOK},
		{http.MethodGet, "/api/v2/admin/users?q=" + f.plain.Email, "", http.StatusOK},
		{http.MethodPost, "/api/v2/admin/users/" + target + "/actions/grant_admin", "", http.StatusOK},
		{http.MethodPost, "/api/v2/admin/users/" + target + "/actions/revoke_admin", "", http.StatusOK},
		{http.MethodGet, "/api/v2/admin/organizations", "", http.StatusOK},
		{http.MethodGet, "/api/v2/admin/organizations/" + f.orgA.Name, "", http.StatusOK},
	}
	return append(routes, versions...)
}

// AC3, AC16: every install-wide route refuses every caller who is not a platform administrator,
// including an organization-bound key with any scopes and a plain user token of a platform
// administrator, and admits the administrator's session.
func TestPlatformAdminAuthz_EveryInstallWideRoute(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	router := platformAdminRouter()
	routes := f.everyRoute(t, router, f.admins)

	assertAllNotFound(t, router, routes, "owner of every organization", jwtAs(f.owner))
	assertAllNotFound(t, router, routes, "member", jwtAs(f.member))
	assertAllNotFound(t, router, routes, "user without memberships", jwtAs(f.plain))
	assertAllNotFound(t, router, routes, "log token of a platform administrator", identity{user: f.admin.ID, method: "log_token"})
	assertAllNotFound(t, router, routes, "plain user token of a platform administrator",
		identity{user: f.admin.ID, method: "api_key", tokenKind: models.APIKeyKindUser})
	assertAllNotFound(t, router, routes, "platform:admin token of a non-holder",
		identity{user: f.owner.ID, method: "api_key", tokenKind: models.APIKeyKindUser, scopes: []string{"platform:admin"}})
	for _, scopes := range [][]string{
		nil,
		{"*"},
		{"platform:admin"},
		{"org:" + f.orgA.ID.String() + ":admin"},
		{"user:admin", "platform:admin", "*"},
	} {
		assertAllNotFound(t, router, routes, fmt.Sprintf("organization-bound key of a platform administrator with scopes %v", scopes),
			identity{user: f.admin.ID, method: "api_key", tokenKind: models.APIKeyKindOrg, scopes: scopes})
	}

	for _, r := range routes {
		rec := platformAdminCall(t, router, r.method, r.path, jwtAs(f.admin), r.body)
		if rec.Code != r.wantOK {
			t.Errorf("platform administrator: %s %s = %d, want %d (%s)", r.method, r.path, rec.Code, r.wantOK, rec.Body.String())
		}
	}
}

// AC13: a platform:admin user token of a platform administrator calls every install-wide route
// with the same results as the administrator's session.
func TestPlatformAdminAuthz_HolderTokenMatchesTheSession(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	router := platformAdminRouter()
	routes := f.everyRoute(t, router, f.admins)
	token := identity{user: f.admin.ID, method: "api_key", tokenKind: models.APIKeyKindUser, scopes: []string{"platform:admin"}}
	for _, r := range routes {
		rec := platformAdminCall(t, router, r.method, r.path, token, r.body)
		if rec.Code != r.wantOK {
			t.Errorf("platform:admin token: %s %s = %d, want %d (%s)", r.method, r.path, rec.Code, r.wantOK, rec.Body.String())
		}
	}
}
