// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Workstream-A authz regression matrix for AUD-151..154 — the org/team read+update
// handlers that leaned on the org-resolution wall alone (which JWT/browser identities
// bypass) and so exposed cross-tenant writes/reads:
//
//   - AUD-151 Organizations.Update: any authenticated user rewrote any org by name.
//   - AUD-152 OrganizationMembership.GetByID: cross-tenant member email/team IDOR.
//   - AUD-153 Team.GetByID (?include=users): cross-tenant member email/username leak.
//   - AUD-154 Team.List / Team.Get: cross-tenant team enumeration.
//
// Each test drives the real handler + real Postgres and asserts an outsider is denied
// (403), an anonymous caller is denied (401), and a legitimate member/owner is allowed.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the dev DB has no backup). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestOrgTeamReadAuthz

//go:build integration
// +build integration

package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

func TestOrgTeamReadAuthz(t *testing.T) {
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
		&models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "otauthz-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "otauthz-b-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "ot-own-" + sfx, Email: "ot-own-" + sfx + "@test.local"}
	member := &models.User{ID: uuid.New(), ZitadelSubject: "ot-mem-" + sfx, Email: "ot-mem-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "ot-out-" + sfx, Email: "ot-out-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	// member's own org-A membership row (drives the AUD-152 self-read path)
	memberMembership := &models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: member.ID}

	seed := []interface{}{
		orgA, orgB, owner, member, outsider, ownersTeam,
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: owner.ID},
		memberMembership,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", ownersTeam.ID).Delete(&models.Team{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{owner.ID, member.ID, outsider.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	userRepo := repository.NewUserRepository(db)
	authService := auth.NewService(userRepo)
	rbacService := rbac.NewServiceWithTeams(orgRepo, teamRepo, repository.NewProjectRepository(db))

	orgH := NewOrganizationHandlerV2(orgRepo, teamRepo, repository.NewProjectRepository(db), nil, authService, nil, rbacService, db)
	memH := NewOrganizationMembershipHandlerV2(orgRepo, userRepo, teamRepo, authService, rbacService)
	teamH := NewTeamHandlerV2(teamRepo, orgRepo, authService, rbacService)

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
	router.PATCH("/organizations/:name", orgH.Update)
	router.GET("/organization-memberships/:id", memH.GetByID)
	router.GET("/organizations/:name/teams", teamH.List)
	router.GET("/organizations/:name/teams/:teamName", teamH.Get)
	router.GET("/teams/:id", teamH.GetByID)

	call := func(method, path string, asUser uuid.UUID, body string) int {
		var r *http.Request
		if body != "" {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		if asUser != uuid.Nil {
			r.Header.Set("X-Test-User", asUser.String())
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, r)
		return rec.Code
	}

	type row struct {
		name   string
		method string
		path   string
		user   uuid.UUID
		body   string
		want   int
	}
	cases := []row{
		// AUD-151 — Organizations.Update
		{"151 outsider update", http.MethodPatch, "/organizations/" + orgA.Name, outsider.ID, "{}", http.StatusForbidden},
		{"151 plain-member update", http.MethodPatch, "/organizations/" + orgA.Name, member.ID, "{}", http.StatusForbidden},
		{"151 anon update", http.MethodPatch, "/organizations/" + orgA.Name, uuid.Nil, "{}", http.StatusUnauthorized},
		{"151 owner update", http.MethodPatch, "/organizations/" + orgA.Name, owner.ID, "{}", http.StatusOK},

		// AUD-152 — OrganizationMembership.GetByID (member's own org-A membership row)
		{"152 outsider read", http.MethodGet, "/organization-memberships/" + memberMembership.ID.String(), outsider.ID, "", http.StatusForbidden},
		{"152 anon read", http.MethodGet, "/organization-memberships/" + memberMembership.ID.String(), uuid.Nil, "", http.StatusUnauthorized},
		{"152 self read", http.MethodGet, "/organization-memberships/" + memberMembership.ID.String(), member.ID, "", http.StatusOK},
		{"152 owner read", http.MethodGet, "/organization-memberships/" + memberMembership.ID.String(), owner.ID, "", http.StatusOK},

		// AUD-154 — Team.List
		{"154 outsider list", http.MethodGet, "/organizations/" + orgA.Name + "/teams", outsider.ID, "", http.StatusForbidden},
		{"154 anon list", http.MethodGet, "/organizations/" + orgA.Name + "/teams", uuid.Nil, "", http.StatusUnauthorized},
		{"154 member list", http.MethodGet, "/organizations/" + orgA.Name + "/teams", member.ID, "", http.StatusOK},

		// AUD-154 — Team.Get (by name)
		{"154 outsider get", http.MethodGet, "/organizations/" + orgA.Name + "/teams/owners", outsider.ID, "", http.StatusForbidden},
		{"154 member get", http.MethodGet, "/organizations/" + orgA.Name + "/teams/owners", member.ID, "", http.StatusOK},

		// AUD-153 — Team.GetByID (?include=users leaks member email)
		{"153 outsider getbyid", http.MethodGet, "/teams/" + ownersTeam.ID.String() + "?include=users", outsider.ID, "", http.StatusForbidden},
		{"153 anon getbyid", http.MethodGet, "/teams/" + ownersTeam.ID.String() + "?include=users", uuid.Nil, "", http.StatusUnauthorized},
		{"153 member getbyid", http.MethodGet, "/teams/" + ownersTeam.ID.String() + "?include=users", member.ID, "", http.StatusOK},
	}

	for _, tc := range cases {
		if got := call(tc.method, tc.path, tc.user, tc.body); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}
