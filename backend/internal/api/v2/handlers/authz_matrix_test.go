// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Authorization regression matrix (AUD-114 harness, bootstrapped by the AUD-003 fix).
//
// Each authorization fix from the codebase audit (docs/internal/codebase-audit-2026-06-analysis.md)
// adds its endpoint × caller-role cases here so the missing-permission-check class can never ship
// silently again. The harness drives real handlers over real Postgres/GORM — no mocks — because the
// defect class lives in the handler↔rbac wiring, which mocks would hide.
//
// Gated behind the `integration` build tag; skips unless $TEST_DATABASE_URL is set, e.g.
// `postgres://iac:iac_password@localhost:5432/iac_platform`. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAuthz

//go:build integration
// +build integration

package handlers

import (
	"bytes"
	"encoding/json"
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

// setupAuthzTestDB connects to $TEST_DATABASE_URL and migrates the models the matrix needs.
func setupAuthzTestDB(t *testing.T) *gorm.DB {
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
		&models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// testUserAuth impersonates a principal the way middleware.AuthMiddleware would: handlers read
// "user_id" from the gin context (auth.Service.GetUserFromContext). An empty header = anonymous.
func testUserAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if v := c.GetHeader("X-Test-User"); v != "" {
			if id, err := uuid.Parse(v); err == nil {
				c.Set("user_id", id)
			}
		}
		c.Next()
	}
}

// authzRequest performs a JSON:API request against the router as the given user.
func authzRequest(t *testing.T, router *gin.Engine, method, path string, asUser uuid.UUID, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/vnd.api+json")
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// --- AUD-003: team organization-membership endpoints ---

type teamAuthzFixture struct {
	router      *gin.Engine
	teamRepo    *repository.TeamRepository
	ownersTeam  *models.Team // orgA "owners"
	devTeam     *models.Team // orgA "developers"
	owner       *models.User // in orgA owners
	member      *models.User // in orgA developers, no org-level permissions
	lead        *models.User // in orgA leads (ManageTeams grant, NOT an owner)
	outsider    *models.User // member of orgB only
	memberships map[uuid.UUID]uuid.UUID // userID -> orgA OrganizationMember.ID
}

func setupTeamAuthzFixture(t *testing.T) *teamAuthzFixture {
	t.Helper()
	db := setupAuthzTestDB(t)
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "authz-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "authz-b-" + sfx}
	users := map[string]*models.User{
		"owner":    {ID: uuid.New(), ZitadelSubject: "authz-owner-" + sfx, Email: "authz-owner-" + sfx + "@test.local"},
		"member":   {ID: uuid.New(), ZitadelSubject: "authz-member-" + sfx, Email: "authz-member-" + sfx + "@test.local"},
		"lead":     {ID: uuid.New(), ZitadelSubject: "authz-lead-" + sfx, Email: "authz-lead-" + sfx + "@test.local"},
		"outsider": {ID: uuid.New(), ZitadelSubject: "authz-out-" + sfx, Email: "authz-out-" + sfx + "@test.local"},
	}
	for _, o := range []*models.Organization{orgA, orgB} {
		if err := db.Create(o).Error; err != nil {
			t.Fatalf("create org: %v", err)
		}
	}
	for _, u := range users {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}
	}

	memberships := map[uuid.UUID]uuid.UUID{}
	for _, name := range []string{"owner", "member", "lead"} {
		m := &models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: users[name].ID}
		if err := db.Create(m).Error; err != nil {
			t.Fatalf("create orgA membership: %v", err)
		}
		memberships[users[name].ID] = m.ID
	}
	outsiderMembership := &models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: users["outsider"].ID}
	if err := db.Create(outsiderMembership).Error; err != nil {
		t.Fatalf("create orgB membership: %v", err)
	}
	memberships[users["outsider"].ID] = outsiderMembership.ID

	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	devTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "developers"}
	leadsTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "leads"}
	for _, tm := range []*models.Team{ownersTeam, devTeam, leadsTeam} {
		if err := db.Create(tm).Error; err != nil {
			t.Fatalf("create team: %v", err)
		}
	}
	if err := db.Create(&models.TeamOrganizationAccess{ID: uuid.New(), TeamID: leadsTeam.ID, ManageTeams: true}).Error; err != nil {
		t.Fatalf("create leads org access: %v", err)
	}
	for teamID, userID := range map[uuid.UUID]uuid.UUID{
		ownersTeam.ID: users["owner"].ID,
		devTeam.ID:    users["member"].ID,
		leadsTeam.ID:  users["lead"].ID,
	} {
		if err := db.Create(&models.TeamMember{ID: uuid.New(), TeamID: teamID, UserID: userID}).Error; err != nil {
			t.Fatalf("create team member: %v", err)
		}
	}

	t.Cleanup(func() {
		teamIDs := []uuid.UUID{ownersTeam.ID, devTeam.ID, leadsTeam.ID}
		db.Where("team_id IN ?", teamIDs).Delete(&models.TeamMember{})
		db.Where("team_id IN ?", teamIDs).Delete(&models.TeamOrganizationAccess{})
		db.Where("id IN ?", teamIDs).Delete(&models.Team{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		for _, u := range users {
			db.Where("id = ?", u.ID).Delete(&models.User{})
		}
	})

	teamRepo := repository.NewTeamRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	userRepo := repository.NewUserRepository(db)
	authService := auth.NewService(userRepo)
	rbacService := rbac.NewServiceWithTeams(orgRepo, teamRepo, repository.NewProjectRepository(db))
	h := NewTeamMemberHandlerV2(teamRepo, orgRepo, userRepo, authService, rbacService)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(testUserAuth())
	router.GET("/api/v2/teams/:id/relationships/organization-memberships", h.ListOrganizationMemberships)
	router.POST("/api/v2/teams/:id/relationships/organization-memberships", h.AddOrganizationMemberships)
	router.DELETE("/api/v2/teams/:id/relationships/organization-memberships", h.RemoveOrganizationMemberships)

	return &teamAuthzFixture{
		router:      router,
		teamRepo:    teamRepo,
		ownersTeam:  ownersTeam,
		devTeam:     devTeam,
		owner:       users["owner"],
		member:      users["member"],
		lead:        users["lead"],
		outsider:    users["outsider"],
		memberships: memberships,
	}
}

func membershipPayload(membershipID uuid.UUID) map[string]any {
	return map[string]any{
		"data": []map[string]string{{"type": "organization-memberships", "id": membershipID.String()}},
	}
}

func (f *teamAuthzFixture) teamPath(teamID uuid.UUID) string {
	return "/api/v2/teams/" + teamID.String() + "/relationships/organization-memberships"
}

func (f *teamAuthzFixture) userInTeam(t *testing.T, teamID, userID uuid.UUID) bool {
	t.Helper()
	members, err := f.teamRepo.GetMembers(teamID)
	if err != nil {
		t.Fatalf("get members: %v", err)
	}
	for _, m := range members {
		if m.ID == userID {
			return true
		}
	}
	return false
}

// TestAuthzTeamMembers_AddOrganizationMemberships is the AUD-003 escalation matrix:
// POST /teams/:id/relationships/organization-memberships must be denied for callers
// without team-management permission, and the owners team must only be manageable by owners.
func TestAuthzTeamMembers_AddOrganizationMemberships(t *testing.T) {
	f := setupTeamAuthzFixture(t)

	cases := []struct {
		name       string
		caller     uuid.UUID
		team       uuid.UUID
		membership uuid.UUID
		wantStatus int
	}{
		// The AUD-003 exploit: a plain member adds their own membership to the owners team.
		{"member self-escalates to owners -> 403", f.member.ID, f.ownersTeam.ID, f.memberships[f.member.ID], http.StatusForbidden},
		// ManageTeams grant is not enough for the owners team (would still be an escalation).
		{"lead with ManageTeams touches owners -> 403", f.lead.ID, f.ownersTeam.ID, f.memberships[f.lead.ID], http.StatusForbidden},
		// Plain member has no team-management permission at all.
		{"member adds to developers -> 403", f.member.ID, f.devTeam.ID, f.memberships[f.member.ID], http.StatusForbidden},
		// Cross-tenant: an orgB user mutating an orgA team (JWT identities bypass the org wall).
		{"outsider adds orgA member to developers -> 403", f.outsider.ID, f.devTeam.ID, f.memberships[f.member.ID], http.StatusForbidden},
		// Anonymous (no user in context).
		{"anonymous -> 401", uuid.Nil, f.devTeam.ID, f.memberships[f.member.ID], http.StatusUnauthorized},
		// Legitimate paths must keep working.
		{"owner adds lead to developers -> 204", f.owner.ID, f.devTeam.ID, f.memberships[f.lead.ID], http.StatusNoContent},
		{"lead with ManageTeams adds member to leads' sibling team -> 204", f.lead.ID, f.devTeam.ID, f.memberships[f.owner.ID], http.StatusNoContent},
		{"owner manages owners team -> 204", f.owner.ID, f.ownersTeam.ID, f.memberships[f.lead.ID], http.StatusNoContent},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := authzRequest(t, f.router, http.MethodPost, f.teamPath(tc.team), tc.caller, membershipPayload(tc.membership))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}

	// Denied additions must not have mutated membership.
	if f.userInTeam(t, f.ownersTeam.ID, f.member.ID) {
		t.Error("denied request still added member to owners team - escalation not closed")
	}
	if f.userInTeam(t, f.ownersTeam.ID, f.lead.ID) == false {
		// owner added lead to owners in the last legit case above
		t.Error("owner-approved addition to owners team did not persist")
	}
}

// TestAuthzTeamMembers_RemoveOrganizationMemberships covers the lockout half of AUD-003:
// stripping owners from the owners team must require owner permission.
func TestAuthzTeamMembers_RemoveOrganizationMemberships(t *testing.T) {
	f := setupTeamAuthzFixture(t)

	cases := []struct {
		name       string
		caller     uuid.UUID
		team       uuid.UUID
		membership uuid.UUID
		wantStatus int
	}{
		{"member strips owner from owners -> 403", f.member.ID, f.ownersTeam.ID, f.memberships[f.owner.ID], http.StatusForbidden},
		{"lead with ManageTeams strips owner from owners -> 403", f.lead.ID, f.ownersTeam.ID, f.memberships[f.owner.ID], http.StatusForbidden},
		{"outsider removes orgA member -> 403", f.outsider.ID, f.devTeam.ID, f.memberships[f.member.ID], http.StatusForbidden},
		{"anonymous -> 401", uuid.Nil, f.devTeam.ID, f.memberships[f.member.ID], http.StatusUnauthorized},
		{"owner removes member from developers -> 204", f.owner.ID, f.devTeam.ID, f.memberships[f.member.ID], http.StatusNoContent},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := authzRequest(t, f.router, http.MethodDelete, f.teamPath(tc.team), tc.caller, membershipPayload(tc.membership))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}

	if f.userInTeam(t, f.ownersTeam.ID, f.owner.ID) == false {
		t.Error("denied removals still stripped the owner from the owners team - lockout not closed")
	}
	if f.userInTeam(t, f.devTeam.ID, f.member.ID) {
		t.Error("owner-approved removal from developers did not persist")
	}
}

// TestAuthzTeamMembers_ListOrganizationMemberships: the read side must at least be
// org-scoped — team membership rosters (usernames + emails) are tenant data.
func TestAuthzTeamMembers_ListOrganizationMemberships(t *testing.T) {
	f := setupTeamAuthzFixture(t)

	cases := []struct {
		name       string
		caller     uuid.UUID
		wantStatus int
	}{
		{"org member lists -> 200", f.member.ID, http.StatusOK},
		{"outsider lists orgA team -> 403", f.outsider.ID, http.StatusForbidden},
		{"anonymous -> 401", uuid.Nil, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := authzRequest(t, f.router, http.MethodGet, f.teamPath(f.devTeam.ID), tc.caller, nil)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}
