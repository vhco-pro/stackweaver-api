// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A team created with `allow-member-token-management: false` must be stored with it off, one
// created without the attribute must have it on, and the two default teams of a new organization
// must carry the values the code gives them: on for owners, off for viewers. The tfe provider
// sends the attribute on every tfe_team create and reads it back, so a server that stored true
// for a sent false plans a diff on every run.
//
// The defect this test was written against: Team.AllowMemberTokenManagement carried
// `gorm:"default:true"`, and GORM substitutes a literal default for a zero value in the INSERT
// (and writes it back into the struct), so a sent false, and the viewers team's hard-coded false,
// were both stored as true. The default lives in TeamHandlerV2.Create instead.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestTeamCreate_AllowMemberTokenManagement

//go:build integration

package handlers

import (
	"net/http"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// deleteOrganizationsByName removes the organizations with exactly these names and everything
// OrganizationHandlerV2.Create bootstraps under them (default teams, memberships, the default
// project and agent pool, the reserved-name record). Row-scoped: it only ever follows the ids of
// the named organizations.
func deleteOrganizationsByName(db *gorm.DB, names []string) {
	var orgIDs []uuid.UUID
	db.Model(&models.Organization{}).Where("name IN ?", names).Pluck("id", &orgIDs)
	if len(orgIDs) > 0 {
		var teamIDs []uuid.UUID
		db.Model(&models.Team{}).Where("organization_id IN ?", orgIDs).Pluck("id", &teamIDs)
		if len(teamIDs) > 0 {
			db.Where("team_id IN ?", teamIDs).Delete(&models.TeamMember{})
			db.Where("team_id IN ?", teamIDs).Delete(&models.TeamOrganizationAccess{})
			db.Where("team_id IN ?", teamIDs).Delete(&models.TeamProjectAccess{})
		}
		db.Model(&models.Organization{}).Where("id IN ?", orgIDs).Update("default_agent_pool_id", nil)
		db.Where("organization_id IN ?", orgIDs).Delete(&models.AgentPool{})
		db.Where("organization_id IN ?", orgIDs).Delete(&models.Team{})
		db.Where("organization_id IN ?", orgIDs).Delete(&models.OrganizationMember{})
		db.Where("organization_id IN ?", orgIDs).Delete(&models.Project{})
		db.Where("id IN ?", orgIDs).Delete(&models.Organization{})
	}
	db.Where("name IN ?", names).Delete(&models.ReservedOrganizationName{})
}

func TestTeamCreate_AllowMemberTokenManagementIsStoredAsSent(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	// Registered first, so it runs after the row cleanup below. The suite shares one Postgres with
	// every other session on the host, and a pool left open holds connections until the test
	// binary exits.
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.ReservedOrganizationName{},
		&models.OrganizationMember{}, &models.Team{}, &models.TeamMember{},
		&models.TeamOrganizationAccess{}, &models.Project{}, &models.TeamProjectAccess{},
		&models.AgentPool{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	owner := &models.User{ID: uuid.New(), ZitadelSubject: "teamtok-" + sfx, Email: "teamtok-" + sfx + "@test.local"}
	if err := db.Create(owner).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// Both organizations are created through the handler, so each gets its default teams and the
	// caller becomes an owner. The first hosts the team creates, the second is the fresh
	// organization whose default teams are read back.
	hostOrg := "teamtok-host-" + sfx
	freshOrg := "teamtok-fresh-" + sfx
	t.Cleanup(func() {
		deleteOrganizationsByName(db, []string{hostOrg, freshOrg})
		db.Where("id = ?", owner.ID).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo)
	orgH := NewOrganizationHandlerV2(orgRepo, teamRepo, projectRepo, repository.NewAgentPoolRepository(db), authService, nil, rbacService, db)
	teamH := NewTeamHandlerV2(teamRepo, orgRepo, authService, rbacService)

	router := storedAsSentRouter()
	router.POST("/api/v2/organizations", orgH.Create)
	router.POST("/api/v2/organizations/:name/teams", teamH.Create)
	router.GET("/api/v2/teams/:id", teamH.GetByID)

	createOrg := func(t *testing.T, name string) uuid.UUID {
		t.Helper()
		code, body := storedAsSentCall(t, router, http.MethodPost, "/api/v2/organizations", owner.ID,
			storedAsSentDocument(t, "organizations", map[string]any{"name": name, "email": name + "@test.local"}))
		if code != http.StatusCreated {
			t.Fatalf("create organization %s = %d, want 201 (%s)", name, code, body)
		}
		org, err := orgRepo.GetByName(name)
		if err != nil {
			t.Fatalf("read organization %s back: %v", name, err)
		}
		return org.ID
	}
	readTeam := func(t *testing.T, id string) map[string]any {
		t.Helper()
		code, body := storedAsSentCall(t, router, http.MethodGet, "/api/v2/teams/"+id, owner.ID, "")
		if code != http.StatusOK {
			t.Fatalf("read team %s = %d, want 200 (%s)", id, code, body)
		}
		_, attrs := storedAsSentResource(t, body)
		return attrs
	}

	const attr = "allow-member-token-management"
	createOrg(t, hostOrg)

	sent := func(v bool) *bool { return &v }
	cases := []struct {
		name  string
		allow *bool // nil leaves the attribute out
		want  bool
	}{
		{"explicit false", sent(false), false},
		{"explicit true", sent(true), true},
		{"absent", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string]any{"name": "teamtok-" + uuid.NewString()[:8]}
			if tc.allow != nil {
				attrs[attr] = *tc.allow
			}
			code, body := storedAsSentCall(t, router, http.MethodPost, "/api/v2/organizations/"+hostOrg+"/teams",
				owner.ID, storedAsSentDocument(t, "teams", attrs))
			if code != http.StatusCreated {
				t.Fatalf("create team = %d, want 201 (%s)", code, body)
			}
			id, created := storedAsSentResource(t, body)
			assertStoredBool(t, "create response", created, attr, tc.want)
			assertStoredBool(t, "read back", readTeam(t, id), attr, tc.want)
		})
	}

	t.Run("default teams of a new organization", func(t *testing.T) {
		orgID := createOrg(t, freshOrg)
		for name, want := range map[string]bool{"owners": true, "viewers": false} {
			team, err := teamRepo.GetByName(orgID, name)
			if err != nil {
				t.Fatalf("find the %s team: %v", name, err)
			}
			assertStoredBool(t, name+" team", readTeam(t, team.ID.String()), attr, want)
		}
	})
}
