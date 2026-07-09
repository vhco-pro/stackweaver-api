// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-004 registry-module authorization matrix. The publish/read plane had no org
// membership or manage-modules check, so any authenticated caller (incl. JWT
// identities, which bypass the org wall) could create modules in, wipe, or read
// any org's registry by name. This extends the AUD-114 harness with those cases.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAuthzRegistryModules

//go:build integration
// +build integration

package handlers

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

type registryAuthzFixture struct {
	router   *gin.Engine
	orgAName string
	owner    *models.User // orgA "owners" team → manage-modules
	member   *models.User // orgA "developers" team → no manage-modules, but a member
	outsider *models.User // orgB only
}

func setupRegistryAuthzFixture(t *testing.T) *registryAuthzFixture {
	t.Helper()
	db := setupAuthzTestDB(t)
	if err := db.AutoMigrate(&models.Module{}, &models.ModuleVersion{}); err != nil {
		t.Fatalf("migrate modules: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "regauthz-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "regauthz-b-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "reg-own-" + sfx, Email: "reg-own-" + sfx + "@test.local"}
	member := &models.User{ID: uuid.New(), ZitadelSubject: "reg-mem-" + sfx, Email: "reg-mem-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "reg-out-" + sfx, Email: "reg-out-" + sfx + "@test.local"}

	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	devTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "developers"}

	seed := []interface{}{
		orgA, orgB, owner, member, outsider, ownersTeam, devTeam,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: member.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: devTeam.ID, UserID: member.ID},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Module{})
		db.Where("team_id IN ?", []uuid.UUID{ownersTeam.ID, devTeam.ID}).Delete(&models.TeamMember{})
		db.Where("id IN ?", []uuid.UUID{ownersTeam.ID, devTeam.ID}).Delete(&models.Team{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		for _, u := range []*models.User{owner, member, outsider} {
			db.Where("id = ?", u.ID).Delete(&models.User{})
		}
	})

	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	// publisher/github/vcs are only reached on a successful create — not exercised by
	// the denial cases here — so nil is safe for this authorization matrix.
	h := NewRegistryPublishingHandler(
		repository.NewModuleRepository(db), repository.NewModuleVersionRepository(db),
		orgRepo, nil, authService, rbacService, nil, nil,
	)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(testUserAuth())
	g := router.Group("/api/v2/organizations/:name/registry/modules")
	g.POST("", h.CreateModule)
	g.GET("", h.ListModules)
	g.DELETE("", h.DeleteAllModules)

	return &registryAuthzFixture{router: router, orgAName: orgA.Name, owner: owner, member: member, outsider: outsider}
}

func (f *registryAuthzFixture) path() string {
	return "/api/v2/organizations/" + f.orgAName + "/registry/modules"
}

// TestAuthzRegistryModules_Manage: create/wipe require manage-modules; a plain
// member and a cross-org caller must be denied.
func TestAuthzRegistryModules_Manage(t *testing.T) {
	f := setupRegistryAuthzFixture(t)

	cases := []struct {
		name       string
		method     string
		caller     uuid.UUID
		body       any
		wantStatus int
	}{
		// The AUD-004 exploit: a non-manager creates a module in the org.
		{"member creates module -> 403", http.MethodPost, f.member.ID, map[string]string{"name": "m", "provider": "aws"}, http.StatusForbidden},
		{"outsider creates module -> 403", http.MethodPost, f.outsider.ID, map[string]string{"name": "m", "provider": "aws"}, http.StatusForbidden},
		{"anonymous creates module -> 401", http.MethodPost, uuid.Nil, map[string]string{"name": "m", "provider": "aws"}, http.StatusUnauthorized},
		// Wipe the whole registry.
		{"member wipes registry -> 403", http.MethodDelete, f.member.ID, nil, http.StatusForbidden},
		{"outsider wipes registry -> 403", http.MethodDelete, f.outsider.ID, nil, http.StatusForbidden},
		{"anonymous wipes registry -> 401", http.MethodDelete, uuid.Nil, nil, http.StatusUnauthorized},
		// The owner (manage-modules) may wipe (no modules seeded -> 200).
		{"owner wipes registry -> 200", http.MethodDelete, f.owner.ID, nil, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := authzRequest(t, f.router, tc.method, f.path(), tc.caller, tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestAuthzRegistryModules_Read: module listings expose VCS wiring, so a non-member
// of the org must be denied while a member (any team) may read.
func TestAuthzRegistryModules_Read(t *testing.T) {
	f := setupRegistryAuthzFixture(t)

	cases := []struct {
		name       string
		caller     uuid.UUID
		wantStatus int
	}{
		{"owner lists -> 200", f.owner.ID, http.StatusOK},
		{"member lists -> 200", f.member.ID, http.StatusOK},
		{"outsider lists -> 403", f.outsider.ID, http.StatusForbidden},
		{"anonymous lists -> 401", uuid.Nil, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := authzRequest(t, f.router, http.MethodGet, f.path(), tc.caller, nil)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// silence unused import if gorm is only referenced transitively.
var _ = gorm.ErrRecordNotFound
