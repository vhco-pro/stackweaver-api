// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-101 variable-set authorization matrix. Every variable_sets.go handler fetched
// the user and then discarded it (`_ = user`) under a TODO — the struct had no
// rbacService — so any authenticated JWT identity could read, create, modify, delete
// and re-assign variable sets (including sensitive values) in any organization, by
// org name or varset- ID. These tests drive the real handler + real rbac.Service +
// real Postgres and assert the TFE model (see docs: managing-variables / go-tfe
// ProjectVariableSetsPermissionType):
//
//   - org-owned sets: any org member reads; "Manage all workspaces"/"projects" writes;
//   - project-owned sets: the project's team access governs read/write;
//   - owners always manage everything; cross-tenant and anonymous callers are denied.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is
// strictly row-scoped (the DB may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestVarsetAuthz

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

type varsetAuthzFixture struct {
	router    *gin.Engine
	orgName   string
	owner     *models.User // orgA owners team
	projAdmin *models.User // orgA, project admin on projA, no org-manage
	outsider  *models.User // orgB only
	orgVarset string       // organization-owned (ProjectID nil)
	projVarset string      // project-owned (ProjectID = projA)
}

func setupVarsetAuthz(t *testing.T) *varsetAuthzFixture {
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
		&models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{}, &models.TeamProjectAccess{},
		&models.Project{}, &models.VariableSet{}, &models.VariableSetVariable{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "vsauthz-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "vsauthz-b-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "vs-own-" + sfx, Email: "vs-own-" + sfx + "@test.local"}
	projAdmin := &models.User{ID: uuid.New(), ZitadelSubject: "vs-padm-" + sfx, Email: "vs-padm-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "vs-out-" + sfx, Email: "vs-out-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	devsTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "devs-" + sfx}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "projA-" + sfx}
	orgVarset := &models.VariableSet{ID: "varset-org" + sfx + "0000", OrganizationID: orgA.ID, Name: "orgvs-" + sfx, Scope: "organization", CreatedBy: owner.ID}
	projVarset := &models.VariableSet{ID: "varset-prj" + sfx + "0000", OrganizationID: orgA.ID, ProjectID: &projA.ID, Name: "prjvs-" + sfx, Scope: "workspace", CreatedBy: owner.ID}

	adminAccess := "admin" // grants project-owned varset write to devs team
	seed := []interface{}{
		orgA, orgB, owner, projAdmin, outsider, ownersTeam, devsTeam, projA, orgVarset, projVarset,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: devsTeam.ID, UserID: projAdmin.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: devsTeam.ID, ProjectID: projA.ID, Access: &adminAccess},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		// Children before parents (FK order). Also sweep any varsets the create test made.
		db.Where("variable_set_id IN (SELECT id FROM variable_sets WHERE organization_id IN ?)", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.VariableSetVariable{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.VariableSet{})
		db.Where("team_id = ?", devsTeam.ID).Delete(&models.TeamProjectAccess{})
		db.Where("team_id IN ?", []uuid.UUID{ownersTeam.ID, devsTeam.ID}).Delete(&models.TeamMember{})
		db.Where("id IN ?", []uuid.UUID{ownersTeam.ID, devsTeam.ID}).Delete(&models.Team{})
		db.Where("id = ?", projA.ID).Delete(&models.Project{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{owner.ID, projAdmin.ID, outsider.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	h := NewVariableSetHandlerV2(
		repository.NewVariableSetRepository(db),
		repository.NewVariableSetVariableRepository(db),
		orgRepo,
		repository.NewProjectRepository(db),
		nil, // workspaceRepo — unused on the tested paths
		nil, // jobTemplateRepo — unused on the tested paths
		authService,
		rbacService,
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
	router.GET("/organizations/:name/varsets", h.ListVariableSets)
	router.POST("/organizations/:name/varsets", h.CreateVariableSet)
	router.GET("/varsets/:id", h.GetVariableSet)
	router.PATCH("/varsets/:id", h.UpdateVariableSet)
	router.DELETE("/varsets/:id", h.DeleteVariableSet)
	router.GET("/varsets/:id/relationships/vars", h.ListVariableSetVariables)
	router.POST("/varsets/:id/relationships/vars", h.CreateVariableSetVariable)

	return &varsetAuthzFixture{
		router:     router,
		orgName:    orgA.Name,
		owner:      owner,
		projAdmin:  projAdmin,
		outsider:   outsider,
		orgVarset:  orgVarset.ID,
		projVarset: projVarset.ID,
	}
}

func varsetReq(t *testing.T, f *varsetAuthzFixture, method, path, body string, asUser uuid.UUID) int {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec.Code
}

// TestVarsetAuthz_CrossTenantDenied is the core AUD-101 assertion: an org-B outsider
// must not reach any org-A variable-set endpoint, and anonymous callers get 401.
func TestVarsetAuthz_CrossTenantDenied(t *testing.T) {
	f := setupVarsetAuthz(t)
	patch := `{"data":{"type":"varsets","attributes":{"description":"pwn"}}}`
	newVar := `{"data":{"type":"vars","attributes":{"key":"k","value":"v"}}}`

	cases := []struct{ m, p, b string }{
		{http.MethodGet, "/organizations/" + f.orgName + "/varsets", ""},
		{http.MethodPost, "/organizations/" + f.orgName + "/varsets", `{"data":{"type":"varsets","attributes":{"name":"x"}}}`},
		{http.MethodGet, "/varsets/" + f.orgVarset, ""},
		{http.MethodGet, "/varsets/" + f.projVarset, ""},
		{http.MethodPatch, "/varsets/" + f.orgVarset, patch},
		{http.MethodDelete, "/varsets/" + f.orgVarset, ""},
		{http.MethodGet, "/varsets/" + f.orgVarset + "/relationships/vars", ""},
		{http.MethodPost, "/varsets/" + f.orgVarset + "/relationships/vars", newVar},
	}
	for _, e := range cases {
		t.Run("outsider "+e.m+" "+e.p, func(t *testing.T) {
			if code := varsetReq(t, f, e.m, e.p, e.b, f.outsider.ID); code != http.StatusForbidden {
				t.Fatalf("outsider %s %s = %d, want 403", e.m, e.p, code)
			}
		})
		t.Run("anon "+e.m+" "+e.p, func(t *testing.T) {
			if code := varsetReq(t, f, e.m, e.p, e.b, uuid.Nil); code != http.StatusUnauthorized {
				t.Fatalf("anon %s %s = %d, want 401", e.m, e.p, code)
			}
		})
	}
}

// TestVarsetAuthz_OwnerAllowed confirms an owner reads their org's variable sets.
func TestVarsetAuthz_OwnerAllowed(t *testing.T) {
	f := setupVarsetAuthz(t)
	reads := []string{
		"/organizations/" + f.orgName + "/varsets",
		"/varsets/" + f.orgVarset,
		"/varsets/" + f.projVarset,
		"/varsets/" + f.orgVarset + "/relationships/vars",
	}
	for _, p := range reads {
		if code := varsetReq(t, f, http.MethodGet, p, "", f.owner.ID); code != http.StatusOK {
			t.Fatalf("owner GET %s = %d, want 200", p, code)
		}
	}
}

// TestVarsetAuthz_TwoTierModel proves the TFE-faithful split: a project admin (no
// org-level manage) can write the project-owned set but NOT the org-owned set, while
// still reading both as an org member.
func TestVarsetAuthz_TwoTierModel(t *testing.T) {
	f := setupVarsetAuthz(t)
	patch := `{"data":{"type":"varsets","attributes":{"description":"edited"}}}`

	if code := varsetReq(t, f, http.MethodPatch, "/varsets/"+f.projVarset, patch, f.projAdmin.ID); code != http.StatusOK {
		t.Fatalf("projAdmin PATCH project-owned varset = %d, want 200", code)
	}
	if code := varsetReq(t, f, http.MethodPatch, "/varsets/"+f.orgVarset, patch, f.projAdmin.ID); code != http.StatusForbidden {
		t.Fatalf("projAdmin PATCH org-owned varset = %d, want 403", code)
	}
	if code := varsetReq(t, f, http.MethodGet, "/varsets/"+f.orgVarset, "", f.projAdmin.ID); code != http.StatusOK {
		t.Fatalf("projAdmin GET org-owned varset = %d, want 200 (org member reads)", code)
	}
	if code := varsetReq(t, f, http.MethodGet, "/varsets/"+f.projVarset, "", f.projAdmin.ID); code != http.StatusOK {
		t.Fatalf("projAdmin GET project-owned varset = %d, want 200", code)
	}
}
