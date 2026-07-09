// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-046 workspace read authorization. GetByOrganizationAndName (GET
// /organizations/:name/workspaces/:workspace_name) and GetByID (GET
// /workspaces/:id) returned the full workspace configuration — VCS repo, agent
// pool, execution mode — with no membership check, so any authenticated user
// (including JWT identities, which bypass the org wall) could read another tenant's
// workspace config by name or UUID. These tests drive the real handler + real
// Postgres and assert cross-tenant and unauthenticated callers are denied while a
// legitimate org member is allowed.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is
// strictly row-scoped (the DB may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestWorkspaceReadAuthz

//go:build integration
// +build integration

package terraform

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

type wsReadFixture struct {
	router        *gin.Engine
	orgName       string
	workspaceName string
	workspaceID   string
	member        *models.User // org A member
	outsider      *models.User // org B only
}

func setupWorkspaceReadAuthz(t *testing.T) *wsReadFixture {
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
		&models.Project{}, &models.Workspace{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "wsread-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "wsread-b-" + sfx}
	member := &models.User{ID: uuid.New(), ZitadelSubject: "wsr-mem-" + sfx, Email: "wsr-mem-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "wsr-out-" + sfx, Email: "wsr-out-" + sfx + "@test.local"}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "projA-" + sfx}
	wsA := &models.Workspace{ID: "ws-" + sfx + "0000000", ProjectID: projA.ID, Name: "wsA-" + sfx}

	seed := []interface{}{
		orgA, orgB, member, outsider, projA, wsA,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: member.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		db.Where("id = ?", wsA.ID).Delete(&models.Workspace{})
		db.Where("id = ?", projA.ID).Delete(&models.Project{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{member.ID, outsider.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	h := NewWorkspaceHandlerV2(
		repository.NewWorkspaceRepository(db), repository.NewProjectRepository(db), orgRepo,
		repository.NewVCSConnectionRepository(db), repository.NewTeamRepository(db),
		nil, nil, authService, nil, rbacService, nil, db,
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
	router.GET("/organizations/:name/workspaces/:workspace_name", h.GetByOrganizationAndName)
	router.GET("/workspaces/:id", h.GetByID)

	return &wsReadFixture{
		router:        router,
		orgName:       orgA.Name,
		workspaceName: wsA.Name,
		workspaceID:   wsA.ID,
		member:        member,
		outsider:      outsider,
	}
}

func wsReadReq(t *testing.T, f *wsReadFixture, path string, asUser uuid.UUID) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec.Code
}

// TestWorkspaceReadAuthz_CrossTenantDenied is the core AUD-046 assertion: an org-B
// outsider must not read org-A workspace config by name or ID, and anonymous callers
// get 401.
func TestWorkspaceReadAuthz_CrossTenantDenied(t *testing.T) {
	f := setupWorkspaceReadAuthz(t)
	paths := []string{
		"/organizations/" + f.orgName + "/workspaces/" + f.workspaceName,
		"/workspaces/" + f.workspaceID,
	}
	for _, p := range paths {
		t.Run("outsider "+p, func(t *testing.T) {
			if code := wsReadReq(t, f, p, f.outsider.ID); code != http.StatusForbidden {
				t.Fatalf("outsider GET %s = %d, want 403", p, code)
			}
		})
		t.Run("anon "+p, func(t *testing.T) {
			if code := wsReadReq(t, f, p, uuid.Nil); code != http.StatusUnauthorized {
				t.Fatalf("anon GET %s = %d, want 401", p, code)
			}
		})
	}
}

// TestWorkspaceReadAuthz_MemberAllowed confirms a legitimate org member still reads
// their own workspace by name and by ID.
func TestWorkspaceReadAuthz_MemberAllowed(t *testing.T) {
	f := setupWorkspaceReadAuthz(t)
	paths := []string{
		"/organizations/" + f.orgName + "/workspaces/" + f.workspaceName,
		"/workspaces/" + f.workspaceID,
	}
	for _, p := range paths {
		if code := wsReadReq(t, f, p, f.member.ID); code != http.StatusOK {
			t.Fatalf("member GET %s = %d, want 200", p, code)
		}
	}
}
