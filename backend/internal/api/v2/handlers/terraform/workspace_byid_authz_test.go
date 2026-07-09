// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-011 workspace by-ID mutation authorization matrix. The TFE-compatible by-ID
// routes DeleteByID (DELETE /workspaces/:id), SafeDeleteByID (POST
// /workspaces/:id/actions/safe-delete) and UpdateByID (PATCH /workspaces/:id)
// performed NO RBAC check, while their org+name twins (Update/Delete) gate on
// org-manage OR workspace-write. Any authenticated user — including JWT identities,
// which bypass the org wall — could delete or reconfigure (repoint VCS repo, change
// agent pool) any workspace by UUID. These tests drive the real handler + real
// rbac.Service + real Postgres and assert cross-tenant and unauthenticated callers
// are denied while a legitimate org member is allowed.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is
// strictly row-scoped (the DB may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestWorkspaceByIDAuthz

//go:build integration
// +build integration

package terraform

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

type wsAuthzFixture struct {
	router      *gin.Engine
	workspaceID string
	owner       *models.User // org A owners team
	outsider    *models.User // org B only
}

func setupWorkspaceByIDAuthzFixture(t *testing.T) *wsAuthzFixture {
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
		&models.Project{}, &models.Workspace{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "wsauthz-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "wsauthz-b-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "ws-own-" + sfx, Email: "ws-own-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "ws-out-" + sfx, Email: "ws-out-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "projA-" + sfx}
	wsA := &models.Workspace{ID: "ws-" + sfx + "0000000", ProjectID: projA.ID, Name: "wsA"}

	adminAccess := "admin" // grants workspace write on the project's workspaces
	seed := []interface{}{
		orgA, orgB, owner, outsider, ownersTeam, projA, wsA,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: ownersTeam.ID, ProjectID: projA.ID, Access: &adminAccess},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		// Delete children before parents to satisfy FK constraints (team_project_access
		// references both team and project; projects reference organizations).
		db.Where("id = ?", wsA.ID).Delete(&models.Workspace{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamProjectAccess{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", ownersTeam.ID).Delete(&models.Team{})
		db.Where("id = ?", projA.ID).Delete(&models.Project{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{owner.ID, outsider.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	h := NewWorkspaceHandlerV2(
		repository.NewWorkspaceRepository(db),
		repository.NewProjectRepository(db),
		orgRepo,
		repository.NewVCSConnectionRepository(db),
		repository.NewTeamRepository(db),
		nil, // poolRepo — unused on the gated paths
		nil, // runRepo — unused on the gated paths
		authService,
		nil, // activityService — by-ID handlers don't log
		rbacService,
		nil, // vcsRegistry — maybeRegisterADOWebhook is nil-safe
		db,
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
	router.DELETE("/workspaces/:id", h.DeleteByID)
	router.POST("/workspaces/:id/actions/safe-delete", h.SafeDeleteByID)
	router.PATCH("/workspaces/:id", h.UpdateByID)

	return &wsAuthzFixture{router: router, workspaceID: wsA.ID, owner: owner, outsider: outsider}
}

func wsAuthzReq(t *testing.T, f *wsAuthzFixture, method, path, body string, asUser uuid.UUID) int {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec.Code
}

// TestWorkspaceByIDAuthz_CrossTenantDenied is the core AUD-011 assertion: an org-B
// outsider must not reach any org-A by-ID mutation endpoint, and anonymous callers
// get 401.
func TestWorkspaceByIDAuthz_CrossTenantDenied(t *testing.T) {
	f := setupWorkspaceByIDAuthzFixture(t)
	base := "/workspaces/" + f.workspaceID
	patchBody := `{"data":{"type":"workspaces","attributes":{"description":"pwn"}}}`

	cases := []struct{ m, p, b string }{
		{http.MethodDelete, base, ""},
		{http.MethodPost, base + "/actions/safe-delete", ""},
		{http.MethodPatch, base, patchBody},
	}

	for _, e := range cases {
		t.Run("outsider "+e.m+" "+e.p, func(t *testing.T) {
			if code := wsAuthzReq(t, f, e.m, e.p, e.b, f.outsider.ID); code != http.StatusForbidden {
				t.Fatalf("outsider %s %s = %d, want 403", e.m, e.p, code)
			}
		})
		t.Run("anon "+e.m+" "+e.p, func(t *testing.T) {
			if code := wsAuthzReq(t, f, e.m, e.p, e.b, uuid.Nil); code != http.StatusUnauthorized {
				t.Fatalf("anon %s %s = %d, want 401", e.m, e.p, code)
			}
		})
	}
}

// TestWorkspaceByIDAuthz_OwnerAllowed confirms a legitimate org member (owners team,
// admin project access) can still update their own workspace by ID — the gate must
// not break the happy path.
func TestWorkspaceByIDAuthz_OwnerAllowed(t *testing.T) {
	f := setupWorkspaceByIDAuthzFixture(t)
	patchBody := `{"data":{"type":"workspaces","attributes":{"description":"owner-edit"}}}`
	if code := wsAuthzReq(t, f, http.MethodPatch, "/workspaces/"+f.workspaceID, patchBody, f.owner.ID); code != http.StatusOK {
		t.Fatalf("owner PATCH workspace = %d, want 200", code)
	}
}
