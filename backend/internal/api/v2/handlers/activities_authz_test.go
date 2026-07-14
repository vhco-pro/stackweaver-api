// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-139 activity/audit-log read authorization. ListActivities honored
// attacker-supplied organization_id/user_id/workspace_id filters with no
// membership check, so any authenticated caller could read another tenant's
// entire audit trail by passing ?organization_id=<victim>. These tests drive the
// real handler + real Postgres and assert cross-tenant filters are denied while a
// member reads their own org and an anonymous caller gets 401.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is
// strictly row-scoped. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestActivitiesAuthz

//go:build integration
// +build integration

package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/activity"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type activitiesAuthzFixture struct {
	router   *gin.Engine
	orgAID   uuid.UUID
	member   *models.User // org A member
	outsider *models.User // org B only
}

func setupActivitiesAuthzFixture(t *testing.T) *activitiesAuthzFixture {
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
		&models.Team{}, &models.TeamMember{}, &models.Project{}, &models.Workspace{},
		&models.AuditLog{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "actauthz-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "actauthz-b-" + sfx}
	member := &models.User{ID: uuid.New(), ZitadelSubject: "act-mem-" + sfx, Email: "act-mem-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "act-out-" + sfx, Email: "act-out-" + sfx + "@test.local"}
	orgAID := orgA.ID
	auditRow := &models.AuditLog{ID: uuid.New(), OrganizationID: &orgAID, Action: "create", ResourceType: "workspace"}

	seed := []interface{}{
		orgA, orgB, member, outsider, auditRow,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: member.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		db.Where("id = ?", auditRow.ID).Delete(&models.AuditLog{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{member.ID, outsider.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	activityService := activity.NewService(repository.NewAuditLogRepository(db))
	h := NewActivityHandlerV2(activityService, authService, orgRepo,
		repository.NewWorkspaceRepository(db), repository.NewProjectRepository(db))

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(testUserAuth())
	router.GET("/activities", h.ListActivities)

	return &activitiesAuthzFixture{router: router, orgAID: orgA.ID, member: member, outsider: outsider}
}

func activitiesReq(t *testing.T, f *activitiesAuthzFixture, query string, asUser uuid.UUID) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/activities"+query, nil)
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec.Code
}

// TestActivitiesAuthz_CrossTenantFilterDenied is the core AUD-139 assertion: an
// org-B outsider filtering by org A's id must be denied (403), not handed org A's
// audit trail; anonymous callers get 401.
func TestActivitiesAuthz_CrossTenantFilterDenied(t *testing.T) {
	f := setupActivitiesAuthzFixture(t)
	q := "?organization_id=" + f.orgAID.String()

	if code := activitiesReq(t, f, q, f.outsider.ID); code != http.StatusForbidden {
		t.Fatalf("outsider GET /activities%s = %d, want 403", q, code)
	}
	if code := activitiesReq(t, f, q, uuid.Nil); code != http.StatusUnauthorized {
		t.Fatalf("anon GET /activities%s = %d, want 401", q, code)
	}
}

// TestActivitiesAuthz_MemberOrgFilterAllowed confirms a member of the requested
// org still reads that org's activity feed.
func TestActivitiesAuthz_MemberOrgFilterAllowed(t *testing.T) {
	f := setupActivitiesAuthzFixture(t)
	q := "?organization_id=" + f.orgAID.String()
	if code := activitiesReq(t, f, q, f.member.ID); code != http.StatusOK {
		t.Fatalf("member GET /activities%s = %d, want 200", q, code)
	}
}

// TestActivitiesAuthz_NoFilterDefaultsToSelf confirms a caller with no org/workspace
// filter still gets a 200 (scoped to their own rows), preserving the default feed.
func TestActivitiesAuthz_NoFilterDefaultsToSelf(t *testing.T) {
	f := setupActivitiesAuthzFixture(t)
	if code := activitiesReq(t, f, "", f.outsider.ID); code != http.StatusOK {
		t.Fatalf("self GET /activities = %d, want 200", code)
	}
}
