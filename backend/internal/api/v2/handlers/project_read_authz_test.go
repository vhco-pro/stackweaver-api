// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-046 project read authorization. ProjectHandlerV2.Get (GET
// /organizations/:name/projects/:project_name) returned project configuration with
// no membership check — unlike its sibling GetByID, which gates on UserInOrg — so
// any authenticated user could read another tenant's project config by name. This
// test drives the real handler + real Postgres and asserts cross-tenant and
// unauthenticated callers are denied while a legitimate member is allowed.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is
// strictly row-scoped (the DB may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestProjectReadAuthz

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
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestProjectReadAuthz(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.OrganizationMember{}, &models.Project{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "prread-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "prread-b-" + sfx}
	member := &models.User{ID: uuid.New(), ZitadelSubject: "pr-mem-" + sfx, Email: "pr-mem-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "pr-out-" + sfx, Email: "pr-out-" + sfx + "@test.local"}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "projA-" + sfx}

	seed := []interface{}{
		orgA, orgB, member, outsider, projA,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: member.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		db.Where("id = ?", projA.ID).Delete(&models.Project{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{member.ID, outsider.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	h := NewProjectHandlerV2(repository.NewProjectRepository(db), orgRepo, repository.NewTeamRepository(db), nil, nil, authService, nil, rbacService)

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
	router.GET("/organizations/:name/projects/:project_name", h.Get)

	do := func(asUser uuid.UUID) int {
		req := httptest.NewRequest(http.MethodGet, "/organizations/"+orgA.Name+"/projects/"+projA.Name, nil)
		if asUser != uuid.Nil {
			req.Header.Set("X-Test-User", asUser.String())
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do(outsider.ID); code != http.StatusForbidden {
		t.Fatalf("outsider GET project = %d, want 403", code)
	}
	if code := do(uuid.Nil); code != http.StatusUnauthorized {
		t.Fatalf("anon GET project = %d, want 401", code)
	}
	if code := do(member.ID); code != http.StatusOK {
		t.Fatalf("member GET project = %d, want 200", code)
	}
}
