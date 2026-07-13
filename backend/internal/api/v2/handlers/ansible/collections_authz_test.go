// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-128 job-collections authorization. ListJobCollections (GET
// /ansible/jobs/:id/collections) is keyed by job ID but performed no auth/RBAC —
// any authenticated JWT identity could hit it for any job. The listing is static
// today, but the endpoint is designed to track per-job installations, so it must be
// gated on the job's read permission now (mirroring jobs.go Get). This test drives
// the real handler + real rbac.Service + real Postgres.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is
// strictly row-scoped (the DB may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestJobCollectionsAuthz

//go:build integration
// +build integration

package ansible

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
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestJobCollectionsAuthz(t *testing.T) {
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
		&models.Team{}, &models.TeamMember{}, &models.TeamProjectAccess{}, &models.TeamOrganizationAccess{},
		&models.Project{}, &models.AnsibleInventory{}, &models.AnsibleJob{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "coll-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "coll-b-" + sfx}
	member := &models.User{ID: uuid.New(), ZitadelSubject: "coll-mem-" + sfx, Email: "coll-mem-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "coll-out-" + sfx, Email: "coll-out-" + sfx + "@test.local"}
	devsTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "devs-" + sfx}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "projA-" + sfx}
	inv := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: orgA.ID, Name: "inv-" + sfx, Type: models.InventoryTypeStatic}
	job := &models.AnsibleJob{ID: uuid.New(), ProjectID: projA.ID, InventoryID: inv.ID, JobType: "run", Status: "pending"}

	adminAccess := "admin" // cascades ansible job read to the project's resources
	seed := []interface{}{
		orgA, orgB, member, outsider, devsTeam, projA, inv, job,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: devsTeam.ID, UserID: member.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: devsTeam.ID, ProjectID: projA.ID, Access: &adminAccess},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		db.Where("id = ?", job.ID).Delete(&models.AnsibleJob{})
		db.Where("id = ?", inv.ID).Delete(&models.AnsibleInventory{})
		db.Where("team_id = ?", devsTeam.ID).Delete(&models.TeamProjectAccess{})
		db.Where("team_id = ?", devsTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", devsTeam.ID).Delete(&models.Team{})
		db.Where("id = ?", projA.ID).Delete(&models.Project{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{member.ID, outsider.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	jobService := ansiblesvc.NewJobService(
		repository.NewAnsibleJobRepository(db), repository.NewAnsiblePlaybookRepository(db),
		repository.NewAnsibleInventoryRepository(db), repository.NewAnsibleJobTemplateRepository(db),
		repository.NewProjectRepository(db), nil,
	)
	h := NewCollectionsHandler(jobService, authService, rbacService)

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
	router.GET("/ansible/jobs/:id/collections", h.ListJobCollections)

	do := func(asUser uuid.UUID) int {
		req := httptest.NewRequest(http.MethodGet, "/ansible/jobs/"+job.ID.String()+"/collections", nil)
		if asUser != uuid.Nil {
			req.Header.Set("X-Test-User", asUser.String())
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do(outsider.ID); code != http.StatusForbidden {
		t.Fatalf("outsider GET job collections = %d, want 403", code)
	}
	if code := do(uuid.Nil); code != http.StatusUnauthorized {
		t.Fatalf("anon GET job collections = %d, want 401", code)
	}
	if code := do(member.ID); code != http.StatusOK {
		t.Fatalf("member GET job collections = %d, want 200", code)
	}
}
