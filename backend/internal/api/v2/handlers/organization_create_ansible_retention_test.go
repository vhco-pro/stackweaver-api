// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// An organization created with `ansible-job-retention-days` must be stored with the value it was
// sent, 0 included (0 means finished Ansible jobs are kept forever, see
// AnsibleJobRepository.CleanupExpiredJobs), and one created without the attribute gets 90 days.
//
// The defect this test was written against had two halves (#878). OrganizationHandlerV2.Create
// declared the attribute and never copied it, so every value sent on create read back 90. And the
// column carried `gorm:"default:90"`: GORM substitutes a literal default for a zero value in the
// INSERT, so reading the attribute alone would still have turned an explicit 0 into 90. The
// default lives in the create handler instead, and create and update apply one rule to the value.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestOrganizationCreate_AnsibleJobRetention

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

// assertStoredNumber checks one numeric attribute of a response. JSON numbers decode as float64.
func assertStoredNumber(t *testing.T, where string, attrs map[string]any, attr string, want int) {
	t.Helper()
	got, ok := attrs[attr].(float64)
	if !ok {
		t.Errorf("%s: %s is %v (%T), want a number", where, attr, attrs[attr], attrs[attr])
		return
	}
	if int(got) != want {
		t.Errorf("%s: %s = %v, want %d", where, attr, got, want)
	}
}

func TestOrganizationCreate_AnsibleJobRetentionDaysIsStoredAsSent(t *testing.T) {
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

	creator := &models.User{ID: uuid.New(), ZitadelSubject: "orgret-" + sfx, Email: "orgret-" + sfx + "@test.local"}
	if err := db.Create(creator).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	sent := func(v int) *int { return &v }
	cases := []struct {
		name    string
		orgName string
		days    *int // nil leaves the attribute out
		want    int
	}{
		{"explicit thirty", "orgret-30-" + sfx, sent(30), 30},
		{"explicit zero keeps jobs forever", "orgret-0-" + sfx, sent(0), 0},
		{"absent", "orgret-absent-" + sfx, nil, 90},
		// The rule the update path has always applied: a negative value is not a retention, so it
		// is ignored and the default stands.
		{"negative is ignored", "orgret-neg-" + sfx, sent(-5), 90},
	}
	names := make([]string, 0, len(cases))
	for _, tc := range cases {
		names = append(names, tc.orgName)
	}
	t.Cleanup(func() {
		deleteOrganizationsByName(db, names)
		db.Where("id = ?", creator.ID).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	orgH := NewOrganizationHandlerV2(orgRepo, teamRepo, projectRepo, repository.NewAgentPoolRepository(db),
		auth.NewService(repository.NewUserRepository(db)), nil, rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo), db)

	router := storedAsSentRouter()
	router.POST("/api/v2/organizations", orgH.Create)
	router.GET("/api/v2/organizations/:name", orgH.Get)
	router.PATCH("/api/v2/organizations/:name", orgH.Update)

	const attr = "ansible-job-retention-days"
	readBack := func(t *testing.T, orgName string, want int) {
		t.Helper()
		code, body := storedAsSentCall(t, router, http.MethodGet, "/api/v2/organizations/"+orgName, creator.ID, "")
		if code != http.StatusOK {
			t.Fatalf("read = %d, want 200 (%s)", code, body)
		}
		_, read := storedAsSentResource(t, body)
		assertStoredNumber(t, "read back", read, attr, want)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string]any{"name": tc.orgName, "email": tc.orgName + "@test.local"}
			if tc.days != nil {
				attrs[attr] = *tc.days
			}
			code, body := storedAsSentCall(t, router, http.MethodPost, "/api/v2/organizations", creator.ID,
				storedAsSentDocument(t, "organizations", attrs))
			if code != http.StatusCreated {
				t.Fatalf("create = %d, want 201 (%s)", code, body)
			}
			_, created := storedAsSentResource(t, body)
			assertStoredNumber(t, "create response", created, attr, tc.want)
			readBack(t, tc.orgName, tc.want)
		})
	}

	// The update path stored the value before this change and must keep doing so, zero included,
	// with the same rule for a negative one.
	t.Run("update stores zero and ignores a negative value", func(t *testing.T) {
		orgName := cases[0].orgName // created with 30 above
		for _, step := range []struct{ send, want int }{{0, 0}, {-1, 0}, {14, 14}} {
			code, body := storedAsSentCall(t, router, http.MethodPatch, "/api/v2/organizations/"+orgName, creator.ID,
				storedAsSentDocument(t, "organizations", map[string]any{attr: step.send}))
			if code != http.StatusOK {
				t.Fatalf("update with %d = %d, want 200 (%s)", step.send, code, body)
			}
			_, updated := storedAsSentResource(t, body)
			assertStoredNumber(t, "update response", updated, attr, step.want)
			readBack(t, orgName, step.want)
		}
	})
}
