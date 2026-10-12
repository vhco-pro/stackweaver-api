// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// An organization created with `cost-estimation-enabled: false` must be stored with it off, one
// created with true must have it on, and one created without the attribute must have it off:
// the Terraform Enterprise API documents the create attribute as "Defaults to false".
//
// The defect this test was written against: Organization.CostEstimationEnabled carried
// `gorm:"default:true"`, and GORM substitutes a literal default for a zero value in the INSERT
// (and writes it back into the struct), so a false sent on create was stored and answered as
// true. The default lives in OrganizationHandlerV2.Create instead.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestOrganizationCreate_CostEstimation

//go:build integration

package handlers

import (
	"net/http"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

func TestOrganizationCreate_CostEstimationEnabledIsStoredAsSent(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.ReservedOrganizationName{},
		&models.OrganizationMember{}, &models.Team{}, &models.TeamMember{},
		&models.TeamOrganizationAccess{}, &models.Project{}, &models.TeamProjectAccess{},
		&models.AgentPool{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	creator := &models.User{ID: uuid.New(), ZitadelSubject: "orgcost-" + sfx, Email: "orgcost-" + sfx + "@test.local"}
	if err := db.Create(creator).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	sent := func(v bool) *bool { return &v }
	cases := []struct {
		name    string
		orgName string
		enabled *bool // nil leaves the attribute out
		want    bool
	}{
		{"explicit false", "orgcost-off-" + sfx, sent(false), false},
		{"explicit true", "orgcost-on-" + sfx, sent(true), true},
		{"absent", "orgcost-absent-" + sfx, nil, false},
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

	const attr = "cost-estimation-enabled"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string]any{"name": tc.orgName, "email": tc.orgName + "@test.local"}
			if tc.enabled != nil {
				attrs[attr] = *tc.enabled
			}
			code, body := storedAsSentCall(t, router, http.MethodPost, "/api/v2/organizations", creator.ID,
				storedAsSentDocument(t, "organizations", attrs))
			if code != http.StatusCreated {
				t.Fatalf("create = %d, want 201 (%s)", code, body)
			}
			_, created := storedAsSentResource(t, body)
			assertStoredBool(t, "create response", created, attr, tc.want)

			code, body = storedAsSentCall(t, router, http.MethodGet, "/api/v2/organizations/"+tc.orgName, creator.ID, "")
			if code != http.StatusOK {
				t.Fatalf("read = %d, want 200 (%s)", code, body)
			}
			_, read := storedAsSentResource(t, body)
			assertStoredBool(t, "read back", read, attr, tc.want)
		})
	}
}
