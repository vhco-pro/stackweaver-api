// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Starting and completing a VCS installation takes the organization-level manage-vcs-settings
// permission. The router-level half of this is in
// routes/vcs_installation_authz_test.go, which drives the real middleware chain but can only
// authenticate with API tokens, and the org wall turns a token away from an organization its
// owner does not belong to before the handler is asked anything.
//
// A signed-in session is not governed by the wall, so for a person who belongs to no team of
// the organization the handler's own check is the only one there is. That case is covered
// here, with the principal placed in the context the way the authentication middleware places
// it and no token involved.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the dev DB has no backup).

//go:build integration

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
)

func TestVCSInstallationAuthz_SessionCallers(t *testing.T) {
	db := setupAuthzTestDB(t)

	sfx := uuid.NewString()[:8]
	org := &models.Organization{ID: uuid.New(), Name: "vcsinstall-" + sfx}
	otherOrg := &models.Organization{ID: uuid.New(), Name: "vcsinstall-other-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "vcsinstall-owner-" + sfx, Email: "vcsinstall-owner-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "vcsinstall-out-" + sfx, Email: "vcsinstall-out-" + sfx + "@test.local"}
	owners := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	otherOwners := &models.Team{ID: uuid.New(), OrganizationID: otherOrg.ID, Name: "owners"}
	// Registered before the rows exist; every statement is keyed on an id this test generated.
	t.Cleanup(func() {
		orgs := []uuid.UUID{org.ID, otherOrg.ID}
		teams := []uuid.UUID{owners.ID, otherOwners.ID}
		db.Where("organization_id IN ?", orgs).Delete(&models.VCSConnection{})
		db.Where("team_id IN ?", teams).Delete(&models.TeamMember{})
		db.Where("id IN ?", teams).Delete(&models.Team{})
		db.Where("id IN ?", orgs).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{owner.ID, outsider.ID}).Delete(&models.User{})
	})
	for _, row := range []any{
		org, otherOrg, owner, outsider, owners, otherOwners,
		&models.TeamMember{TeamID: owners.ID, UserID: owner.ID},
		// The outsider owns another organization: holding the permission somewhere is not
		// holding it here.
		&models.TeamMember{TeamID: otherOwners.ID, UserID: outsider.ID},
	} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	orgRepo := repository.NewOrganizationRepository(db)
	// Neither provider is configured, so a caller who is let through reaches the handler's
	// "not configured" answer and no provider is ever called.
	h := NewVCSAppInstallationHandlerV2(
		repository.NewVCSConnectionRepository(db), orgRepo,
		nil, nil, nil, nil, nil, nil, nil,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db)),
		nil, nil, nil, nil, nil, nil,
	)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(testUserAuth())
	group := router.Group("/organizations/:name/vcs-connections")
	group.GET("/github/install", h.InitiateInstallation)
	group.POST("/github/installations/:installation_id", h.CreateConnectionFromInstallation)
	group.GET("/azure-devops/install", h.InitiateAzureDevOpsInstallation)

	routes := []struct {
		name, method, suffix string
	}{
		{"start a GitHub App installation", http.MethodGet, "/github/install"},
		{"complete a GitHub App installation", http.MethodPost, "/github/installations/424242"},
		{"start an Azure DevOps installation", http.MethodGet, "/azure-devops/install?ado_org=acme"},
	}
	callers := []struct {
		name string
		user uuid.UUID
		want int
	}{
		{"someone who belongs to no team of the organization", outsider.ID, http.StatusForbidden},
		{"nobody", uuid.Nil, http.StatusUnauthorized},
		// 500 is "not configured", the answer that follows the permission check here.
		{"an owner", owner.ID, http.StatusInternalServerError},
	}
	for _, route := range routes {
		for _, caller := range callers {
			t.Run(route.name+"/"+caller.name, func(t *testing.T) {
				path := "/organizations/" + org.Name + "/vcs-connections" + route.suffix
				rec := authzRequest(t, router, route.method, path, caller.user, nil)
				if rec.Code != caller.want {
					t.Fatalf("%s %s = %d, want %d.\nbody: %s", route.method, path, rec.Code, caller.want, rec.Body.String())
				}
			})
		}
	}

	var connections int64
	if err := db.Model(&models.VCSConnection{}).Where("organization_id = ?", org.ID).Count(&connections).Error; err != nil {
		t.Fatalf("count connections: %v", err)
	}
	if connections != 0 {
		t.Errorf("the organization holds %d VCS connection(s) after these requests, want none", connections)
	}
}
