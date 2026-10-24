// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Organization creation as a deployment setting (#132, D6, AC17, AC18). Under everyone (the
// default) any session or user token creates an organization as before; under platform-admins
// only a platform administrator does, and the creator still owns what they create and joins
// nothing else. The organization-bound key's 403 comes from the org wall (orgListCreate) and is
// held by the wall's own tests and by the real-router tests of this feature.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestOrganizationCreatePolicy

//go:build integration

package handlers

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestOrganizationCreatePolicy(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	var created []string
	t.Cleanup(func() { deleteOrganizationsByName(f.db, created) })

	orgRepo := repository.NewOrganizationRepository(f.db)
	teamRepo := repository.NewTeamRepository(f.db)
	projectRepo := repository.NewProjectRepository(f.db)
	create := func(t *testing.T, setting platformadmin.OrganizationCreation, as identity) int {
		t.Helper()
		h := NewOrganizationHandlerV2(orgRepo, teamRepo, projectRepo, repository.NewAgentPoolRepository(f.db),
			f.authSvc, nil, rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo), f.db)
		h.SetPlatformAdmin(f.service(platformadmin.Config{OrganizationCreation: setting}))
		router := platformAdminRouter()
		router.POST("/api/v2/organizations", h.Create)
		name := "platadm-new-" + uuid.NewString()[:8]
		created = append(created, name)
		body := `{"data":{"type":"organizations","attributes":{"name":"` + name + `","email":"` + name + `@test.local"}}}`
		rec := platformAdminCall(t, router, http.MethodPost, "/api/v2/organizations", as, body)
		if rec.Code == http.StatusCreated {
			var org models.Organization
			if err := f.db.Where("name = ?", name).First(&org).Error; err != nil {
				t.Fatalf("created organization not stored: %v", err)
			}
			var owners int64
			f.db.Model(&models.TeamMember{}).Joins("JOIN teams ON teams.id = team_members.team_id").
				Where("teams.organization_id = ? AND teams.name = 'owners' AND team_members.user_id = ?", org.ID, as.user).Count(&owners)
			if owners != 1 {
				t.Errorf("the creator is not the new organization's owner")
			}
		}
		return rec.Code
	}
	userToken := func(u *models.User) identity {
		return identity{user: u.ID, method: "api_key", tokenKind: models.APIKeyKindUser}
	}

	// AC17
	for _, setting := range []platformadmin.OrganizationCreation{"", platformadmin.OrganizationCreationEveryone} {
		if code := create(t, setting, jwtAs(f.plain)); code != http.StatusCreated {
			t.Errorf("%q: session create = %d, want 201", setting, code)
		}
		if code := create(t, setting, userToken(f.plain)); code != http.StatusCreated {
			t.Errorf("%q: user token create = %d, want 201", setting, code)
		}
	}

	// AC18
	limited := platformadmin.OrganizationCreationPlatformAdmins
	if code := create(t, limited, jwtAs(f.plain)); code != http.StatusForbidden {
		t.Errorf("platform-admins: non-administrator session = %d, want 403", code)
	}
	if code := create(t, limited, userToken(f.owner)); code != http.StatusForbidden {
		t.Errorf("platform-admins: non-administrator user token = %d, want 403", code)
	}
	if code := create(t, limited, jwtAs(f.admin)); code != http.StatusCreated {
		t.Errorf("platform-admins: platform administrator = %d, want 201", code)
	}
	// The administrator joined only what they created.
	var memberships int64
	f.db.Model(&models.OrganizationMember{}).Where("user_id = ?", f.admin.ID).Count(&memberships)
	if memberships != 1 {
		t.Errorf("the platform administrator belongs to %d organizations after one create, want 1", memberships)
	}
}
