// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The Ansible configuration reads, through the router the server mounts, with real API tokens.
// An ansible.cfg can hold credentials (a Galaxy server token, for one), so reading the
// organization's or a project's configuration requires what reading the organization's Ansible
// resources requires, or what writing the configuration requires. The effective configuration
// is resolved inside the organization the route names: a project or workspace of another
// organization is not found there.

//go:build integration

package routes_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestAnsibleConfigRoutes_ReadsRequireAnsibleRead(t *testing.T) {
	h := setupGoldenHarness(t)

	var owner models.User
	if err := h.db.Raw(`
		SELECT u.* FROM users u JOIN api_keys k ON k.user_id = u.id
		WHERE k.name = 'golden-harness' LIMIT 1`).Scan(&owner).Error; err != nil || owner.ID == uuid.Nil {
		t.Fatalf("find the harness user: %v", err)
	}
	var org models.Organization
	if err := h.db.Raw(`
		SELECT o.* FROM organizations o
		JOIN teams t ON t.organization_id = o.id AND t.name = 'owners'
		JOIN team_members tm ON tm.team_id = t.id AND tm.user_id = ?
		ORDER BY o.name LIMIT 1`, owner.ID).Scan(&org).Error; err != nil || org.ID == uuid.Nil {
		t.Fatalf("find an organization the harness user owns: %v", err)
	}

	// The harness database is a throwaway, dropped when the test ends.
	suffix := uuid.NewString()[:8]
	project := models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "acfg-" + suffix}
	otherOrg := models.Organization{ID: uuid.New(), Name: "acfg-other-" + suffix}
	otherOwners := models.Team{ID: uuid.New(), OrganizationID: otherOrg.ID, Name: "owners"}
	otherProject := models.Project{ID: uuid.New(), OrganizationID: otherOrg.ID, Name: "acfg-other-" + suffix}
	const otherContent = "[galaxy_server.other]\ntoken=other-organization-secret\n"
	rows := []any{
		&project, &otherOrg, &otherOwners, &otherProject,
		&models.TeamMember{TeamID: otherOwners.ID, UserID: owner.ID},
		&models.AnsibleConfig{ProjectID: &project.ID, ConfigContent: "[defaults]\nforks=5\n", CreatedByID: owner.ID, UpdatedByID: owner.ID},
		&models.AnsibleConfig{ProjectID: &otherProject.ID, ConfigContent: otherContent, CreatedByID: owner.ID, UpdatedByID: owner.ID},
	}
	// The seeded organization may already hold an organization-level configuration.
	var orgConfigs int64
	h.db.Model(&models.AnsibleConfig{}).Where("organization_id = ? AND project_id IS NULL AND workspace_id IS NULL", org.ID).Count(&orgConfigs)
	if orgConfigs == 0 {
		rows = append(rows, &models.AnsibleConfig{OrganizationID: &org.ID, ConfigContent: "[defaults]\nforks=10\n", CreatedByID: owner.ID, UpdatedByID: owner.ID})
	}
	for _, row := range rows {
		if err := h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	keys := apikey.NewService(
		repository.NewAPIKeyRepository(h.db),
		repository.NewOrganizationRepository(h.db),
		repository.NewProjectRepository(h.db),
		repository.NewTeamRepository(h.db),
	)
	// member adds a user to the organization through a team with the given access, and returns
	// a user token for them.
	member := func(access models.TeamOrganizationAccess, projectAccess string) string {
		t.Helper()
		s := uuid.NewString()[:8]
		user := models.User{ID: uuid.New(), ZitadelSubject: "acfg-" + s, Email: "acfg-" + s + "@test.local"}
		team := models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "acfg-" + s}
		access.ID, access.TeamID = uuid.New(), team.ID
		seed := []any{
			&user, &team, &access,
			&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: user.ID},
			&models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: user.ID},
		}
		if projectAccess != "" {
			level := projectAccess
			seed = append(seed, &models.TeamProjectAccess{ID: uuid.New(), TeamID: team.ID, ProjectID: project.ID, Access: &level})
		}
		for _, row := range seed {
			if err := h.db.Create(row).Error; err != nil {
				t.Fatalf("seed %T: %v", row, err)
			}
		}
		_, token, err := keys.CreateUserToken(user.ID, "acfg-"+s, nil)
		if err != nil {
			t.Fatalf("mint a user token: %v", err)
		}
		return token
	}
	orgToken := func(bound uuid.UUID) string {
		t.Helper()
		_, token, err := keys.CreateAPIKey(owner.ID, "acfg-"+uuid.NewString()[:8], []string{"org:" + bound.String() + ":admin"}, nil)
		if err != nil {
			t.Fatalf("mint an organization token: %v", err)
		}
		return token
	}
	get := func(t *testing.T, token, path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		return rec
	}

	reads := map[string]string{
		"organization": "/api/v2/organizations/" + org.Name + "/ansible-config",
		"project":      "/api/v2/projects/" + project.ID.String() + "/ansible-config",
		"effective":    "/api/v2/organizations/" + org.Name + "/ansible-config/effective?project_id=" + project.ID.String(),
	}
	const ok, refused = http.StatusOK, http.StatusForbidden
	callers := []struct {
		name  string
		token string
		want  map[string]int // by scope
	}{
		{
			"a member without Ansible access", member(models.TeamOrganizationAccess{}, ""),
			map[string]int{"organization": refused, "project": refused, "effective": refused},
		},
		// Project write access carries Ansible read in that project, not in the organization; the
		// effective configuration can be the organization's.
		{
			"a project member", member(models.TeamOrganizationAccess{}, "write"),
			map[string]int{"organization": refused, "project": ok, "effective": refused},
		},
		{
			"a token bound to another organization", orgToken(otherOrg.ID),
			map[string]int{"organization": refused, "project": refused, "effective": refused},
		},
		{
			"a member with Ansible read", member(models.TeamOrganizationAccess{ReadAnsible: true}, ""),
			map[string]int{"organization": ok, "project": ok, "effective": ok},
		},
		{
			"a member who manages workspaces", member(models.TeamOrganizationAccess{ManageWorkspaces: true}, ""),
			map[string]int{"organization": ok, "project": ok, "effective": ok},
		},
		{
			"the owner", h.token,
			map[string]int{"organization": ok, "project": ok, "effective": ok},
		},
	}
	for _, caller := range callers {
		for scope, path := range reads {
			t.Run(caller.name+"/"+scope, func(t *testing.T) {
				rec := get(t, caller.token, path)
				if want := caller.want[scope]; rec.Code != want {
					t.Errorf("GET %s = %d, want %d.\nbody: %s", path, rec.Code, want, rec.Body.String())
				}
			})
		}
	}

	// The organization's own token names another organization's project in the query.
	t.Run("effective configuration of another organization's project", func(t *testing.T) {
		path := "/api/v2/organizations/" + org.Name + "/ansible-config/effective?project_id=" + otherProject.ID.String()
		rec := get(t, orgToken(org.ID), path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404.\nbody: %s", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "other-organization-secret") {
			t.Errorf("a token bound to %s read the configuration of %s", org.Name, otherOrg.Name)
		}
	})
}
