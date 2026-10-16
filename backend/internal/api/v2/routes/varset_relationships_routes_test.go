// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A variable set's workspace and project attachments are addressed by two route shapes that
// share one set of handlers:
//
//   - /api/v2/varsets/:id/relationships/{workspaces,projects}, where the org wall resolves the
//     organization from the set itself;
//   - /api/v2/organizations/:name/varsets/:id/relationships/{workspaces,projects}, where it
//     resolves the organization from :name.
//
// On the organization-scoped shape the handler must act only on a set of that organization,
// so the organization the wall authorized is the one the handler changes. These tests go
// through the router the server mounts with a key bound to one organization that names
// itself in :name and another organization's set in :id.

//go:build integration

package routes_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestVarsetRelationships_OrgBoundKeyCannotReachAnotherOrganization(t *testing.T) {
	h := setupGoldenHarness(t)

	var owner models.User
	if err := h.db.Raw(`
		SELECT u.* FROM users u JOIN api_keys k ON k.user_id = u.id
		WHERE k.name = 'golden-harness' LIMIT 1`).Scan(&owner).Error; err != nil || owner.ID == uuid.Nil {
		t.Fatalf("find the harness user: %v", err)
	}
	var victimOrg models.Organization
	if err := h.db.Raw(`
		SELECT o.* FROM organizations o
		JOIN teams t ON t.organization_id = o.id AND t.name = 'owners'
		JOIN team_members tm ON tm.team_id = t.id AND tm.user_id = ?
		ORDER BY o.name LIMIT 1`, owner.ID).Scan(&victimOrg).Error; err != nil || victimOrg.ID == uuid.Nil {
		t.Fatalf("find an organization the harness user owns: %v", err)
	}

	// The harness database is a throwaway, dropped when the test ends.
	suffix := uuid.NewString()[:8]
	attachedProject := models.Project{ID: uuid.New(), OrganizationID: victimOrg.ID, Name: "vsr-attached-" + suffix}
	otherProject := models.Project{ID: uuid.New(), OrganizationID: victimOrg.ID, Name: "vsr-other-" + suffix}
	attachedWS := models.Workspace{ID: "ws-vsra" + suffix + "000", ProjectID: attachedProject.ID, Name: "vsr-attached-" + suffix}
	otherWS := models.Workspace{ID: "ws-vsro" + suffix + "000", ProjectID: attachedProject.ID, Name: "vsr-other-" + suffix}
	victim := models.VariableSet{
		ID: "varset-vsr" + suffix + "0000", OrganizationID: victimOrg.ID, Name: "vsr-" + suffix,
		Workspaces: []models.Workspace{attachedWS}, Projects: []models.Project{attachedProject},
	}

	// A second organization the same person owns, which the key is bound to.
	keyOrg := models.Organization{ID: uuid.New(), Name: "vsr-key-org-" + suffix}
	keyOrgOwners := models.Team{ID: uuid.New(), OrganizationID: keyOrg.ID, Name: "owners"}
	for _, row := range []any{
		&attachedProject, &otherProject, &attachedWS, &otherWS, &victim,
		&keyOrg, &keyOrgOwners, &models.TeamMember{TeamID: keyOrgOwners.ID, UserID: owner.ID},
	} {
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
	_, key, err := keys.CreateAPIKey(owner.ID, "vsr-"+suffix, []string{"org:" + keyOrg.ID.String() + ":admin"}, nil)
	if err != nil {
		t.Fatalf("mint a key bound to %s: %v", keyOrg.Name, err)
	}

	attached := func(table, column, id string) bool {
		var n int64
		if err := h.db.Table(table).Where("variable_set_id = ? AND "+column+" = ?", victim.ID, id).Count(&n).Error; err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n > 0
	}
	ref := func(typ, id string) map[string]any {
		return map[string]any{"data": []map[string]string{{"type": typ, "id": id}}}
	}

	base := "/api/v2/organizations/" + keyOrg.Name + "/varsets/" + victim.ID + "/relationships/"
	requests := []struct {
		name, method, path string
		body               any
		// unchanged reports whether the victim's attachments are as they were.
		unchanged func() bool
	}{
		{
			"attach a workspace", http.MethodPost, base + "workspaces", ref("workspaces", otherWS.ID),
			func() bool { return !attached("variable_set_workspaces", "workspace_id", otherWS.ID) },
		},
		{
			"detach a workspace", http.MethodDelete, base + "workspaces", ref("workspaces", attachedWS.ID),
			func() bool { return attached("variable_set_workspaces", "workspace_id", attachedWS.ID) },
		},
		{
			"attach a project", http.MethodPost, base + "projects", ref("projects", otherProject.ID.String()),
			func() bool { return !attached("variable_set_projects", "project_id", otherProject.ID.String()) },
		},
		{
			"detach a project", http.MethodDelete, base + "projects", ref("projects", attachedProject.ID.String()),
			func() bool { return attached("variable_set_projects", "project_id", attachedProject.ID.String()) },
		},
	}
	for _, rq := range requests {
		t.Run(rq.name, func(t *testing.T) {
			payload, err := json.Marshal(rq.body)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			req := httptest.NewRequestWithContext(t.Context(), rq.method, rq.path, bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/vnd.api+json")
			req.Header.Set("Authorization", "Bearer "+key)
			rec := httptest.NewRecorder()
			h.router.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 404.\nbody: %s", rq.method, rq.path, rec.Code, rec.Body.String())
			}
			if !rq.unchanged() {
				t.Errorf("a key bound to %s changed a variable set of %s (%s)", keyOrg.Name, victimOrg.Name, rq.name)
			}
		})
	}

	// Named under its own organization, the set is attached as before.
	t.Run("the set's own organization attaches", func(t *testing.T) {
		path := "/api/v2/organizations/" + victimOrg.Name + "/varsets/" + victim.ID + "/relationships/workspaces"
		payload, err := json.Marshal(ref("workspaces", otherWS.ID))
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/vnd.api+json")
		req.Header.Set("Authorization", "Bearer "+h.token)
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("POST %s = %d, want 204.\nbody: %s", path, rec.Code, rec.Body.String())
		}
		if !attached("variable_set_workspaces", "workspace_id", otherWS.ID) {
			t.Errorf("the attachment answered 204 and was not made")
		}
	})
}
