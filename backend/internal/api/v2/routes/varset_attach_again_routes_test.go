// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Applying a variable set to a workspace or project it is already applied to succeeds and
// changes nothing. TFE answers POST /varsets/:id/relationships/{workspaces,projects} with 204,
// and these are JSON:API relationship endpoints, where a member that is already present is
// not added again and the request still succeeds. terraform-provider-tfe re-applies sets it
// believes are missing, so a 500 here fails a plan for no reason.

//go:build integration

package routes_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func TestVarsetRelationships_ApplyingAgainSucceeds(t *testing.T) {
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
	project := models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "vsa-" + suffix}
	workspace := models.Workspace{ID: "ws-vsaa" + suffix + "000", ProjectID: project.ID, Name: "vsa-" + suffix}
	set := models.VariableSet{
		ID: "varset-vsa" + suffix + "0000", OrganizationID: org.ID, Name: "vsa-" + suffix,
		Workspaces: []models.Workspace{workspace}, Projects: []models.Project{project},
	}
	for _, row := range []any{&project, &workspace, &set} {
		if err := h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	count := func(table, column, id string) int64 {
		var n int64
		if err := h.db.Table(table).Where("variable_set_id = ? AND "+column+" = ?", set.ID, id).Count(&n).Error; err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}

	for _, tc := range []struct {
		name, relationship, typ, id, table, column string
	}{
		{"workspace", "workspaces", "workspaces", workspace.ID, "variable_set_workspaces", "workspace_id"},
		{"project", "projects", "projects", project.ID.String(), "variable_set_projects", "project_id"},
	} {
		for _, shape := range []string{
			"/api/v2/varsets/" + set.ID + "/relationships/" + tc.relationship,
			"/api/v2/organizations/" + org.Name + "/varsets/" + set.ID + "/relationships/" + tc.relationship,
		} {
			t.Run(tc.name+" via "+shape, func(t *testing.T) {
				payload, err := json.Marshal(map[string]any{"data": []map[string]string{{"type": tc.typ, "id": tc.id}}})
				if err != nil {
					t.Fatalf("marshal body: %v", err)
				}
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, shape, bytes.NewReader(payload))
				req.Header.Set("Content-Type", "application/vnd.api+json")
				req.Header.Set("Authorization", "Bearer "+h.token)
				rec := httptest.NewRecorder()
				h.router.ServeHTTP(rec, req)

				if rec.Code != http.StatusNoContent {
					t.Errorf("applying the set to a %s it is already applied to = %d, want 204.\nbody: %s", tc.name, rec.Code, rec.Body.String())
				}
				if n := count(tc.table, tc.column, tc.id); n != 1 {
					t.Errorf("the set is applied to the %s %d time(s), want 1", tc.name, n)
				}
			})
		}
	}
}
