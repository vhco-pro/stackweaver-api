// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A team workspace access is addressed by two route shapes that share one set of handlers:
//
//   - /api/v2/team-workspaces/:id, the shape terraform-provider-tfe uses for tfe_team_access,
//     where :id is the access;
//   - /api/v2/workspaces/:id/relationships/team-access/:access_id, where :id is the workspace.
//
// The handlers used to work out which parameter held the access each in their own way, and two
// of the three got it wrong for the TFE shape: Update read only :access_id, which that route
// does not have, and answered 400 "Invalid access ID format"; Delete compared the access's
// workspace with an empty string and answered 404. So tfe_team_access could be created and read
// but never changed or destroyed.
//
// That is a mismatch between what a route names its parameters and what its handler reads, which
// a test calling the handler with hand-set parameters cannot see. This one goes through the
// router the server mounts, once per shape, and also holds the workspace-scoped shape to its
// promise: an access of another workspace is not found there.

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

// teamWorkspaceAccessFixture is a seeded organization with two of its workspaces.
type teamWorkspaceAccessFixture struct {
	h              *goldenHarness
	org            models.Organization
	workspace      string
	otherWorkspace string
}

func setupTeamWorkspaceAccess(t *testing.T) *teamWorkspaceAccessFixture {
	t.Helper()
	h := setupGoldenHarness(t)

	orgName, ok := firstCol(h.db, "organizations", "name")
	if !ok {
		t.Skip("no seeded organization")
	}
	f := &teamWorkspaceAccessFixture{h: h}
	if err := h.db.Where("name = ?", orgName).First(&f.org).Error; err != nil {
		t.Fatalf("load organization %s: %v", orgName, err)
	}

	var workspaceIDs []string
	if err := h.db.Model(&models.Workspace{}).
		Joins("JOIN projects ON projects.id = workspaces.project_id").
		Where("projects.organization_id = ?", f.org.ID).
		Order("workspaces.name").Limit(2).
		Pluck("workspaces.id", &workspaceIDs).Error; err != nil {
		t.Fatalf("load workspaces of %s: %v", orgName, err)
	}
	if len(workspaceIDs) < 2 {
		t.Skipf("organization %s has %d seeded workspace(s), need 2", orgName, len(workspaceIDs))
	}
	f.workspace, f.otherWorkspace = workspaceIDs[0], workspaceIDs[1]
	return f
}

// grant gives a team of its own read access to the fixture's first workspace. A team per call
// keeps the (team, workspace) pair unique, so cases do not depend on each other's rows. The
// harness database is a throwaway, dropped when the test ends.
func (f *teamWorkspaceAccessFixture) grant(t *testing.T) uuid.UUID {
	t.Helper()
	team := models.Team{OrganizationID: f.org.ID, Name: "twa-routes-" + uuid.NewString()[:8]}
	if err := f.h.db.Create(&team).Error; err != nil {
		t.Fatalf("seed team: %v", err)
	}
	read := "read"
	access := models.TeamWorkspaceAccess{TeamID: team.ID, WorkspaceID: f.workspace, Access: &read}
	if err := f.h.db.Create(&access).Error; err != nil {
		t.Fatalf("seed team workspace access: %v", err)
	}
	return access.ID
}

func (f *teamWorkspaceAccessFixture) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("Authorization", "Bearer "+f.h.token)
	rec := httptest.NewRecorder()
	f.h.router.ServeHTTP(rec, req)
	return rec
}

// stored returns the access level the row holds, and whether the row still exists.
func (f *teamWorkspaceAccessFixture) stored(t *testing.T, id uuid.UUID) (string, bool) {
	t.Helper()
	var rows []models.TeamWorkspaceAccess
	if err := f.h.db.Where("id = ?", id).Find(&rows).Error; err != nil {
		t.Fatalf("load team workspace access %s: %v", id, err)
	}
	if len(rows) == 0 {
		return "", false
	}
	if rows[0].Access == nil {
		return "", true
	}
	return *rows[0].Access, true
}

// teamWorkspaceAccessDoc is the part of the response the assertions read.
type teamWorkspaceAccessDoc struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Access string `json:"access"`
		} `json:"attributes"`
	} `json:"data"`
}

func teamWorkspaceAccessUpdate(access string) map[string]any {
	return map[string]any{"data": map[string]any{
		"type":       "team-workspaces",
		"attributes": map[string]any{"access": access},
	}}
}

func TestTeamWorkspaceAccessByID_BothRouteShapes(t *testing.T) {
	f := setupTeamWorkspaceAccess(t)

	shapes := []struct {
		name string
		path func(accessID string) string
	}{
		{"TFE shape", func(id string) string { return "/api/v2/team-workspaces/" + id }},
		{"workspace-scoped shape", func(id string) string {
			return "/api/v2/workspaces/" + f.workspace + "/relationships/team-access/" + id
		}},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			id := f.grant(t)
			path := shape.path(id.String())

			// Each verb is its own subtest so that one failing does not hide the next: the two
			// defects this file was written for sat on different verbs of the same route.
			t.Run("get", func(t *testing.T) {
				rec := f.do(t, http.MethodGet, path, nil)
				if rec.Code != http.StatusOK {
					t.Fatalf("GET %s = %d, want 200.\nbody: %s", path, rec.Code, rec.Body.String())
				}
				var got teamWorkspaceAccessDoc
				if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
					t.Fatalf("GET body is not JSON: %v\nbody: %s", err, rec.Body.String())
				}
				if got.Data.ID != id.String() || got.Data.Type != "team-workspaces" || got.Data.Attributes.Access != "read" {
					t.Errorf("GET returned id %q, type %q, access %q; want %q, team-workspaces, read",
						got.Data.ID, got.Data.Type, got.Data.Attributes.Access, id)
				}
			})

			t.Run("update", func(t *testing.T) {
				rec := f.do(t, http.MethodPatch, path, teamWorkspaceAccessUpdate("write"))
				if rec.Code != http.StatusOK {
					t.Fatalf("PATCH %s = %d, want 200.\nbody: %s", path, rec.Code, rec.Body.String())
				}
				var updated teamWorkspaceAccessDoc
				if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
					t.Fatalf("PATCH body is not JSON: %v\nbody: %s", err, rec.Body.String())
				}
				if updated.Data.ID != id.String() || updated.Data.Attributes.Access != "write" {
					t.Errorf("PATCH returned id %q, access %q; want %q, write",
						updated.Data.ID, updated.Data.Attributes.Access, id)
				}
				if access, _ := f.stored(t, id); access != "write" {
					t.Errorf("after PATCH the row holds access %q, want write", access)
				}
			})

			t.Run("delete", func(t *testing.T) {
				rec := f.do(t, http.MethodDelete, path, nil)
				if rec.Code != http.StatusNoContent {
					t.Fatalf("DELETE %s = %d, want 204.\nbody: %s", path, rec.Code, rec.Body.String())
				}
				if _, exists := f.stored(t, id); exists {
					t.Errorf("the row survived a DELETE that answered 204")
				}
			})
		})
	}
}

// The workspace-scoped shape names a workspace, and an access is only found under its own.
func TestTeamWorkspaceAccessByID_OtherWorkspaceIsNotFound(t *testing.T) {
	f := setupTeamWorkspaceAccess(t)
	id := f.grant(t)
	path := "/api/v2/workspaces/" + f.otherWorkspace + "/relationships/team-access/" + id.String()

	requests := []struct {
		method string
		body   any
	}{
		{http.MethodGet, nil},
		{http.MethodPatch, teamWorkspaceAccessUpdate("admin")},
		{http.MethodDelete, nil},
	}
	for _, rq := range requests {
		t.Run(rq.method, func(t *testing.T) {
			rec := f.do(t, rq.method, path, rq.body)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s %s = %d, want 404.\nbody: %s", rq.method, path, rec.Code, rec.Body.String())
			}
			// A 404 that still did the work would be no refusal at all.
			access, exists := f.stored(t, id)
			if !exists {
				t.Fatalf("%s through another workspace deleted the access", rq.method)
			}
			if access != "read" {
				t.Errorf("%s through another workspace changed the access to %q", rq.method, access)
			}
		})
	}
}
