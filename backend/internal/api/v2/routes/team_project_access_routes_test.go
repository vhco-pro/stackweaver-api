// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A team project access is addressed by two route shapes that share one set of handlers:
//
//   - /api/v2/team-projects/:id, the shape terraform-provider-tfe uses for
//     tfe_team_project_access, where :id is the access;
//   - /api/v2/projects/:id/relationships/team-access/:access_id, where :id is the project.
//
// The by-id handlers read the access from :id on both. On the project-scoped shape that is the
// project, so a correctly addressed request looked up an access by a project's id and answered
// 404 "Team project access not found"; :access_id was never read. Putting the access id in both
// positions happened to work, which is how it went unnoticed.
//
// That is a mismatch between what a route names its parameters and what its handler reads, which
// a test calling the handler with hand-set parameters cannot see. This one goes through the
// router the server mounts, once per shape, and also holds the project-scoped shape to its
// promise: an access of another project is not found there.

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

// teamProjectAccessFixture is a seeded organization with two projects of its own.
type teamProjectAccessFixture struct {
	h            *goldenHarness
	org          models.Organization
	project      models.Project
	otherProject models.Project
}

func setupTeamProjectAccess(t *testing.T) *teamProjectAccessFixture {
	t.Helper()
	h := setupGoldenHarness(t)

	orgName, ok := firstCol(h.db, "organizations", "name")
	if !ok {
		t.Skip("no seeded organization")
	}
	f := &teamProjectAccessFixture{h: h}
	if err := h.db.Where("name = ?", orgName).First(&f.org).Error; err != nil {
		t.Fatalf("load organization %s: %v", orgName, err)
	}

	// The harness database is a throwaway, dropped when the test ends.
	suffix := uuid.NewString()[:8]
	f.project = models.Project{OrganizationID: f.org.ID, Name: "tpa-routes-" + suffix}
	f.otherProject = models.Project{OrganizationID: f.org.ID, Name: "tpa-routes-other-" + suffix}
	for _, p := range []*models.Project{&f.project, &f.otherProject} {
		if err := h.db.Create(p).Error; err != nil {
			t.Fatalf("seed project %s: %v", p.Name, err)
		}
	}
	return f
}

// grant gives a team of its own read access to the fixture's first project. A team per call
// keeps the (team, project) pair unique, so cases do not depend on each other's rows.
func (f *teamProjectAccessFixture) grant(t *testing.T) uuid.UUID {
	t.Helper()
	team := models.Team{OrganizationID: f.org.ID, Name: "tpa-routes-" + uuid.NewString()[:8]}
	if err := f.h.db.Create(&team).Error; err != nil {
		t.Fatalf("seed team: %v", err)
	}
	read := "read"
	access := models.TeamProjectAccess{TeamID: team.ID, ProjectID: f.project.ID, Access: &read}
	if err := f.h.db.Create(&access).Error; err != nil {
		t.Fatalf("seed team project access: %v", err)
	}
	return access.ID
}

func (f *teamProjectAccessFixture) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
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
func (f *teamProjectAccessFixture) stored(t *testing.T, id uuid.UUID) (string, bool) {
	t.Helper()
	var rows []models.TeamProjectAccess
	if err := f.h.db.Where("id = ?", id).Find(&rows).Error; err != nil {
		t.Fatalf("load team project access %s: %v", id, err)
	}
	if len(rows) == 0 {
		return "", false
	}
	if rows[0].Access == nil {
		return "", true
	}
	return *rows[0].Access, true
}

// teamProjectAccessDoc is the part of the response the assertions read.
type teamProjectAccessDoc struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Access string `json:"access"`
		} `json:"attributes"`
	} `json:"data"`
}

func teamProjectAccessUpdate(access string) map[string]any {
	return map[string]any{"data": map[string]any{
		"type":       "team-projects",
		"attributes": map[string]any{"access": access},
	}}
}

func TestTeamProjectAccessByID_BothRouteShapes(t *testing.T) {
	f := setupTeamProjectAccess(t)

	shapes := []struct {
		name string
		path func(accessID string) string
	}{
		{"TFE shape", func(id string) string { return "/api/v2/team-projects/" + id }},
		{"project-scoped shape", func(id string) string {
			return "/api/v2/projects/" + f.project.ID.String() + "/relationships/team-access/" + id
		}},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			id := f.grant(t)
			path := shape.path(id.String())

			// Each verb is its own subtest so that one failing does not hide the next.
			t.Run("get", func(t *testing.T) {
				rec := f.do(t, http.MethodGet, path, nil)
				if rec.Code != http.StatusOK {
					t.Fatalf("GET %s = %d, want 200.\nbody: %s", path, rec.Code, rec.Body.String())
				}
				var got teamProjectAccessDoc
				if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
					t.Fatalf("GET body is not JSON: %v\nbody: %s", err, rec.Body.String())
				}
				if got.Data.ID != id.String() || got.Data.Type != "team-projects" || got.Data.Attributes.Access != "read" {
					t.Errorf("GET returned id %q, type %q, access %q; want %q, team-projects, read",
						got.Data.ID, got.Data.Type, got.Data.Attributes.Access, id)
				}
			})

			t.Run("update", func(t *testing.T) {
				rec := f.do(t, http.MethodPatch, path, teamProjectAccessUpdate("write"))
				if rec.Code != http.StatusOK {
					t.Fatalf("PATCH %s = %d, want 200.\nbody: %s", path, rec.Code, rec.Body.String())
				}
				var updated teamProjectAccessDoc
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

// The project-scoped shape names a project, and an access is only found under its own. The
// second path is the request that used to succeed by accident: the access id where the project
// belongs.
func TestTeamProjectAccessByID_OtherProjectIsNotFound(t *testing.T) {
	f := setupTeamProjectAccess(t)
	id := f.grant(t)

	paths := []struct {
		name string
		path string
	}{
		{"another project", "/api/v2/projects/" + f.otherProject.ID.String() + "/relationships/team-access/" + id.String()},
		{"the access id as the project", "/api/v2/projects/" + id.String() + "/relationships/team-access/" + id.String()},
	}
	requests := []struct {
		method string
		body   any
	}{
		{http.MethodGet, nil},
		{http.MethodPatch, teamProjectAccessUpdate("admin")},
		{http.MethodDelete, nil},
	}
	for _, p := range paths {
		for _, rq := range requests {
			t.Run(p.name+"/"+rq.method, func(t *testing.T) {
				rec := f.do(t, rq.method, p.path, rq.body)
				if rec.Code != http.StatusNotFound {
					t.Fatalf("%s %s = %d, want 404.\nbody: %s", rq.method, p.path, rec.Code, rec.Body.String())
				}
				// A 404 that still did the work would be no refusal at all.
				access, exists := f.stored(t, id)
				if !exists {
					t.Fatalf("%s through %s deleted the access", rq.method, p.name)
				}
				if access != "read" {
					t.Errorf("%s through %s changed the access to %q", rq.method, p.name, access)
				}
			})
		}
	}
}

// The org wall authorizes this route by its :access_id (see org_wall_registry.go), and the
// handlers must act on that same access. When they read :id instead, a key bound to one
// organization could name an access of its own organization where the wall looks and an access
// of another organization where the handler looked, and the handler's own check only asks what
// the key's OWNER may do. That is the #806 escalation by another door, so it is pinned here: the
// key is refused, and the other organization's access is neither read, changed nor removed.
func TestTeamProjectAccessByID_OrgBoundKeyCannotReachAnotherOrganization(t *testing.T) {
	f := setupTeamProjectAccess(t)
	victim := f.grant(t) // in the seeded organization, where the key's owner is an admin

	var owner models.User
	if err := f.h.db.Raw(`
		SELECT u.* FROM users u JOIN api_keys k ON k.user_id = u.id
		WHERE k.name = 'golden-harness' LIMIT 1`).Scan(&owner).Error; err != nil || owner.ID == uuid.Nil {
		t.Fatalf("find the harness user: %v", err)
	}

	// A second organization the same person belongs to, with an access of its own.
	suffix := uuid.NewString()[:8]
	keyOrg := models.Organization{ID: uuid.New(), Name: "tpa-routes-key-org-" + suffix}
	keyOrgOwners := models.Team{ID: uuid.New(), OrganizationID: keyOrg.ID, Name: "owners"}
	keyOrgTeam := models.Team{ID: uuid.New(), OrganizationID: keyOrg.ID, Name: "tpa-routes-" + suffix}
	keyOrgProject := models.Project{ID: uuid.New(), OrganizationID: keyOrg.ID, Name: "tpa-routes-" + suffix}
	read := "read"
	own := models.TeamProjectAccess{ID: uuid.New(), TeamID: keyOrgTeam.ID, ProjectID: keyOrgProject.ID, Access: &read}
	for _, row := range []any{
		&keyOrg, &keyOrgOwners, &keyOrgTeam, &keyOrgProject, &own,
		&models.TeamMember{TeamID: keyOrgOwners.ID, UserID: owner.ID},
	} {
		if err := f.h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	keys := apikey.NewService(
		repository.NewAPIKeyRepository(f.h.db),
		repository.NewOrganizationRepository(f.h.db),
		repository.NewProjectRepository(f.h.db),
		repository.NewTeamRepository(f.h.db),
	)
	_, key, err := keys.CreateAPIKey(owner.ID, "tpa-routes-"+suffix, []string{"org:" + keyOrg.ID.String() + ":admin"}, nil)
	if err != nil {
		t.Fatalf("mint a key bound to %s: %v", keyOrg.Name, err)
	}

	// The victim where the handlers used to read the access, the key's own where the wall does.
	path := "/api/v2/projects/" + victim.String() + "/relationships/team-access/" + own.ID.String()
	requests := []struct {
		method string
		body   any
	}{
		{http.MethodGet, nil},
		{http.MethodPatch, teamProjectAccessUpdate("admin")},
		{http.MethodDelete, nil},
	}
	for _, rq := range requests {
		t.Run(rq.method, func(t *testing.T) {
			var payload []byte
			if rq.body != nil {
				var err error
				if payload, err = json.Marshal(rq.body); err != nil {
					t.Fatalf("marshal body: %v", err)
				}
			}
			req := httptest.NewRequestWithContext(t.Context(), rq.method, path, bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/vnd.api+json")
			req.Header.Set("Authorization", "Bearer "+key)
			rec := httptest.NewRecorder()
			f.h.router.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 404.\nbody: %s", rq.method, path, rec.Code, rec.Body.String())
			}
			access, exists := f.stored(t, victim)
			if !exists {
				t.Fatalf("a key bound to %s deleted an access of %s", keyOrg.Name, f.org.Name)
			}
			if access != "read" {
				t.Errorf("a key bound to %s changed an access of %s to %q", keyOrg.Name, f.org.Name, access)
			}
		})
	}
}
