// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a member of an organization can read, through the router the server mounts.
//
// As in Terraform Enterprise, membership alone reads nothing: a member reads a workspace through a
// grant on it, on its project, or the organization-level "view all workspaces" or "manage all
// workspaces", and a project through a grant on it or "view all projects" or "manage all
// projects". The owners team reads everything. A user is judged by the same rule as a team or
// project token, so a listing holds exactly what its single reads return, and every read of
// something that belongs to a workspace, its runs, configuration versions, variables, state, run
// triggers, notifications, run tasks and team access, follows the workspace.

//go:build integration

package routes_test

import (
	"encoding/json"
	"net/http"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// memberToken seeds a member of the fixture's organization, on one team holding grant, and mints
// the member's user token. grant is "none", "workspace" (read on wsInP), "project" (read on the
// project holding wsInP), or "org-read" (view all workspaces and view all projects).
func memberToken(t *testing.T, f *scopedTokensFixture, grant string) string {
	t.Helper()
	s := uuid.NewString()[:8]
	member := models.User{ID: uuid.New(), ZitadelSubject: "visibility-" + s, Email: "visibility-" + s + "@test.local"}
	team := models.Team{ID: uuid.New(), OrganizationID: f.org.ID, Name: "visibility-" + s, Visibility: "secret"}
	read := "read"
	rows := []any{
		&member, &team,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.org.ID, UserID: member.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: member.ID},
	}
	switch grant {
	case "none":
	case "workspace":
		rows = append(rows, &models.TeamWorkspaceAccess{ID: uuid.New(), TeamID: team.ID, WorkspaceID: f.wsInP.ID, Access: &read})
	case "project":
		rows = append(rows, &models.TeamProjectAccess{ID: uuid.New(), TeamID: team.ID, ProjectID: f.project.ID, Access: &read})
	case "org-read":
		rows = append(rows, &models.TeamOrganizationAccess{ID: uuid.New(), TeamID: team.ID, ReadWorkspaces: true, ReadProjects: true})
	default:
		t.Fatalf("unknown grant %q", grant)
	}
	for _, row := range rows {
		if err := f.h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	_, token, err := f.keys.CreateUserToken(member.ID, "visibility-"+s, nil)
	if err != nil {
		t.Fatalf("mint the member's user token: %v", err)
	}
	return token
}

// visibilityFixture is what each workspace of the fixture holds, so every read that belongs to a
// workspace can be asked of both.
type visibilityFixture struct {
	*scopedTokensFixture
	run        map[string]string // workspace id -> a queued run
	cv         map[string]string // workspace id -> a configuration version
	teamAccess map[string]string // workspace id -> an organization-visible team's access row
	projAccess map[string]string // project id -> an organization-visible team's access row
}

func setupVisibility(t *testing.T) *visibilityFixture {
	t.Helper()
	f := &visibilityFixture{
		scopedTokensFixture: setupScopedTokens(t),
		run:                 map[string]string{},
		cv:                  map[string]string{},
		teamAccess:          map[string]string{},
		projAccess:          map[string]string{},
	}
	visible := models.Team{ID: uuid.New(), OrganizationID: f.org.ID, Name: "visibility-shown-" + uuid.NewString()[:8], Visibility: "organization"}
	if err := f.h.db.Create(&visible).Error; err != nil {
		t.Fatalf("seed team: %v", err)
	}
	read := "read"
	for _, ws := range []models.Workspace{f.wsInP, f.wsInQ} {
		s := uuid.NewString()[:8]
		cv := models.ConfigurationVersion{ID: "cv-vis" + s + "00", WorkspaceID: ws.ID, Status: models.ConfigurationVersionStatusUploaded}
		run := models.Run{ID: "run-vis" + s + "000", WorkspaceID: ws.ID, Status: models.RunStatusPending, Operation: models.RunOperationPlanAndApply}
		access := models.TeamWorkspaceAccess{ID: uuid.New(), TeamID: visible.ID, WorkspaceID: ws.ID, Access: &read}
		for _, row := range []any{&cv, &run, &access} {
			if err := f.h.db.Create(row).Error; err != nil {
				t.Fatalf("seed %T: %v", row, err)
			}
		}
		f.cv[ws.ID], f.run[ws.ID], f.teamAccess[ws.ID] = cv.ID, run.ID, access.ID.String()
	}
	for _, p := range []models.Project{f.project, f.other} {
		access := models.TeamProjectAccess{ID: uuid.New(), TeamID: visible.ID, ProjectID: p.ID, Access: &read}
		if err := f.h.db.Create(&access).Error; err != nil {
			t.Fatalf("seed team project access: %v", err)
		}
		f.projAccess[p.ID.String()] = access.ID.String()
	}
	return f
}

// workspaceReads is every read that belongs to one workspace.
func (f *visibilityFixture) workspaceReads(ws models.Workspace) map[string]string {
	return map[string]string{
		"workspace":                     "/api/v2/workspaces/" + ws.ID,
		"workspace by name":             "/api/v2/organizations/" + f.org.Name + "/workspaces/" + ws.Name,
		"runs":                          "/api/v2/workspaces/" + ws.ID + "/runs",
		"a run":                         "/api/v2/runs/" + f.run[ws.ID],
		"configuration versions":        "/api/v2/workspaces/" + ws.ID + "/configuration-versions",
		"a configuration version":       "/api/v2/configuration-versions/" + f.cv[ws.ID],
		"variables":                     "/api/v2/workspaces/" + ws.ID + "/vars",
		"state versions":                "/api/v2/workspaces/" + ws.ID + "/state-versions",
		"run triggers":                  "/api/v2/workspaces/" + ws.ID + "/run-triggers",
		"notification configurations":   "/api/v2/workspaces/" + ws.ID + "/notification-configurations",
		"run tasks":                     "/api/v2/workspaces/" + ws.ID + "/tasks",
		"tag bindings":                  "/api/v2/workspaces/" + ws.ID + "/tag-bindings",
		"team access":                   "/api/v2/team-workspaces?filter[workspace][id]=" + ws.ID,
		"team access, legacy route":     "/api/v2/workspaces/" + ws.ID + "/relationships/team-access",
		"a team access":                 "/api/v2/team-workspaces/" + f.teamAccess[ws.ID],
		"activity of the workspace":     "/api/v2/activities?workspace_id=" + ws.ID,
		"a team access, legacy route":   "/api/v2/workspaces/" + ws.ID + "/relationships/team-access/" + f.teamAccess[ws.ID],
		"effective tag bindings":        "/api/v2/workspaces/" + ws.ID + "/effective-tag-bindings",
		"current state version outputs": "/api/v2/workspaces/" + ws.ID + "/current-state-version-outputs",
	}
}

// projectReads is every read that belongs to one project.
func (f *visibilityFixture) projectReads(p models.Project) map[string]string {
	id := p.ID.String()
	return map[string]string{
		"project":                     "/api/v2/projects/" + id,
		"project by name":             "/api/v2/organizations/" + f.org.Name + "/projects/" + p.Name,
		"tag bindings":                "/api/v2/projects/" + id + "/tag-bindings",
		"effective tag bindings":      "/api/v2/projects/" + id + "/effective-tag-bindings",
		"notification configurations": "/api/v2/projects/" + id + "/notification-configurations",
		"team access":                 "/api/v2/team-projects?filter[project][id]=" + id,
		"team access, legacy route":   "/api/v2/projects/" + id + "/relationships/team-access",
	}
}

// readsFollow asserts each read of a workspace or project answers as whether it may be read.
func readsFollow(t *testing.T, f *visibilityFixture, token string, reads map[string]string, readable bool) {
	t.Helper()
	for name, path := range reads {
		rec := f.do(t, token, http.MethodGet, path, nil)
		switch {
		case readable && name == "current state version outputs":
			// A workspace with no state answers 404 to a reader; what matters is that it is not 403.
			if rec.Code == http.StatusForbidden {
				t.Errorf("%s: GET %s = 403, want it readable.\nbody: %s", name, path, rec.Body.String())
			}
		case readable && rec.Code != http.StatusOK:
			t.Errorf("%s: GET %s = %d, want 200.\nbody: %s", name, path, rec.Code, rec.Body.String())
		case !readable && rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound:
			t.Errorf("%s: GET %s = %d, want 403 or 404.\nbody: %s", name, path, rec.Code, rec.Body.String())
		}
	}
}

func orgWorkspaceIDs(t *testing.T, f *visibilityFixture) []string {
	t.Helper()
	var ids []string
	if err := f.h.db.Model(&models.Workspace{}).Joins("JOIN projects ON projects.id = workspaces.project_id").
		Where("projects.organization_id = ?", f.org.ID).Order("workspaces.id").Pluck("workspaces.id", &ids).Error; err != nil {
		t.Fatalf("load workspaces: %v", err)
	}
	sort.Strings(ids) // as listedIDs sorts, whatever the database's collation
	return ids
}

func orgProjectIDs(t *testing.T, f *visibilityFixture) []string {
	t.Helper()
	var ids []string
	if err := f.h.db.Model(&models.Project{}).Where("organization_id = ?", f.org.ID).Order("id").Pluck("id", &ids).Error; err != nil {
		t.Fatalf("load projects: %v", err)
	}
	sort.Strings(ids)
	return ids
}

// fixtureIDs keeps the ids of the fixture's own workspaces, projects or runs, sorted.
func fixtureIDs(ids []string, of ...string) []string {
	var out []string
	for _, id := range ids {
		if contains(of, id) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func analyticsStatus(t *testing.T, f *visibilityFixture, token string) int {
	t.Helper()
	return f.do(t, token, http.MethodGet, "/api/v2/organizations/"+f.org.Name+"/analytics", nil).Code
}

// orgActivityWorkspaces is the workspaces named by the organization's activity feed.
func orgActivityWorkspaces(t *testing.T, f *visibilityFixture, token string) []string {
	t.Helper()
	path := "/api/v2/activities?limit=100&organization_id=" + f.org.ID.String()
	rec := f.do(t, token, http.MethodGet, path, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200.\nbody: %s", path, rec.Code, rec.Body.String())
	}
	var doc struct {
		Data []struct {
			Attributes struct {
				Details map[string]any `json:"details"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("activities body is not JSON: %v", err)
	}
	var out []string
	for _, d := range doc.Data {
		if ws, ok := d.Attributes.Details["workspace_id"].(string); ok {
			out = append(out, ws)
		}
	}
	return out
}

func TestMemberVisibility(t *testing.T) {
	f := setupVisibility(t)
	// The organization's activity feed records a change to each fixture workspace.
	for _, ws := range []models.Workspace{f.wsInP, f.wsInQ} {
		row := models.AuditLog{
			ID: uuid.New(), OrganizationID: &f.org.ID, ProjectID: &ws.ProjectID, Action: "update", ResourceType: "workspace",
			Details: models.AuditDetails{"workspace_id": ws.ID, "resource_id": ws.ID, "resource_name": ws.Name},
		}
		if err := f.h.db.Create(&row).Error; err != nil {
			t.Fatalf("seed activity: %v", err)
		}
	}
	allWorkspaces, allProjects := orgWorkspaceIDs(t, f), orgProjectIDs(t, f)
	wsList := "/api/v2/organizations/" + f.org.Name + "/workspaces?page[size]=100"
	projList := "/api/v2/organizations/" + f.org.Name + "/projects?page[size]=100"
	runList := "/api/v2/organizations/" + f.org.Name + "/runs?page[size]=100"
	queue := "/api/v2/organizations/" + f.org.Name + "/runs/queue"
	fixtureWorkspaces := []string{f.wsInP.ID, f.wsInQ.ID}
	fixtureProjects := []string{f.project.ID.String(), f.other.ID.String()}
	fixtureRuns := []string{f.run[f.wsInP.ID], f.run[f.wsInQ.ID]}

	cases := []struct {
		name       string
		token      string
		workspaces []string // of the fixture's, the ones it reads
		projects   []string
		whole      bool // reads every workspace and project of the organization
		analytics  bool
	}{
		{"a member without access", memberToken(t, f.scopedTokensFixture, "none"), nil, nil, false, false},
		{"a member whose team reads one workspace", memberToken(t, f.scopedTokensFixture, "workspace"), []string{f.wsInP.ID}, nil, false, false},
		{"a member whose team reads a project", memberToken(t, f.scopedTokensFixture, "project"), []string{f.wsInP.ID}, []string{f.project.ID.String()}, false, false},
		{"a member who may view all workspaces and projects", memberToken(t, f.scopedTokensFixture, "org-read"), fixtureWorkspaces, fixtureProjects, true, true},
		{"an owner", f.h.token, fixtureWorkspaces, fixtureProjects, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, ws := range []models.Workspace{f.wsInP, f.wsInQ} {
				t.Run("reads of "+ws.Name, func(t *testing.T) {
					readsFollow(t, f, tc.token, f.workspaceReads(ws), contains(tc.workspaces, ws.ID))
				})
			}
			for _, p := range []models.Project{f.project, f.other} {
				t.Run("reads of "+p.Name, func(t *testing.T) {
					readsFollow(t, f, tc.token, f.projectReads(p), contains(tc.projects, p.ID.String()))
				})
			}

			t.Run("the workspace listing holds what it reads", func(t *testing.T) {
				got := listedIDs(t, f.scopedTokensFixture, tc.token, wsList)
				if g := fixtureIDs(got, fixtureWorkspaces...); !sameIDs(g, fixtureIDs(fixtureWorkspaces, tc.workspaces...)) {
					t.Errorf("lists %v of the fixture's workspaces, want %v", g, tc.workspaces)
				}
				if tc.whole && !sameIDs(got, allWorkspaces) {
					t.Errorf("lists %d workspaces, the organization has %d", len(got), len(allWorkspaces))
				}
				if one := readableOneByOne(t, f.scopedTokensFixture, tc.token, "workspaces"); !sameIDs(got, one) {
					t.Errorf("the listing %v and the single reads %v disagree", got, one)
				}
			})
			t.Run("the project listing holds what it reads", func(t *testing.T) {
				got := listedIDs(t, f.scopedTokensFixture, tc.token, projList)
				if g := fixtureIDs(got, fixtureProjects...); !sameIDs(g, fixtureIDs(fixtureProjects, tc.projects...)) {
					t.Errorf("lists %v of the fixture's projects, want %v", g, tc.projects)
				}
				if tc.whole && !sameIDs(got, allProjects) {
					t.Errorf("lists %d projects, the organization has %d", len(got), len(allProjects))
				}
				if one := readableOneByOne(t, f.scopedTokensFixture, tc.token, "projects"); !sameIDs(got, one) {
					t.Errorf("the listing %v and the single reads %v disagree", got, one)
				}
			})
			var wantRuns []string
			for _, ws := range tc.workspaces {
				wantRuns = append(wantRuns, f.run[ws])
			}
			for name, path := range map[string]string{"the organization's runs": runList, "the run queue": queue} {
				t.Run(name+" hold the runs it reads", func(t *testing.T) {
					got := fixtureIDs(listedIDs(t, f.scopedTokensFixture, tc.token, path), fixtureRuns...)
					if !sameIDs(got, fixtureIDs(fixtureRuns, wantRuns...)) {
						t.Errorf("lists %v of the fixture's runs, want %v", got, wantRuns)
					}
				})
			}
			t.Run("the activity feed names only workspaces it reads", func(t *testing.T) {
				got := fixtureIDs(orgActivityWorkspaces(t, f, tc.token), fixtureWorkspaces...)
				for _, ws := range got {
					if !contains(tc.workspaces, ws) {
						t.Errorf("the feed names %s, which it cannot read", ws)
					}
				}
				for _, ws := range tc.workspaces {
					if !contains(got, ws) {
						t.Errorf("the feed omits %s, which it reads", ws)
					}
				}
			})
			t.Run("the dashboard counts what the listings hold", func(t *testing.T) {
				got, ok := dashboardOrgs(t, f.scopedTokensFixture, tc.token)[f.org.ID.String()]
				if !ok {
					t.Fatalf("the dashboard does not show %s", f.org.Name)
				}
				if want := int64(len(listedIDs(t, f.scopedTokensFixture, tc.token, wsList))); got.Workspaces != want {
					t.Errorf("counts %d workspaces, the listing holds %d", got.Workspaces, want)
				}
				if want := int64(len(listedIDs(t, f.scopedTokensFixture, tc.token, projList))); got.Projects != want {
					t.Errorf("counts %d projects, the listing holds %d", got.Projects, want)
				}
				live := liveExecutionIDs(t, f.scopedTokensFixture, tc.token)
				for _, ws := range fixtureWorkspaces {
					if want := contains(tc.workspaces, ws); live[f.run[ws]] != want {
						t.Errorf("live operations show the run of %s: %v, want %v", ws, live[f.run[ws]], want)
					}
				}
			})
			t.Run("analytics follow Explorer's rule", func(t *testing.T) {
				code := analyticsStatus(t, f, tc.token)
				if tc.analytics && code != http.StatusOK {
					t.Errorf("GET analytics = %d, want 200", code)
				}
				if !tc.analytics && code != http.StatusForbidden {
					t.Errorf("GET analytics = %d, want 403", code)
				}
			})
		})
	}
}
