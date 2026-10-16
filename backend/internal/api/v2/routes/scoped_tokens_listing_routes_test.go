// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Listings for team and project tokens, through the router the server mounts: a listing returns
// exactly what the token could read one by one, by plain list and by tag filter. Organization
// tokens and user tokens list as before.

//go:build integration

package routes_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// listedIDs reads the ids of a JSON:API collection.
func listedIDs(t *testing.T, f *scopedTokensFixture, token, path string) []string {
	t.Helper()
	rec := f.do(t, token, http.MethodGet, path, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200.\nbody: %s", path, rec.Code, rec.Body.String())
	}
	var doc struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("GET %s: body is not JSON: %v", path, err)
	}
	ids := make([]string, 0, len(doc.Data))
	for _, d := range doc.Data {
		ids = append(ids, d.ID)
	}
	sort.Strings(ids)
	return ids
}

func sameIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// readableOneByOne is every workspace (or project) of the organization the token can read alone.
func readableOneByOne(t *testing.T, f *scopedTokensFixture, token, collection string) []string {
	t.Helper()
	var ids []string
	switch collection {
	case "workspaces":
		var all []models.Workspace
		if err := f.h.db.Joins("JOIN projects ON projects.id = workspaces.project_id").Where("projects.organization_id = ?", f.org.ID).Find(&all).Error; err != nil {
			t.Fatalf("load workspaces: %v", err)
		}
		for _, w := range all {
			if f.do(t, token, http.MethodGet, "/api/v2/workspaces/"+w.ID, nil).Code == http.StatusOK {
				ids = append(ids, w.ID)
			}
		}
	case "projects":
		var all []models.Project
		if err := f.h.db.Where("organization_id = ?", f.org.ID).Find(&all).Error; err != nil {
			t.Fatalf("load projects: %v", err)
		}
		for _, p := range all {
			if f.do(t, token, http.MethodGet, "/api/v2/projects/"+p.ID.String(), nil).Code == http.StatusOK {
				ids = append(ids, p.ID.String())
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func TestScopedTokens_ListingsMatchSingleReads(t *testing.T) {
	f := setupScopedTokens(t)
	// The same tag on a workspace inside and one outside the key's project.
	tag := "scoped-tag-" + uuid.NewString()[:8]
	for i, ws := range []string{f.wsInP.ID, f.wsInQ.ID} {
		wsID := ws
		if err := f.h.db.Create(&models.TagBinding{ID: fmt.Sprintf("tb-scoped%d%s", i, uuid.NewString()[:8]), Key: tag, WorkspaceID: &wsID}).Error; err != nil {
			t.Fatalf("seed tag binding: %v", err)
		}
	}
	wsList := "/api/v2/organizations/" + f.org.Name + "/workspaces?page[size]=100"
	projList := "/api/v2/organizations/" + f.org.Name + "/projects?page[size]=100"

	projectKey := f.scopedKey(t, "project:"+f.project.ID.String()+":read")
	t.Run("a project key lists its project's workspaces and nothing else", func(t *testing.T) {
		got := listedIDs(t, f, projectKey, wsList)
		if !sameIDs(got, []string{f.wsInP.ID}) {
			t.Errorf("listed %v, want only %s", got, f.wsInP.ID)
		}
		if one := readableOneByOne(t, f, projectKey, "workspaces"); !sameIDs(got, one) {
			t.Errorf("the listing %v and the single reads %v disagree", got, one)
		}
	})
	t.Run("a project key's tag filter stays in its project", func(t *testing.T) {
		got := listedIDs(t, f, projectKey, wsList+"&search[tags]="+tag)
		if !sameIDs(got, []string{f.wsInP.ID}) {
			t.Errorf("listed %v, want only %s", got, f.wsInP.ID)
		}
	})
	t.Run("a project key lists its project and nothing else", func(t *testing.T) {
		got := listedIDs(t, f, projectKey, projList)
		if !sameIDs(got, []string{f.project.ID.String()}) {
			t.Errorf("listed %v, want only %s", got, f.project.ID)
		}
		if one := readableOneByOne(t, f, projectKey, "projects"); !sameIDs(got, one) {
			t.Errorf("the listing %v and the single reads %v disagree", got, one)
		}
	})

	teamToken := f.teamToken(t, "write")
	t.Run("a team token lists its team's workspaces", func(t *testing.T) {
		got := listedIDs(t, f, teamToken, wsList)
		if !sameIDs(got, []string{f.wsInP.ID}) {
			t.Errorf("listed %v, want only %s", got, f.wsInP.ID)
		}
		if one := readableOneByOne(t, f, teamToken, "workspaces"); !sameIDs(got, one) {
			t.Errorf("the listing %v and the single reads %v disagree", got, one)
		}
		if tagged := listedIDs(t, f, teamToken, wsList+"&search[tags]="+tag); !sameIDs(tagged, []string{f.wsInP.ID}) {
			t.Errorf("tag filter listed %v, want only %s", tagged, f.wsInP.ID)
		}
	})

	t.Run("a team token with project access lists that project's workspaces", func(t *testing.T) {
		team := models.Team{ID: uuid.New(), OrganizationID: f.org.ID, Name: "scoped-pa-" + uuid.NewString()[:8]}
		level := "read"
		for _, row := range []any{&team, &models.TeamProjectAccess{ID: uuid.New(), TeamID: team.ID, ProjectID: f.project.ID, Access: &level}} {
			if err := f.h.db.Create(row).Error; err != nil {
				t.Fatalf("seed %T: %v", row, err)
			}
		}
		_, token, err := f.keys.CreateTeamToken(f.owner.ID, team.ID, f.org.ID, nil)
		if err != nil {
			t.Fatalf("mint a team token: %v", err)
		}
		got := listedIDs(t, f, token, wsList)
		if !sameIDs(got, []string{f.wsInP.ID}) {
			t.Errorf("listed %v, want only %s", got, f.wsInP.ID)
		}
		if one := readableOneByOne(t, f, token, "workspaces"); !sameIDs(got, one) {
			t.Errorf("the listing %v and the single reads %v disagree", got, one)
		}
		if ps := listedIDs(t, f, token, projList); !sameIDs(ps, []string{f.project.ID.String()}) {
			t.Errorf("projects listed %v, want only %s", ps, f.project.ID)
		}
	})

	orgToken := f.scopedKey(t, "org:"+f.org.ID.String()+":admin")
	for name, token := range map[string]string{"an organization token": orgToken, "the owner's user token": f.h.token} {
		t.Run(name+" lists the whole organization", func(t *testing.T) {
			ws := listedIDs(t, f, token, wsList)
			if !contains(ws, f.wsInP.ID) || !contains(ws, f.wsInQ.ID) {
				t.Errorf("workspaces listed %v, want both %s and %s", ws, f.wsInP.ID, f.wsInQ.ID)
			}
			ps := listedIDs(t, f, token, projList)
			if !contains(ps, f.project.ID.String()) || !contains(ps, f.other.ID.String()) {
				t.Errorf("projects listed %v, want both of the fixture's projects", ps)
			}
		})
	}
}
