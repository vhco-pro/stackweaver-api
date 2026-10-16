// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The dashboard, through the router the server mounts, answers a token with only what that token
// may see: an organization token its own organization, a team or project token what its subject can
// read, counted from the same readable sets the listings return. User tokens are unchanged.

//go:build integration

package routes_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

type dashboardOrg struct {
	ID         string `json:"id"`
	Projects   int64  `json:"projects"`
	Workspaces int64  `json:"terraform_workspaces"`
}

func dashboardOrgs(t *testing.T, f *scopedTokensFixture, token string) map[string]dashboardOrg {
	t.Helper()
	rec := f.do(t, token, http.MethodGet, "/api/v2/dashboard/stats", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET dashboard/stats = %d, want 200.\nbody: %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Data struct {
			Attributes struct {
				Organizations []dashboardOrg `json:"organizations"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("dashboard/stats body is not JSON: %v", err)
	}
	out := map[string]dashboardOrg{}
	for _, o := range doc.Data.Attributes.Organizations {
		out[o.ID] = o
	}
	return out
}

func liveExecutionIDs(t *testing.T, f *scopedTokensFixture, token string) map[string]bool {
	t.Helper()
	rec := f.do(t, token, http.MethodGet, "/api/v2/dashboard/operations", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET dashboard/operations = %d, want 200.\nbody: %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Data struct {
			Attributes struct {
				Executions []struct {
					ID string `json:"id"`
				} `json:"executions"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("dashboard/operations body is not JSON: %v", err)
	}
	out := map[string]bool{}
	for _, e := range doc.Data.Attributes.Executions {
		out[e.ID] = true
	}
	return out
}

func TestScopedTokens_Dashboard(t *testing.T) {
	f := setupScopedTokens(t)
	// A run executing in each of the fixture's projects.
	runs := map[string]string{}
	for name, ws := range map[string]string{"inside": f.wsInP.ID, "outside": f.wsInQ.ID} {
		run := models.Run{ID: "run-scd" + uuid.NewString()[:8] + "0000", WorkspaceID: ws, Status: models.RunStatusPlanning, Operation: models.RunOperationPlanAndApply}
		if err := f.h.db.Create(&run).Error; err != nil {
			t.Fatalf("seed run: %v", err)
		}
		runs[name] = run.ID
	}
	wsList := "/api/v2/organizations/" + f.org.Name + "/workspaces?page[size]=100"
	projList := "/api/v2/organizations/" + f.org.Name + "/projects?page[size]=100"
	// A second organization the owner belongs to, with a token bound to it.
	foreign := otherOrgToken(t, f)
	// The owner's user token sees every organization the owner belongs to.
	everyOrg := dashboardOrgs(t, f, f.h.token)
	if len(everyOrg) < 2 {
		t.Fatalf("the harness user belongs to %d organizations; the test needs at least two", len(everyOrg))
	}

	for name, token := range map[string]string{
		"a project key":               f.scopedKey(t, "project:"+f.project.ID.String()+":read"),
		"a team token":                f.teamToken(t, "write"),
		"a team-scoped key of member": teamKeyOfAMember(t, f),
	} {
		t.Run(name+" sees its organization, counted from what it can read", func(t *testing.T) {
			orgs := dashboardOrgs(t, f, token)
			if len(orgs) != 1 {
				t.Fatalf("dashboard shows %d organizations, want only %s", len(orgs), f.org.Name)
			}
			got, ok := orgs[f.org.ID.String()]
			if !ok {
				t.Fatalf("dashboard does not show %s", f.org.Name)
			}
			if want := int64(len(listedIDs(t, f, token, wsList))); got.Workspaces != want {
				t.Errorf("dashboard counts %d workspaces, the listing returns %d", got.Workspaces, want)
			}
			if want := int64(len(listedIDs(t, f, token, projList))); got.Projects != want {
				t.Errorf("dashboard counts %d projects, the listing returns %d", got.Projects, want)
			}
			live := liveExecutionIDs(t, f, token)
			if !live[runs["inside"]] {
				t.Errorf("live operations omit the run in its scope")
			}
			if live[runs["outside"]] {
				t.Errorf("live operations show a run outside its scope")
			}
		})
	}

	t.Run("an organization token sees only its own organization", func(t *testing.T) {
		orgs := dashboardOrgs(t, f, foreign)
		if len(orgs) != 1 {
			t.Errorf("dashboard shows %d organizations, want only the token's own", len(orgs))
		}
		if _, ok := orgs[f.org.ID.String()]; ok {
			t.Errorf("a token bound to another organization sees %s", f.org.Name)
		}
		if live := liveExecutionIDs(t, f, foreign); live[runs["inside"]] || live[runs["outside"]] {
			t.Errorf("a token bound to another organization sees %s's live runs", f.org.Name)
		}
	})

	t.Run("the owner's user token is unchanged", func(t *testing.T) {
		got := everyOrg[f.org.ID.String()]
		var workspaces, projects int64
		f.h.db.Model(&models.Workspace{}).Joins("JOIN projects ON projects.id = workspaces.project_id").Where("projects.organization_id = ?", f.org.ID).Count(&workspaces)
		f.h.db.Model(&models.Project{}).Where("organization_id = ?", f.org.ID).Count(&projects)
		if got.Workspaces != workspaces || got.Projects != projects {
			t.Errorf("dashboard counts %d workspaces and %d projects, the organization has %d and %d", got.Workspaces, got.Projects, workspaces, projects)
		}
		live := liveExecutionIDs(t, f, f.h.token)
		if !live[runs["inside"]] || !live[runs["outside"]] {
			t.Errorf("the owner's live operations omit a run of the organization")
		}
	})
}
