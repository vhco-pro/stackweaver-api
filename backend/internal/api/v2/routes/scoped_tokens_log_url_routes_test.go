// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A run's log-read-url, through the router the server mounts, reads the run's logs only while the
// credential it was minted for still may: revoking the API token, or removing its team's access to
// the workspace, stops the URL at once.

//go:build integration

package routes_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// teamTokenWithReadOn creates a team with read access on wsInP and mints its team token, returning
// the token, its key id and the access row.
func teamTokenWithReadOn(t *testing.T, f *scopedTokensFixture) (token string, keyID uuid.UUID, access models.TeamWorkspaceAccess) {
	t.Helper()
	team := models.Team{ID: uuid.New(), OrganizationID: f.org.ID, Name: "scoped-lu-" + uuid.NewString()[:8]}
	level := "read"
	access = models.TeamWorkspaceAccess{ID: uuid.New(), TeamID: team.ID, WorkspaceID: f.wsInP.ID, Access: &level}
	for _, row := range []any{&team, &access} {
		if err := f.h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	key, token, err := f.keys.CreateTeamToken(f.owner.ID, team.ID, f.org.ID, nil)
	if err != nil {
		t.Fatalf("mint a team token: %v", err)
	}
	return token, key.ID, access
}

// logReadURLPath reads the run's plan with the token and returns the path and query of its
// log-read-url, as a client following it would request it.
func logReadURLPath(t *testing.T, f *scopedTokensFixture, token, runID string) string {
	t.Helper()
	rec := f.do(t, token, http.MethodGet, "/api/v2/runs/"+runID+"/plan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET plan = %d.\nbody: %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Data struct {
			Attributes struct {
				LogReadURL string `json:"log-read-url"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("plan body is not JSON: %v", err)
	}
	u, err := url.Parse(doc.Data.Attributes.LogReadURL)
	if err != nil || u.Query().Get("token") == "" {
		t.Fatalf("log-read-url %q carries no log token", doc.Data.Attributes.LogReadURL)
	}
	return u.RequestURI()
}

func TestScopedTokens_LogReadURLFollowsTheCredential(t *testing.T) {
	f := setupScopedTokens(t)
	run := models.Run{ID: "run-slu" + uuid.NewString()[:8] + "0000", WorkspaceID: f.wsInP.ID, Status: models.RunStatusPlanned, Operation: models.RunOperationPlanAndApply}
	if err := f.h.db.Create(&run).Error; err != nil {
		t.Fatalf("seed run: %v", err)
	}
	follow := func(t *testing.T, path string) int {
		t.Helper()
		return f.do(t, "", http.MethodGet, path, nil).Code
	}

	t.Run("revoking the API token stops the URL", func(t *testing.T) {
		token, keyID, _ := teamTokenWithReadOn(t, f)
		path := logReadURLPath(t, f, token, run.ID)
		if code := follow(t, path); !logReadAuthorized(code) {
			t.Fatalf("the log-read-url answered %d before anything was revoked", code)
		}
		if err := f.h.db.Where("id = ?", keyID).Delete(&models.APIKey{}).Error; err != nil {
			t.Fatalf("revoke the token: %v", err)
		}
		if code := follow(t, path); code != http.StatusUnauthorized {
			t.Errorf("after the token was revoked the log-read-url answered %d, want 401", code)
		}
	})

	t.Run("removing the team's access stops the URL", func(t *testing.T) {
		token, _, access := teamTokenWithReadOn(t, f)
		path := logReadURLPath(t, f, token, run.ID)
		if code := follow(t, path); !logReadAuthorized(code) {
			t.Fatalf("the log-read-url answered %d before access was removed", code)
		}
		if err := f.h.db.Where("id = ?", access.ID).Delete(&models.TeamWorkspaceAccess{}).Error; err != nil {
			t.Fatalf("remove the team's access: %v", err)
		}
		if code := follow(t, path); code != http.StatusForbidden && code != http.StatusNotFound {
			t.Errorf("after the team lost access the log-read-url answered %d, want 403 or 404", code)
		}
	})

	t.Run("the owner's URL keeps working", func(t *testing.T) {
		if code := follow(t, logReadURLPath(t, f, f.h.token, run.ID)); !logReadAuthorized(code) {
			t.Errorf("the owner's log-read-url answered %d", code)
		}
	})
}
