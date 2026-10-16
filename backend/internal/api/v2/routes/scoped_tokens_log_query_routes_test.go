// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A token passed as ?token= on the run log routes, through the router the server mounts, is the same
// token it would be in the Authorization header: judged as its team or project, and held by the org
// wall to its organization.

//go:build integration

package routes_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// logsWithQueryToken reads a run's logs with the token in ?token= and no Authorization header.
func logsWithQueryToken(t *testing.T, f *scopedTokensFixture, token, runID, suffix string) int {
	t.Helper()
	rec := f.do(t, "", http.MethodGet, "/api/v2/runs/"+runID+"/logs"+suffix+"?token="+token, nil)
	return rec.Code
}

// logReadAuthorized reports whether a log read got past authorization. The harness has no log
// store, so a read that is authorized is answered 503 by the store; with one it is a 200.
func logReadAuthorized(code int) bool {
	return code == http.StatusOK || code == http.StatusServiceUnavailable
}

func TestScopedTokens_QueryTokenOnRunLogs(t *testing.T) {
	f := setupScopedTokens(t)
	runs := map[string]string{}
	for name, ws := range map[string]string{"inside": f.wsInP.ID, "outside": f.wsInQ.ID} {
		run := models.Run{ID: "run-scl" + uuid.NewString()[:8] + "0000", WorkspaceID: ws, Status: models.RunStatusPlanned, Operation: models.RunOperationPlanAndApply}
		if err := f.h.db.Create(&run).Error; err != nil {
			t.Fatalf("seed run: %v", err)
		}
		runs[name] = run.ID
	}

	for name, token := range map[string]string{
		"a project key":            f.scopedKey(t, "project:"+f.project.ID.String()+":read"),
		"a team token":             f.teamToken(t, "read"),
		"a team-scoped member key": teamKeyOfAMember(t, f),
	} {
		for _, suffix := range []string{"", "/plan", "/apply"} {
			t.Run(name+" reads logs"+suffix+" of a run inside its scope", func(t *testing.T) {
				if code := logsWithQueryToken(t, f, token, runs["inside"], suffix); !logReadAuthorized(code) {
					t.Errorf("got %d, want the read authorized", code)
				}
			})
			t.Run(name+" cannot read logs"+suffix+" of a run outside its scope", func(t *testing.T) {
				if code := logsWithQueryToken(t, f, token, runs["outside"], suffix); code != http.StatusForbidden && code != http.StatusNotFound {
					t.Errorf("got %d, want 403 or 404", code)
				}
			})
		}
	}

	foreign := otherOrgToken(t, f)
	t.Run("a token bound to another organization cannot read logs by ?token=", func(t *testing.T) {
		if code := logsWithQueryToken(t, f, foreign, runs["inside"], ""); code != http.StatusForbidden && code != http.StatusNotFound {
			t.Errorf("got %d, want 403 or 404", code)
		}
	})
	t.Run("the owner's user token reads logs by ?token=", func(t *testing.T) {
		if code := logsWithQueryToken(t, f, f.h.token, runs["outside"], ""); !logReadAuthorized(code) {
			t.Errorf("got %d, want the read authorized", code)
		}
	})
}
