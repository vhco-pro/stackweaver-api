// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Unlocking a workspace removes the caller's own lock. TFE's POST
// /workspaces/:id/actions/unlock needs the lock permission and answers a lock held by someone
// else with 409 whatever the caller's access, naming the holder's kind ("is locked by User"),
// which go-tfe turns into ErrWorkspaceLockedByUser. Removing someone else's lock is
// force-unlock, which needs admin access on the workspace.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration
// +build integration

package terraform

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func (f *forceUnlockFixture) unlock(t *testing.T, asUser uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v2/workspaces/"+f.workspaceID+"/actions/unlock", nil)
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func TestUnlockAuthz_OnlyTheHolderUnlocks(t *testing.T) {
	f := setupForceUnlockFixture(t) // the lock is held by the "project-write" user

	// Someone else's lock: 409 in TFE's shape, whatever access the caller has, including admin.
	for _, caller := range []string{"workspace-write", "owner", "manage-all", "project-admin", "workspace-admin"} {
		t.Run(caller+" cannot remove another user's lock", func(t *testing.T) {
			f.lock(t)
			rec := f.unlock(t, f.users[caller])
			if rec.Code != http.StatusConflict {
				t.Fatalf("unlock as %s = %d, want 409.\nbody: %s", caller, rec.Code, rec.Body.String())
			}
			var body struct {
				Errors []struct {
					Status string `json:"status"`
					Title  string `json:"title"`
					Detail string `json:"detail"`
				} `json:"errors"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Errors) != 1 {
				t.Fatalf("answer must be one JSON:API error: %v %s", err, rec.Body.String())
			}
			e := body.Errors[0]
			if e.Status != "409" || !strings.Contains(e.Title+"\n\n"+e.Detail, "is locked by User") {
				t.Errorf("go-tfe recognises this refusal by \"is locked by User\"; got %+v", e)
			}
			if !strings.Contains(e.Detail, "different user") {
				t.Errorf("the web app offers force-unlock on \"different user\"; got %q", e.Detail)
			}
			if !f.locked(t) {
				t.Errorf("unlock as %s removed another user's lock", caller)
			}
		})
	}

	// Callers without the lock permission are refused before the lock state is read.
	for _, tc := range []struct {
		caller string
		want   int
	}{
		{"project-read", http.StatusForbidden},
		{"outsider", http.StatusForbidden},
		{"anonymous", http.StatusUnauthorized},
	} {
		t.Run(tc.caller+" is refused", func(t *testing.T) {
			f.lock(t)
			if rec := f.unlock(t, f.users[tc.caller]); rec.Code != tc.want {
				t.Errorf("unlock as %s = %d, want %d.\nbody: %s", tc.caller, rec.Code, tc.want, rec.Body.String())
			}
			if !f.locked(t) {
				t.Errorf("unlock as %s removed the lock", tc.caller)
			}
		})
	}

	t.Run("a lock with no recorded holder is not the caller's", func(t *testing.T) {
		f.lock(t)
		if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.workspaceID).Update("locked_by", nil).Error; err != nil {
			t.Fatalf("clear holder: %v", err)
		}
		if rec := f.unlock(t, f.users["project-write"]); rec.Code != http.StatusConflict {
			t.Errorf("unlock of a holderless lock = %d, want 409.\nbody: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("the holder unlocks their own lock", func(t *testing.T) {
		f.lock(t)
		if rec := f.unlock(t, f.locker); rec.Code != http.StatusOK {
			t.Fatalf("unlock by the holder = %d, want 200.\nbody: %s", rec.Code, rec.Body.String())
		}
		if f.locked(t) {
			t.Errorf("unlock by the holder answered 200 and left the lock")
		}
		if rec := f.unlock(t, f.locker); rec.Code != http.StatusConflict {
			t.Errorf("unlocking an unlocked workspace = %d, want 409", rec.Code)
		}
	})
}
