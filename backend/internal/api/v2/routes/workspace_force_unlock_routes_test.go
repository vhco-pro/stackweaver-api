// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// POST /api/v2/workspaces/:id/actions/force-unlock through the router the server mounts, with
// real API tokens. The org wall admits a user token whose user belongs to the workspace's
// organization and an organization token bound to it; what that member or token may then do is
// the handler's to decide, and force-unlock requires admin access on the workspace, as in TFE.

//go:build integration

package routes_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

type forceUnlockRoutesFixture struct {
	h         *goldenHarness
	keys      *apikey.Service
	org       models.Organization
	owner     models.User
	workspace models.Workspace
}

func setupForceUnlockRoutes(t *testing.T) *forceUnlockRoutesFixture {
	t.Helper()
	h := setupGoldenHarness(t)
	f := &forceUnlockRoutesFixture{h: h}

	// The harness database is a throwaway, dropped when the test ends.
	if err := h.db.Raw(`
		SELECT u.* FROM users u JOIN api_keys k ON k.user_id = u.id
		WHERE k.name = 'golden-harness' LIMIT 1`).Scan(&f.owner).Error; err != nil || f.owner.ID == uuid.Nil {
		t.Fatalf("find the harness user: %v", err)
	}
	if err := h.db.Raw(`
		SELECT o.* FROM organizations o
		JOIN teams t ON t.organization_id = o.id AND t.name = 'owners'
		JOIN team_members tm ON tm.team_id = t.id AND tm.user_id = ?
		ORDER BY o.name LIMIT 1`, f.owner.ID).Scan(&f.org).Error; err != nil || f.org.ID == uuid.Nil {
		t.Fatalf("find an organization the harness user owns: %v", err)
	}

	suffix := uuid.NewString()[:8]
	project := models.Project{ID: uuid.New(), OrganizationID: f.org.ID, Name: "fu-routes-" + suffix}
	f.workspace = models.Workspace{ID: "ws-fur" + suffix + "0000", ProjectID: project.ID, Name: "fu-routes-" + suffix}
	for _, row := range []any{&project, &f.workspace} {
		if err := h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	f.keys = apikey.NewService(
		repository.NewAPIKeyRepository(h.db),
		repository.NewOrganizationRepository(h.db),
		repository.NewProjectRepository(h.db),
		repository.NewTeamRepository(h.db),
	)
	return f
}

// member adds a user to the organization through a team holding the given access on the
// workspace's project, and returns a user token for them.
func (f *forceUnlockRoutesFixture) member(t *testing.T, projectAccess string) string {
	t.Helper()
	suffix := uuid.NewString()[:8]
	user := models.User{ID: uuid.New(), ZitadelSubject: "fu-routes-" + suffix, Email: "fu-routes-" + suffix + "@test.local"}
	team := models.Team{ID: uuid.New(), OrganizationID: f.org.ID, Name: "fu-routes-" + suffix}
	level := projectAccess
	for _, row := range []any{
		&user, &team,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.org.ID, UserID: user.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: user.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: team.ID, ProjectID: f.workspace.ProjectID, Access: &level},
	} {
		if err := f.h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	_, token, err := f.keys.CreateUserToken(user.ID, "fu-routes-"+suffix, nil)
	if err != nil {
		t.Fatalf("mint a user token: %v", err)
	}
	return token
}

// orgToken mints an organization token with admin scope, owned by the harness user, bound to org.
func (f *forceUnlockRoutesFixture) orgToken(t *testing.T, org uuid.UUID) string {
	t.Helper()
	_, token, err := f.keys.CreateAPIKey(f.owner.ID, "fu-routes-"+uuid.NewString()[:8], []string{"org:" + org.String() + ":admin"}, nil)
	if err != nil {
		t.Fatalf("mint an organization token: %v", err)
	}
	return token
}

func (f *forceUnlockRoutesFixture) lock(t *testing.T) {
	t.Helper()
	if err := f.h.db.Model(&models.Workspace{}).Where("id = ?", f.workspace.ID).
		Updates(map[string]any{"locked": true, "locked_by": f.owner.ID, "locked_at": time.Now(), "locked_reason": "held"}).Error; err != nil {
		t.Fatalf("lock workspace: %v", err)
	}
}

func (f *forceUnlockRoutesFixture) locked(t *testing.T) bool {
	t.Helper()
	var ws models.Workspace
	if err := f.h.db.Where("id = ?", f.workspace.ID).First(&ws).Error; err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	return ws.Locked
}

func (f *forceUnlockRoutesFixture) forceUnlock(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/workspaces/"+f.workspace.ID+"/actions/force-unlock", nil)
	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.h.router.ServeHTTP(rec, req)
	return rec
}

func TestForceUnlockRoute_RequiresWorkspaceAdmin(t *testing.T) {
	f := setupForceUnlockRoutes(t)

	// A second organization the harness user owns, for a token bound elsewhere.
	other := models.Organization{ID: uuid.New(), Name: "fu-routes-other-" + uuid.NewString()[:8]}
	otherOwners := models.Team{ID: uuid.New(), OrganizationID: other.ID, Name: "owners"}
	for _, row := range []any{&other, &otherOwners, &models.TeamMember{TeamID: otherOwners.ID, UserID: f.owner.ID}} {
		if err := f.h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	refused := []struct {
		name  string
		token string
		want  int
	}{
		{"a member with read access", f.member(t, "read"), http.StatusForbidden},
		{"a member with write access", f.member(t, "write"), http.StatusForbidden},
		{"a token bound to another organization", f.orgToken(t, other.ID), http.StatusForbidden},
	}
	for _, tc := range refused {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			f.lock(t)
			rec := f.forceUnlock(t, tc.token)
			if rec.Code != tc.want {
				t.Errorf("force-unlock = %d, want %d.\nbody: %s", rec.Code, tc.want, rec.Body.String())
			}
			if !f.locked(t) {
				t.Errorf("%s removed the lock", tc.name)
			}
		})
	}

	permitted := []struct {
		name  string
		token string
	}{
		{"a member with admin access", f.member(t, "admin")},
		{"the owner's user token", f.h.token},
		{"the organization's own token", f.orgToken(t, f.org.ID)},
	}
	for _, tc := range permitted {
		t.Run(tc.name+" force-unlocks", func(t *testing.T) {
			f.lock(t)
			rec := f.forceUnlock(t, tc.token)
			if rec.Code != http.StatusOK {
				t.Fatalf("force-unlock = %d, want 200.\nbody: %s", rec.Code, rec.Body.String())
			}
			if f.locked(t) {
				t.Errorf("%s got 200 and the lock stayed", tc.name)
			}
		})
	}
}
