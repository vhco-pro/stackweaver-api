// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Organization tokens scoped to a team or a project, through the router the server mounts.
//
// A team token acts as its team, as in Terraform Enterprise: it reaches what the team's access
// reaches, for reads and writes, and nothing its owner could reach beyond that. A project-scoped
// key reaches only its project, up to the level its scope names. Organization tokens and user
// tokens are judged as before.

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

type scopedTokensFixture struct {
	h          *goldenHarness
	keys       *apikey.Service
	owner      models.User
	org        models.Organization
	project    models.Project // P: holds wsInP
	other      models.Project // Q: holds wsInQ
	wsInP      models.Workspace
	wsInQ      models.Workspace
	freeVCS    string // a provider the organization has no connection for
	projectsAt string
}

func setupScopedTokens(t *testing.T) *scopedTokensFixture {
	t.Helper()
	h := setupGoldenHarness(t)
	f := &scopedTokensFixture{h: h}
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

	// The harness database is a throwaway, dropped when the test ends.
	s := uuid.NewString()[:8]
	f.project = models.Project{ID: uuid.New(), OrganizationID: f.org.ID, Name: "scoped-p-" + s}
	f.other = models.Project{ID: uuid.New(), OrganizationID: f.org.ID, Name: "scoped-q-" + s}
	f.wsInP = models.Workspace{ID: "ws-scp" + s + "0000", ProjectID: f.project.ID, Name: "scoped-p-" + s}
	f.wsInQ = models.Workspace{ID: "ws-scq" + s + "0000", ProjectID: f.other.ID, Name: "scoped-q-" + s}
	for _, row := range []any{&f.project, &f.other, &f.wsInP, &f.wsInQ} {
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
	for _, p := range []string{"gitlab", "bitbucket", "azure_devops", "github"} {
		var n int64
		h.db.Model(&models.VCSConnection{}).Where("organization_id = ? AND provider = ?", f.org.ID, p).Count(&n)
		if n == 0 {
			f.freeVCS = p
			break
		}
	}
	f.projectsAt = "/api/v2/organizations/" + f.org.Name + "/projects"
	return f
}

// teamToken creates a team with the given workspace access on wsInP ("" for none) and mints its
// team token the way the team token endpoint does: by an organization owner.
func (f *scopedTokensFixture) teamToken(t *testing.T, workspaceAccess string) string {
	t.Helper()
	team := models.Team{ID: uuid.New(), OrganizationID: f.org.ID, Name: "scoped-" + uuid.NewString()[:8]}
	if err := f.h.db.Create(&team).Error; err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if workspaceAccess != "" {
		level := workspaceAccess
		if err := f.h.db.Create(&models.TeamWorkspaceAccess{ID: uuid.New(), TeamID: team.ID, WorkspaceID: f.wsInP.ID, Access: &level}).Error; err != nil {
			t.Fatalf("seed team workspace access: %v", err)
		}
	}
	_, token, err := f.keys.CreateTeamToken(f.owner.ID, team.ID, f.org.ID, nil)
	if err != nil {
		t.Fatalf("mint a team token: %v", err)
	}
	return token
}

func (f *scopedTokensFixture) scopedKey(t *testing.T, scopes ...string) string {
	t.Helper()
	_, token, err := f.keys.CreateAPIKey(f.owner.ID, "scoped-"+uuid.NewString()[:8], scopes, nil)
	if err != nil {
		t.Fatalf("mint a key with %v: %v", scopes, err)
	}
	return token
}

func (f *scopedTokensFixture) do(t *testing.T, token, method, path string, body any) *httptest.ResponseRecorder {
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
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.h.router.ServeHTTP(rec, req)
	return rec
}

// action is one request a token makes, and how to tell whether it took effect.
type action struct {
	name string
	run  func(t *testing.T, f *scopedTokensFixture, token string) *httptest.ResponseRecorder
	// done reports whether the request had its effect, and undoes it so the next case starts clean.
	done func(t *testing.T, f *scopedTokensFixture) bool
}

func readWorkspace(ws func(*scopedTokensFixture) string) func(*testing.T, *scopedTokensFixture, string) *httptest.ResponseRecorder {
	return func(t *testing.T, f *scopedTokensFixture, token string) *httptest.ResponseRecorder {
		return f.do(t, token, http.MethodGet, "/api/v2/workspaces/"+ws(f), nil)
	}
}

func lockWorkspace(ws func(*scopedTokensFixture) string) action {
	return action{
		run: func(t *testing.T, f *scopedTokensFixture, token string) *httptest.ResponseRecorder {
			return f.do(t, token, http.MethodPost, "/api/v2/workspaces/"+ws(f)+"/actions/lock", map[string]any{"reason": "scoped"})
		},
		done: func(t *testing.T, f *scopedTokensFixture) bool {
			var w models.Workspace
			if err := f.h.db.Where("id = ?", ws(f)).First(&w).Error; err != nil {
				t.Fatalf("load workspace: %v", err)
			}
			f.h.db.Model(&models.Workspace{}).Where("id = ?", ws(f)).Updates(map[string]any{"locked": false, "locked_by": nil, "locked_at": nil, "locked_reason": ""})
			return w.Locked
		},
	}
}

func queueRun(ws func(*scopedTokensFixture) string) action {
	return action{
		run: func(t *testing.T, f *scopedTokensFixture, token string) *httptest.ResponseRecorder {
			return f.do(t, token, http.MethodPost, "/api/v2/runs", map[string]any{"data": map[string]any{
				"type":          "runs",
				"attributes":    map[string]any{"message": "scoped", "plan-only": true},
				"relationships": map[string]any{"workspace": map[string]any{"data": map[string]any{"type": "workspaces", "id": ws(f)}}},
			}})
		},
		done: func(t *testing.T, f *scopedTokensFixture) bool {
			var n int64
			f.h.db.Model(&models.Run{}).Where("workspace_id = ?", ws(f)).Count(&n)
			f.h.db.Where("workspace_id = ?", ws(f)).Delete(&models.Run{})
			return n > 0
		},
	}
}

func inP(f *scopedTokensFixture) string { return f.wsInP.ID }
func inQ(f *scopedTokensFixture) string { return f.wsInQ.ID }

// refused asserts a write was refused and had no effect.
func refused(t *testing.T, f *scopedTokensFixture, token string, a action) {
	t.Helper()
	rec := a.run(t, f, token)
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Errorf("got %d, want 403 or 404.\nbody: %s", rec.Code, rec.Body.String())
	}
	if a.done(t, f) {
		t.Errorf("a refused request took effect")
	}
}

// permitted asserts a write passed authorization and took effect.
func permitted(t *testing.T, f *scopedTokensFixture, token string, a action) {
	t.Helper()
	rec := a.run(t, f, token)
	if rec.Code >= 300 {
		t.Errorf("got %d, want success.\nbody: %s", rec.Code, rec.Body.String())
	}
	if !a.done(t, f) {
		t.Errorf("the request answered %d and had no effect", rec.Code)
	}
}

func readStatus(t *testing.T, f *scopedTokensFixture, token, path string, want int) {
	t.Helper()
	rec := f.do(t, token, http.MethodGet, path, nil)
	if want == http.StatusForbidden {
		if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 403 or 404.\nbody: %s", path, rec.Code, rec.Body.String())
		}
		return
	}
	if rec.Code != want {
		t.Errorf("GET %s = %d, want %d.\nbody: %s", path, rec.Code, want, rec.Body.String())
	}
}

// organizationWritesRefused asserts the token can neither create a project nor a VCS connection.
func organizationWritesRefused(t *testing.T, f *scopedTokensFixture, token string) {
	t.Helper()
	t.Run("cannot create a project", func(t *testing.T) {
		name := "scoped-made-" + uuid.NewString()[:8]
		rec := f.do(t, token, http.MethodPost, f.projectsAt, map[string]any{"data": map[string]any{"type": "projects", "attributes": map[string]any{"name": name}}})
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST projects = %d, want 403.\nbody: %s", rec.Code, rec.Body.String())
		}
		var n int64
		f.h.db.Model(&models.Project{}).Where("organization_id = ? AND name = ?", f.org.ID, name).Count(&n)
		if n != 0 {
			t.Errorf("the token created a project")
		}
	})
	t.Run("cannot create a VCS connection", func(t *testing.T) {
		if f.freeVCS == "" {
			t.Skip("the organization has a connection for every provider")
		}
		t.Cleanup(func() {
			f.h.db.Where("organization_id = ? AND provider = ? AND account_name = ?", f.org.ID, f.freeVCS, "scoped").Delete(&models.VCSConnection{})
		})
		body := map[string]any{"provider": f.freeVCS, "access_token": "scoped", "account_name": "scoped", "account_type": "organization"}
		rec := f.do(t, token, http.MethodPost, "/api/v2/organizations/"+f.org.Name+"/vcs-connections", body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST vcs-connections = %d, want 403.\nbody: %s", rec.Code, rec.Body.String())
		}
		var n int64
		f.h.db.Model(&models.VCSConnection{}).Where("organization_id = ? AND provider = ?", f.org.ID, f.freeVCS).Count(&n)
		if n != 0 {
			t.Errorf("the token created a VCS connection")
		}
	})
}

func TestScopedTokens_TeamTokenWithoutAccess(t *testing.T) {
	f := setupScopedTokens(t)
	token := f.teamToken(t, "")

	t.Run("cannot read the workspace", func(t *testing.T) { readStatus(t, f, token, "/api/v2/workspaces/"+f.wsInP.ID, http.StatusForbidden) })
	t.Run("cannot read the project", func(t *testing.T) {
		readStatus(t, f, token, "/api/v2/projects/"+f.project.ID.String(), http.StatusForbidden)
	})
	t.Run("cannot lock the workspace", func(t *testing.T) { refused(t, f, token, lockWorkspace(inP)) })
	t.Run("cannot queue a run", func(t *testing.T) { refused(t, f, token, queueRun(inP)) })
	organizationWritesRefused(t, f, token)
	t.Run("still lists the organization's projects", func(t *testing.T) { readStatus(t, f, token, f.projectsAt, http.StatusOK) })
}

func TestScopedTokens_TeamTokenWithWorkspaceWrite(t *testing.T) {
	f := setupScopedTokens(t)
	token := f.teamToken(t, "write")

	t.Run("reads its workspace", func(t *testing.T) { readStatus(t, f, token, "/api/v2/workspaces/"+f.wsInP.ID, http.StatusOK) })
	t.Run("queues a run on its workspace", func(t *testing.T) { permitted(t, f, token, queueRun(inP)) })
	t.Run("locks its workspace", func(t *testing.T) { permitted(t, f, token, lockWorkspace(inP)) })
	t.Run("cannot read another workspace", func(t *testing.T) { readStatus(t, f, token, "/api/v2/workspaces/"+f.wsInQ.ID, http.StatusForbidden) })
	t.Run("cannot queue a run on another workspace", func(t *testing.T) { refused(t, f, token, queueRun(inQ)) })
	t.Run("cannot lock another workspace", func(t *testing.T) { refused(t, f, token, lockWorkspace(inQ)) })
	organizationWritesRefused(t, f, token)
}

func TestScopedTokens_ProjectKeys(t *testing.T) {
	f := setupScopedTokens(t)
	read := f.scopedKey(t, "project:"+f.project.ID.String()+":read")
	write := f.scopedKey(t, "project:"+f.project.ID.String()+":write")

	t.Run("read key", func(t *testing.T) {
		t.Run("reads a workspace of its project", func(t *testing.T) { readStatus(t, f, read, "/api/v2/workspaces/"+f.wsInP.ID, http.StatusOK) })
		t.Run("reads its project", func(t *testing.T) { readStatus(t, f, read, "/api/v2/projects/"+f.project.ID.String(), http.StatusOK) })
		t.Run("cannot read another project's workspace", func(t *testing.T) { readStatus(t, f, read, "/api/v2/workspaces/"+f.wsInQ.ID, http.StatusForbidden) })
		t.Run("cannot read another project", func(t *testing.T) {
			readStatus(t, f, read, "/api/v2/projects/"+f.other.ID.String(), http.StatusForbidden)
		})
		t.Run("cannot lock a workspace of its project", func(t *testing.T) { refused(t, f, read, lockWorkspace(inP)) })
		t.Run("cannot queue a run in its project", func(t *testing.T) { refused(t, f, read, queueRun(inP)) })
		organizationWritesRefused(t, f, read)
	})
	t.Run("write key", func(t *testing.T) {
		t.Run("reads a workspace of its project", func(t *testing.T) { readStatus(t, f, write, "/api/v2/workspaces/"+f.wsInP.ID, http.StatusOK) })
		t.Run("locks a workspace of its project", func(t *testing.T) { permitted(t, f, write, lockWorkspace(inP)) })
		t.Run("queues a run in its project", func(t *testing.T) { permitted(t, f, write, queueRun(inP)) })
		t.Run("cannot read another project's workspace", func(t *testing.T) { readStatus(t, f, write, "/api/v2/workspaces/"+f.wsInQ.ID, http.StatusForbidden) })
		t.Run("cannot lock another project's workspace", func(t *testing.T) { refused(t, f, write, lockWorkspace(inQ)) })
		t.Run("cannot queue a run in another project", func(t *testing.T) { refused(t, f, write, queueRun(inQ)) })
		organizationWritesRefused(t, f, write)
	})
}

// A key scoped to a team is judged as that team only while its owner belongs to the team:
// anyone in the organization can mint one, so it must not lend its owner a team they are not in.
func TestScopedTokens_TeamScopedKeyOfANonMember(t *testing.T) {
	f := setupScopedTokens(t)
	owners := models.Team{}
	if err := f.h.db.Where("organization_id = ? AND name = ?", f.org.ID, "owners").First(&owners).Error; err != nil {
		t.Fatalf("load owners team: %v", err)
	}
	s := uuid.NewString()[:8]
	member := models.User{ID: uuid.New(), ZitadelSubject: "scoped-" + s, Email: "scoped-" + s + "@test.local"}
	team := models.Team{ID: uuid.New(), OrganizationID: f.org.ID, Name: "scoped-member-" + s}
	for _, row := range []any{
		&member, &team,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.org.ID, UserID: member.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: member.ID},
	} {
		if err := f.h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	_, token, err := f.keys.CreateAPIKey(member.ID, "scoped-"+s, []string{"team:" + owners.ID.String() + ":admin"}, nil)
	if err != nil {
		t.Fatalf("mint a key scoped to the owners team: %v", err)
	}
	t.Run("cannot lock a workspace", func(t *testing.T) { refused(t, f, token, lockWorkspace(inP)) })
	organizationWritesRefused(t, f, token)
}

func TestScopedTokens_OrganizationAndUserTokensUnchanged(t *testing.T) {
	f := setupScopedTokens(t)
	orgToken := f.scopedKey(t, "org:"+f.org.ID.String()+":admin")
	for name, token := range map[string]string{"organization token": orgToken, "owner's user token": f.h.token} {
		t.Run(name, func(t *testing.T) {
			pName := "scoped-made-" + uuid.NewString()[:8]
			rec := f.do(t, token, http.MethodPost, f.projectsAt, map[string]any{"data": map[string]any{"type": "projects", "attributes": map[string]any{"name": pName}}})
			if rec.Code != http.StatusCreated {
				t.Errorf("POST projects = %d, want 201.\nbody: %s", rec.Code, rec.Body.String())
			}
			permitted(t, f, token, lockWorkspace(inQ))
			readStatus(t, f, token, "/api/v2/workspaces/"+f.wsInQ.ID, http.StatusOK)
		})
	}
	t.Run("owner's user token queues a run", func(t *testing.T) { permitted(t, f, f.h.token, queueRun(inQ)) })
}
