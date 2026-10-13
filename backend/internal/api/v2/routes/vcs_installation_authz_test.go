// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Starting and completing a VCS installation for an organization takes the same permission as
// creating or deleting one of its VCS connections: organization-level manage-vcs-settings,
// checked by rbac.Service.CheckOrgManageVCSSettings. Three routes are held to that here:
//
//   - GET  /api/v2/organizations/:name/vcs-connections/github/install
//   - POST /api/v2/organizations/:name/vcs-connections/github/installations/:installation_id
//   - GET  /api/v2/organizations/:name/vcs-connections/azure-devops/install
//
// The first two start and complete a GitHub App installation. The third starts the Azure DevOps
// flow by issuing the signed state its callback accepts as proof of who began it, so the check
// belongs where the state is issued.
//
// The requests go through the router the server mounts, with the middleware each route really
// has. The callers are user-bound tokens, which act as their owner: the org wall admits them to
// any organization the owner belongs to, and what the owner may do there is the handler's to
// decide.

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

// vcsInstallAuthzFixture is two organizations and two people.
//
// The manager holds manage-vcs-settings in org and is an ordinary member of otherOrg. The member
// belongs to org and holds no organization permission at all.
type vcsInstallAuthzFixture struct {
	h        *goldenHarness
	org      models.Organization
	otherOrg models.Organization
	manager  string // token
	member   string // token
}

func setupVCSInstallAuthz(t *testing.T) *vcsInstallAuthzFixture {
	t.Helper()
	// No GitHub App, so a caller who is let through reaches the handler's "not configured"
	// answer instead of GitHub. Azure DevOps is configured, with values that are never used to
	// call it: starting that flow only builds a URL.
	t.Setenv("GITHUB_APP_ID", "")
	t.Setenv("AZURE_DEVOPS_CLIENT_ID", "vcs-install-authz-test")
	t.Setenv("AZURE_DEVOPS_CLIENT_SECRET", "not-a-real-secret")
	t.Setenv("AZURE_DEVOPS_REDIRECT_URI", "http://localhost:5173/vcs/azure-devops/callback")

	h := setupGoldenHarness(t)
	f := &vcsInstallAuthzFixture{h: h}

	// The harness database is a throwaway, dropped when the test ends.
	sfx := uuid.NewString()[:8]
	f.org = models.Organization{ID: uuid.New(), Name: "vcs-install-" + sfx}
	f.otherOrg = models.Organization{ID: uuid.New(), Name: "vcs-install-other-" + sfx}
	manager := models.User{ID: uuid.New(), ZitadelSubject: "vcs-install-manager-" + sfx, Email: "vcs-install-manager-" + sfx + "@test.local"}
	member := models.User{ID: uuid.New(), ZitadelSubject: "vcs-install-member-" + sfx, Email: "vcs-install-member-" + sfx + "@test.local"}
	vcsAdmins := models.Team{ID: uuid.New(), OrganizationID: f.org.ID, Name: "vcs-admins"}
	members := models.Team{ID: uuid.New(), OrganizationID: f.org.ID, Name: "members"}
	otherMembers := models.Team{ID: uuid.New(), OrganizationID: f.otherOrg.ID, Name: "members"}
	for _, row := range []any{
		&f.org, &f.otherOrg, &manager, &member, &vcsAdmins, &members, &otherMembers,
		&models.TeamOrganizationAccess{TeamID: vcsAdmins.ID, ManageVCSSettings: true},
		&models.TeamMember{TeamID: vcsAdmins.ID, UserID: manager.ID},
		&models.TeamMember{TeamID: members.ID, UserID: member.ID},
		&models.TeamMember{TeamID: otherMembers.ID, UserID: manager.ID},
	} {
		if err := h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	keys := apikey.NewService(
		repository.NewAPIKeyRepository(h.db),
		repository.NewOrganizationRepository(h.db),
		repository.NewProjectRepository(h.db),
		repository.NewTeamRepository(h.db),
	)
	var err error
	if _, f.manager, err = keys.CreateUserToken(manager.ID, "vcs-install-manager-"+sfx, nil); err != nil {
		t.Fatalf("mint the manager's token: %v", err)
	}
	if _, f.member, err = keys.CreateUserToken(member.ID, "vcs-install-member-"+sfx, nil); err != nil {
		t.Fatalf("mint the member's token: %v", err)
	}
	return f
}

func (f *vcsInstallAuthzFixture) do(t *testing.T, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.h.router.ServeHTTP(rec, req)
	return rec
}

// connections counts every VCS connection the two organizations hold.
func (f *vcsInstallAuthzFixture) connections(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := f.h.db.Model(&models.VCSConnection{}).
		Where("organization_id IN ?", []uuid.UUID{f.org.ID, f.otherOrg.ID}).Count(&n).Error; err != nil {
		t.Fatalf("count connections: %v", err)
	}
	return n
}

// vcsInstallRoute is one gated route, as a path under an organization.
type vcsInstallRoute struct {
	name   string
	method string
	suffix string
	// past is what a caller who holds the permission is answered in this harness. It is not a
	// success for the GitHub routes, and does not need to be: it is the answer that comes after
	// the permission check, which is all these cases are about.
	past int
}

var vcsInstallRoutes = []vcsInstallRoute{
	{"start a GitHub App installation", http.MethodGet, "/vcs-connections/github/install", http.StatusInternalServerError},
	{"complete a GitHub App installation", http.MethodPost, "/vcs-connections/github/installations/424242", http.StatusInternalServerError},
	{"start an Azure DevOps installation", http.MethodGet, "/vcs-connections/azure-devops/install?ado_org=acme", http.StatusOK},
}

func vcsInstallPath(orgName, suffix string) string {
	return "/api/v2/organizations/" + orgName + suffix
}

func TestVCSInstallation_RequiresTheVCSSettingsPermission(t *testing.T) {
	f := setupVCSInstallAuthz(t)

	// What creating a connection answers the same callers. The gated routes are held to these
	// answers exactly, so a caller learns nothing from one that it does not learn from the other.
	createPath := "/vcs-connections"
	refusedLikeCreate := f.do(t, http.MethodPost, vcsInstallPath(f.org.Name, createPath), f.member)
	if refusedLikeCreate.Code != http.StatusForbidden {
		t.Fatalf("creating a connection without the permission = %d, want 403; the fixture's member is not what this test assumes.\nbody: %s",
			refusedLikeCreate.Code, refusedLikeCreate.Body.String())
	}
	unknownLikeCreate := f.do(t, http.MethodPost, vcsInstallPath("vcs-install-no-such-organization", createPath), f.member)

	for _, route := range vcsInstallRoutes {
		t.Run(route.name, func(t *testing.T) {
			t.Run("a member without the permission is refused", func(t *testing.T) {
				rec := f.do(t, route.method, vcsInstallPath(f.org.Name, route.suffix), f.member)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("got %d, want 403.\nbody: %s", rec.Code, rec.Body.String())
				}
				if rec.Body.String() != refusedLikeCreate.Body.String() {
					t.Errorf("the refusal differs from the one creating a connection gives the same caller.\ngot:  %s\nwant: %s",
						rec.Body.String(), refusedLikeCreate.Body.String())
				}
			})

			t.Run("the permission in one organization does not carry to another", func(t *testing.T) {
				rec := f.do(t, route.method, vcsInstallPath(f.otherOrg.Name, route.suffix), f.manager)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("got %d, want 403.\nbody: %s", rec.Code, rec.Body.String())
				}
			})

			t.Run("an unknown organization is answered as creating a connection answers it", func(t *testing.T) {
				rec := f.do(t, route.method, vcsInstallPath("vcs-install-no-such-organization", route.suffix), f.member)
				if rec.Code != unknownLikeCreate.Code || rec.Body.String() != unknownLikeCreate.Body.String() {
					t.Errorf("got %d %s, want %d %s", rec.Code, rec.Body.String(), unknownLikeCreate.Code, unknownLikeCreate.Body.String())
				}
			})

			t.Run("a caller with the permission gets past the check", func(t *testing.T) {
				rec := f.do(t, route.method, vcsInstallPath(f.org.Name, route.suffix), f.manager)
				if rec.Code != route.past {
					t.Fatalf("got %d, want %d (the answer that follows the permission check here).\nbody: %s",
						rec.Code, route.past, rec.Body.String())
				}
			})
		})
	}

	// A refusal that still did the work would be no refusal, and nothing above should have
	// written a connection either way: the GitHub App is not configured and starting the Azure
	// DevOps flow only issues a URL.
	if n := f.connections(t); n != 0 {
		t.Errorf("the two organizations hold %d VCS connection(s) after these requests, want none", n)
	}
}

// An organization-bound key is the org wall's to judge, before any handler: it is held to its
// own organization and to its scope, and the permission its owner holds is not consulted to let
// it past either. The owner here holds manage-vcs-settings in the organization the requests
// name, so a handler that fell back on the owner would let both of these through.
func TestVCSInstallation_OrgBoundKeyIsHeldToItsOrganizationAndScope(t *testing.T) {
	f := setupVCSInstallAuthz(t)

	var manager models.User
	if err := f.h.db.Raw(`
		SELECT u.* FROM users u JOIN team_members tm ON tm.user_id = u.id
		JOIN teams t ON t.id = tm.team_id
		WHERE t.organization_id = ? AND t.name = 'vcs-admins' LIMIT 1`, f.org.ID).Scan(&manager).Error; err != nil || manager.ID == uuid.Nil {
		t.Fatalf("find the manager: %v", err)
	}
	keys := apikey.NewService(
		repository.NewAPIKeyRepository(f.h.db),
		repository.NewOrganizationRepository(f.h.db),
		repository.NewProjectRepository(f.h.db),
		repository.NewTeamRepository(f.h.db),
	)
	_, elsewhere, err := keys.CreateAPIKey(manager.ID, "vcs-install-elsewhere", []string{"org:" + f.otherOrg.ID.String() + ":admin"}, nil)
	if err != nil {
		t.Fatalf("mint a key bound to the other organization: %v", err)
	}
	_, readOnly, err := keys.CreateAPIKey(manager.ID, "vcs-install-read-only", []string{"org:" + f.org.ID.String() + ":read"}, nil)
	if err != nil {
		t.Fatalf("mint a read-only key: %v", err)
	}

	for _, route := range vcsInstallRoutes {
		t.Run("a key bound to another organization/"+route.name, func(t *testing.T) {
			rec := f.do(t, route.method, vcsInstallPath(f.org.Name, route.suffix), elsewhere)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("got %d, want 403.\nbody: %s", rec.Code, rec.Body.String())
			}
		})
	}
	t.Run("a read-only key completing an installation", func(t *testing.T) {
		complete := vcsInstallRoutes[1]
		rec := f.do(t, complete.method, vcsInstallPath(f.org.Name, complete.suffix), readOnly)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("got %d, want 403.\nbody: %s", rec.Code, rec.Body.String())
		}
	})

	if n := f.connections(t); n != 0 {
		t.Errorf("the two organizations hold %d VCS connection(s) after these requests, want none", n)
	}
}

// The Azure DevOps callback writes the connection, and it has no caller to check: it accepts
// the signed state issued when the flow was started. So the state must only ever be issued to
// a caller who holds the permission, and a caller who does not must come away without one.
func TestAzureDevOpsInstallation_IssuesStateOnlyWithThePermission(t *testing.T) {
	f := setupVCSInstallAuthz(t)
	path := vcsInstallPath(f.org.Name, "/vcs-connections/azure-devops/install?ado_org=acme")

	authURL := func(t *testing.T, rec *httptest.ResponseRecorder) string {
		t.Helper()
		var doc struct {
			Data struct {
				AuthURL string `json:"auth_url"`
			} `json:"data"`
			AuthURL string `json:"auth_url"`
		}
		// A refusal has no such member; an unparseable body leaves both empty.
		_ = json.Unmarshal(rec.Body.Bytes(), &doc)
		if doc.Data.AuthURL != "" {
			return doc.Data.AuthURL
		}
		return doc.AuthURL
	}

	if got := authURL(t, f.do(t, http.MethodGet, path, f.member)); got != "" {
		t.Errorf("a member without the permission was issued an authorization URL carrying a signed state: %s", got)
	}
	if got := authURL(t, f.do(t, http.MethodGet, path, f.manager)); got == "" {
		t.Errorf("a caller with the permission was issued no authorization URL")
	}
}
