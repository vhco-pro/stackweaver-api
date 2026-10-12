// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a workspace may name as its VCS connection (#916): a connection of its own organization,
// however the request names it (`vcs-connection-id`, or the TFE `vcs-repo` block's
// `oauth-token-id` and `github-app-installation-id`). A connection that exists in another
// organization is answered exactly like an identifier that names nothing, and a workspace row
// that already names one gets nothing of it: no clone on a run, no detail in a response.
//
// The defect these tests were written against: a create checked that the connection exists and
// nothing else, an update by workspace id did not check even that, and an installation id was
// resolved across every organization. A run of the workspace clones with the connection's token,
// so a member of one organization could point a workspace of their own at another organization's
// connection and at any repository it can read.
//
// Terraform Enterprise documents no answer for a workspace that names an OAuth token it may not
// use, so the answer pinned here is this API's own "VCS connection not found".
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run 'TestWorkspaceVCSConnection'

//go:build integration

package terraform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// What tells the second organization's connection apart in anything built or rendered from it.
// GitLab is the provider whose clone URL is built from the stored token with no network.
const (
	otherVCSToken        = "token-of-the-other-organization"
	otherVCSAccount      = "account-of-the-other-organization"
	otherVCSInstallation = "9160002"
	ownVCSInstallation   = "9160001"
	// Both organizations are connected through this installation, each with a row of its own.
	sharedVCSInstallation = "9160003"
)

// workspaceConnectionFixture is workspaceBooleansFixture with VCS connections: three in the
// fixture's organization and two in a second organization the caller has no part in.
type workspaceConnectionFixture struct {
	*workspaceBooleansFixture
	own, own2, ownShared, other, otherShared *models.VCSConnection
}

func setupWorkspaceConnections(t *testing.T) *workspaceConnectionFixture {
	t.Helper()
	base := setupWorkspaceBooleans(t)
	if err := base.db.AutoMigrate(&models.VCSConnection{}); err != nil {
		t.Fatalf("migrating VCS connections: %v", err)
	}
	sfx := uuid.NewString()[:8]
	var project models.Project
	if err := base.db.First(&project, "id = ?", base.projectID).Error; err != nil {
		t.Fatalf("reading the fixture's project: %v", err)
	}
	otherOrg := &models.Organization{ID: uuid.New(), Name: "wsconn-b-" + sfx}
	connection := func(organizationID uuid.UUID, installation, token, account string) *models.VCSConnection {
		return &models.VCSConnection{
			ID: uuid.New(), OrganizationID: organizationID, Provider: models.VCSProviderGitLab,
			InstallationID: installation, AccessToken: token, AccountName: account,
		}
	}
	f := &workspaceConnectionFixture{
		workspaceBooleansFixture: base,
		own:                      connection(project.OrganizationID, ownVCSInstallation, "token-of-its-own-organization", "wsconn-a-"+sfx),
		own2:                     connection(project.OrganizationID, "", "token-of-its-own-organization", "wsconn-a2-"+sfx),
		ownShared:                connection(project.OrganizationID, sharedVCSInstallation, "token-of-its-own-organization", "wsconn-a3-"+sfx),
		other:                    connection(otherOrg.ID, otherVCSInstallation, otherVCSToken, otherVCSAccount),
		otherShared:              connection(otherOrg.ID, sharedVCSInstallation, otherVCSToken, otherVCSAccount),
	}
	connections := []*models.VCSConnection{f.own, f.own2, f.ownShared, f.other, f.otherShared}
	if err := base.db.Create(otherOrg).Error; err != nil {
		t.Fatalf("seeding the second organization: %v", err)
	}
	connectionIDs := make([]uuid.UUID, 0, len(connections))
	for _, row := range connections {
		if err := base.db.Create(row).Error; err != nil {
			t.Fatalf("seeding the VCS connection %s: %v", row.AccountName, err)
		}
		connectionIDs = append(connectionIDs, row.ID)
	}
	// Registered after the shared fixture's cleanup, so it runs before it: the workspaces that
	// name a connection are the fixture project's and go first, then the connections and the
	// second organization, each by its own identifier.
	t.Cleanup(func() {
		base.db.Where("project_id = ? AND vcs_connection_id IN ?", base.projectID, connectionIDs).Delete(&models.Workspace{})
		base.db.Where("id IN ?", connectionIDs).Delete(&models.VCSConnection{})
		base.db.Where("id = ?", otherOrg.ID).Delete(&models.Organization{})
	})
	return f
}

// send posts one workspace document and returns the raw answer.
func (f *workspaceConnectionFixture) send(t *testing.T, method, path string, attrs map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"data": map[string]any{"type": "workspaces", "attributes": attrs}})
	if err != nil {
		t.Fatalf("marshalling the request document: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// connectionOf reads the connection a workspace names, empty when it names none.
func (f *workspaceConnectionFixture) connectionOf(t *testing.T, workspaceID string) string {
	t.Helper()
	var workspace models.Workspace
	if err := f.db.Select("vcs_connection_id").First(&workspace, "id = ?", workspaceID).Error; err != nil {
		t.Fatalf("reading workspace %s: %v", workspaceID, err)
	}
	if workspace.VCSConnectionID == nil {
		return ""
	}
	return workspace.VCSConnectionID.String()
}

// namingOther counts the workspaces that name a connection of the second organization.
func (f *workspaceConnectionFixture) namingOther(t *testing.T) int64 {
	t.Helper()
	var n int64
	err := f.db.Model(&models.Workspace{}).
		Where("vcs_connection_id IN ?", []uuid.UUID{f.other.ID, f.otherShared.ID}).Count(&n).Error
	if err != nil {
		t.Fatalf("counting the workspaces: %v", err)
	}
	return n
}

// workspaceWrite is one way to send a workspace write whose attributes name a connection.
type workspaceWrite struct {
	name string
	send func(t *testing.T, f *workspaceConnectionFixture, attrs map[string]any) *httptest.ResponseRecorder
}

// workspaceWrites are the three handlers that store a workspace's connection. The two updates
// each get a workspace of their own that names no connection yet.
func workspaceWrites() []workspaceWrite {
	return []workspaceWrite{
		{"a create", func(t *testing.T, f *workspaceConnectionFixture, attrs map[string]any) *httptest.ResponseRecorder {
			attrs["name"], attrs["project-id"] = "wsconn-"+uuid.NewString()[:8], f.projectID.String()
			return f.send(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/workspaces", attrs)
		}},
		{"an update by name", func(t *testing.T, f *workspaceConnectionFixture, attrs map[string]any) *httptest.ResponseRecorder {
			_, name, _ := f.create(t, nil)
			return f.send(t, http.MethodPatch, "/api/v2/organizations/"+f.orgName+"/workspaces/"+name, attrs)
		}},
		{"an update by id", func(t *testing.T, f *workspaceConnectionFixture, attrs map[string]any) *httptest.ResponseRecorder {
			id, _, _ := f.create(t, nil)
			return f.send(t, http.MethodPatch, "/api/v2/workspaces/"+id, attrs)
		}},
	}
}

func TestWorkspaceVCSConnection_AnotherOrganizationReadsAsNotFound(t *testing.T) {
	f := setupWorkspaceConnections(t)
	// The two ways a request names a connection by its identifier.
	namings := map[string]func(connection string) map[string]any{
		"vcs-connection-id": func(connection string) map[string]any {
			return map[string]any{"vcs-connection-id": connection, "vcs-repository": "acme/infra"}
		},
		"vcs-repo.oauth-token-id": func(connection string) map[string]any {
			return map[string]any{"vcs-repo": map[string]any{"identifier": "acme/infra", "oauth-token-id": connection}}
		},
	}
	for _, write := range workspaceWrites() {
		for naming, attrs := range namings {
			t.Run(write.name+" naming "+naming, func(t *testing.T) {
				foreign := write.send(t, f, attrs(f.other.ID.String()))
				missing := write.send(t, f, attrs(uuid.NewString()))
				if foreign.Code != http.StatusBadRequest || !strings.Contains(foreign.Body.String(), "VCS connection not found") {
					t.Errorf("another organization's connection: %d %s, want 400 VCS connection not found", foreign.Code, foreign.Body.String())
				}
				if foreign.Code != missing.Code || !bytes.Equal(foreign.Body.Bytes(), missing.Body.Bytes()) {
					t.Errorf("another organization's connection and one that does not exist are answered differently:\n  other organization: %d %s\n  does not exist:     %d %s",
						foreign.Code, foreign.Body.String(), missing.Code, missing.Body.String())
				}
			})
		}
	}
	if got := f.namingOther(t); got != 0 {
		t.Errorf("%d workspace(s) name the other organization's connection", got)
	}
}

// TestWorkspaceVCSConnection_InstallationOfAnotherOrganization is the third way to name a
// connection: by the GitHub App installation it was made through. An installation that resolves
// to no connection has always left the workspace without one, so that is the one answer for an
// installation only another organization is connected through, and an installation both are
// connected through resolves to the organization's own row.
func TestWorkspaceVCSConnection_InstallationOfAnotherOrganization(t *testing.T) {
	f := setupWorkspaceConnections(t)
	naming := func(installation string) map[string]any {
		return map[string]any{"vcs-repo": map[string]any{"identifier": "acme/infra", "github-app-installation-id": installation}}
	}
	workspaceID := func(t *testing.T, rec *httptest.ResponseRecorder) string {
		t.Helper()
		var doc struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || doc.Data.ID == "" {
			t.Fatalf("decoding the workspace: %v (%d %s)", err, rec.Code, rec.Body.String())
		}
		return doc.Data.ID
	}
	for _, write := range workspaceWrites() {
		t.Run(write.name, func(t *testing.T) {
			foreign := write.send(t, f, naming(otherVCSInstallation))
			unknown := write.send(t, f, naming("9169999"))
			if foreign.Code != unknown.Code {
				t.Fatalf("an installation of another organization answers %d and an unknown one %d", foreign.Code, unknown.Code)
			}
			if got := f.connectionOf(t, workspaceID(t, foreign)); got != "" {
				t.Errorf("naming another organization's installation stored connection %q, want none, as for an unknown installation", got)
			}
			if strings.Contains(foreign.Body.String(), otherVCSAccount) {
				t.Errorf("the answer carries the other organization's account name")
			}

			own := write.send(t, f, naming(ownVCSInstallation))
			if got := f.connectionOf(t, workspaceID(t, own)); got != f.own.ID.String() {
				t.Errorf("naming the organization's own installation stored %q, want %q", got, f.own.ID)
			}
			shared := write.send(t, f, naming(sharedVCSInstallation))
			if got := f.connectionOf(t, workspaceID(t, shared)); got != f.ownShared.ID.String() {
				t.Errorf("naming an installation both organizations use stored %q, want the organization's own row %q", got, f.ownShared.ID)
			}
		})
	}
	if got := f.namingOther(t); got != 0 {
		t.Errorf("%d workspace(s) name the other organization's connection", got)
	}
}

func TestWorkspaceVCSConnection_OwnOrganizationIsAccepted(t *testing.T) {
	f := setupWorkspaceConnections(t)
	naming := func(connection *models.VCSConnection) map[string]any {
		return map[string]any{"vcs-connection-id": connection.ID.String(), "vcs-repository": "acme/infra"}
	}

	id, name, _ := f.create(t, naming(f.own))
	if got := f.connectionOf(t, id); got != f.own.ID.String() {
		t.Fatalf("the created workspace names %q, want %q", got, f.own.ID)
	}
	// Both updates load the workspace with its connection attached, and must still be able to
	// change it.
	if rec := f.send(t, http.MethodPatch, "/api/v2/workspaces/"+id, naming(f.own2)); rec.Code != http.StatusOK {
		t.Fatalf("changing the connection by workspace id: %d %s", rec.Code, rec.Body.String())
	}
	if got := f.connectionOf(t, id); got != f.own2.ID.String() {
		t.Errorf("after the change by id the workspace names %q, want %q", got, f.own2.ID)
	}
	rec := f.send(t, http.MethodPatch, "/api/v2/organizations/"+f.orgName+"/workspaces/"+name, naming(f.own))
	if rec.Code != http.StatusOK {
		t.Fatalf("changing the connection by workspace name: %d %s", rec.Code, rec.Body.String())
	}
	if got := f.connectionOf(t, id); got != f.own.ID.String() {
		t.Errorf("after the change by name the workspace names %q, want %q", got, f.own.ID)
	}
	// The response describes the connection: its installation and its account.
	if body := rec.Body.String(); !strings.Contains(body, ownVCSInstallation) || !strings.Contains(body, f.own.AccountName) {
		t.Errorf("the response does not describe the organization's own connection: %s", body)
	}
}

// TestWorkspaceVCSConnection_StoredRowIsNotTrusted writes a workspace row directly, the way one
// stored before the API checked the connection would be, and uses it: a read, and a run, which
// is where the platform clones for a workspace that is not agent-executed.
func TestWorkspaceVCSConnection_StoredRowIsNotTrusted(t *testing.T) {
	f := setupWorkspaceConnections(t)
	// git refuses the transport before it opens a connection, so a clone this test must not
	// see cannot reach the network either.
	t.Setenv("GIT_ALLOW_PROTOCOL", "file")
	if err := f.db.AutoMigrate(&models.Run{}, &models.ConfigurationVersion{}); err != nil {
		t.Fatalf("migrating runs and configuration versions: %v", err)
	}
	stored := &models.Workspace{
		ID: "ws-" + uuid.NewString()[:8] + "9160000", ProjectID: f.projectID, Name: "wsconn-stored-" + uuid.NewString()[:8],
		VCSConnectionID: &f.other.ID, VCSRepository: "acme/infra", VCSBranch: "main", ExecutionMode: "remote",
	}
	if err := f.db.Create(stored).Error; err != nil {
		t.Fatalf("writing the workspace row: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("workspace_id = ?", stored.ID).Delete(&models.Run{})
		f.db.Where("workspace_id = ?", stored.ID).Delete(&models.ConfigurationVersion{})
		f.db.Where("id = ?", stored.ID).Delete(&models.Workspace{})
	})

	t.Run("a read renders nothing of the connection", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/workspaces/"+stored.ID, nil)
		rec := httptest.NewRecorder()
		f.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("reading the workspace: %d %s", rec.Code, rec.Body.String())
		}
		for what, value := range map[string]string{"installation": otherVCSInstallation, "account name": otherVCSAccount, "token": otherVCSToken} {
			if strings.Contains(rec.Body.String(), value) {
				t.Errorf("the response carries the other organization's %s", what)
			}
		}
	})

	t.Run("a run does not clone with the connection", func(t *testing.T) {
		orgRepo := repository.NewOrganizationRepository(f.db)
		runs := NewRunHandlerV2(
			repository.NewRunRepository(f.db), repository.NewWorkspaceRepository(f.db), orgRepo,
			auth.NewService(repository.NewUserRepository(f.db)), nil, repository.NewConfigurationVersionRepository(f.db),
			repository.NewVCSConnectionRepository(f.db), vcs.NewProviderRegistry(nil, nil, nil, nil), nil, nil,
			rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)),
			nil, nil, nil, nil, nil, middleware.NewDBOrgResolver(f.db),
		)
		var owner models.OrganizationMember
		if err := f.db.Joins("JOIN organizations ON organizations.id = organization_members.organization_id").
			Where("organizations.name = ?", f.orgName).First(&owner).Error; err != nil {
			t.Fatalf("reading the fixture's owner: %v", err)
		}
		// Creating a run takes run and write permission on the workspace, which the owner's
		// team gets through the project.
		var team models.Team
		if err := f.db.First(&team, "organization_id = ?", owner.OrganizationID).Error; err != nil {
			t.Fatalf("reading the fixture's team: %v", err)
		}
		adminAccess := "admin"
		access := &models.TeamProjectAccess{ID: uuid.New(), TeamID: team.ID, ProjectID: f.projectID, Access: &adminAccess}
		if err := f.db.Create(access).Error; err != nil {
			t.Fatalf("granting the team access to the project: %v", err)
		}
		t.Cleanup(func() { f.db.Where("id = ?", access.ID).Delete(&models.TeamProjectAccess{}) })
		router := gin.New()
		router.Use(func(c *gin.Context) { c.Set("user_id", owner.UserID); c.Next() })
		router.POST("/api/v2/runs", runs.Create)

		body, err := json.Marshal(map[string]any{"data": map[string]any{
			"type":       "runs",
			"attributes": map[string]any{"message": "stored row", "plan-only": true},
			"relationships": map[string]any{
				"workspace": map[string]any{"data": map[string]any{"type": "workspaces", "id": stored.ID}},
			},
		}})
		if err != nil {
			t.Fatalf("marshalling the request document: %v", err)
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runs", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/vnd.api+json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		// The answer a workspace whose connection no longer exists has always got. Reaching the
		// clone instead answers 500.
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Failed to get VCS connection for workspace") {
			t.Errorf("status = %d %s, want the 400 of a workspace whose connection is not found", rec.Code, rec.Body.String())
		}
		for table, model := range map[string]any{"run": &models.Run{}, "configuration version": &models.ConfigurationVersion{}} {
			var n int64
			if err := f.db.Model(model).Where("workspace_id = ?", stored.ID).Count(&n).Error; err != nil {
				t.Fatalf("counting the %ss: %v", table, err)
			}
			if n != 0 {
				t.Errorf("the refused run left %d %s(s) behind", n, table)
			}
		}
	})
}
