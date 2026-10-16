// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Connecting a GitHub App installation is three requests, each holding the next to what the
// previous one issued:
//
//  1. GET  .../github/install                                 issues the install state;
//  2. GET  .../github/installations/:installation_id/authorize takes the install state back from
//     GitHub's Setup URL redirect and issues the authorization state;
//  3. POST .../github/installations/:installation_id           takes the authorization state and
//     the code GitHub returned with it, and connects the installation only when the person who
//     authorized the App can access it at GitHub.
//
// GitHub is served by a fake here: its OAuth token endpoint, the user installations listing and
// the App's installation lookup. The handler is the one the server mounts, wired with a GitHub
// App manager pointed at the fake.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the dev DB has no backup).

//go:build integration

package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"gorm.io/gorm"
)

// fakeGitHub answers as GitHub would for the users in codes: each authorization code belongs to
// one GitHub user, who can access the installations listed for it.
type fakeGitHub struct {
	server *httptest.Server
	codes  map[string][]int64 // authorization code -> installations its user can access
	// connected counts the installation lookups, which happen only once ownership is confirmed.
	lookups int
	// revokeStatus is what the token revocation answers; revoked lists the tokens revoked.
	revokeStatus int
	revoked      []string
}

func newFakeGitHub(t *testing.T, codes map[string][]int64) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{codes: codes, revokeStatus: http.StatusNoContent}
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /applications/{client_id}/token", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		var body struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !ok || user != "Iv1.github-access-test" || pass != "github-access-test-secret" {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		f.revoked = append(f.revoked, body.AccessToken)
		w.WriteHeader(f.revokeStatus)
	})
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		code := r.PostForm.Get("code")
		if _, ok := f.codes[code]; !ok || r.PostForm.Get("client_secret") != "github-access-test-secret" {
			_, _ = fmt.Fprint(w, `{"error":"bad_verification_code"}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"access_token":"ghu_for_%s","token_type":"bearer"}`, code)
	})
	mux.HandleFunc("GET /user/installations", func(w http.ResponseWriter, r *http.Request) {
		code, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ghu_for_")
		installations, known := f.codes[code]
		if !ok || !known {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		type inst struct {
			ID int64 `json:"id"`
		}
		out := struct {
			TotalCount    int    `json:"total_count"`
			Installations []inst `json:"installations"`
		}{TotalCount: len(installations), Installations: []inst{}}
		if r.URL.Query().Get("page") == "1" {
			for _, id := range installations {
				out.Installations = append(out.Installations, inst{ID: id})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /app/installations/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.lookups++
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":%d,"account":{"login":"gh-account-%d","type":"Organization"}}`, id, id)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// newGitHubAppManagerForFake is a configured GitHub App, with a throwaway key and OAuth client,
// that reaches GitHub at the fake.
func newGitHubAppManagerForFake(t *testing.T, gh *fakeGitHub) *vcs.GitHubAppManager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate a throwaway app key: %v", err)
	}
	t.Setenv("GITHUB_APP_ID", "1")
	t.Setenv("GITHUB_APP_NAME", "stackweaver-access-test")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	t.Setenv("GITHUB_APP_PRIVATE_KEY_PATH", "")
	t.Setenv("GITHUB_APP_CLIENT_ID", "Iv1.github-access-test")
	t.Setenv("GITHUB_APP_CLIENT_SECRET", "github-access-test-secret")
	m, err := vcs.NewGitHubAppManager()
	if err != nil || !m.IsEnabled() {
		t.Fatalf("configure the GitHub App: %v", err)
	}
	m.SetEndpoints(gh.server.URL, gh.server.URL)
	return m
}

// githubFlowFixture is an organization, two of its owners, another organization the first owner
// also owns, and the installation handler wired to a fake GitHub.
type githubFlowFixture struct {
	db       *gorm.DB
	gh       *fakeGitHub
	router   *gin.Engine
	org      *models.Organization
	otherOrg *models.Organization
	owner    *models.User
	coOwner  *models.User
}

func setupGitHubFlow(t *testing.T, codes map[string][]int64) *githubFlowFixture {
	t.Helper()
	db := setupAuthzTestDB(t)
	SetOAuthStateSecret([]byte("github-install-state-test-secret!"))
	t.Cleanup(func() { SetOAuthStateSecret(nil) })

	sfx := uuid.NewString()[:8]
	f := &githubFlowFixture{
		db:       db,
		gh:       newFakeGitHub(t, codes),
		org:      &models.Organization{ID: uuid.New(), Name: "ghstate-" + sfx},
		otherOrg: &models.Organization{ID: uuid.New(), Name: "ghstate-other-" + sfx},
		owner:    &models.User{ID: uuid.New(), ZitadelSubject: "ghstate-owner-" + sfx, Email: "ghstate-owner-" + sfx + "@test.local"},
		coOwner:  &models.User{ID: uuid.New(), ZitadelSubject: "ghstate-coowner-" + sfx, Email: "ghstate-coowner-" + sfx + "@test.local"},
	}
	owners := &models.Team{ID: uuid.New(), OrganizationID: f.org.ID, Name: "owners"}
	otherOwners := &models.Team{ID: uuid.New(), OrganizationID: f.otherOrg.ID, Name: "owners"}
	t.Cleanup(func() {
		orgs := []uuid.UUID{f.org.ID, f.otherOrg.ID}
		teams := []uuid.UUID{owners.ID, otherOwners.ID}
		db.Where("organization_id IN ?", orgs).Delete(&models.VCSConnection{})
		db.Where("team_id IN ?", teams).Delete(&models.TeamMember{})
		db.Where("id IN ?", teams).Delete(&models.Team{})
		db.Where("id IN ?", orgs).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{f.owner.ID, f.coOwner.ID}).Delete(&models.User{})
	})
	for _, row := range []any{
		f.org, f.otherOrg, f.owner, f.coOwner, owners, otherOwners,
		// The owner may connect both organizations; the co-owner only the first.
		&models.TeamMember{TeamID: owners.ID, UserID: f.owner.ID},
		&models.TeamMember{TeamID: otherOwners.ID, UserID: f.owner.ID},
		&models.TeamMember{TeamID: owners.ID, UserID: f.coOwner.ID},
	} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	// Azure DevOps is configured only so the tests can obtain a state issued for that flow.
	t.Setenv("AZURE_DEVOPS_CLIENT_ID", "github-state-test")
	t.Setenv("AZURE_DEVOPS_CLIENT_SECRET", "not-a-real-secret")
	t.Setenv("AZURE_DEVOPS_REDIRECT_URI", "http://localhost:5173/vcs/azure-devops/callback")
	ado, err := vcs.NewAzureDevOpsManager()
	if err != nil || !ado.IsEnabled() {
		t.Fatalf("configure Azure DevOps: %v", err)
	}

	orgRepo := repository.NewOrganizationRepository(db)
	h := NewVCSAppInstallationHandlerV2(
		repository.NewVCSConnectionRepository(db), orgRepo,
		nil, nil, nil, nil, nil, nil, nil,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db)),
		newGitHubAppManagerForFake(t, f.gh), ado, nil, nil, nil, nil,
	)
	h.SetAppURL("https://stackweaver.test")

	gin.SetMode(gin.TestMode)
	f.router = gin.New()
	f.router.Use(testUserAuth())
	group := f.router.Group("/organizations/:name/vcs-connections")
	group.GET("/github/install", h.InitiateInstallation)
	group.GET("/github/installations/:installation_id/authorize", h.AuthorizeInstallation)
	group.POST("/github/installations/:installation_id", h.CreateConnectionFromInstallation)
	group.GET("/azure-devops/install", h.InitiateAzureDevOpsInstallation)
	return f
}

// providerState requests path as the user and returns the state the provider URL it answers
// with carries.
func (f *githubFlowFixture) providerState(t *testing.T, path string, user uuid.UUID) string {
	t.Helper()
	rec := authzRequest(t, f.router, http.MethodGet, path, user, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200.\nbody: %s", path, rec.Code, rec.Body.String())
	}
	var doc struct {
		Data struct {
			InstallURL string `json:"install_url"`
			AuthURL    string `json:"auth_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	raw := doc.Data.InstallURL + doc.Data.AuthURL
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse provider URL %q: %v", raw, err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("the provider URL carries no state: %s", raw)
	}
	return state
}

// installState is the state a start for orgName issues to the user.
func (f *githubFlowFixture) installState(t *testing.T, orgName string, user uuid.UUID) string {
	t.Helper()
	return f.providerState(t, "/organizations/"+orgName+"/vcs-connections/github/install?return=%2Fapp%2F"+orgName+"%2Fworkspaces", user)
}

func (f *githubFlowFixture) authorizePath(installation, state string) string {
	p := "/organizations/" + f.org.Name + "/vcs-connections/github/installations/" + installation + "/authorize"
	if state != "" {
		p += "?state=" + url.QueryEscape(state)
	}
	return p
}

// authorizationState is the state the authorize step issues to the user for installation, from
// the user's own start.
func (f *githubFlowFixture) authorizationState(t *testing.T, installation string, user uuid.UUID) string {
	t.Helper()
	return f.providerState(t, f.authorizePath(installation, f.installState(t, f.org.Name, user)), user)
}

func (f *githubFlowFixture) complete(t *testing.T, user uuid.UUID, installation, code, state string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/organizations/" + f.org.Name + "/vcs-connections/github/installations/" + installation
	if state != "" {
		path += "?state=" + url.QueryEscape(state)
	}
	var body any
	if code != "" {
		body = map[string]string{"code": code}
	}
	return authzRequest(t, f.router, http.MethodPost, path, user, body)
}

func (f *githubFlowFixture) connections(t *testing.T) []models.VCSConnection {
	t.Helper()
	var rows []models.VCSConnection
	if err := f.db.Where("organization_id IN ?", []uuid.UUID{f.org.ID, f.otherOrg.ID}).Find(&rows).Error; err != nil {
		t.Fatalf("list connections: %v", err)
	}
	return rows
}

func requireForbiddenShape(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403.\nbody: %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Errors []struct {
			Status string `json:"status"`
			Title  string `json:"title"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || len(doc.Errors) != 1 ||
		doc.Errors[0].Status != "403" || doc.Errors[0].Title != "Forbidden" {
		t.Errorf("the refusal is not shaped like the permission refusal: %s", rec.Body.String())
	}
}

// A GitHub App installation completes only from the state its own start issued: signed by this
// deployment, unexpired, issued for the organization in the path and to the caller. The start's
// state is now taken back by the authorize step, which carries it on in the authorization state
// the completion takes; a state that is wrong in any of these ways is refused at both steps. The
// earlier form of this test had the completion take the start's state directly and expected it
// past the check; that state alone no longer completes anything (see
// TestGitHubInstallation_TakesAPersonWhoCanAccessTheInstallation).
func TestGitHubInstallation_CompletesOnlyWithTheStateItsStartIssued(t *testing.T) {
	f := setupGitHubFlow(t, map[string][]int64{"code-owner": {424242}})

	refused := []struct {
		name  string
		state func(t *testing.T) string
	}{
		{"no state", func(*testing.T) string { return "" }},
		{"a state this deployment did not sign", func(*testing.T) string {
			return f.org.Name + "|%2Fapp|" + f.owner.ID.String() + "|" + uuid.NewString()
		}},
		{"a state issued for another organization", func(t *testing.T) string {
			return f.installState(t, f.otherOrg.Name, f.owner.ID)
		}},
		{"a state issued to another caller", func(t *testing.T) string {
			return f.installState(t, f.org.Name, f.coOwner.ID)
		}},
		{"an expired state, otherwise the one its start issued", func(t *testing.T) string {
			// The issued state with its expiry moved into the past and signed again with the
			// deployment's key, so the expiry is the only thing wrong with it.
			issued := f.installState(t, f.org.Name, f.owner.ID)
			b64, _, _ := strings.Cut(issued, ".")
			body := b64 + "." + strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)
			return body + "." + signOAuthState(stateGitHubAppInstall, body)
		}},
		{"a state issued for the Azure DevOps flow", func(t *testing.T) string {
			return f.providerState(t, "/organizations/"+f.org.Name+"/vcs-connections/azure-devops/install?ado_org=acme", f.owner.ID)
		}},
	}
	for _, tc := range refused {
		t.Run("authorize refuses "+tc.name, func(t *testing.T) {
			requireForbiddenShape(t, authzRequest(t, f.router, http.MethodGet, f.authorizePath("424242", tc.state(t)), f.owner.ID, nil))
		})
		t.Run("completion refuses "+tc.name, func(t *testing.T) {
			requireForbiddenShape(t, f.complete(t, f.owner.ID, "424242", "code-owner", tc.state(t)))
		})
	}

	t.Run("the state its own start issued gets past the check", func(t *testing.T) {
		state := f.installState(t, f.org.Name, f.owner.ID)
		rec := authzRequest(t, f.router, http.MethodGet, f.authorizePath("424242", state), f.owner.ID, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want 200.\nbody: %s", rec.Code, rec.Body.String())
		}
	})

	if rows := f.connections(t); len(rows) != 0 {
		t.Errorf("the organizations hold %d VCS connection(s) after these requests, want none", len(rows))
	}
}

// An installation id reaches the server through the browser and says nothing about who
// installed it, so the installation is connected only when the person completing the flow,
// having authorized the App at GitHub, can access it there (GET /user/installations).
func TestGitHubInstallation_TakesAPersonWhoCanAccessTheInstallation(t *testing.T) {
	// The owner's GitHub account can access installation 111 and not 222.
	f := setupGitHubFlow(t, map[string][]int64{"code-owner": {111}, "code-elsewhere": {333}})

	t.Run("the start's state alone does not complete an installation", func(t *testing.T) {
		requireForbiddenShape(t, f.complete(t, f.owner.ID, "222", "", f.installState(t, f.org.Name, f.owner.ID)))
	})

	t.Run("an installation the person cannot access is refused", func(t *testing.T) {
		state := f.authorizationState(t, "222", f.owner.ID)
		requireForbiddenShape(t, f.complete(t, f.owner.ID, "222", "code-owner", state))
	})

	t.Run("a missing authorization is refused", func(t *testing.T) {
		state := f.authorizationState(t, "111", f.owner.ID)
		requireForbiddenShape(t, f.complete(t, f.owner.ID, "111", "", state))
	})

	t.Run("an authorization GitHub does not accept is refused", func(t *testing.T) {
		state := f.authorizationState(t, "111", f.owner.ID)
		requireForbiddenShape(t, f.complete(t, f.owner.ID, "111", "forged-code", state))
	})

	t.Run("an authorization state for one installation does not complete another", func(t *testing.T) {
		state := f.authorizationState(t, "333", f.owner.ID)
		requireForbiddenShape(t, f.complete(t, f.owner.ID, "222", "code-elsewhere", state))
	})

	t.Run("an authorization state issued to another caller is refused", func(t *testing.T) {
		state := f.authorizationState(t, "111", f.coOwner.ID)
		requireForbiddenShape(t, f.complete(t, f.owner.ID, "111", "code-owner", state))
	})

	if rows := f.connections(t); len(rows) != 0 {
		t.Fatalf("refused requests left %d connection(s): %+v", len(rows), rows)
	}
	if f.gh.lookups != 0 {
		t.Errorf("GitHub was asked about an installation %d time(s) by refused requests", f.gh.lookups)
	}

	t.Run("the user token is revoked after a refusal", func(t *testing.T) {
		f.gh.revoked = nil
		state := f.authorizationState(t, "222", f.owner.ID)
		requireForbiddenShape(t, f.complete(t, f.owner.ID, "222", "code-owner", state))
		if len(f.gh.revoked) != 1 || f.gh.revoked[0] != "ghu_for_code-owner" {
			t.Errorf("revoked %v, want the one user token", f.gh.revoked)
		}
	})

	t.Run("a revocation GitHub refuses keeps the refusal", func(t *testing.T) {
		f.gh.revoked, f.gh.revokeStatus = nil, http.StatusInternalServerError
		t.Cleanup(func() { f.gh.revokeStatus = http.StatusNoContent })
		state := f.authorizationState(t, "222", f.owner.ID)
		requireForbiddenShape(t, f.complete(t, f.owner.ID, "222", "code-owner", state))
	})

	t.Run("an installation the person can access is connected", func(t *testing.T) {
		state := f.authorizationState(t, "111", f.owner.ID)
		rec := f.complete(t, f.owner.ID, "111", "code-owner", state)
		if rec.Code != http.StatusCreated {
			t.Fatalf("got %d, want 201.\nbody: %s", rec.Code, rec.Body.String())
		}
		rows := f.connections(t)
		if len(rows) != 1 || rows[0].OrganizationID != f.org.ID || rows[0].InstallationID != "111" || rows[0].AccountName != "gh-account-111" {
			t.Fatalf("connections after a completed installation: %+v", rows)
		}
	})
}

// Revoking the user token is cleanup after the check: a revocation GitHub refuses does not stop
// the connection.
func TestGitHubInstallation_ConnectsWhenTheTokenRevocationFails(t *testing.T) {
	f := setupGitHubFlow(t, map[string][]int64{"code-owner": {111}})
	f.gh.revokeStatus = http.StatusUnprocessableEntity

	state := f.authorizationState(t, "111", f.owner.ID)
	rec := f.complete(t, f.owner.ID, "111", "code-owner", state)
	if rec.Code != http.StatusCreated {
		t.Fatalf("got %d, want 201.\nbody: %s", rec.Code, rec.Body.String())
	}
	if len(f.gh.revoked) != 1 {
		t.Errorf("revocations = %v, want one attempt", f.gh.revoked)
	}
	if rows := f.connections(t); len(rows) != 1 || rows[0].InstallationID != "111" {
		t.Fatalf("connections = %+v, want installation 111", rows)
	}
}
