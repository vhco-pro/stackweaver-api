// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Connecting a GitHub App installation through the router the server mounts, with a GitHub App
// configured and GitHub served by a fake: the installation is connected only when the person
// completing the flow, having authorized the App at GitHub, can access it there. The handler-level
// half, with every state the steps refuse, is handlers/vcs_github_installation_access_test.go.
//
// The other way an installation id could reach a connection, POST .../vcs-connections, takes
// none: an installation is connected through the installation flow only.

//go:build integration

package routes_test

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

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// fakeGitHubForRouter answers for one GitHub user, whose authorization code is "code-manager"
// and who can access installation 111 only.
func fakeGitHubForRouter(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("code") != "code-manager" || r.PostForm.Get("client_secret") != "router-access-test-secret" {
			_, _ = fmt.Fprint(w, `{"error":"bad_verification_code"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"access_token":"ghu_manager","token_type":"bearer"}`)
	})
	mux.HandleFunc("GET /user/installations", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghu_manager" {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") != "1" {
			_, _ = fmt.Fprint(w, `{"total_count":1,"installations":[]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"total_count":1,"installations":[{"id":111}]}`)
	})
	mux.HandleFunc("GET /app/installations/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":%d,"account":{"login":"gh-account-%d","type":"Organization"}}`, id, id)
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func setupGitHubAccessRouter(t *testing.T) (*vcsInstallAuthzFixture, *httptest.Server) {
	t.Helper()
	gh := fakeGitHubForRouter(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate a throwaway app key: %v", err)
	}
	t.Setenv("GITHUB_APP_ID", "1")
	t.Setenv("GITHUB_APP_NAME", "stackweaver-router-access-test")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	t.Setenv("GITHUB_APP_PRIVATE_KEY_PATH", "")
	t.Setenv("GITHUB_APP_CLIENT_ID", "Iv1.router-access-test")
	t.Setenv("GITHUB_APP_CLIENT_SECRET", "router-access-test-secret")
	t.Setenv("STACKWEAVER_APP_URL", "https://stackweaver.test")
	m, err := vcs.NewGitHubAppManager()
	if err != nil || !m.IsEnabled() {
		t.Fatalf("configure the GitHub App: %v", err)
	}
	m.SetEndpoints(gh.URL, gh.URL)
	return setupVCSInstallAuthzWithGitHub(t, m), gh
}

// stateOf returns the state in the provider URL a start or an authorize step answered with.
func stateOf(t *testing.T, rec *httptest.ResponseRecorder) (string, *url.URL) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200.\nbody: %s", rec.Code, rec.Body.String())
	}
	raw := providerURL(rec)
	u, err := url.Parse(raw)
	if err != nil || u.Query().Get("state") == "" {
		t.Fatalf("no state in the provider URL %q", raw)
	}
	return u.Query().Get("state"), u
}

func TestGitHubInstallation_RouterTakesAPersonWhoCanAccessTheInstallation(t *testing.T) {
	f, gh := setupGitHubAccessRouter(t)
	base := vcsInstallPath(f.org.Name, "/vcs-connections/github")

	// authorize runs the first two steps as the token's owner and returns the authorization
	// state for installation.
	authorize := func(t *testing.T, token, installation string) string {
		t.Helper()
		installState, _ := stateOf(t, f.do(t, http.MethodGet, base+"/install", token))
		authState, authURL := stateOf(t, f.do(t, http.MethodGet,
			base+"/installations/"+installation+"/authorize?state="+url.QueryEscape(installState), token))
		if got := authURL.Scheme + "://" + authURL.Host + authURL.Path; got != gh.URL+"/login/oauth/authorize" {
			t.Errorf("the authorize step sends the browser to %s, want GitHub's authorize page", got)
		}
		q := authURL.Query()
		if q.Get("client_id") != "Iv1.router-access-test" || q.Get("redirect_uri") != "https://stackweaver.test/vcs/github/authorized" {
			t.Errorf("authorize query = %v", q)
		}
		return authState
	}
	complete := func(t *testing.T, installation, code, state string) *httptest.ResponseRecorder {
		t.Helper()
		// #858: the code travels in a vcs-connections document; an empty one is sent as such, so
		// that GitHub's refusal of it is what answers.
		body := fmt.Sprintf(`{"data":{"type":"vcs-connections","attributes":{"code":%q}}}`, code)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
			base+"/installations/"+installation+"?state="+url.QueryEscape(state), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+f.manager)
		rec := httptest.NewRecorder()
		f.h.router.ServeHTTP(rec, req)
		return rec
	}

	t.Run("an installation the person cannot access is refused", func(t *testing.T) {
		rec := complete(t, "222", "code-manager", authorize(t, f.manager, "222"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("got %d, want 403.\nbody: %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("a missing authorization is refused", func(t *testing.T) {
		rec := complete(t, "111", "", authorize(t, f.manager, "111"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("got %d, want 403.\nbody: %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("an authorization GitHub does not accept is refused", func(t *testing.T) {
		rec := complete(t, "111", "forged-code", authorize(t, f.manager, "111"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("got %d, want 403.\nbody: %s", rec.Code, rec.Body.String())
		}
	})
	if n := f.connections(t); n != 0 {
		t.Fatalf("refused requests left %d connection(s)", n)
	}

	t.Run("a read-only key cannot take the authorize step", func(t *testing.T) {
		var manager models.User
		if err := f.h.db.Raw(`
			SELECT u.* FROM users u JOIN team_members tm ON tm.user_id = u.id
			JOIN teams t ON t.id = tm.team_id
			WHERE t.organization_id = ? AND t.name = 'vcs-admins' LIMIT 1`, f.org.ID).Scan(&manager).Error; err != nil || manager.ID == uuid.Nil {
			t.Fatalf("find the manager: %v", err)
		}
		keys := apikey.NewService(repository.NewAPIKeyRepository(f.h.db), repository.NewOrganizationRepository(f.h.db),
			repository.NewProjectRepository(f.h.db), repository.NewTeamRepository(f.h.db))
		_, readOnly, err := keys.CreateAPIKey(manager.ID, "github-authorize-read", []string{"org:" + f.org.ID.String() + ":read"}, nil)
		if err != nil {
			t.Fatalf("mint a read-only key: %v", err)
		}
		installState, _ := stateOf(t, f.do(t, http.MethodGet, base+"/install", f.manager))
		rec := f.do(t, http.MethodGet, base+"/installations/111/authorize?state="+url.QueryEscape(installState), readOnly)
		if rec.Code != http.StatusForbidden || providerURL(rec) != "" {
			t.Fatalf("got %d %s, want a 403 without a provider URL", rec.Code, rec.Body.String())
		}
	})

	t.Run("an installation the person can access is connected", func(t *testing.T) {
		rec := complete(t, "111", "code-manager", authorize(t, f.manager, "111"))
		if rec.Code != http.StatusCreated {
			t.Fatalf("got %d, want 201.\nbody: %s", rec.Code, rec.Body.String())
		}
		var conn models.VCSConnection
		if err := f.h.db.Where("organization_id = ? AND provider = ?", f.org.ID, models.VCSProviderGitHub).First(&conn).Error; err != nil {
			t.Fatalf("load the connection: %v", err)
		}
		if conn.InstallationID != "111" || conn.AccountName != "gh-account-111" {
			t.Errorf("connection = installation %q account %q, want 111 / gh-account-111", conn.InstallationID, conn.AccountName)
		}
	})
}

// Creating a connection directly names no installation. A request that names one is refused
// with 400, as the handler refuses its other unusable attributes, and its detail points at the
// installation flow, the only way an installation reaches a connection. An earlier form of this
// test accepted the request and checked the installation was dropped; a client was then handed a
// connection that was not the one it asked for, so the request is refused instead.
func TestVCSConnectionCreate_TakesNoInstallation(t *testing.T) {
	f := setupVCSInstallAuthz(t)
	post := func(t *testing.T, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, vcsInstallPath(f.org.Name, "/vcs-connections"), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+f.manager)
		rec := httptest.NewRecorder()
		f.h.router.ServeHTTP(rec, req)
		return rec
	}

	for _, provider := range []string{"github", "gitlab"} {
		t.Run("refused for "+provider, func(t *testing.T) {
			// #858: the create is a vcs-connections document, and the refusal reads its attributes.
			rec := post(t, `{"data":{"type":"vcs-connections","attributes":{"provider":"`+provider+`","installation_id":"222","access_token":"not-a-real-token","account_name":"acme","account_type":"organization"}}}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400.\nbody: %s", rec.Code, rec.Body.String())
			}
			var doc struct {
				Errors []struct {
					Status string `json:"status"`
					Detail string `json:"detail"`
				} `json:"errors"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || len(doc.Errors) != 1 || doc.Errors[0].Status != "400" ||
				!strings.Contains(doc.Errors[0].Detail, "GitHub App installation flow") {
				t.Errorf("the refusal does not point at the installation flow: %s", rec.Body.String())
			}
		})
	}
	if n := f.connections(t); n != 0 {
		t.Fatalf("refused requests left %d connection(s)", n)
	}

	t.Run("an empty installation_id names none", func(t *testing.T) {
		rec := post(t, `{"data":{"type":"vcs-connections","attributes":{"provider":"gitlab","installation_id":"","access_token":"not-a-real-token","account_name":"acme","account_type":"organization"}}}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("got %d, want 201.\nbody: %s", rec.Code, rec.Body.String())
		}
	})
}
