// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// An organization holds one connection per GitHub App installation and per Azure DevOps
// organization (#938, AC-01 to AC-04). These tests drive the real router: GitHub is a local fake
// and Azure DevOps answers through a swapped default transport.

//go:build integration

package routes_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// fakeGitHubTwoInstallations answers for one GitHub user, whose authorization code is
// "code-manager" and who can access installations 111 and 222. An installation's account login
// is gh-account-<id>, unless renamed holds a new login for it.
func fakeGitHubTwoInstallations(t *testing.T, renamed *sync.Map) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("code") != "code-manager" {
			_, _ = fmt.Fprint(w, `{"error":"bad_verification_code"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"access_token":"ghu_manager","token_type":"bearer"}`)
	})
	mux.HandleFunc("GET /user/installations", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") != "1" {
			_, _ = fmt.Fprint(w, `{"total_count":2,"installations":[]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"total_count":2,"installations":[{"id":111},{"id":222}]}`)
	})
	mux.HandleFunc("GET /app/installations/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		login := fmt.Sprintf("gh-account-%d", id)
		if v, ok := renamed.Load(id); ok {
			login = v.(string)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":%d,"account":{"login":%q,"type":"Organization"}}`, id, login)
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func setupMultipleConnectionsRouter(t *testing.T, renamed *sync.Map) *vcsInstallAuthzFixture {
	t.Helper()
	gh := fakeGitHubTwoInstallations(t, renamed)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate a throwaway app key: %v", err)
	}
	t.Setenv("GITHUB_APP_ID", "1")
	t.Setenv("GITHUB_APP_NAME", "stackweaver-multiple-connections-test")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	t.Setenv("GITHUB_APP_PRIVATE_KEY_PATH", "")
	t.Setenv("GITHUB_APP_CLIENT_ID", "Iv1.multiple-connections-test")
	t.Setenv("GITHUB_APP_CLIENT_SECRET", "multiple-connections-test-secret")
	t.Setenv("STACKWEAVER_APP_URL", "https://stackweaver.test")
	m, err := vcs.NewGitHubAppManager()
	if err != nil || !m.IsEnabled() {
		t.Fatalf("configure the GitHub App: %v", err)
	}
	m.SetEndpoints(gh.URL, gh.URL)
	return setupVCSInstallAuthzWithGitHub(t, m)
}

// completeGitHub runs the three installation steps for installation as the fixture's manager.
func completeGitHub(t *testing.T, f *vcsInstallAuthzFixture, installation string) *httptest.ResponseRecorder {
	t.Helper()
	return finishGitHub(t, f, installation, authorizeGitHub(t, f, installation))
}

func authorizeGitHub(t *testing.T, f *vcsInstallAuthzFixture, installation string) string {
	t.Helper()
	base := vcsInstallPath(f.org.Name, "/vcs-connections/github")
	installState, _ := stateOf(t, f.do(t, http.MethodGet, base+"/install", f.manager))
	authState, _ := stateOf(t, f.do(t, http.MethodGet,
		base+"/installations/"+installation+"/authorize?state="+url.QueryEscape(installState), f.manager))
	return authState
}

func finishGitHub(t *testing.T, f *vcsInstallAuthzFixture, installation, state string) *httptest.ResponseRecorder {
	t.Helper()
	base := vcsInstallPath(f.org.Name, "/vcs-connections/github")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		base+"/installations/"+installation+"?state="+url.QueryEscape(state),
		strings.NewReader(`{"data":{"type":"vcs-connections","attributes":{"code":"code-manager"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.manager)
	rec := httptest.NewRecorder()
	f.h.router.ServeHTTP(rec, req)
	return rec
}

func (f *vcsInstallAuthzFixture) connectionsOf(t *testing.T, provider models.VCSProvider) []models.VCSConnection {
	t.Helper()
	var conns []models.VCSConnection
	if err := f.h.db.Where("organization_id = ? AND provider = ?", f.org.ID, provider).Order("created_at").Find(&conns).Error; err != nil {
		t.Fatalf("load connections: %v", err)
	}
	return conns
}

func TestGitHubInstallations_EachIsItsOwnConnection(t *testing.T) {
	renamed := &sync.Map{}
	f := setupMultipleConnectionsRouter(t, renamed)

	if rec := completeGitHub(t, f, "111"); rec.Code != http.StatusCreated {
		t.Fatalf("installation 111: got %d, want 201.\nbody: %s", rec.Code, rec.Body.String())
	}
	first := f.connectionsOf(t, models.VCSProviderGitHub)

	t.Run("a second installation adds a connection and leaves the first as it was", func(t *testing.T) {
		if rec := completeGitHub(t, f, "222"); rec.Code != http.StatusCreated {
			t.Fatalf("installation 222: got %d, want 201.\nbody: %s", rec.Code, rec.Body.String())
		}
		conns := f.connectionsOf(t, models.VCSProviderGitHub)
		if len(conns) != 2 {
			t.Fatalf("%d GitHub connections, want 2", len(conns))
		}
		if conns[0].ID != first[0].ID || conns[0].InstallationID != "111" || conns[0].AccountName != "gh-account-111" {
			t.Errorf("connection A became installation %q account %q, want it unchanged (111 / gh-account-111)", conns[0].InstallationID, conns[0].AccountName)
		}
		if conns[1].InstallationID != "222" || conns[1].AccountName != "gh-account-222" {
			t.Errorf("connection B = installation %q account %q, want 222 / gh-account-222", conns[1].InstallationID, conns[1].AccountName)
		}
	})

	t.Run("completing an installation again updates its connection in place", func(t *testing.T) {
		renamed.Store(int64(111), "gh-account-111-renamed")
		rec := completeGitHub(t, f, "111")
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want 200.\nbody: %s", rec.Code, rec.Body.String())
		}
		conns := f.connectionsOf(t, models.VCSProviderGitHub)
		on111 := 0
		for _, c := range conns {
			if c.InstallationID == "111" {
				on111++
				if c.ID != first[0].ID || c.AccountName != "gh-account-111-renamed" {
					t.Errorf("the connection on 111 is %s with account %q, want %s renamed", c.ID, c.AccountName, first[0].ID)
				}
			}
		}
		if on111 != 1 || len(conns) != 2 {
			t.Errorf("%d connection(s) on 111 and %d in all, want 1 and 2", on111, len(conns))
		}
	})
}

func TestGitHubInstallations_ConcurrentCompletionsLeaveOne(t *testing.T) {
	f := setupMultipleConnectionsRouter(t, &sync.Map{})
	states := []string{authorizeGitHub(t, f, "111"), authorizeGitHub(t, f, "111")}
	codes := make([]int, len(states))
	var wg sync.WaitGroup
	for i, s := range states {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = finishGitHub(t, f, "111", s).Code
		}()
	}
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusCreated && code != http.StatusOK {
			t.Errorf("completion %d answered %d, want 201 or 200", i, code)
		}
	}
	conns := f.connectionsOf(t, models.VCSProviderGitHub)
	if len(conns) != 1 || conns[0].InstallationID != "111" || conns[0].AccountName != "gh-account-111" {
		t.Errorf("got %d connection(s) %+v, want exactly one on 111 for gh-account-111", len(conns), conns)
	}
}

// acceptAzureDevOpsOAuth answers Microsoft's token endpoint with a token whose value names the
// code it was exchanged for, and the Azure DevOps account check with 200, for the rest of the
// test. Every other request goes to the real transport.
func acceptAzureDevOpsOAuth(t *testing.T) {
	t.Helper()
	real := http.DefaultTransport
	http.DefaultTransport = azureDevOpsOAuthAccepting{next: real}
	t.Cleanup(func() { http.DefaultTransport = real })
}

type azureDevOpsOAuthAccepting struct{ next http.RoundTripper }

func (a azureDevOpsOAuthAccepting) RoundTrip(req *http.Request) (*http.Response, error) {
	respond := func(body string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	}
	switch req.URL.Host {
	case "login.microsoftonline.com":
		_ = req.ParseForm()
		code := req.PostForm.Get("code")
		return respond(fmt.Sprintf(`{"access_token":"ado-access-%s","refresh_token":"ado-refresh-%s","expires_in":3600,"token_type":"Bearer"}`, code, code))
	case "app.vssps.visualstudio.com", "dev.azure.com":
		return respond(`{}`)
	}
	return a.next.RoundTrip(req)
}

// completeAzureDevOps runs the Azure DevOps flow for adoOrg with an authorization code.
func completeAzureDevOps(t *testing.T, f *vcsInstallAuthzFixture, adoOrg, code string) *httptest.ResponseRecorder {
	t.Helper()
	state, _ := stateOf(t, f.do(t, http.MethodGet,
		vcsInstallPath(f.org.Name, "/vcs-connections/azure-devops/install?ado_org="+url.QueryEscape(adoOrg)), f.manager))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v2/vcs-connections/azure-devops/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
	rec := httptest.NewRecorder()
	f.h.router.ServeHTTP(rec, req)
	return rec
}

func TestAzureDevOpsOrganizations_EachIsItsOwnConnection(t *testing.T) {
	f := setupMultipleConnectionsRouter(t, &sync.Map{})
	acceptAzureDevOpsOAuth(t)

	if rec := completeAzureDevOps(t, f, "Contoso", "x1"); rec.Code != http.StatusCreated {
		t.Fatalf("Azure DevOps organization X: got %d, want 201.\nbody: %s", rec.Code, rec.Body.String())
	}
	x := f.connectionsOf(t, models.VCSProviderAzureDevOps)[0]

	t.Run("a second Azure DevOps organization adds a connection and leaves the first as it was", func(t *testing.T) {
		if rec := completeAzureDevOps(t, f, "Fabrikam", "y1"); rec.Code != http.StatusCreated {
			t.Fatalf("Azure DevOps organization Y: got %d, want 201.\nbody: %s", rec.Code, rec.Body.String())
		}
		conns := f.connectionsOf(t, models.VCSProviderAzureDevOps)
		if len(conns) != 2 {
			t.Fatalf("%d Azure DevOps connections, want 2", len(conns))
		}
		if conns[0].ID != x.ID || conns[0].AccountName != "Contoso" || conns[0].AccessToken != x.AccessToken {
			t.Errorf("connection X changed: account %q, tokens replaced: %v", conns[0].AccountName, conns[0].AccessToken != x.AccessToken)
		}
	})

	t.Run("reconnecting X in another case refreshes its tokens and creates nothing", func(t *testing.T) {
		rec := completeAzureDevOps(t, f, "contoso", "x2")
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want 200.\nbody: %s", rec.Code, rec.Body.String())
		}
		conns := f.connectionsOf(t, models.VCSProviderAzureDevOps)
		if len(conns) != 2 {
			t.Fatalf("%d Azure DevOps connections, want 2", len(conns))
		}
		if conns[0].ID != x.ID || conns[0].AccessToken == x.AccessToken {
			t.Errorf("connection X (%s) was not refreshed in place: got %s, tokens replaced %v", x.ID, conns[0].ID, conns[0].AccessToken != x.AccessToken)
		}
		if conns[1].AccountName != "Fabrikam" {
			t.Errorf("connection Y became %q", conns[1].AccountName)
		}
	})
}
