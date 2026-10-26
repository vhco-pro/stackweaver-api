// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// memLoginTransactions is an in-memory loginTransactionStore.
type memLoginTransactions struct {
	mu      sync.Mutex
	byState map[string]*models.LoginTransaction
}

func newMemLoginTransactions() *memLoginTransactions {
	return &memLoginTransactions{byState: map[string]*models.LoginTransaction{}}
}

func (m *memLoginTransactions) CreateLoginTransaction(tx *models.LoginTransaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *tx
	m.byState[tx.State] = &cp
	return nil
}

func (m *memLoginTransactions) TakeLoginTransaction(state string, now time.Time) (*models.LoginTransaction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, ok := m.byState[state]
	if !ok {
		return nil, repository.ErrLoginTransactionNotFound
	}
	delete(m.byState, state)
	if !tx.ExpiresAt.After(now) {
		return nil, repository.ErrLoginTransactionNotFound
	}
	return tx, nil
}

func (m *memLoginTransactions) all() []*models.LoginTransaction {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*models.LoginTransaction, 0, len(m.byState))
	for _, tx := range m.byState {
		out = append(out, tx)
	}
	return out
}

// authorizeZitadel answers Zitadel's authorize endpoint with a redirect carrying an auth request
// id, and records the query it received.
type authorizeZitadel struct {
	mu        sync.Mutex
	lastQuery url.Values
	authReq   string
}

func (z *authorizeZitadel) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		z.mu.Lock()
		z.lastQuery = r.URL.Query()
		authReq := z.authReq
		z.mu.Unlock()
		if authReq == "" {
			authReq = "V2_123"
		}
		w.Header().Set("Location", "http://localhost:5173/login?authRequest="+authReq)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

const (
	testBFFClientID    = "bff-client"
	testRedirectURI    = "https://app.example.com/auth/callback"
	testBFFSecret      = "bff-secret"
	testPublicFrontend = "https://app.example.com"
)

// bffProxyConfig is the configuration a proxy that runs the backend-for-frontend sign-in needs.
func bffProxyConfig(zitadelURL string, tx loginTransactionStore) AuthProxyConfig {
	return AuthProxyConfig{
		ZitadelInternalURL: zitadelURL,
		PAT:                "test-pat",
		DefaultRedirectURI: testRedirectURI,
		PublicFrontendURL:  testPublicFrontend,
		BFFClientID:        testBFFClientID,
		BFFClientSecret:    testBFFSecret,
		LoginTransactions:  tx,
	}
}

// bindingCookie is the login binding cookie a browser sends back.
func bindingCookie(state, value string) *http.Cookie {
	return &http.Cookie{Name: loginBindingCookieName(state), Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}
}

func runAuthorize(t *testing.T, proxy *AuthProxy, query string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/oidc/authorize?"+query)
	for _, ck := range cookies {
		c.Request.AddCookie(ck)
	}
	proxy.Authorize(c)
	return w
}

func loginCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, ck := range w.Result().Cookies() {
		if strings.HasPrefix(ck.Name, loginBindingCookiePrefix) && ck.MaxAge > 0 {
			return ck
		}
	}
	t.Fatalf("no %s* cookie set", loginBindingCookiePrefix)
	return nil
}

// The authorize request Zitadel receives carries the BFF's own client id, redirect URI, state,
// nonce and PKCE challenge, whatever the caller sent, and never offline_access; the caller's
// prompt, login hint and organization scope still pass through.
func TestAuthorize_UsesTheBFFsOwnParameters(t *testing.T) {
	z := &authorizeZitadel{}
	srv := z.serve(t)
	txs := newMemLoginTransactions()
	proxy := NewAuthProxy(bffProxyConfig(srv.URL, txs))
	t.Cleanup(proxy.StopDecoyOrgIDsSweeper)

	caller := url.Values{
		"client_id":             {"public-spa-client"},
		"redirect_uri":          {"https://evil.example/cb"},
		"code_challenge":        {"caller-challenge"},
		"code_challenge_method": {"S256"},
		"state":                 {"caller-state"},
		"nonce":                 {"caller-nonce"},
		"scope":                 {"openid offline_access urn:zitadel:iam:org:id:4242"},
		"prompt":                {"select_account"},
		"login_hint":            {"ada@example.com"},
	}
	w := runAuthorize(t, proxy, caller.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}

	q := z.lastQuery
	if q.Get("client_id") != testBFFClientID {
		t.Errorf("client_id = %q, want the BFF client", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != testRedirectURI {
		t.Errorf("redirect_uri = %q, want the configured %q", q.Get("redirect_uri"), testRedirectURI)
	}
	if q.Get("state") == "caller-state" || q.Get("nonce") == "caller-nonce" || q.Get("code_challenge") == "caller-challenge" {
		t.Errorf("caller-supplied state, nonce or challenge reached Zitadel: %v", q)
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
		t.Errorf("want response_type=code with an S256 challenge, got %v", q)
	}
	scope := strings.Fields(q.Get("scope"))
	for _, want := range []string{"openid", "profile", "email", "urn:zitadel:iam:org:id:4242"} {
		if !slices.Contains(scope, want) {
			t.Errorf("scope %v lacks %q", scope, want)
		}
	}
	if slices.Contains(scope, "offline_access") {
		t.Errorf("scope must never request offline_access: %v", scope)
	}
	if q.Get("prompt") != "select_account" || q.Get("login_hint") != "ada@example.com" {
		t.Errorf("prompt and login_hint must pass through, got %v", q)
	}

	// The stored transaction holds what Zitadel was sent: its state, nonce, and the verifier whose
	// S256 is the challenge.
	stored := txs.all()
	if len(stored) != 1 {
		t.Fatalf("want one stored transaction, got %d", len(stored))
	}
	tx := stored[0]
	if tx.State != q.Get("state") || tx.Nonce != q.Get("nonce") {
		t.Errorf("stored state/nonce do not match what Zitadel received")
	}
	sum := sha256.Sum256([]byte(tx.CodeVerifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") {
		t.Errorf("the challenge sent is not the S256 of the stored verifier")
	}
	if tx.ExpiresAt.Sub(tx.CreatedAt) != loginTransactionTTL {
		t.Errorf("transaction lifetime = %s, want %s", tx.ExpiresAt.Sub(tx.CreatedAt), loginTransactionTTL)
	}
}

// The login binding cookie is __Host- prefixed, HttpOnly, Secure, SameSite=Lax, Path=/, without
// Domain, with a ten-minute lifetime, and keeps its value across authorize requests from one
// browser, so every transaction that browser starts records the same binding.
func TestAuthorize_BindingCookie(t *testing.T) {
	z := &authorizeZitadel{}
	srv := z.serve(t)
	txs := newMemLoginTransactions()
	proxy := NewAuthProxy(bffProxyConfig(srv.URL, txs))
	t.Cleanup(proxy.StopDecoyOrgIDsSweeper)

	first := loginCookie(t, runAuthorize(t, proxy, ""))
	if !first.HttpOnly || !first.Secure || first.SameSite != http.SameSiteLaxMode || first.Path != "/" || first.Domain != "" {
		t.Fatalf("binding cookie attributes wrong: %+v", first)
	}
	if first.MaxAge != int(loginTransactionTTL.Seconds()) {
		t.Fatalf("binding cookie Max-Age = %d, want %d", first.MaxAge, int(loginTransactionTTL.Seconds()))
	}
	if len(first.Value) < 40 {
		t.Fatalf("binding value too short to be 32 random bytes: %q", first.Value)
	}
	tx := txs.all()[0]
	if first.Name != loginBindingCookieName(tx.State) || tx.BrowserBinding != first.Value {
		t.Fatalf("the cookie must be named for its sign-in's state and carry the binding the transaction records")
	}

	// Each sign-in gets its own cookie, so two tabs that start at once cannot overwrite each
	// other's binding.
	second := loginCookie(t, runAuthorize(t, proxy, "", first))
	if second.Name == first.Name || second.Value == first.Value {
		t.Fatalf("a second sign-in must get its own binding cookie")
	}
}

// AC20: two tabs of a browser with no binding cookie yet start sign-in at the same moment, so
// neither request carries the other's cookie. Both sign-ins stay redeemable, in either order.
func TestTakeLoginTransaction_ConcurrentTabs(t *testing.T) {
	z := &authorizeZitadel{}
	srv := z.serve(t)
	txs := newMemLoginTransactions()
	proxy := NewAuthProxy(bffProxyConfig(srv.URL, txs))
	t.Cleanup(proxy.StopDecoyOrgIDsSweeper)

	// Both authorize requests leave the browser before either answer has set a cookie.
	tabA := loginCookie(t, runAuthorize(t, proxy, ""))
	tabB := loginCookie(t, runAuthorize(t, proxy, ""))
	stored := txs.all()

	// The browser now holds both cookies; tab B finishes first.
	take := func(state string) error {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = newTestRequest(http.MethodPost, "/auth/session")
		c.Request.AddCookie(tabA)
		c.Request.AddCookie(tabB)
		_, err := proxy.takeLoginTransaction(c, state)
		return err
	}
	if err := take(stored[1].State); err != nil {
		t.Fatalf("tab B's sign-in was refused: %v", err)
	}
	if err := take(stored[0].State); err != nil {
		t.Fatalf("tab A's sign-in was refused after tab B finished: %v", err)
	}
}

// Without the BFF client configured, browser sign-in is unavailable rather than falling back to
// a public client.
func TestAuthorize_RequiresTheBFFClient(t *testing.T) {
	z := &authorizeZitadel{}
	srv := z.serve(t)
	cfg := bffProxyConfig(srv.URL, newMemLoginTransactions())
	cfg.BFFClientID = ""
	proxy := NewAuthProxy(cfg)
	t.Cleanup(proxy.StopDecoyOrgIDsSweeper)
	if w := runAuthorize(t, proxy, ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 without the BFF client, got %d", w.Code)
	}
}

// takeLoginTransaction redeems a transaction once, only from the browser that started it, and
// only before it expires; two transactions from one browser are both redeemable.
func TestTakeLoginTransaction(t *testing.T) {
	z := &authorizeZitadel{}
	srv := z.serve(t)
	txs := newMemLoginTransactions()
	proxy := NewAuthProxy(bffProxyConfig(srv.URL, txs))
	t.Cleanup(proxy.StopDecoyOrgIDsSweeper)

	first := loginCookie(t, runAuthorize(t, proxy, ""))
	second := loginCookie(t, runAuthorize(t, proxy, "", first))
	binding := second
	stored := txs.all()
	if len(stored) != 2 {
		t.Fatalf("want two transactions from one browser, got %d", len(stored))
	}
	// The store has no order; tell the two sign-ins apart by the cookie each one set.
	firstState, secondState := stored[0].State, stored[1].State
	if loginBindingCookieName(firstState) != first.Name {
		firstState, secondState = secondState, firstState
	}

	take := func(state string, cookie *http.Cookie) error {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = newTestRequest(http.MethodPost, "/auth/session")
		if cookie != nil {
			c.Request.AddCookie(cookie)
		}
		_, err := proxy.takeLoginTransaction(c, state)
		return err
	}

	stranger := bindingCookie(firstState, "another-browser-binding-value-0000000000")
	if err := take(firstState, stranger); !errors.Is(err, errLoginTransactionRefused) {
		t.Fatalf("another browser's binding: got %v, want refused", err)
	}
	// A take is final even when refused, so a code presented with the wrong binding cannot be
	// retried; the rightful browser signs in again, which is the safe outcome.
	if err := take(secondState, binding); err != nil {
		t.Fatalf("the second transaction must be redeemable: %v", err)
	}
	if err := take(secondState, binding); !errors.Is(err, errLoginTransactionRefused) {
		t.Fatalf("a replay must be refused, got %v", err)
	}
	if err := take("unknown-state", binding); !errors.Is(err, errLoginTransactionRefused) {
		t.Fatalf("an unknown state must be refused, got %v", err)
	}
	if err := take(firstState, first); !errors.Is(err, errLoginTransactionRefused) {
		t.Fatalf("the first sign-in was already taken (refused) and must stay refused, got %v", err)
	}
	if err := take(firstState, nil); !errors.Is(err, errLoginTransactionRefused) {
		t.Fatalf("no binding cookie must be refused, got %v", err)
	}

	expired := &models.LoginTransaction{
		State: "expired-state", Nonce: "n", CodeVerifier: "v", BrowserBinding: binding.Value,
		CreatedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := txs.CreateLoginTransaction(expired); err != nil {
		t.Fatalf("seed expired: %v", err)
	}
	if err := take("expired-state", binding); !errors.Is(err, errLoginTransactionRefused) {
		t.Fatalf("an expired transaction must be refused, got %v", err)
	}
}
