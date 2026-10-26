// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
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
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/auth/authtest"
	"github.com/michielvha/stackweaver/core/models"
)

const signInIssuer = "https://zitadel.example.com"

// fakeSignIn records what ProvisionBrowserUser received.
type fakeSignIn struct {
	identity    auth.BrowserIdentity
	accessToken string
	err         error
}

func (f *fakeSignIn) ProvisionBrowserUser(_ context.Context, id auth.BrowserIdentity, accessToken string) (*models.User, error) {
	f.identity, f.accessToken = id, accessToken
	if f.err != nil {
		return nil, f.err
	}
	return &models.User{ID: uuid.New(), ZitadelSubject: id.Subject, Email: id.Email}, nil
}

// signInZitadel is a fake Zitadel for the code flow: authorize redirects with an auth request,
// keys publishes the signing key, and token answers the code exchange with an ID token built
// from the claims the test chooses.
type signInZitadel struct {
	t      *testing.T
	signer jose.Signer
	jwks   jose.JSONWebKeySet

	mu          sync.Mutex
	nonce       string
	idClaims    func(nonce string) map[string]any
	tokenForm   url.Values
	tokenUser   string
	tokenSecret string
	// What the session-ending endpoints received.
	deletedSessions []string
	endSessionForm  url.Values
	// endSessionLocation is where end_session redirects the browser; empty means the login UI's
	// logout page on the app.
	endSessionLocation string
}

func newSignInZitadel(t *testing.T) (*signInZitadel, *httptest.Server) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: priv, KeyID: "k1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	z := &signInZitadel{
		t:      t,
		signer: signer,
		jwks:   jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &priv.PublicKey, KeyID: "k1", Algorithm: string(jose.RS256), Use: "sig"}}},
	}
	z.idClaims = z.validIDClaims
	srv := httptest.NewServer(http.HandlerFunc(z.handle))
	t.Cleanup(srv.Close)
	return z, srv
}

func (z *signInZitadel) validIDClaims(nonce string) map[string]any {
	return map[string]any{
		"iss": signInIssuer, "aud": []string{testBFFClientID}, "sub": "user-1", "sid": "sid-1",
		"nonce": nonce, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"email": "ada@example.com", "email_verified": true, "name": "Ada Lovelace",
		"given_name": "Ada", "family_name": "Lovelace", "picture": "https://img.example/ada.png",
		"urn:zitadel:iam:user:resourceowner:id": "org-1",
	}
}

func (z *signInZitadel) sign(claims map[string]any) string {
	raw, err := jwt.Signed(z.signer).Claims(claims).Serialize()
	if err != nil {
		z.t.Fatalf("sign: %v", err)
	}
	return raw
}

func (z *signInZitadel) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/oauth/v2/authorize":
		z.mu.Lock()
		z.nonce = r.URL.Query().Get("nonce")
		z.mu.Unlock()
		w.Header().Set("Location", "http://localhost:5173/login?authRequest=V2_1")
		w.WriteHeader(http.StatusFound)
	case "/oauth/v2/keys":
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(z.jwks); err != nil {
			z.t.Errorf("encode keys: %v", err)
		}
	case "/oauth/v2/token":
		_ = r.ParseForm()
		user, secret, _ := r.BasicAuth()
		z.mu.Lock()
		z.tokenForm, z.tokenUser, z.tokenSecret = r.PostForm, user, secret
		nonce := z.nonce
		claimsFn := z.idClaims
		z.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"id_token":     z.sign(claimsFn(nonce)),
			"access_token": "access-token-value",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}); err != nil {
			z.t.Errorf("encode tokens: %v", err)
		}
	case "/oidc/v1/end_session":
		_ = r.ParseForm()
		z.mu.Lock()
		z.endSessionForm = r.PostForm
		location := z.endSessionLocation
		z.mu.Unlock()
		if location == "" {
			location = testPublicFrontend + "/login/logout?post_logout_redirect=" + url.QueryEscape(r.PostForm.Get("post_logout_redirect_uri"))
		}
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusFound)
	default:
		if sid, ok := strings.CutPrefix(r.URL.Path, "/v2/sessions/"); ok && r.Method == http.MethodDelete {
			z.mu.Lock()
			z.deletedSessions = append(z.deletedSessions, sid)
			z.mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

type signInHarness struct {
	z        *signInZitadel
	proxy    *AuthProxy
	txs      *memLoginTransactions
	sessions *authtest.MemSessions
	signIn   *fakeSignIn
}

func newSignInHarness(t *testing.T) *signInHarness {
	t.Helper()
	z, srv := newSignInZitadel(t)
	h := &signInHarness{z: z, txs: newMemLoginTransactions(), sessions: authtest.NewMemSessions(), signIn: &fakeSignIn{}}
	cfg := bffProxyConfig(srv.URL, h.txs)
	cfg.ZitadelIssuer = signInIssuer
	cfg.SignIn = h.signIn
	cfg.BrowserSessions = auth.NewSessions(h.sessions, auth.DefaultSessionLimits, time.Now)
	h.proxy = NewAuthProxy(cfg)
	cfg.BrowserSessions.SetZitadel(h.proxy)
	t.Cleanup(h.proxy.StopDecoyOrgIDsSweeper)
	return h
}

// signedIn runs a whole sign-in and returns the session cookie.
func (h *signInHarness) signedIn(t *testing.T) *http.Cookie {
	t.Helper()
	binding, state := h.begin(t)
	w := h.redeem(t, state, binding)
	if w.Code != http.StatusCreated {
		t.Fatalf("sign-in: %d %s", w.Code, w.Body.String())
	}
	return sessionCookieFrom(t, w)
}

// serve sends one request to handler with the given cookies.
func serve(handler gin.HandlerFunc, method, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(method, target)
	for _, ck := range cookies {
		c.Request.AddCookie(ck)
	}
	handler(c)
	// gin's engine writes the status at the end of every request; a redirect that answers a POST
	// writes no body, so without this the recorder would still show 200.
	c.Writer.WriteHeaderNow()
	return w
}

// begin runs the authorize step and returns the browser's binding cookie and the sign-in state.
func (h *signInHarness) begin(t *testing.T) (*http.Cookie, string) {
	t.Helper()
	w := runAuthorize(t, h.proxy, "")
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	stored := h.txs.all()
	return loginCookie(t, w), stored[len(stored)-1].State
}

func (h *signInHarness) redeem(t *testing.T, state string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"data":{"type":"sessions","attributes":{"code":"the-code","state":"` + state + `"}}}`
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/session", body)
	c.Request.Header.Set("Content-Type", "application/vnd.api+json")
	for _, ck := range cookies {
		c.Request.AddCookie(ck)
	}
	h.proxy.CreateBrowserSession(c)
	return w
}

func sessionCookieFrom(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookieName {
			return ck
		}
	}
	t.Fatalf("no %s cookie set: %s", sessionCookieName, w.Body.String())
	return nil
}

// A sign-in redeems the code as the confidential client with the transaction's verifier, starts a
// session holding only the hash of a strict, Secure, httpOnly cookie, and answers the profile; no
// OAuth token reaches the response or the store.
func TestCreateBrowserSession_SignsIn(t *testing.T) {
	h := newSignInHarness(t)
	binding, state := h.begin(t)
	verifier := h.txs.all()[0].CodeVerifier

	w := h.redeem(t, state, binding)
	if w.Code != http.StatusCreated {
		t.Fatalf("redeem: %d %s", w.Code, w.Body.String())
	}

	if h.z.tokenUser != testBFFClientID || h.z.tokenSecret != testBFFSecret {
		t.Errorf("the code exchange must authenticate as the BFF client with its secret")
	}
	f := h.z.tokenForm
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "the-code" ||
		f.Get("redirect_uri") != testRedirectURI || f.Get("code_verifier") != verifier {
		t.Errorf("token request form wrong: %v", f)
	}

	ck := sessionCookieFrom(t, w)
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.Domain != "" {
		t.Errorf("session cookie attributes wrong: %+v", ck)
	}
	if ck.MaxAge != int(auth.DefaultSessionLimits.Absolute.Seconds()) {
		t.Errorf("session cookie Max-Age = %d, want the absolute limit", ck.MaxAge)
	}

	s := h.sessions.Only(t)
	if s.TokenHash != auth.HashSessionToken(ck.Value) {
		t.Errorf("the store must hold the hash of the cookie value")
	}
	if s.ZitadelSID != "sid-1" || s.OrganizationID != "org-1" || s.Email != "ada@example.com" {
		t.Errorf("session record wrong: %+v", s)
	}
	if h.signIn.accessToken != "access-token-value" || !h.signIn.identity.EmailVerified || h.signIn.identity.Subject != "user-1" {
		t.Errorf("provisioning got the wrong sign-in: %+v", h.signIn)
	}

	body := w.Body.String()
	for _, secret := range []string{"access-token-value", h.z.sign(h.z.validIDClaims(""))[:20], ck.Value} {
		if strings.Contains(body, secret) {
			t.Errorf("the response must carry no token or cookie value")
		}
	}
	var doc struct {
		Data struct {
			Type       string            `json:"type"`
			Attributes SessionAttributes `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || doc.Data.Type != "sessions" || doc.Data.Attributes.Email != "ada@example.com" {
		t.Errorf("response must be the JSON:API sessions resource, got %s", body)
	}
}

// Every sign-in mints a new cookie value; a value the browser held before is never adopted.
func TestCreateBrowserSession_NeverAdoptsAPresentedValue(t *testing.T) {
	h := newSignInHarness(t)
	binding, state := h.begin(t)
	planted := &http.Cookie{Name: sessionCookieName, Value: "planted-by-someone-else", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}

	ck := sessionCookieFrom(t, h.redeem(t, state, binding, planted))
	if ck.Value == planted.Value {
		t.Fatalf("sign-in adopted the presented cookie value")
	}
	if _, err := h.proxy.config.BrowserSessions.Lookup(planted.Value); err == nil {
		t.Fatalf("the planted value must not name a session")
	}
}

// An unverified email is refused with its own code, so the SPA can tell it from any other 403.
func TestCreateBrowserSession_UnverifiedEmailIsCoded(t *testing.T) {
	h := newSignInHarness(t)
	h.signIn.err = auth.ErrEmailNotVerified
	ck, state := h.begin(t)
	w := h.redeem(t, state, ck)
	if w.Code != http.StatusForbidden {
		t.Fatalf("answered %d, want 403: %s", w.Code, w.Body.String())
	}
	var doc struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || len(doc.Errors) != 1 || doc.Errors[0].Code != auth.CodeEmailNotVerified {
		t.Fatalf("error document %s, want code %q", w.Body.String(), auth.CodeEmailNotVerified)
	}
}

// A refused sign-in starts no session: an unverified email, a nonce from another sign-in, an ID
// token for another client, an expired one, and a state from another browser.
func TestCreateBrowserSession_Refusals(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(h *signInHarness)
		binding  func(real *http.Cookie) *http.Cookie
		wantCode int
	}{
		{name: "unverified email", mutate: func(h *signInHarness) { h.signIn.err = auth.ErrEmailNotVerified }, wantCode: http.StatusForbidden},
		{name: "nonce from another sign-in", mutate: func(h *signInHarness) {
			h.z.idClaims = func(string) map[string]any { c := h.z.validIDClaims("other-nonce"); return c }
		}, wantCode: http.StatusBadRequest},
		{name: "ID token for another client", mutate: func(h *signInHarness) {
			h.z.idClaims = func(n string) map[string]any {
				c := h.z.validIDClaims(n)
				c["aud"] = []string{"someone-else"}
				return c
			}
		}, wantCode: http.StatusBadRequest},
		{name: "expired ID token", mutate: func(h *signInHarness) {
			h.z.idClaims = func(n string) map[string]any {
				c := h.z.validIDClaims(n)
				c["exp"] = time.Now().Add(-time.Minute).Unix()
				return c
			}
		}, wantCode: http.StatusBadRequest},
		{name: "ID token without a session id", mutate: func(h *signInHarness) {
			h.z.idClaims = func(n string) map[string]any { c := h.z.validIDClaims(n); delete(c, "sid"); return c }
		}, wantCode: http.StatusBadRequest},
		{name: "state from another browser", binding: func(real *http.Cookie) *http.Cookie {
			return &http.Cookie{Name: real.Name, Value: "another-browser-binding-value-0000000000", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}
		}, wantCode: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSignInHarness(t)
			if tc.mutate != nil {
				tc.mutate(h)
			}
			binding, state := h.begin(t)
			if tc.binding != nil {
				binding = tc.binding(binding)
			}
			w := h.redeem(t, state, binding)
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			for _, ck := range w.Result().Cookies() {
				if ck.Name == sessionCookieName {
					t.Fatalf("a refused sign-in must set no session cookie")
				}
			}
			if h.sessions.Len() != 0 {
				t.Fatalf("a refused sign-in must store no session")
			}
		})
	}
}

// GET /auth/session answers the profile for a live session and 401 otherwise.
func TestGetBrowserSession(t *testing.T) {
	h := newSignInHarness(t)
	binding, state := h.begin(t)
	ck := sessionCookieFrom(t, h.redeem(t, state, binding))

	get := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequest(http.MethodGet, "/auth/session")
		if cookie != nil {
			c.Request.AddCookie(cookie)
		}
		h.proxy.GetBrowserSession(c)
		return w
	}
	if w := get(ck); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ada@example.com") {
		t.Fatalf("live session: %d %s", w.Code, w.Body.String())
	}
	if w := get(nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no cookie: got %d, want 401", w.Code)
	}
	if w := get(&http.Cookie{Name: sessionCookieName, Value: "unknown", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown cookie: got %d, want 401", w.Code)
	}
}

// #829 D5 at sign-in: Zitadel puts email_verified into the ID token only through userinfo
// assertion, and omits it when false, so an absent claim reaches provisioning as unverified,
// where ProvisionBrowserUser refuses it (TestProvisionBrowserUser_RefusesUnverifiedEmail). This
// rule used to be pinned on the per-request userinfo call (TestExtractUserInfo_EmailVerified),
// which went with the JWT bearer path.
func TestCreateBrowserSession_EmailVerifiedComesOnlyFromTheClaim(t *testing.T) {
	for name, set := range map[string]func(map[string]any){
		"claim absent": func(c map[string]any) { delete(c, "email_verified") },
		"claim false":  func(c map[string]any) { c["email_verified"] = false },
	} {
		t.Run(name, func(t *testing.T) {
			h := newSignInHarness(t)
			h.z.idClaims = func(n string) map[string]any { c := h.z.validIDClaims(n); set(c); return c }
			binding, state := h.begin(t)
			h.redeem(t, state, binding)
			if h.signIn.identity.Subject != "user-1" {
				t.Fatalf("the sign-in never reached provisioning")
			}
			if h.signIn.identity.EmailVerified {
				t.Errorf("an ID token with the claim %s reached provisioning as verified", name)
			}
		})
	}
}

// AC5, AC21: sign-out deletes the session and its Zitadel session, clears the cookie, and sends the
// browser through Zitadel's end_session as the BFF client, with no ID token anywhere the SPA can
// read it.
func TestEndBrowserSession_SignsOut(t *testing.T) {
	h := newSignInHarness(t)
	ck := h.signedIn(t)

	w := serve(h.proxy.EndBrowserSession, http.MethodPost, "/auth/session/end", ck)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("sign-out answered %d, want 303: %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, testPublicFrontend+"/login/logout?") {
		t.Errorf("sign-out redirected to %q, want the login UI's logout page", loc)
	}
	if h.sessions.Len() != 0 {
		t.Error("the session survived sign-out")
	}
	h.z.mu.Lock()
	deleted, form := h.z.deletedSessions, h.z.endSessionForm
	h.z.mu.Unlock()
	if len(deleted) != 1 || deleted[0] != "sid-1" {
		t.Errorf("Zitadel session deletes = %v, want [sid-1]", deleted)
	}
	if form.Get("client_id") != testBFFClientID || form.Get("post_logout_redirect_uri") != testPublicFrontend {
		t.Errorf("end_session form = %v, want the BFF client and the app's origin", form)
	}
	if form.Has("id_token_hint") {
		t.Error("end_session was sent an ID token; none is kept")
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			cleared = c.MaxAge < 0 && c.Secure && c.HttpOnly && c.Path == "/" && c.SameSite == http.SameSiteStrictMode
		}
	}
	if !cleared {
		t.Error("sign-out did not clear the session cookie with its own attributes")
	}

	// The old value is refused afterwards.
	if w := serve(h.proxy.GetBrowserSession, http.MethodGet, "/auth/session", ck); w.Code != http.StatusUnauthorized {
		t.Errorf("the signed-out cookie answered %d on GET /auth/session, want 401", w.Code)
	}
}

// A browser with no session still gets the cookie cleared and the end_session hop, and no Zitadel
// session is touched.
func TestEndBrowserSession_WithoutASession(t *testing.T) {
	h := newSignInHarness(t)
	w := serve(h.proxy.EndBrowserSession, http.MethodPost, "/auth/session/end")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("answered %d, want 303", w.Code)
	}
	h.z.mu.Lock()
	defer h.z.mu.Unlock()
	if len(h.z.deletedSessions) != 0 {
		t.Errorf("deleted Zitadel sessions %v without a session", h.z.deletedSessions)
	}
}

// A redirect from Zitadel to a host the API does not trust is not followed: the browser goes to
// the app instead.
func TestEndBrowserSession_RefusesAForeignRedirect(t *testing.T) {
	h := newSignInHarness(t)
	h.z.endSessionLocation = "https://evil.example.net/phish"
	w := serve(h.proxy.EndBrowserSession, http.MethodPost, "/auth/session/end", h.signedIn(t))
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || loc != testPublicFrontend {
		t.Fatalf("answered %d to %q, want 303 to the app", w.Code, loc)
	}
}

// A store that cannot be read is not a missing session: the session endpoints answer a 503 the SPA
// retries, not the coded 401 it signs out on, and sign-out keeps the cookie rather than claim an
// end it could not make. Once the store is back, the browser is still signed in.
func TestBrowserSessionEndpoints_StoreFailureIsNotASignOut(t *testing.T) {
	h := newSignInHarness(t)
	ck := h.signedIn(t)
	h.sessions.Fail = errors.New("database is unreachable")

	if w := serve(h.proxy.GetBrowserSession, http.MethodGet, "/auth/session", ck); w.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /auth/session with the store down answered %d, want 503: %s", w.Code, w.Body.String())
	}
	if w := serve(h.proxy.TouchBrowserSession, http.MethodPost, "/auth/session/touch", ck); w.Code != http.StatusServiceUnavailable {
		t.Errorf("POST /auth/session/touch with the store down answered %d, want 503", w.Code)
	}
	w := serve(h.proxy.EndBrowserSession, http.MethodPost, "/auth/session/end", ck)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("sign-out with the store down answered %d, want 503", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			t.Errorf("sign-out cleared the cookie although it could not end the session")
		}
	}

	h.sessions.Fail = nil
	if w := serve(h.proxy.GetBrowserSession, http.MethodGet, "/auth/session", ck); w.Code != http.StatusOK {
		t.Errorf("after the store came back the session answered %d, want 200", w.Code)
	}
}

// AC8: the SPA's activity touch extends the idle limit; without a session it is the coded 401.
func TestTouchBrowserSession(t *testing.T) {
	h := newSignInHarness(t)
	ck := h.signedIn(t)
	before := h.sessions.Only(t).IdleExpiresAt
	time.Sleep(10 * time.Millisecond)

	if w := serve(h.proxy.TouchBrowserSession, http.MethodPost, "/auth/session/touch", ck); w.Code != http.StatusNoContent {
		t.Fatalf("touch answered %d, want 204: %s", w.Code, w.Body.String())
	}
	if after := h.sessions.Only(t).IdleExpiresAt; !after.After(before) {
		t.Errorf("the touch did not extend the idle limit (%s, then %s)", before, after)
	}

	w := serve(h.proxy.TouchBrowserSession, http.MethodPost, "/auth/session/touch")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), auth.CodeAuthenticationRequired) {
		t.Fatalf("a touch without a session answered %d %s, want the coded 401", w.Code, w.Body.String())
	}
}

// A sign-in started with max_age (OIDC Core 3.1.2.1) accepts an ID token only when the person
// authenticated within that many seconds: auth_time must be present and recent enough.
func TestCreateBrowserSession_MaxAge(t *testing.T) {
	cases := map[string]struct {
		authTime any // nil leaves the claim out
		wantCode int
	}{
		"recent authentication":   {authTime: time.Now().Add(-30 * time.Second).Unix(), wantCode: http.StatusCreated},
		"authentication too old":  {authTime: time.Now().Add(-10 * time.Minute).Unix(), wantCode: http.StatusBadRequest},
		"no auth_time in a token": {authTime: nil, wantCode: http.StatusBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newSignInHarness(t)
			h.z.idClaims = func(n string) map[string]any {
				c := h.z.validIDClaims(n)
				if tc.authTime != nil {
					c["auth_time"] = tc.authTime
				}
				return c
			}
			w := runAuthorize(t, h.proxy, "max_age=300")
			if w.Code != http.StatusOK {
				t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
			}
			stored := h.txs.all()
			got := h.redeem(t, stored[len(stored)-1].State, loginCookie(t, w))
			if got.Code != tc.wantCode {
				t.Fatalf("redeem answered %d, want %d: %s", got.Code, tc.wantCode, got.Body.String())
			}
		})
	}
}

// Without max_age, auth_time is not required.
func TestCreateBrowserSession_NoMaxAgeNeedsNoAuthTime(t *testing.T) {
	h := newSignInHarness(t)
	binding, state := h.begin(t)
	if w := h.redeem(t, state, binding); w.Code != http.StatusCreated {
		t.Fatalf("redeem answered %d: %s", w.Code, w.Body.String())
	}
}

func TestAuthorize_RefusesAMalformedMaxAge(t *testing.T) {
	h := newSignInHarness(t)
	for _, v := range []string{"-1", "soon", "1e3"} {
		if w := runAuthorize(t, h.proxy, "max_age="+v); w.Code != http.StatusBadRequest {
			t.Errorf("max_age=%s answered %d, want 400", v, w.Code)
		}
	}
}

// A browser that signs in again, as the same person or another, ends with the new session only:
// the session its cookie named is ended, so it can neither be reused nor linger. Its Zitadel
// session is ended too, unless the new sign-in reused it.
func TestCreateBrowserSession_ReplacesTheBrowsersSession(t *testing.T) {
	for name, tc := range map[string]struct {
		secondSID   string
		wantDeleted []string
	}{
		"another Zitadel session":  {secondSID: "sid-2", wantDeleted: []string{"sid-1"}},
		"the same Zitadel session": {secondSID: "sid-1", wantDeleted: nil},
	} {
		t.Run(name, func(t *testing.T) {
			h := newSignInHarness(t)
			first := h.signedIn(t)
			firstSession := h.sessions.Only(t)

			h.z.idClaims = func(n string) map[string]any { c := h.z.validIDClaims(n); c["sid"] = tc.secondSID; return c }
			binding, state := h.begin(t)
			w := h.redeem(t, state, binding, first)
			if w.Code != http.StatusCreated {
				t.Fatalf("the second sign-in answered %d: %s", w.Code, w.Body.String())
			}
			second := sessionCookieFrom(t, w)
			if second.Value == first.Value {
				t.Fatal("the second sign-in kept the first cookie value")
			}
			if h.sessions.ByID(firstSession.ID) != nil {
				t.Error("the session the browser's cookie named survived the new sign-in")
			}
			if n := h.sessions.Len(); n != 1 {
				t.Errorf("%d sessions stored, want only the new one", n)
			}
			h.z.mu.Lock()
			deleted := append([]string(nil), h.z.deletedSessions...)
			h.z.mu.Unlock()
			if !slices.Equal(deleted, tc.wantDeleted) {
				t.Errorf("Zitadel sessions deleted %v, want %v", deleted, tc.wantDeleted)
			}
		})
	}
}
