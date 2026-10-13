// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

// userScopedUpstream stands in for Zitadel behind the user-scoped routes. It answers
// `GET /v2/sessions/{id}` with the factors a test chooses, answers everything under
// `/v2/users/` with a Zitadel-shaped success, and records every call it receives so a
// test can assert what did and did not reach the identity provider.
type userScopedUpstream struct {
	mu            sync.Mutex
	calls         []string
	sessionStatus int
	factors       map[string]any
}

func newUserScopedUpstream(factors map[string]any) *userScopedUpstream {
	return &userScopedUpstream{sessionStatus: http.StatusOK, factors: factors}
}

func (u *userScopedUpstream) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.calls = append(u.calls, r.Method+" "+r.URL.Path)
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/sessions/"):
			w.WriteHeader(u.sessionStatus)
			body, _ := json.Marshal(map[string]any{"session": map[string]any{
				"id":      strings.TrimPrefix(r.URL.Path, "/v2/sessions/"),
				"factors": u.factors,
			}})
			_, _ = w.Write(body)
		case strings.HasPrefix(r.URL.Path, "/v2/users/"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"details":{"sequence":"7","changeDate":"2026-01-01T00:00:00Z","resourceOwner":"1"},"uri":"otpauth://x","secret":"S"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func (u *userScopedUpstream) received(prefix string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, c := range u.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// userOnlyFactors is what Zitadel reports for a session created from a login name alone:
// the user factor is verified (the name resolved), nothing else is.
func userOnlyFactors(userID string) map[string]any {
	return map[string]any{
		"user": map[string]any{"verifiedAt": "2026-01-01T00:00:00Z", "id": userID, "loginName": "u@example.com"},
	}
}

func withVerified(factors map[string]any, name string) map[string]any {
	out := make(map[string]any, len(factors)+1)
	for k, v := range factors {
		out[k] = v
	}
	out[name] = map[string]any{"verifiedAt": "2026-01-01T00:00:01Z"}
	return out
}

// seedCookie returns the cookies the proxy writes for the given entries.
func seedCookie(t *testing.T, proxy *AuthProxy, entries []sessionEntry) []*http.Cookie {
	t.Helper()
	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, entries)
	return seed.Result().Cookies()
}

// userScopedWriteRoutes lists every user-scoped write the proxy exposes, with the handler
// and the extra URL params it reads. Keeping the list here, rather than in one test, is
// what makes a newly added write route fail the suite until it is covered.
var userScopedWriteRoutes = []struct {
	name    string
	handler func(*AuthProxy) gin.HandlerFunc
	params  gin.Params
}{
	{"totp", func(p *AuthProxy) gin.HandlerFunc { return p.RegisterTOTP }, nil},
	{"totp/verify", func(p *AuthProxy) gin.HandlerFunc { return p.VerifyTOTP }, nil},
	{"passkeys", func(p *AuthProxy) gin.HandlerFunc { return p.RegisterPasskey }, nil},
	{"passkeys/pk1", func(p *AuthProxy) gin.HandlerFunc { return p.VerifyPasskey }, gin.Params{{Key: "pkId", Value: "pk1"}}},
	{"u2f", func(p *AuthProxy) gin.HandlerFunc { return p.RegisterU2F }, nil},
	{"u2f/u1", func(p *AuthProxy) gin.HandlerFunc { return p.VerifyU2F }, gin.Params{{Key: "u2fId", Value: "u1"}}},
	{"otp-email", func(p *AuthProxy) gin.HandlerFunc { return p.EnableOTPEmail }, nil},
	{"otp-sms", func(p *AuthProxy) gin.HandlerFunc { return p.EnableOTPSMS }, nil},
}

func callUserScoped(proxy *AuthProxy, handler gin.HandlerFunc, method, userID, suffix string, extra gin.Params, cookies []*http.Cookie) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	target := "/auth/users/" + userID + "/" + suffix
	if method == http.MethodGet {
		c.Request = newTestRequest(method, target)
	} else {
		c.Request = newTestRequestWithBody(method, target, `{"code":"123456"}`)
	}
	c.Params = append(gin.Params{{Key: "id", Value: userID}}, extra...)
	for _, ck := range cookies {
		c.Request.AddCookie(ck)
	}
	handler(c)
	return w
}

func TestUserScopedProxy_WriteRefusesSessionThatOnlyNamedTheUser(t *testing.T) {
	for _, route := range userScopedWriteRoutes {
		t.Run(route.name, func(t *testing.T) {
			upstream := newUserScopedUpstream(userOnlyFactors("aaa"))
			server := httptest.NewServer(upstream.handler())
			defer server.Close()
			proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: server.URL, PAT: "pat"})
			cookies := seedCookie(t, proxy, []sessionEntry{{ID: "s1", Token: "t1", UserID: "aaa"}})

			w := callUserScoped(proxy, route.handler(proxy), http.MethodPost, "aaa", route.name, route.params, cookies)

			if w.Code != http.StatusForbidden {
				t.Fatalf("a session that has only named the user must be refused with 403, got %d: %s", w.Code, w.Body.String())
			}
			if upstream.received("POST /v2/users/") {
				t.Errorf("the write must not reach Zitadel on an unverified session")
			}
		})
	}
}

func TestUserScopedProxy_WriteAcceptsAnyVerifiedCredentialFactor(t *testing.T) {
	for _, factor := range []string{"password", "webAuthN", "intent", "totp", "otpSms", "otpEmail"} {
		t.Run(factor, func(t *testing.T) {
			upstream := newUserScopedUpstream(withVerified(userOnlyFactors("aaa"), factor))
			server := httptest.NewServer(upstream.handler())
			defer server.Close()
			proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: server.URL, PAT: "pat"})
			cookies := seedCookie(t, proxy, []sessionEntry{{ID: "s1", Token: "t1", UserID: "aaa"}})

			w := callUserScoped(proxy, proxy.RegisterTOTP, http.MethodPost, "aaa", "totp", nil, cookies)

			if w.Code != http.StatusOK {
				t.Fatalf("a session with a verified %s factor must be forwarded, got %d: %s", factor, w.Code, w.Body.String())
			}
			if !upstream.received("POST /v2/users/aaa/totp") {
				t.Errorf("the write must reach Zitadel once the session has proven a credential")
			}
			if !upstream.received("GET /v2/sessions/s1") {
				t.Errorf("the verdict must come from Zitadel's session resource, not from the cookie")
			}
		})
	}
}

// An empty verifiedAt is how Zitadel encodes "not verified" for a factor that is present
// in the response; it must count as nothing proven.
func TestUserScopedProxy_WriteRefusesFactorWithoutVerifiedAt(t *testing.T) {
	factors := userOnlyFactors("aaa")
	factors["password"] = map[string]any{}
	upstream := newUserScopedUpstream(factors)
	server := httptest.NewServer(upstream.handler())
	defer server.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: server.URL, PAT: "pat"})
	cookies := seedCookie(t, proxy, []sessionEntry{{ID: "s1", Token: "t1", UserID: "aaa"}})

	w := callUserScoped(proxy, proxy.RegisterTOTP, http.MethodPost, "aaa", "totp", nil, cookies)

	if w.Code != http.StatusForbidden {
		t.Fatalf("a password factor without verifiedAt proves nothing, want 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUserScopedProxy_WriteRefusedWhenZitadelNoLongerKnowsTheSession(t *testing.T) {
	upstream := newUserScopedUpstream(withVerified(userOnlyFactors("aaa"), "password"))
	upstream.sessionStatus = http.StatusNotFound
	server := httptest.NewServer(upstream.handler())
	defer server.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: server.URL, PAT: "pat"})
	cookies := seedCookie(t, proxy, []sessionEntry{{ID: "s1", Token: "t1", UserID: "aaa"}})

	w := callUserScoped(proxy, proxy.RegisterTOTP, http.MethodPost, "aaa", "totp", nil, cookies)

	if w.Code != http.StatusForbidden {
		t.Fatalf("a session Zitadel cannot return proves nothing, want 403, got %d: %s", w.Code, w.Body.String())
	}
	if upstream.received("POST /v2/users/") {
		t.Errorf("the write must not reach Zitadel")
	}
}

// A caller who signed in twice carries two sessions for the same user; the one that has
// proven a credential is enough, whichever position it holds in the cookie.
func TestUserScopedProxy_WriteAcceptsAnyVerifiedSessionBoundToTheUser(t *testing.T) {
	upstream := newUserScopedUpstream(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v2/sessions/unverified" {
			upstream.factors = userOnlyFactors("aaa")
		} else {
			upstream.factors = withVerified(userOnlyFactors("aaa"), "password")
		}
		upstream.handler()(w, r)
	}))
	defer server.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: server.URL, PAT: "pat"})
	cookies := seedCookie(t, proxy, []sessionEntry{
		{ID: "unverified", Token: "t1", UserID: "aaa"},
		{ID: "verified", Token: "t2", UserID: "aaa"},
	})

	w := callUserScoped(proxy, proxy.RegisterTOTP, http.MethodPost, "aaa", "totp", nil, cookies)

	if w.Code != http.StatusOK {
		t.Fatalf("the verified session must carry the write, got %d: %s", w.Code, w.Body.String())
	}
}

// userScopedReadRoutes lists the two self-reads. The login pages make them only after
// the password has been verified on the session (Password.tsx::checkForcedFlows runs
// after the password PATCH succeeded), so they are held to the same proof as the writes:
// the user record carries the profile, email, phone and state, which a caller who has
// only typed a login name must not see.
var userScopedReadRoutes = []struct {
	name    string
	handler func(*AuthProxy) gin.HandlerFunc
	suffix  string
}{
	{"authentication_methods", func(p *AuthProxy) gin.HandlerFunc { return p.ListAuthMethods }, "authentication_methods"},
	{"user record", func(p *AuthProxy) gin.HandlerFunc { return p.GetUserByID }, ""},
}

func TestUserScopedProxy_ReadRefusesSessionThatOnlyNamedTheUser(t *testing.T) {
	for _, read := range userScopedReadRoutes {
		t.Run(read.name, func(t *testing.T) {
			upstream := newUserScopedUpstream(userOnlyFactors("aaa"))
			server := httptest.NewServer(upstream.handler())
			defer server.Close()
			proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: server.URL, PAT: "pat"})
			cookies := seedCookie(t, proxy, []sessionEntry{{ID: "s1", Token: "t1", UserID: "aaa"}})

			w := callUserScoped(proxy, read.handler(proxy), http.MethodGet, "aaa", read.suffix, nil, cookies)

			if w.Code != http.StatusForbidden {
				t.Fatalf("a self-read on a session that only named the user must be refused with 403, got %d: %s", w.Code, w.Body.String())
			}
			if upstream.received("GET /v2/users/") {
				t.Errorf("the read must not reach Zitadel on an unverified session")
			}
		})
	}
}

func TestUserScopedProxy_ReadForwardsOnceACredentialIsVerified(t *testing.T) {
	for _, read := range userScopedReadRoutes {
		t.Run(read.name, func(t *testing.T) {
			upstream := newUserScopedUpstream(withVerified(userOnlyFactors("aaa"), "password"))
			server := httptest.NewServer(upstream.handler())
			defer server.Close()
			proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: server.URL, PAT: "pat"})
			cookies := seedCookie(t, proxy, []sessionEntry{{ID: "s1", Token: "t1", UserID: "aaa"}})

			w := callUserScoped(proxy, read.handler(proxy), http.MethodGet, "aaa", read.suffix, nil, cookies)

			if w.Code != http.StatusOK {
				t.Fatalf("a self-read after the password must forward, got %d: %s", w.Code, w.Body.String())
			}
			if !upstream.received("GET /v2/users/aaa") {
				t.Errorf("the read must reach Zitadel")
			}
		})
	}
}

// A decoy session (minted for a login name Zitadel does not know) can never have proven a
// credential, so a request on it is refused exactly like one on a real session that has
// proven nothing: same status, same body, for reads and writes alike. Any difference would
// tell a caller whether the login name exists.
func TestUserScopedProxy_DecoyIsIndistinguishableFromUnverifiedRealSession(t *testing.T) {
	upstream := newUserScopedUpstream(userOnlyFactors("aaa"))
	server := httptest.NewServer(upstream.handler())
	defer server.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: server.URL, PAT: "pat"})

	loginName := "ghost@example.com"
	decoyUserID := deriveDecoySnowflake(proxy.decoySecret, "user:"+loginName)
	decoyCookies := seedCookie(t, proxy, []sessionEntry{{ID: "111111111111111111", Token: "tok", LoginName: loginName, Decoy: true}})
	realCookies := seedCookie(t, proxy, []sessionEntry{{ID: "s1", Token: "t1", UserID: "aaa"}})

	for _, route := range userScopedWriteRoutes {
		t.Run(route.name, func(t *testing.T) {
			decoy := callUserScoped(proxy, route.handler(proxy), http.MethodPost, decoyUserID, route.name, route.params, decoyCookies)
			real := callUserScoped(proxy, route.handler(proxy), http.MethodPost, "aaa", route.name, route.params, realCookies)

			if decoy.Code != http.StatusForbidden {
				t.Fatalf("decoy write must be refused with 403, got %d: %s", decoy.Code, decoy.Body.String())
			}
			if decoy.Code != real.Code || decoy.Body.String() != real.Body.String() {
				t.Errorf("decoy and unverified-real refusals must match:\n decoy %d %s\n real  %d %s", decoy.Code, decoy.Body.String(), real.Code, real.Body.String())
			}
			if upstream.received("POST /v2/users/") {
				t.Errorf("neither write may reach Zitadel")
			}
		})
	}

	for _, read := range userScopedReadRoutes {
		t.Run("read "+read.name, func(t *testing.T) {
			decoy := callUserScoped(proxy, read.handler(proxy), http.MethodGet, decoyUserID, read.suffix, nil, decoyCookies)
			real := callUserScoped(proxy, read.handler(proxy), http.MethodGet, "aaa", read.suffix, nil, realCookies)

			if decoy.Code != http.StatusForbidden {
				t.Fatalf("decoy read must be refused with 403, got %d: %s", decoy.Code, decoy.Body.String())
			}
			if decoy.Code != real.Code || decoy.Body.String() != real.Body.String() {
				t.Errorf("decoy and unverified-real refusals must match:\n decoy %d %s\n real  %d %s", decoy.Code, decoy.Body.String(), real.Code, real.Body.String())
			}
			if upstream.received("GET /v2/users/") {
				t.Errorf("neither read may reach Zitadel")
			}
		})
	}
}

// --- ChangePassword: the request itself must carry proof ---

// changePassword posts the given raw body to POST /auth/users/:id/password with no cookie.
func changePassword(proxy *AuthProxy, userID, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/"+userID+"/password", body)
	c.Params = gin.Params{{Key: "id", Value: userID}}
	proxy.ChangePassword(c)
	return w
}

// Zitadel honours a password set that carries no verification when the caller holds the
// proxy's service token, so the proxy must refuse any body in which neither currentPassword
// nor verificationCode is a non-empty string. JSON null is "unset" to Zitadel and must count
// as absent; a body with both is a oneof violation Zitadel rejects before any lookup and is
// refused here for the same reason.
func TestChangePassword_RefusesBodyWithoutProof(t *testing.T) {
	const newPw = `"newPassword":{"password":"NewPass1!","changeRequired":false}`
	for _, tc := range []struct{ name, body string }{
		{"neither", `{` + newPw + `}`},
		{"empty currentPassword", `{"currentPassword":"",` + newPw + `}`},
		{"null currentPassword", `{"currentPassword":null,` + newPw + `}`},
		{"empty verificationCode", `{"verificationCode":"",` + newPw + `}`},
		{"null verificationCode", `{"verificationCode":null,` + newPw + `}`},
		{"non-string currentPassword", `{"currentPassword":12345,` + newPw + `}`},
		{"non-string verificationCode", `{"verificationCode":{"code":"x"},` + newPw + `}`},
		{"both present", `{"currentPassword":"old","verificationCode":"123456",` + newPw + `}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newUserScopedUpstream(nil)
			server := httptest.NewServer(upstream.handler())
			defer server.Close()
			proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: server.URL, PAT: "pat"})

			w := changePassword(proxy, "aaa", tc.body)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("a password change without proof must be refused with 400, got %d: %s", w.Code, w.Body.String())
			}
			if w.Body.String() != string(canonicalCodeInvalidResponse()) {
				t.Errorf("refusal must use the canonical code-invalid shape, got %s", w.Body.String())
			}
			if upstream.received("POST /v2/users/") {
				t.Errorf("a body without proof must never reach Zitadel")
			}
		})
	}
}

func TestChangePassword_ForwardsBodyThatCarriesProof(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"currentPassword", `{"currentPassword":"OldPass1!","newPassword":{"password":"NewPass1!","changeRequired":false}}`},
		{"verificationCode", `{"verificationCode":"123456","newPassword":{"password":"NewPass1!","changeRequired":false}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newUserScopedUpstream(nil)
			server := httptest.NewServer(upstream.handler())
			defer server.Close()
			proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: server.URL, PAT: "pat"})

			w := changePassword(proxy, "aaa", tc.body)

			if w.Code != http.StatusOK {
				t.Fatalf("a password change carrying %s must be forwarded for Zitadel to judge, got %d: %s", tc.name, w.Code, w.Body.String())
			}
			if !upstream.received("POST /v2/users/aaa/password") {
				t.Errorf("the change must reach Zitadel")
			}
		})
	}
}

// The refusal is decided before the user id is looked at, so by construction it cannot say
// whether the id exists; this pins that it also carries the same status and body the proxy
// gives an unknown user who did send proof, so a direct prober sees one shape either way.
func TestChangePassword_RefusalMatchesUnknownUserAnswer(t *testing.T) {
	unknownUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":5,"message":"Errors.User.NotFound (QUERY-3M9fs)"}`))
	}))
	defer unknownUpstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: unknownUpstream.URL, PAT: "pat"})

	unknown := changePassword(proxy, "111111111111111111", `{"verificationCode":"123456","newPassword":{"password":"NewPass1!"}}`)
	noProof := changePassword(proxy, "aaa", `{"newPassword":{"password":"NewPass1!"}}`)

	if unknown.Code != noProof.Code || unknown.Body.String() != noProof.Body.String() {
		t.Errorf("unknown-user and no-proof answers must match:\n unknown %d %s\n no proof %d %s", unknown.Code, unknown.Body.String(), noProof.Code, noProof.Body.String())
	}
}

// The forced second-factor enrollment flow: the password page has verified the password
// on the session, then sends the user to register a factor. The whole register and
// verify pair must go through.
func TestUserScopedProxy_ForcedSecondFactorSetupAfterPassword(t *testing.T) {
	upstream := newUserScopedUpstream(withVerified(userOnlyFactors("aaa"), "password"))
	server := httptest.NewServer(upstream.handler())
	defer server.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: server.URL, PAT: "pat"})
	cookies := seedCookie(t, proxy, []sessionEntry{{ID: "s1", Token: "t1", UserID: "aaa"}})

	if w := callUserScoped(proxy, proxy.RegisterTOTP, http.MethodPost, "aaa", "totp", nil, cookies); w.Code != http.StatusOK {
		t.Fatalf("register TOTP after password must succeed, got %d: %s", w.Code, w.Body.String())
	}
	if w := callUserScoped(proxy, proxy.VerifyTOTP, http.MethodPost, "aaa", "totp/verify", nil, cookies); w.Code != http.StatusOK {
		t.Fatalf("verify TOTP after password must succeed, got %d: %s", w.Code, w.Body.String())
	}
	if !upstream.received("POST /v2/users/aaa/totp/verify") {
		t.Errorf("the verify step must reach Zitadel")
	}
}
