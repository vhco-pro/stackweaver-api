// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// A user who has no way to sign in yet (an invited user, or one an administrator created without
// a password) sets a first password with no current password and no reset code. The proof is
// the email verification code the user has just entered in the same browser, the rule Zitadel's
// own login applies: a password may be set without a code only for a user with no authentication
// method, after a verification that this browser completed moments ago.

const (
	spNoMethods   = "395290139665891339" // exists, has no authentication method
	spHasPassword = "395290138306936843" // exists, has a password
	spRightCode   = "RIGHTCODE"
	spNewPassword = `{"newPassword":{"password":"NewPassword1!","changeRequired":false}}`
)

// setPasswordZitadel stands in for the Zitadel endpoints the flow touches and records what the
// proxy sent to SetPassword.
type setPasswordZitadel struct {
	mu        sync.Mutex
	passwords map[string][]map[string]any // user id -> SetPassword bodies received
	passkeys  map[string][]string         // user id -> "start" / "verify" calls received
	hasMethod map[string]bool
}

func newSetPasswordZitadel() *setPasswordZitadel {
	return &setPasswordZitadel{
		passwords: map[string][]map[string]any{},
		passkeys:  map[string][]string{},
		hasMethod: map[string]bool{spHasPassword: true},
	}
}

func (z *setPasswordZitadel) setCalls(userID string) []map[string]any {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.passwords[userID]
}

func (z *setPasswordZitadel) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		rest := strings.TrimPrefix(r.URL.Path, "/v2/users/")
		userID, sub, _ := strings.Cut(rest, "/")
		known := userID == spNoMethods || userID == spHasPassword
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		switch {
		case !known:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":5,"message":"User could not be found (QUERY-Dfbg2)","details":[]}`))
		case sub == "email/verify" && body["verificationCode"] == spRightCode:
			_, _ = w.Write([]byte(`{"details":{"sequence":"3","changeDate":"2026-10-16T00:00:00Z","resourceOwner":"1"}}`))
		case sub == "email/verify":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":3,"message":"Code is invalid (CODE-woT0xc)","details":[]}`))
		case sub == "invite_code/verify" && body["verificationCode"] == spRightInvite:
			_, _ = w.Write([]byte(`{"details":{"sequence":"4","changeDate":"2026-10-16T00:00:00Z","resourceOwner":"1"}}`))
		case sub == "invite_code/verify":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":3,"message":"Code is invalid (CODE-woT0xc)","details":[]}`))
		case sub == "passkeys":
			z.mu.Lock()
			z.passkeys[userID] = append(z.passkeys[userID], "start")
			z.mu.Unlock()
			_, _ = w.Write([]byte(`{"details":{},"passkeyId":"pk-1","publicKeyCredentialCreationOptions":{"publicKey":{"challenge":"Y2hhbGxlbmdl"}}}`))
		case strings.HasPrefix(sub, "passkeys/"):
			z.mu.Lock()
			z.passkeys[userID] = append(z.passkeys[userID], "verify")
			z.hasMethod[userID] = true
			z.mu.Unlock()
			_, _ = w.Write([]byte(`{"details":{"sequence":"10","changeDate":"2026-10-16T00:00:00Z","resourceOwner":"1"}}`))
		case sub == "authentication_methods" && r.Method == http.MethodGet:
			z.mu.Lock()
			has := z.hasMethod[userID]
			z.mu.Unlock()
			if has {
				_, _ = w.Write([]byte(`{"details":{"totalResult":"1"},"authMethodTypes":["AUTHENTICATION_METHOD_TYPE_PASSWORD"]}`))
				return
			}
			_, _ = w.Write([]byte(`{"details":{}}`))
		case sub == "password":
			z.mu.Lock()
			z.passwords[userID] = append(z.passwords[userID], body)
			z.hasMethod[userID] = true
			z.mu.Unlock()
			_, _ = w.Write([]byte(`{"details":{"sequence":"9","changeDate":"2026-10-16T00:00:00Z","resourceOwner":"1"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":5,"message":"not found","details":[]}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// spCall runs one proxy handler with the given cookies and returns the recorder.
func spCall(handler gin.HandlerFunc, path, userID, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, path, body)
	for _, ck := range cookies {
		c.Request.AddCookie(ck)
	}
	c.Params = gin.Params{{Key: "id", Value: userID}}
	handler(c)
	return w
}

func spVerify(proxy *AuthProxy, userID, code string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	return spCall(proxy.VerifyEmail, "/auth/users/"+userID+"/email", userID, `{"verificationCode":"`+code+`"}`, cookies)
}

func spSet(proxy *AuthProxy, userID, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	return spCall(proxy.ChangePassword, "/auth/users/"+userID+"/password", userID, body, cookies)
}

// verificationCheckCookie is the cookie a browser would send back after a verification.
func verificationCheckCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name: VerificationCheckCookieName, Value: value,
		Path: verificationCheckPath, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
}

// liveCookies returns the cookies a response sets that a browser would keep.
func liveCookies(w *httptest.ResponseRecorder) []*http.Cookie {
	var out []*http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.MaxAge >= 0 && ck.Value != "" {
			out = append(out, ck)
		}
	}
	return out
}

func TestSetPassword_VerifiedUserWithoutMethodsSetsFirstPassword(t *testing.T) {
	zitadel := newSetPasswordZitadel()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: zitadel.server(t).URL, PAT: "pat"})

	verified := spVerify(proxy, spNoMethods, spRightCode, nil)
	if verified.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200 (%s)", verified.Code, verified.Body.String())
	}
	var answer struct {
		AuthenticatorSetupRequired bool `json:"authenticatorSetupRequired"`
	}
	if err := json.Unmarshal(verified.Body.Bytes(), &answer); err != nil {
		t.Fatalf("verify answer must be JSON: %v", err)
	}
	if !answer.AuthenticatorSetupRequired {
		t.Errorf("verify must tell the login a user without authentication methods sets one up next: %s", verified.Body.String())
	}

	set := spSet(proxy, spNoMethods, spNewPassword, liveCookies(verified))
	if set.Code != http.StatusOK {
		t.Fatalf("setting a first password after verification = %d, want 200 (%s)", set.Code, set.Body.String())
	}
	calls := zitadel.setCalls(spNoMethods)
	if len(calls) != 1 {
		t.Fatalf("Zitadel received %d password set(s), want 1", len(calls))
	}
	for key := range calls[0] {
		if key != "newPassword" {
			t.Errorf("the forwarded body carries %q; only newPassword may be forwarded", key)
		}
	}

	// The check is spent: the same browser cannot set a password again on it.
	again := spSet(proxy, spNoMethods, spNewPassword, append(liveCookies(verified), liveCookies(set)...))
	if again.Code != http.StatusBadRequest || len(zitadel.setCalls(spNoMethods)) != 1 {
		t.Errorf("a second set on the same verification = %d with %d calls, want 400 and no new call", again.Code, len(zitadel.setCalls(spNoMethods)))
	}
}

// Every way of asking without the verification that belongs to this user, or for a user who
// already has a way to sign in, gets the refusal a body without proof has always had, and
// nothing reaches Zitadel.
func TestSetPassword_RefusedWithoutTheUsersOwnFreshVerification(t *testing.T) {
	zitadel := newSetPasswordZitadel()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: zitadel.server(t).URL, PAT: "pat"})
	now := time.Now()

	otherUsersCheck := liveCookies(spVerify(proxy, spNoMethods, spRightCode, nil))
	wrongCode := spVerify(proxy, spNoMethods, "WRONG", nil)
	if wrongCode.Code != http.StatusBadRequest || len(liveCookies(wrongCode)) != 0 {
		t.Fatalf("a wrong code must be refused and record nothing: %d %v", wrongCode.Code, wrongCode.Result().Cookies())
	}
	hasPassword := spVerify(proxy, spHasPassword, spRightCode, nil)
	if len(liveCookies(hasPassword)) != 0 || strings.Contains(hasPassword.Body.String(), "authenticatorSetupRequired") {
		t.Fatalf("verifying a user who has a password must record nothing: %v %s", hasPassword.Result().Cookies(), hasPassword.Body.String())
	}
	check := func(userID string, expires time.Time) []*http.Cookie {
		return []*http.Cookie{verificationCheckCookie(proxy.verificationCheckValue(userID, expires))}
	}
	tampered := []*http.Cookie{verificationCheckCookie(strings.Replace(
		proxy.verificationCheckValue(spNoMethods, now.Add(time.Minute)), spNoMethods, spHasPassword, 1))}

	cases := []struct {
		name    string
		userID  string
		cookies []*http.Cookie
	}{
		{"no verification", spNoMethods, nil},
		{"verification of another user", spHasPassword, otherUsersCheck},
		{"user who has a password", spHasPassword, check(spHasPassword, now.Add(time.Minute))},
		{"expired verification", spNoMethods, check(spNoMethods, now.Add(-time.Second))},
		{"tampered verification", spHasPassword, tampered},
		{"unknown user", "999999999999999999", check("999999999999999999", now.Add(time.Minute))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := spSet(proxy, tc.userID, spNewPassword, tc.cookies)
			if w.Code != http.StatusBadRequest || w.Body.String() != string(canonicalCodeInvalidResponse()) {
				t.Errorf("= %d %s, want the canonical refusal", w.Code, w.Body.String())
			}
		})
	}
	for _, id := range []string{spNoMethods, spHasPassword, "999999999999999999"} {
		if n := len(zitadel.setCalls(id)); n != 0 {
			t.Errorf("Zitadel received %d password set(s) for %s, want 0", n, id)
		}
	}
}

// A user with a password keeps needing the current password or a reset code, with or without
// a verification in the browser.
func TestSetPassword_ProofStillRequiredForUsersWithAPassword(t *testing.T) {
	zitadel := newSetPasswordZitadel()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: zitadel.server(t).URL, PAT: "pat"})
	cookies := []*http.Cookie{verificationCheckCookie(proxy.verificationCheckValue(spHasPassword, time.Now().Add(time.Minute)))}

	for _, body := range []string{
		spNewPassword,
		`{"currentPassword":"","newPassword":{"password":"NewPassword1!"}}`,
		`{"currentPassword":"old","verificationCode":"123456","newPassword":{"password":"NewPassword1!"}}`,
	} {
		if w := spSet(proxy, spHasPassword, body, cookies); w.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", body, w.Code)
		}
	}
	if n := len(zitadel.setCalls(spHasPassword)); n != 0 {
		t.Errorf("Zitadel received %d password set(s), want 0", n)
	}
}
