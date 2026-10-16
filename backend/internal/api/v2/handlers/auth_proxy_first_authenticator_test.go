// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// A user with no authentication method may register a first passkey on the same proof as a first
// password: a fresh verification check for that user, issued by an email or invite verification
// this browser completed. Registering and verifying a passkey otherwise needs a session that has
// proven a credential, which such a user cannot have.

func (z *setPasswordZitadel) passkeyCalls(userID string) []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.passkeys[userID]
}

func spCallParams(handler gin.HandlerFunc, path, body string, params gin.Params, cookies []*http.Cookie) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, path, body)
	for _, ck := range cookies {
		c.Request.AddCookie(ck)
	}
	c.Params = params
	handler(c)
	return w
}

func spRegisterPasskey(proxy *AuthProxy, userID string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	return spCallParams(proxy.RegisterPasskey, "/auth/users/"+userID+"/passkeys", `{"domain":"localhost"}`,
		gin.Params{{Key: "id", Value: userID}}, cookies)
}

func spVerifyPasskey(proxy *AuthProxy, userID string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	return spCallParams(proxy.VerifyPasskey, "/auth/users/"+userID+"/passkeys/pk-1",
		`{"publicKeyCredential":{"type":"public-key","id":"x"},"passkeyName":"Passkey"}`,
		gin.Params{{Key: "id", Value: userID}, {Key: "pkId", Value: "pk-1"}}, cookies)
}

func TestFirstPasskey_VerifiedUserWithoutMethodsRegistersOne(t *testing.T) {
	zitadel := newSetPasswordZitadel()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: zitadel.server(t).URL, PAT: "pat"})

	check := liveCookies(spVerify(proxy, spNoMethods, spRightCode, nil))
	if len(check) == 0 {
		t.Fatalf("verifying the email recorded no verification check")
	}
	start := spRegisterPasskey(proxy, spNoMethods, check)
	if start.Code != http.StatusOK {
		t.Fatalf("starting a first passkey registration = %d, want 200 (%s)", start.Code, start.Body.String())
	}
	verify := spVerifyPasskey(proxy, spNoMethods, check)
	if verify.Code != http.StatusOK {
		t.Fatalf("finishing a first passkey registration = %d, want 200 (%s)", verify.Code, verify.Body.String())
	}
	if got := zitadel.passkeyCalls(spNoMethods); len(got) != 2 {
		t.Fatalf("Zitadel received %v, want a start and a verify", got)
	}
	// The check is spent once the passkey is registered.
	cleared := false
	for _, ck := range verify.Result().Cookies() {
		if ck.Name == VerificationCheckCookieName && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("finishing the registration must clear the verification check")
	}
}

// The session gate still applies to everyone else, and nothing reaches Zitadel.
func TestFirstPasskey_RefusedWithoutTheUsersOwnFreshVerification(t *testing.T) {
	zitadel := newSetPasswordZitadel()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: zitadel.server(t).URL, PAT: "pat"})
	now := time.Now()
	check := func(userID string, expires time.Time) []*http.Cookie {
		return []*http.Cookie{verificationCheckCookie(proxy.verificationCheckValue(userID, expires))}
	}
	otherUsers := liveCookies(spVerify(proxy, spNoMethods, spRightCode, nil))

	for _, tc := range []struct {
		name    string
		userID  string
		cookies []*http.Cookie
	}{
		{"no verification", spNoMethods, nil},
		{"verification of another user", spHasPassword, otherUsers},
		{"user who has a method", spHasPassword, check(spHasPassword, now.Add(time.Minute))},
		{"expired verification", spNoMethods, check(spNoMethods, now.Add(-time.Second))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := spRegisterPasskey(proxy, tc.userID, tc.cookies); w.Code != http.StatusForbidden {
				t.Errorf("start = %d, want the session gate's 403 (%s)", w.Code, w.Body.String())
			}
			if w := spVerifyPasskey(proxy, tc.userID, tc.cookies); w.Code != http.StatusForbidden {
				t.Errorf("verify = %d, want the session gate's 403 (%s)", w.Code, w.Body.String())
			}
		})
	}
	for _, id := range []string{spNoMethods, spHasPassword} {
		if got := zitadel.passkeyCalls(id); len(got) != 0 {
			t.Errorf("Zitadel received %v for %s, want nothing", got, id)
		}
	}
}
