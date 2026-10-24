// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// finalizeZitadel is a stand-in for the Zitadel endpoints FinalizeAuthRequest consults: the
// session, the user's login settings and authentication methods, and the auth-request callback.
type finalizeZitadel struct {
	session      map[string]any
	sessionCode  int
	forceMfa     bool
	forceMfaLocl bool
	methods      []string
	finalized    bool
	finalizePath string
}

func (z *finalizeZitadel) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/sessions/"):
			if z.sessionCode != 0 && z.sessionCode != http.StatusOK {
				w.WriteHeader(z.sessionCode)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"session": z.session})
		case r.Method == http.MethodGet && r.URL.Path == "/v2/settings/login":
			_ = json.NewEncoder(w).Encode(map[string]any{"settings": map[string]any{
				"forceMfa": z.forceMfa, "forceMfaLocalOnly": z.forceMfaLocl,
			}})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/authentication_methods"):
			_ = json.NewEncoder(w).Encode(map[string]any{"authMethodTypes": z.methods})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v2/oidc/auth_requests/"):
			z.finalized = true
			z.finalizePath = r.URL.EscapedPath()
			_, _ = w.Write([]byte(`{"callbackUrl":"https://app.example/auth/callback?code=c&state=s"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const verified = "2026-10-24T08:00:00Z"

// factorsSession builds a session body with a user factor plus the named verified factors.
// "passkey" is a user-verified WebAuthn factor; "u2f" is a presence-only one.
func factorsSession(names ...string) map[string]any {
	factors := map[string]any{
		"user": map[string]any{"verifiedAt": verified, "id": "user-1", "organizationId": "org-1"},
	}
	for _, n := range names {
		switch n {
		case "password", "intent", "totp", "otpSms", "otpEmail":
			factors[n] = map[string]any{"verifiedAt": verified}
		case "passkey":
			factors["webAuthN"] = map[string]any{"verifiedAt": verified, "userVerified": true}
		case "u2f":
			factors["webAuthN"] = map[string]any{"verifiedAt": verified, "userVerified": false}
		}
	}
	return map[string]any{"id": "sess-1", "factors": factors}
}

func runFinalize(t *testing.T, z *finalizeZitadel) *httptest.ResponseRecorder {
	t.Helper()
	srv := z.serve(t)
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "pat"})
	t.Cleanup(proxy.StopDecoyOrgIDsSweeper)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/oidc/finalize",
		`{"authRequestId":"oidc_abc","sessionId":"sess-1","sessionToken":"tok"}`)
	proxy.FinalizeAuthRequest(c)
	return w
}

// A sign-in may finish only on a session that verified a primary credential and, when the user
// has a second factor enrolled or the login policy forces one, a second factor. Zitadel leaves
// this check to the login client, so the proxy makes it before forwarding.
func TestFinalizeAuthRequest_RequiresAnAuthenticatedSession(t *testing.T) {
	cases := []struct {
		name    string
		z       finalizeZitadel
		allowed bool
	}{
		{name: "login name only", z: finalizeZitadel{session: factorsSession()}},
		{name: "presence-only security key alone", z: finalizeZitadel{session: factorsSession("u2f")}},
		{name: "one-time code alone", z: finalizeZitadel{session: factorsSession("totp")}},
		{name: "password, nothing enrolled", z: finalizeZitadel{session: factorsSession("password")}, allowed: true},
		{name: "passkey", z: finalizeZitadel{session: factorsSession("passkey")}, allowed: true},
		{name: "identity provider", z: finalizeZitadel{session: factorsSession("intent")}, allowed: true},
		{name: "password with an enrolled TOTP left unverified", z: finalizeZitadel{session: factorsSession("password"), methods: []string{"AUTHENTICATION_METHOD_TYPE_PASSWORD", "AUTHENTICATION_METHOD_TYPE_TOTP"}}},
		{name: "password and the enrolled TOTP", z: finalizeZitadel{session: factorsSession("password", "totp"), methods: []string{"AUTHENTICATION_METHOD_TYPE_PASSWORD", "AUTHENTICATION_METHOD_TYPE_TOTP"}}, allowed: true},
		{name: "password and a code of a kind not enrolled", z: finalizeZitadel{session: factorsSession("password", "otpEmail"), methods: []string{"AUTHENTICATION_METHOD_TYPE_TOTP"}}},
		{name: "password and the enrolled security key", z: finalizeZitadel{session: factorsSession("password", "u2f"), methods: []string{"AUTHENTICATION_METHOD_TYPE_U2F"}}, allowed: true},
		{name: "passkey with an enrolled TOTP", z: finalizeZitadel{session: factorsSession("passkey"), methods: []string{"AUTHENTICATION_METHOD_TYPE_TOTP"}}, allowed: true},
		{name: "password under forced MFA without a second factor", z: finalizeZitadel{session: factorsSession("password"), forceMfa: true}},
		{name: "password under forced MFA with a code", z: finalizeZitadel{session: factorsSession("password", "otpEmail"), forceMfa: true}, allowed: true},
		{name: "identity provider under forced MFA without a second factor", z: finalizeZitadel{session: factorsSession("intent"), forceMfa: true}},
		{name: "identity provider under local-only MFA", z: finalizeZitadel{session: factorsSession("intent"), forceMfaLocl: true}, allowed: true},
		{name: "password under local-only MFA without a second factor", z: finalizeZitadel{session: factorsSession("password"), forceMfaLocl: true}},
		{name: "expired session", z: finalizeZitadel{session: func() map[string]any {
			s := factorsSession("password")
			s["expirationDate"] = "2020-01-01T00:00:00Z"
			return s
		}()}},
		{name: "session not found", z: finalizeZitadel{sessionCode: http.StatusNotFound}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z := tc.z
			w := runFinalize(t, &z)
			if tc.allowed {
				if w.Code != http.StatusOK || !z.finalized {
					t.Fatalf("want the auth request finalized (200), got %d finalized=%v: %s", w.Code, z.finalized, w.Body.String())
				}
				return
			}
			if z.finalized {
				t.Fatalf("the auth request must not reach Zitadel's finalize")
			}
			if w.Code != http.StatusPreconditionFailed {
				t.Fatalf("want 412 (the precondition shape a decoy session gets), got %d: %s", w.Code, w.Body.String())
			}
			if w.Body.String() != string(buildDecoyFinalizePreconditionResponse()) {
				t.Errorf("a refused session must answer exactly like a decoy session, got %s", w.Body.String())
			}
		})
	}
}

// The auth request id is a single path segment at Zitadel: a value carrying slashes or dot
// segments cannot steer the service-token call to another endpoint.
func TestFinalizeAuthRequest_EscapesTheAuthRequestID(t *testing.T) {
	z := &finalizeZitadel{session: factorsSession("password")}
	srv := z.serve(t)
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "pat"})
	t.Cleanup(proxy.StopDecoyOrgIDsSweeper)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/oidc/finalize",
		`{"authRequestId":"x/../../users/u1","sessionId":"sess-1","sessionToken":"tok"}`)
	proxy.FinalizeAuthRequest(c)

	if want := "/v2/oidc/auth_requests/x%2F..%2F..%2Fusers%2Fu1"; z.finalizePath != want {
		t.Fatalf("finalize path = %q, want %q", z.finalizePath, want)
	}
}
