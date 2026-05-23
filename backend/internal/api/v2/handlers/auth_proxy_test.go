// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// newTestRequest creates an http.Request with context.Background() for test use.
func newTestRequest(method, target string) *http.Request {
	req, _ := http.NewRequestWithContext(context.Background(), method, target, nil)
	return req
}

func init() {
	gin.SetMode(gin.TestMode)
}

// --- parseCustomHeaders tests ---

func TestParseCustomHeaders_Empty(t *testing.T) {
	result := parseCustomHeaders("")
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
}

func TestParseCustomHeaders_Single(t *testing.T) {
	result := parseCustomHeaders("x-zitadel-instance-host:localhost:8080")
	if v, ok := result["x-zitadel-instance-host"]; !ok || v != "localhost:8080" {
		t.Errorf("expected x-zitadel-instance-host=localhost:8080, got %v", result)
	}
}

func TestParseCustomHeaders_Multiple(t *testing.T) {
	result := parseCustomHeaders("x-zitadel-instance-host:foo, x-other:bar")
	if len(result) != 2 {
		t.Errorf("expected 2 headers, got %d", len(result))
	}
	if result["x-zitadel-instance-host"] != "foo" {
		t.Errorf("expected foo, got %s", result["x-zitadel-instance-host"])
	}
	if result["x-other"] != "bar" {
		t.Errorf("expected bar, got %s", result["x-other"])
	}
}

func TestParseCustomHeaders_TrailingComma(t *testing.T) {
	result := parseCustomHeaders("x-foo:bar,")
	if len(result) != 1 {
		t.Errorf("expected 1 header, got %d: %v", len(result), result)
	}
}

// TestParseCustomHeaders_RejectsCRLF asserts that header names/values
// containing CR, LF or NUL bytes are dropped rather than silently passed
// through to outbound requests. Defense-in-depth against header-injection
// if the CUSTOM_REQUEST_HEADERS env var is ever tainted.
func TestParseCustomHeaders_RejectsCRLF(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"CR in value", "x-foo:bar\rX-Evil: injected"},
		{"LF in value", "x-foo:bar\nX-Evil: injected"},
		{"CRLF in value", "x-foo:bar\r\nX-Evil: injected"},
		{"NUL in value", "x-foo:bar\x00baz"},
		{"CR in name", "x-\rfoo:bar"},
		{"LF in name", "x-\nfoo:bar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseCustomHeaders(tc.input)
			for k, v := range result {
				if strings.ContainsAny(k, "\r\n\x00") || strings.ContainsAny(v, "\r\n\x00") {
					t.Errorf("control characters survived parse: %q -> %q", k, v)
				}
			}
		})
	}
}

// --- Session cookie FIFO eviction tests ---

func TestSessionCookieFIFOEviction(t *testing.T) {
	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: "http://localhost:8080",
		PAT:                "test-pat",
		IsProduction:       false,
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/")

	// Create entries that will exceed the 2KB limit
	var entries []sessionEntry
	for i := range 20 {
		entries = append(entries, sessionEntry{
			ID:           strings.Repeat("a", 50) + string(rune('0'+i%10)),
			Token:        strings.Repeat("t", 100),
			LoginName:    "user@example.com",
			Organization: "org-" + string(rune('0'+i%10)),
		})
	}

	proxy.writeSessionCookie(c, entries)

	// Verify the cookie was set and is within size limit
	cookies := w.Result().Cookies()
	found := false
	for _, cookie := range cookies {
		if cookie.Name == SessionCookieName {
			found = true
			// Cookie values are URL-encoded by Gin
			decoded, err := url.QueryUnescape(cookie.Value)
			if err != nil {
				t.Fatalf("failed to URL-decode cookie: %v", err)
			}
			// Round 25 Wave 6 (item 19 / R25a #3): the cookie format is
			// `<base64url-hmac>.<json>`. Strip the HMAC prefix before
			// JSON-decoding.
			payload, ok := proxy.verifySessionCookie(decoded)
			if !ok {
				t.Fatalf("cookie failed HMAC verification: %s", decoded)
			}
			// Verify we can parse it back
			var parsed []sessionEntry
			if err := json.Unmarshal(payload, &parsed); err != nil {
				t.Fatalf("failed to parse cookie: %v", err)
			}
			if len(parsed) == 0 {
				t.Error("expected at least one session entry after eviction")
			}
			// Verify FIFO: the last entries should survive (oldest evicted first)
			lastParsed := parsed[len(parsed)-1]
			lastOriginal := entries[len(entries)-1]
			if lastParsed.ID != lastOriginal.ID {
				t.Errorf("FIFO violated: last entry should be %s, got %s", lastOriginal.ID, lastParsed.ID)
			}
			break
		}
	}
	if !found {
		t.Error("sessions cookie not found in response")
	}
}

// TestSessionCookieFIFOBudget_EncodedSize pins the Round-16 invariant:
// the budget guardrail must be measured against the URL-encoded cookie
// value, not the raw JSON. Gin's `c.SetCookie` runs `url.QueryEscape`
// on the value, which inflates JSON by ~25% (every `"`, `,`, `{`, `}`,
// etc. becomes `%XX`). Pre-fix, a 30-entry cookie passed the in-Go
// `len(json) <= 2048` check at ~2000 bytes but went out the wire as
// ~2468 bytes. F-sec-19 caught it on the tunnel.
func TestSessionCookieFIFOBudget_EncodedSize(t *testing.T) {
	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: "http://localhost:8080",
		PAT:                "test-pat",
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/")

	// 30 entries with realistic-ish sizing (Zitadel session ids are ~18
	// digits, session tokens are ~70-char base64). Way more than fits
	// in 2 KB encoded.
	var entries []sessionEntry
	for i := range 30 {
		entries = append(entries, sessionEntry{
			ID:           strings.Repeat("a", 18) + string(rune('0'+i%10)),
			Token:        strings.Repeat("t", 70),
			LoginName:    "user@example.com",
			Organization: "org-1",
		})
	}

	proxy.writeSessionCookie(c, entries)

	cookies := w.Result().Cookies()
	var sessionsCookie *http.Cookie
	for _, ck := range cookies {
		if ck.Name == SessionCookieName {
			sessionsCookie = ck
			break
		}
	}
	if sessionsCookie == nil {
		t.Fatal("sessions cookie not set")
	}

	// `cookie.Value` here is the post-URL-encoded value Gin emits to
	// the wire. The budget check must hold against THIS, not against
	// the JSON we'd see post-URL-decode.
	if encodedLen := len(sessionsCookie.Value); encodedLen > SessionCookieMaxBytes {
		t.Errorf("encoded cookie size %d exceeds budget %d", encodedLen, SessionCookieMaxBytes)
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: "http://localhost:8080",
		PAT:                "test-pat",
		IsProduction:       true,
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/")

	entries := []sessionEntry{{ID: "test-id", Token: "test-token"}}
	proxy.writeSessionCookie(c, entries)

	cookies := w.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == SessionCookieName {
			if !cookie.HttpOnly {
				t.Error("expected httpOnly flag")
			}
			if !cookie.Secure {
				t.Error("expected Secure flag in production mode")
			}
			if cookie.SameSite != http.SameSiteLaxMode {
				t.Errorf("expected SameSite=Lax, got %v", cookie.SameSite)
			}
			if cookie.MaxAge != 0 {
				t.Errorf("expected session-only (MaxAge=0), got %d", cookie.MaxAge)
			}
			return
		}
	}
	t.Error("sessions cookie not found")
}

func TestSessionCookieNotSecureInDev(t *testing.T) {
	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: "http://localhost:8080",
		PAT:                "test-pat",
		IsProduction:       false,
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/")

	entries := []sessionEntry{{ID: "test-id", Token: "test-token"}}
	proxy.writeSessionCookie(c, entries)

	cookies := w.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == SessionCookieName {
			if cookie.Secure {
				t.Error("expected Secure flag OFF in dev mode")
			}
			return
		}
	}
	t.Error("sessions cookie not found")
}

// --- getPublicHost tests ---

func TestGetPublicHost_ZitadelPublicHost(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/")
	c.Request.Header.Set("X-Zitadel-Public-Host", "public.example.com")
	c.Request.Header.Set("X-Forwarded-Host", "forwarded.example.com")
	c.Request.Host = "host.example.com"

	host := getPublicHost(c)
	if host != "public.example.com" {
		t.Errorf("expected public.example.com, got %s", host)
	}
}

func TestGetPublicHost_ForwardHost(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/")
	c.Request.Header.Set("X-Zitadel-Forward-Host", "forward.example.com")
	c.Request.Host = "host.example.com"

	host := getPublicHost(c)
	if host != "forward.example.com" {
		t.Errorf("expected forward.example.com, got %s", host)
	}
}

func TestGetPublicHost_XForwardedHost(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/")
	c.Request.Header.Set("X-Forwarded-Host", "xfwd.example.com")
	c.Request.Host = "host.example.com"

	host := getPublicHost(c)
	if host != "xfwd.example.com" {
		t.Errorf("expected xfwd.example.com, got %s", host)
	}
}

func TestGetPublicHost_FallbackToHost(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/")
	c.Request.Host = "fallback.example.com"

	host := getPublicHost(c)
	if host != "fallback.example.com" {
		t.Errorf("expected fallback.example.com, got %s", host)
	}
}

// --- getPublicBaseURL tests ---
//
// Behind a TLS-terminating reverse proxy (Cloudflare Tunnel, k8s ingress,
// nginx) the api receives an http connection but the browser-visible URL
// is https. `X-Forwarded-Proto` is the source of truth in that layout —
// the previous "scheme = http unless TLS" rule mis-built the discovery
// doc + IdP success URLs as http://… and the SPA redirect chain broke.

func TestGetPublicBaseURL_PrefersForwardedProtoHTTPS(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/")
	// Plain http to the api, https at the edge.
	c.Request.Header.Set("X-Forwarded-Proto", "https")
	c.Request.Host = "stackweaver.vhco.pro"

	got := getPublicBaseURL(c)
	if got != "https://stackweaver.vhco.pro" {
		t.Errorf("expected https://stackweaver.vhco.pro, got %s", got)
	}
}

func TestGetPublicBaseURL_HonorsForwardedProtoHTTP(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/")
	c.Request.Header.Set("X-Forwarded-Proto", "http")
	c.Request.Host = "internal.example.com"

	got := getPublicBaseURL(c)
	if got != "http://internal.example.com" {
		t.Errorf("expected http://internal.example.com, got %s", got)
	}
}

func TestGetPublicBaseURL_FallsBackToTLSDetection(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/")
	// No X-Forwarded-Proto, no TLS on the request → must default to http.
	c.Request.Host = "localhost:8022"

	got := getPublicBaseURL(c)
	if got != "http://localhost:8022" {
		t.Errorf("expected http://localhost:8022, got %s", got)
	}
}

// --- getFrontendBaseURL tests ---
//
// IdP success/failure URLs land on the SPA, not the api. In split-domain
// deployments (api on api.example.com, SPA on app.example.com) using the
// api's own host produces a 404 — the SPA route doesn't exist there.
// PublicFrontendURL gives operators an explicit override; same-origin
// deployments (network_mode: host on a single localhost) leave it unset
// and fall through to the request-derived host.

func TestGetFrontendBaseURL_PrefersConfiguredURL(t *testing.T) {
	proxy := NewAuthProxy(AuthProxyConfig{PublicFrontendURL: "https://app.example.com"})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodPost, "/auth/idp/start")
	// Request-derived host should be IGNORED when PublicFrontendURL is set,
	// otherwise an api on api.example.com would still redirect IdP success
	// onto api.example.com instead of app.example.com.
	c.Request.Header.Set("X-Forwarded-Proto", "https")
	c.Request.Host = "api.example.com"

	got := proxy.getFrontendBaseURL(c)
	if got != "https://app.example.com" {
		t.Errorf("expected https://app.example.com, got %s", got)
	}
}

func TestGetFrontendBaseURL_StripsTrailingSlash(t *testing.T) {
	// Operators sometimes copy URLs with trailing slashes from browsers; the
	// helper concatenates with `/login/idp/...` so a stray slash would
	// produce `//login/idp/...`. Strip once at read time.
	proxy := NewAuthProxy(AuthProxyConfig{PublicFrontendURL: "https://app.example.com/"})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodPost, "/auth/idp/start")

	got := proxy.getFrontendBaseURL(c)
	if got != "https://app.example.com" {
		t.Errorf("expected https://app.example.com, got %s", got)
	}
}

func TestGetFrontendBaseURL_FallsBackToRequestHost(t *testing.T) {
	// Same-origin deployment: PublicFrontendURL unset → use the request host
	// (matches pre-fix behavior so existing compose-localhost setups don't
	// require any new env var).
	proxy := NewAuthProxy(AuthProxyConfig{})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodPost, "/auth/idp/start")
	c.Request.Header.Set("X-Forwarded-Proto", "https")
	c.Request.Host = "stackweaver.example.com"

	got := proxy.getFrontendBaseURL(c)
	if got != "https://stackweaver.example.com" {
		t.Errorf("expected https://stackweaver.example.com, got %s", got)
	}
}

// --- returnCode mode translation tests ---

func TestInjectReturnCodeFlags_OTPEmail(t *testing.T) {
	proxy := NewAuthProxy(AuthProxyConfig{
		NotificationMode: NotificationModeReturnCode,
	})

	body := map[string]any{
		"challenges": map[string]any{
			"otpEmail": map[string]any{},
		},
	}
	proxy.injectReturnCodeFlags(body)

	// Wave 14: Zitadel v4 expects returnCode as an empty message
	// (`{}`) rather than a boolean — see injectReturnCodeFlags for
	// the rationale. The shape ON THE WIRE is `{"returnCode": {}}`.
	challenges := body["challenges"].(map[string]any)
	otpEmail := challenges["otpEmail"].(map[string]any)
	rc, ok := otpEmail["returnCode"].(map[string]any)
	if !ok {
		t.Errorf("expected returnCode: {} (empty message) on otpEmail, got %v", otpEmail)
	}
	if len(rc) != 0 {
		t.Errorf("returnCode message must be empty `{}`; got %v", rc)
	}
}

func TestInjectReturnCodeFlags_OTPSms(t *testing.T) {
	proxy := NewAuthProxy(AuthProxyConfig{
		NotificationMode: NotificationModeReturnCode,
	})

	body := map[string]any{
		"challenges": map[string]any{
			"otpSms": map[string]any{},
		},
	}
	proxy.injectReturnCodeFlags(body)

	challenges := body["challenges"].(map[string]any)
	otpSms := challenges["otpSms"].(map[string]any)
	rc, ok := otpSms["returnCode"].(map[string]any)
	if !ok {
		t.Errorf("expected returnCode: {} (empty message) on otpSms, got %v", otpSms)
	}
	if len(rc) != 0 {
		t.Errorf("returnCode message must be empty `{}`; got %v", rc)
	}
}

func TestInjectReturnCodeFlags_NoChallenges(t *testing.T) {
	proxy := NewAuthProxy(AuthProxyConfig{
		NotificationMode: NotificationModeReturnCode,
	})

	body := map[string]any{
		"checks": map[string]any{"user": map[string]any{"loginName": "test"}},
	}
	// Should not panic
	proxy.injectReturnCodeFlags(body)
}

// --- Prefix dispatch tests (A2.1) ---

func TestAuthorize_RejectsSAMLPrefix(t *testing.T) {
	// Create a mock Zitadel server that returns a redirect with a saml_ auth request
	mockZitadel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://localhost:5173/login?authRequest=saml_test123")
		w.WriteHeader(http.StatusFound)
	}))
	defer mockZitadel.Close()

	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: mockZitadel.URL,
		PAT:                "test-pat",
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/oidc/authorize?client_id=test")

	proxy.Authorize(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for SAML prefix, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "SAML") {
		t.Errorf("expected SAML error message, got %s", w.Body.String())
	}
}

func TestAuthorize_RejectsDevicePrefix(t *testing.T) {
	mockZitadel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://localhost:5173/login?authRequest=device_test123")
		w.WriteHeader(http.StatusFound)
	}))
	defer mockZitadel.Close()

	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: mockZitadel.URL,
		PAT:                "test-pat",
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/oidc/authorize?client_id=test")

	proxy.Authorize(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for device prefix, got %d", w.Code)
	}
}

func TestAuthorize_AcceptsOIDCPrefix(t *testing.T) {
	mockZitadel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://localhost:5173/login?authRequest=oidc_test123")
		w.WriteHeader(http.StatusFound)
	}))
	defer mockZitadel.Close()

	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: mockZitadel.URL,
		PAT:                "test-pat",
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/oidc/authorize?client_id=test&login_hint=user@test.com")

	proxy.Authorize(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["authRequest"] != "oidc_test123" {
		t.Errorf("expected authRequest=oidc_test123, got %v", resp["authRequest"])
	}
	if resp["loginHint"] != "user@test.com" {
		t.Errorf("expected loginHint=user@test.com, got %v", resp["loginHint"])
	}
}

// --- SearchSessions cookie-scoped query tests ---

// TestSearchSessions_NoCookie_ReturnsEmpty asserts that a caller without a
// sessions cookie gets an empty result and the proxy never contacts Zitadel.
// Prevents a privacy leak where the service PAT could otherwise enumerate
// sessions belonging to other users on the instance.
func TestSearchSessions_NoCookie_ReturnsEmpty(t *testing.T) {
	zitadelHit := false
	mockZitadel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		zitadelHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer mockZitadel.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: mockZitadel.URL, PAT: "test-pat"})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/sessions/search", `{}`)

	proxy.SearchSessions(c)

	if zitadelHit {
		t.Error("proxy must not hit Zitadel when caller has no sessions cookie")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "\"sessions\":[]") {
		t.Errorf("expected empty sessions array, got %s", w.Body.String())
	}
}

// TestSearchSessions_OverridesClientQueries asserts that a client-supplied
// `queries` filter is stripped and replaced with an IdsQuery scoped to the
// caller's own cookie sessions. Without this, a malicious client could send
// a broad filter and read sessions from other users.
func TestSearchSessions_OverridesClientQueries(t *testing.T) {
	var receivedBody map[string]any
	mockZitadel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"sessions":[]}`))
	}))
	defer mockZitadel.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: mockZitadel.URL, PAT: "test-pat"})

	// Seed the caller's sessions cookie by running writeSessionCookie, then
	// replaying the resulting Set-Cookie back on a fresh request — mirrors how
	// the browser would round-trip the cookie and matches Gin's URL-encoding.
	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: "sess-a", Token: "tok-a"},
		{ID: "sess-b", Token: "tok-b"},
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Client tries to inject a broad filter (simulating a malicious caller).
	body := `{"queries":[{"userIdsQuery":{"userIds":["victim-1","victim-2"]}}]}`
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/sessions/search", body)
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}

	proxy.SearchSessions(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	queries, ok := receivedBody["queries"].([]any)
	if !ok || len(queries) != 1 {
		t.Fatalf("expected exactly 1 query sent to Zitadel, got %v", receivedBody["queries"])
	}
	q := queries[0].(map[string]any)
	if _, hasUserQuery := q["userIdsQuery"]; hasUserQuery {
		t.Error("client-supplied userIdsQuery must be stripped")
	}
	ids, ok := q["idsQuery"].(map[string]any)["ids"].([]any)
	if !ok || len(ids) != 2 {
		t.Fatalf("expected idsQuery.ids length 2, got %v", q["idsQuery"])
	}
	if ids[0] != "sess-a" || ids[1] != "sess-b" {
		t.Errorf("expected ids [sess-a sess-b], got %v", ids)
	}
}

// --- Org discovery tests (A7.1) ---

// TestLookupOrgByDomain_StripsSensitiveFields asserts the public org-discovery
// response only exposes id / name / primaryDomain even if Zitadel adds extra
// fields over time.
func TestLookupOrgByDomain_StripsSensitiveFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Round 25 Wave 3 (item 21): LookupOrgByDomain now ALSO calls
		// /v2/settings/login?ctx.orgId=<id> to enforce per-org
		// allowDomainDiscovery. The mock must respond with the
		// allowDomainDiscovery=true settings so the org passes the
		// filter and the existing assertions hold.
		if strings.HasPrefix(r.URL.Path, "/v2/settings/login") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"settings":{"allowDomainDiscovery":true}}`))
			return
		}
		// Zitadel's real response includes `details`, `resourceOwner`, etc.
		// This test body deliberately includes extra fields we don't want leaked.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"details":{"totalResult":"1"},
			"result":[
				{"id":"1","name":"Acme","primaryDomain":"acme.example","state":"ORGANIZATION_STATE_ACTIVE","details":{"changeDate":"2026-01-01T00:00:00Z","resourceOwner":"root","sequence":"42"},"internalField":"leak me"},
				{"id":"2","name":"Inactive","primaryDomain":"inactive.example","state":"ORGANIZATION_STATE_INACTIVE"}
			]
		}`))
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/orgs/by-domain?domain=Acme.Example")

	proxy.LookupOrgByDomain(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, unwanted := range []string{"details", "changeDate", "resourceOwner", "sequence", "internalField", "Inactive"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("response leaked %q: %s", unwanted, body)
		}
	}
	for _, wanted := range []string{`"id":"1"`, `"name":"Acme"`, `"primaryDomain":"acme.example"`} {
		if !strings.Contains(body, wanted) {
			t.Errorf("response missing %q: %s", wanted, body)
		}
	}
}

func TestLookupOrgByDomain_RequiresDomainParam(t *testing.T) {
	gin.SetMode(gin.TestMode)

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: "http://unused", PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/orgs/by-domain?domain=")

	proxy.LookupOrgByDomain(c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing domain, got %d", w.Code)
	}
}

// Round 25 Wave 3 (item 21 / R23-4 + R25b F5): orgs that have opted out
// of domain discovery (allowDomainDiscovery=false) MUST be filtered
// from the response. From the caller's perspective the response is
// shape-identical to "no match found" so the gap can't be used as an
// existence oracle.
func TestLookupOrgByDomain_FiltersOrgsWithDomainDiscoveryDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Per-org login policy: opted out.
		if strings.HasPrefix(r.URL.Path, "/v2/settings/login") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"settings":{"allowDomainDiscovery":false}}`))
			return
		}
		// Org search returns a real, active org.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"result":[
				{"id":"42","name":"PrivateCo","primaryDomain":"private.example","state":"ORGANIZATION_STATE_ACTIVE"}
			]
		}`))
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/orgs/by-domain?domain=private.example")
	proxy.LookupOrgByDomain(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, `"id":"42"`) || strings.Contains(body, "PrivateCo") {
		t.Errorf("opted-out org leaked in response: %s", body)
	}
	// The response must be shape-identical to "no match found".
	if !strings.Contains(body, `"result":[]`) {
		t.Errorf("expected empty result for opted-out org, got: %s", body)
	}
}

// Round 25 Wave 3 (item 21 / R25c H-4): the (domain → result) lookup
// is cached for `lookupOrgByDomainTTL`. A second probe of the same
// domain must NOT trigger a second `/_search` call upstream.
func TestLookupOrgByDomain_CachesResult(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var searchCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/v2/settings/login") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"settings":{"allowDomainDiscovery":true}}`))
			return
		}
		searchCalls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"result":[
				{"id":"7","name":"Acme","primaryDomain":"acme.example","state":"ORGANIZATION_STATE_ACTIVE"}
			]
		}`))
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	for range 5 {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequest(http.MethodGet, "/auth/orgs/by-domain?domain=acme.example")
		proxy.LookupOrgByDomain(c)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"id":"7"`) {
			t.Errorf("response missing org id: %s", w.Body.String())
		}
	}

	if searchCalls != 1 {
		t.Errorf("expected upstream /_search to be called exactly once across 5 probes, got %d", searchCalls)
	}
}

// Round 25 Wave 3 (item 21 / R25c H-4): empty results MUST also be
// cached so an attacker probing 10k random domains burns at most 10k
// upstream queries (one per unique domain), not one per probe.
func TestLookupOrgByDomain_CachesEmptyResult(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var searchCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/v2/settings/login") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"settings":{"allowDomainDiscovery":true}}`))
			return
		}
		searchCalls++
		// No matching org.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":[]}`))
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	for range 5 {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequest(http.MethodGet, "/auth/orgs/by-domain?domain=nonexistent.example")
		proxy.LookupOrgByDomain(c)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for empty result, got %d", w.Code)
		}
	}

	if searchCalls != 1 {
		t.Errorf("expected empty-result amortisation: 1 upstream call across 5 probes, got %d", searchCalls)
	}
}

// Round 25 Wave 3 (item 21): domain values are normalised to
// lowercase before keying the cache, so two probes for the same
// domain in different cases share the cached result. This was always
// true for the upstream Zitadel call; with the cache it's now
// observable via the upstream-call counter.
func TestLookupOrgByDomain_CaseInsensitiveCache(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var searchCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/v2/settings/login") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"settings":{"allowDomainDiscovery":true}}`))
			return
		}
		searchCalls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"result":[
				{"id":"1","name":"Acme","primaryDomain":"acme.example","state":"ORGANIZATION_STATE_ACTIVE"}
			]
		}`))
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	for _, d := range []string{"Acme.Example", "ACME.EXAMPLE", "acme.example"} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequest(http.MethodGet, "/auth/orgs/by-domain?domain="+d)
		proxy.LookupOrgByDomain(c)
		if w.Code != http.StatusOK {
			t.Fatalf("probe %q: expected 200, got %d", d, w.Code)
		}
	}

	if searchCalls != 1 {
		t.Errorf("case-insensitive cache miss: want 1 upstream call across 3 probes, got %d", searchCalls)
	}
}

// --- Origin/Referer CSRF tests (via middleware) ---

func TestCSRFProtection_is_tested_via_middleware_package(t *testing.T) {
	// CSRF is implemented in middleware/csrf.go — tests belong in that package.
	// This test documents that the CSRF middleware is wired to /auth/* routes
	// via setupAuthProxyRoutes in routes.go.
	t.Log("CSRF tests live in backend/internal/api/middleware/csrf_test.go")
}

// newTestRequestWithBody creates an http.Request with a JSON body for tests.
func newTestRequestWithBody(method, target, body string) *http.Request {
	req, _ := http.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// --- F-sec-23: CUSTOM_REQUEST_HEADERS multi-header wire integration ---
//
// The unit tests above (`TestParseCustomHeaders_*`) cover parsing behavior
// exhaustively. F-sec-23's contract is the wire-level integration property:
// that every header parsed from `CUSTOM_REQUEST_HEADERS` actually lands on
// the outgoing Zitadel request. A regression where `parseCustomHeaders`
// kept all entries but `parsedHeaders()`/`proxyRequest()` dropped some
// (e.g. iterated over a stale map snapshot) would slip past the parsing
// tests but break production silently.
//
// Spins up an `httptest.Server` standing in for Zitadel, points the proxy
// at it, and asserts EVERY configured custom header appears on the
// upstream request.

func TestCustomRequestHeaders_AllPairsReachUpstream(t *testing.T) {
	// Capture inbound headers on a stand-in Zitadel.
	var captured http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	// Three pairs — covers single-host (instance-host pattern from D4)
	// + two diagnostic headers an operator might add. The trailing
	// comma exercises the same edge case as TestParseCustomHeaders_TrailingComma.
	custom := "x-zitadel-instance-host:zitadel.example.com,x-trace-id:abc-123,x-tenant:acme,"
	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL:   upstream.URL,
		PAT:                  "test-pat",
		CustomRequestHeaders: custom,
	})

	_, status, _, err := proxy.proxyRequest(context.Background(), http.MethodGet, "/test", nil, "")
	if err != nil {
		t.Fatalf("proxyRequest returned error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("upstream returned status %d, want 200", status)
	}
	if captured == nil {
		t.Fatal("upstream handler did not capture headers (request never arrived?)")
	}

	// Each parsed pair MUST land on the upstream request — values
	// preserved verbatim, no truncation, no shuffling.
	wants := map[string]string{
		"X-Zitadel-Instance-Host": "zitadel.example.com",
		"X-Trace-Id":              "abc-123",
		"X-Tenant":                "acme",
	}
	for name, want := range wants {
		if got := captured.Get(name); got != want {
			t.Errorf("header %q: want %q on upstream, got %q", name, want, got)
		}
	}

	// PAT must also be set — guards against a regression where the
	// custom-header injection clobbered the Authorization header.
	if got := captured.Get("Authorization"); got != "Bearer test-pat" {
		t.Errorf("Authorization header: want %q, got %q", "Bearer test-pat", got)
	}
}

// --- F-sec-24: IdP successUrl/failureUrl Host-header priority chain ---
//
// `getPublicHost` priority chain (per D4): x-zitadel-public-host →
// x-zitadel-forward-host → x-forwarded-host → request.Host. The host
// picked there flows into `getFrontendBaseURL` (Round 11) which
// builds the IdP success/failure URLs in `StartIdP`. Existing
// `TestGetPublicHost_*` unit tests cover the priority logic in
// isolation; F-sec-24 closes the wire-level integration gap by
// asserting the picked host LANDS on the outgoing IdP-intent body
// at `urls.successUrl` / `urls.failureUrl`. A regression where the
// priority chain returned the right value but `StartIdP` ignored it
// (e.g. cached an old request, used a stale frontendBase) would slip
// past the unit tests.
//
// Five table cases: each header-priority branch + the
// `PublicFrontendURL` override + the fall-through to `Host`.

func TestStartIdP_SuccessUrlPriorityChain(t *testing.T) {
	// Capture the outgoing IdP intent body on a fake Zitadel.
	var captured map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make(map[string]any)
		_ = json.NewDecoder(r.Body).Decode(&body)
		captured = body
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"idpIntentId":"test-intent"}`))
	}))
	defer upstream.Close()

	cases := []struct {
		name              string
		publicFrontendURL string
		// Headers to set on the request gin sees. Empty string means
		// "don't set this header".
		zitadelPublicHost  string
		zitadelForwardHost string
		xForwardedHost     string
		// requestHost is the gin request's `Host` field (the
		// last-resort fallback per `getPublicHost`).
		requestHost string
		// xForwardedProto controls the scheme — when set, beats the
		// `r.TLS == nil → http` fallback.
		xForwardedProto string
		wantHostInURL   string
		wantSchemeInURL string
	}{
		{
			name:               "x-zitadel-public-host wins over all other headers",
			zitadelPublicHost:  "public.example.com",
			zitadelForwardHost: "forward.example.com",
			xForwardedHost:     "xfwd.example.com",
			requestHost:        "host.example.com",
			xForwardedProto:    "https",
			wantHostInURL:      "public.example.com",
			wantSchemeInURL:    "https",
		},
		{
			name:               "x-zitadel-forward-host wins when public-host absent",
			zitadelForwardHost: "forward.example.com",
			xForwardedHost:     "xfwd.example.com",
			requestHost:        "host.example.com",
			xForwardedProto:    "https",
			wantHostInURL:      "forward.example.com",
			wantSchemeInURL:    "https",
		},
		{
			name:            "x-forwarded-host wins when both zitadel headers absent",
			xForwardedHost:  "xfwd.example.com",
			requestHost:     "host.example.com",
			xForwardedProto: "https",
			wantHostInURL:   "xfwd.example.com",
			wantSchemeInURL: "https",
		},
		{
			name:            "request Host fallback when all forwarding headers absent",
			requestHost:     "host.example.com",
			xForwardedProto: "https",
			wantHostInURL:   "host.example.com",
			wantSchemeInURL: "https",
		},
		{
			name:               "PublicFrontendURL override wins over every header",
			publicFrontendURL:  "https://app.example.com",
			zitadelPublicHost:  "public.example.com", // ignored
			zitadelForwardHost: "forward.example.com",
			xForwardedHost:     "xfwd.example.com",
			requestHost:        "host.example.com",
			xForwardedProto:    "https",
			wantHostInURL:      "app.example.com",
			wantSchemeInURL:    "https",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			captured = nil
			proxy := NewAuthProxy(AuthProxyConfig{
				ZitadelInternalURL: upstream.URL,
				PAT:                "test-pat",
				PublicFrontendURL:  tc.publicFrontendURL,
			})

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = newTestRequestWithBody(http.MethodPost, "/auth/idp/start", `{"idpId":"test-idp-id"}`)
			c.Request.Host = tc.requestHost
			if tc.zitadelPublicHost != "" {
				c.Request.Header.Set("X-Zitadel-Public-Host", tc.zitadelPublicHost)
			}
			if tc.zitadelForwardHost != "" {
				c.Request.Header.Set("X-Zitadel-Forward-Host", tc.zitadelForwardHost)
			}
			if tc.xForwardedHost != "" {
				c.Request.Header.Set("X-Forwarded-Host", tc.xForwardedHost)
			}
			if tc.xForwardedProto != "" {
				c.Request.Header.Set("X-Forwarded-Proto", tc.xForwardedProto)
			}

			proxy.StartIdP(c)

			if w.Code != http.StatusOK {
				t.Fatalf("StartIdP returned status %d, want 200; body: %s", w.Code, w.Body.String())
			}
			if captured == nil {
				t.Fatal("upstream did not capture the outgoing body (request never arrived?)")
			}
			urls, ok := captured["urls"].(map[string]any)
			if !ok {
				t.Fatalf("captured body missing urls map: %v", captured)
			}
			successURL, _ := urls["successUrl"].(string)
			failureURL, _ := urls["failureUrl"].(string)

			wantSuccess := tc.wantSchemeInURL + "://" + tc.wantHostInURL + "/login/idp/test-idp-id/process"
			wantFailure := tc.wantSchemeInURL + "://" + tc.wantHostInURL + "/login/idp/test-idp-id/failure"
			if successURL != wantSuccess {
				t.Errorf("successUrl: want %q, got %q", wantSuccess, successURL)
			}
			if failureURL != wantFailure {
				t.Errorf("failureUrl: want %q, got %q", wantFailure, failureURL)
			}
		})
	}
}

// TestStartIdP_NoHeadersDoesNotCrash pins the negative property the
// plan calls out explicitly: "missing header → fallback, not crash".
// Older versions of `getPublicHost` could panic on a nil header map
// or an empty Request.Host; this test guarantees the fallback path
// returns a usable URL even with the bare-minimum request shape.
func TestStartIdP_NoHeadersDoesNotCrash(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: upstream.URL,
		PAT:                "test-pat",
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/idp/start", `{"idpId":"test"}`)
	// Intentionally no headers, no Host. The handler must not panic.
	c.Request.Host = ""

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("StartIdP panicked on bare request: %v", r)
		}
	}()
	proxy.StartIdP(c)

	// Some 2xx — the URL might be schemeless / hostless but the
	// handler must complete without crashing.
	if w.Code >= 500 {
		t.Errorf("StartIdP 5xx'd on bare request (want 2xx fallback); got %d", w.Code)
	}
}

// TestCustomRequestHeaders_EmptyConfig pins the no-op path: with no
// custom headers configured, the upstream sees only Authorization +
// the standard request headers. A regression that iterated over a
// nil map / pre-allocated stale data could surface here.
func TestCustomRequestHeaders_EmptyConfig(t *testing.T) {
	var captured http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: upstream.URL,
		PAT:                "test-pat",
		// CustomRequestHeaders intentionally empty.
	})

	if _, _, _, err := proxy.proxyRequest(context.Background(), http.MethodGet, "/test", nil, ""); err != nil {
		t.Fatalf("proxyRequest returned error: %v", err)
	}
	// Sanity: only the auth header (and maybe Go's default User-Agent /
	// Accept-Encoding) should be on the upstream. We assert Authorization
	// is set and no x-* customs leaked from a prior test's state.
	if got := captured.Get("Authorization"); got != "Bearer test-pat" {
		t.Errorf("Authorization header: want %q, got %q", "Bearer test-pat", got)
	}
	for k := range captured {
		if strings.HasPrefix(strings.ToLower(k), "x-zitadel-") || strings.HasPrefix(strings.ToLower(k), "x-trace-") || strings.HasPrefix(strings.ToLower(k), "x-tenant") {
			t.Errorf("unexpected custom header on upstream with empty config: %s=%q", k, captured.Get(k))
		}
	}
}

// --- F-sec-7: anti-enumeration decoy session ---
//
// The proxy MUST hide whether a loginName exists when the org's login
// policy has `ignoreUnknownUsernames: true`. Zitadel's session API
// 404s on unknown users regardless of that policy (the flag only
// affects the hosted login UI), so the proxy fakes a decoy success
// for createSession and a canonical password-invalid rejection on the
// follow-up updateSession. These tests pin the decoy logic so a
// future refactor can't quietly drop the masking and re-open the
// enumeration leak.

// fakeUpstream returns an httptest.Server that routes /v2/settings/login
// to a synthesized policy response and /v2/sessions to the configured
// session handler. Two-call test harness — most F-sec-7 tests need
// both endpoints answered.
func fakeUpstream(loginPolicy map[string]any, sessionHandler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/settings/login") {
			body, _ := json.Marshal(map[string]any{"settings": loginPolicy})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v2/sessions") {
			sessionHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestCreateSession_FakesDecoyOnUnknownUserWhenPolicyEnabled(t *testing.T) {
	upstream := fakeUpstream(
		map[string]any{"ignoreUnknownUsernames": true},
		func(w http.ResponseWriter, _ *http.Request) {
			// Real Zitadel returns 404 for unknown loginNames at the
			// session API regardless of the policy.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":5,"message":"User not found"}`))
		},
	)
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/sessions",
		`{"checks":{"user":{"loginName":"ghost@example.com"}}}`)

	proxy.CreateSession(c)

	// Decoy MUST fake a 201 Created — same status path as a real success.
	if w.Code != http.StatusCreated {
		t.Fatalf("decoy must return 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		SessionID    string         `json:"sessionId"`
		SessionToken string         `json:"sessionToken"`
		Details      map[string]any `json:"details"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoy body must unmarshal: %v: %s", err, w.Body.String())
	}
	// Decoy id MUST NOT carry a visible "decoy-" tell — it has to look
	// like a real Zitadel snowflake (numeric only).
	for _, ch := range resp.SessionID {
		if ch < '0' || ch > '9' {
			t.Errorf("decoy id must be all-digits (Zitadel snowflake shape), got %q", resp.SessionID)
			break
		}
	}
	if len(resp.SessionID) < 16 {
		t.Errorf("decoy id must be at least 16 digits, got %d (%q)", len(resp.SessionID), resp.SessionID)
	}
	if resp.SessionToken == "" {
		t.Errorf("decoy must include non-empty sessionToken")
	}
	if resp.Details == nil {
		t.Errorf("decoy must include `details` block (Zitadel-shape)")
	}
}

func TestCreateSession_ForwardsRealNotFoundWhenPolicyDisabled(t *testing.T) {
	upstream := fakeUpstream(
		map[string]any{"ignoreUnknownUsernames": false},
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":5,"message":"User not found"}`))
		},
	)
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/sessions",
		`{"checks":{"user":{"loginName":"ghost@example.com"}}}`)

	proxy.CreateSession(c)

	// Policy off → real 404 forwards through. Operators who explicitly
	// opted out of the masking must keep getting the truthful error.
	if w.Code != http.StatusNotFound {
		t.Fatalf("with policy off, must forward 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateSession_NoDecoyForUserIDCheck(t *testing.T) {
	upstream := fakeUpstream(
		map[string]any{"ignoreUnknownUsernames": true},
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":5,"message":"User not found"}`))
		},
	)
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// userId-based check — no enumeration leak to mask, since attackers
	// can't probe for arbitrary user IDs the way they can probe email
	// loginNames. Forward the 404 truthfully.
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/sessions",
		`{"checks":{"user":{"userId":"123456"}}}`)

	proxy.CreateSession(c)

	if w.Code != http.StatusNotFound {
		t.Fatalf("userId check must forward 404 (no decoy), got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateSession_DecoyShortCircuitsWithCanonicalPasswordInvalid(t *testing.T) {
	zitadelHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		zitadelHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	// Decoy id is numeric (mirrors Zitadel's snowflake shape) and the
	// cookie entry has Decoy=true so UpdateSession short-circuits.
	decoyID := "123456789012345678"

	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: decoyID, Token: "decoytoken", Decoy: true},
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPatch, "/auth/sessions/"+decoyID,
		`{"checks":{"password":{"password":"hunter2"}}}`)
	c.Params = gin.Params{{Key: "id", Value: decoyID}}
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}

	proxy.UpdateSession(c)

	// MUST 400 with Zitadel-shaped {code, message, details}.
	if w.Code != http.StatusBadRequest {
		t.Fatalf("decoy update must 400 (canonical password-invalid), got %d: %s",
			w.Code, w.Body.String())
	}
	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Details []any  `json:"details"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoy update body must unmarshal: %v: %s", err, w.Body.String())
	}
	if resp.Code != 7 {
		t.Errorf("decoy update code: want 7 (FailedPrecondition), got %d", resp.Code)
	}
	if !strings.Contains(strings.ToLower(resp.Message), "password is invalid") {
		t.Errorf("decoy update message must contain `Password is invalid`, got %q", resp.Message)
	}
	// Critical: Zitadel MUST NOT have been called. A decoy id
	// forwarded upstream would 404 (different shape from real
	// password-failure) — the short-circuit closes that gap.
	if zitadelHit {
		t.Errorf("decoy update must NOT forward to Zitadel (would leak via different error shape)")
	}
}

func TestBuildDecoyPasswordInvalidResponse_Shape(t *testing.T) {
	body := buildDecoyPasswordInvalidResponse()
	var parsed struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Details []any  `json:"details"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("must unmarshal: %v", err)
	}
	if parsed.Code != 7 {
		t.Errorf("code: want 7, got %d", parsed.Code)
	}
	if !strings.Contains(parsed.Message, "Password is invalid") {
		t.Errorf("message: want canonical 'Password is invalid', got %q", parsed.Message)
	}
	if parsed.Details == nil {
		t.Errorf("details: must be present (even if empty) to mirror Zitadel shape")
	}
}

func TestBuildDecoySessionResponse_LooksRealAndUnique(t *testing.T) {
	body, id := buildDecoySessionResponse()
	var parsed struct {
		SessionID    string `json:"sessionId"`
		SessionToken string `json:"sessionToken"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("must unmarshal: %v", err)
	}
	if parsed.SessionID != id {
		t.Errorf("returned id (%q) must match body sessionId (%q)", id, parsed.SessionID)
	}
	// Decoy id must look like a Zitadel snowflake — pure digits, no
	// "decoy-" prefix that would tip off a network observer.
	for _, ch := range parsed.SessionID {
		if ch < '0' || ch > '9' {
			t.Errorf("decoy id must be all-digits, got %q", parsed.SessionID)
			break
		}
	}
	if len(parsed.SessionToken) < 40 {
		t.Errorf("decoy token must be a realistic length, got %d chars", len(parsed.SessionToken))
	}
	// Two consecutive decoys MUST differ — fixed decoy ids would let
	// attackers detect the fake by repeating the probe.
	otherBody, otherID := buildDecoySessionResponse()
	if id == otherID {
		t.Errorf("two decoys must produce different ids; got %q twice", id)
	}
	if string(body) == string(otherBody) {
		t.Errorf("two decoy bodies must differ")
	}
}

// --- Audit Round 20 follow-up: decoy short-circuits on
// GetSession / DeleteSession / FinalizeAuthRequest. These three
// handlers each had a bypass — forwarding the decoy to Zitadel
// produced a distinguishably different status (404) than a real
// loginName-only session (200/412/200), letting an attacker
// enumerate users by skipping the SPA's normal PATCH flow.

func TestGetSession_DecoyShortCircuitsWithRealisticShape(t *testing.T) {
	// Round 21 Finding 1: the decoy GET must mirror Zitadel's full
	// loginName-only response shape — a populated `factors.user` block
	// with id/loginName/organizationId, plus top-level sequence /
	// creationDate / changeDate. The previous version emitted
	// `factors: {}` which was wire-distinguishable from a real session.
	zitadelHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		zitadelHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	decoyID := "987654321098765432"
	probedLoginName := "ghost@example.com"
	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: decoyID, Token: "decoytoken", LoginName: probedLoginName, Decoy: true},
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/sessions/"+decoyID)
	c.Params = gin.Params{{Key: "id", Value: decoyID}}
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}

	proxy.GetSession(c)

	if w.Code != http.StatusOK {
		t.Fatalf("decoy GET must mirror real loginName-only session 200, got %d: %s", w.Code, w.Body.String())
	}
	if zitadelHit {
		t.Errorf("decoy GET must NOT forward to Zitadel (would 404 and leak)")
	}
	var resp struct {
		Session struct {
			ID           string `json:"id"`
			CreationDate string `json:"creationDate"`
			ChangeDate   string `json:"changeDate"`
			Sequence     string `json:"sequence"`
			Factors      struct {
				User struct {
					VerifiedAt     string `json:"verifiedAt"`
					ID             string `json:"id"`
					LoginName      string `json:"loginName"`
					OrganizationID string `json:"organizationId"`
				} `json:"user"`
			} `json:"factors"`
		} `json:"session"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoy GET body must unmarshal: %v: %s", err, w.Body.String())
	}
	if resp.Session.ID != decoyID {
		t.Errorf("decoy GET session.id mismatch: want %q, got %q", decoyID, resp.Session.ID)
	}
	if resp.Session.Sequence == "" {
		t.Errorf("decoy GET must carry a non-empty `sequence` (real shape includes it)")
	}
	if resp.Session.Factors.User.ID == "" {
		t.Errorf("decoy GET MUST populate factors.user.id (Round 21 Finding 1)")
	}
	if resp.Session.Factors.User.LoginName != probedLoginName {
		t.Errorf("decoy GET factors.user.loginName: want %q, got %q",
			probedLoginName, resp.Session.Factors.User.LoginName)
	}
	if resp.Session.Factors.User.OrganizationID == "" {
		t.Errorf("decoy GET MUST populate factors.user.organizationId")
	}
	if resp.Session.Factors.User.VerifiedAt == "" {
		t.Errorf("decoy GET MUST populate factors.user.verifiedAt")
	}
}

// TestGetSession_DecoyIDsAreDeterministicPerLoginName: Round 21 Finding 1
// — two probes of the SAME unknown loginName must produce identical fake
// user/org ids; otherwise an attacker hitting the same decoy twice would
// see divergent ids while a real user would see stable ones.
func TestGetSession_DecoyIDsAreDeterministicPerLoginName(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	type ids struct{ userID, orgID string }
	probe := func(decoyID string) ids {
		seed := httptest.NewRecorder()
		seedCtx, _ := gin.CreateTestContext(seed)
		seedCtx.Request = newTestRequest(http.MethodGet, "/")
		proxy.writeSessionCookie(seedCtx, []sessionEntry{
			{ID: decoyID, Token: "tok", LoginName: "ghost@example.com", Decoy: true},
		})
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequest(http.MethodGet, "/auth/sessions/"+decoyID)
		c.Params = gin.Params{{Key: "id", Value: decoyID}}
		for _, ck := range seed.Result().Cookies() {
			c.Request.AddCookie(ck)
		}
		proxy.GetSession(c)
		var resp struct {
			Session struct {
				Factors struct {
					User struct {
						ID             string `json:"id"`
						OrganizationID string `json:"organizationId"`
					} `json:"user"`
				} `json:"factors"`
			} `json:"session"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return ids{resp.Session.Factors.User.ID, resp.Session.Factors.User.OrganizationID}
	}
	// Two probes with DIFFERENT decoy session ids but same loginName
	// must return matching user/org ids (loginName drives the hash).
	a := probe("111111111111111111")
	b := probe("222222222222222222")
	if a.userID != b.userID {
		t.Errorf("same loginName must produce same fake userID across probes: %q vs %q", a.userID, b.userID)
	}
	if a.orgID != b.orgID {
		t.Errorf("same loginName must produce same fake orgID across probes: %q vs %q", a.orgID, b.orgID)
	}
	// Sanity: ids must look like Zitadel snowflakes (18 digits).
	if len(a.userID) != 18 {
		t.Errorf("fake userID must be 18 digits, got %q (len %d)", a.userID, len(a.userID))
	}
}

func TestDeleteSession_DecoyShortCircuitsAndClearsCookie(t *testing.T) {
	zitadelHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		zitadelHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	decoyID := "987654321098765432"
	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: decoyID, Token: "decoytoken", Decoy: true},
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodDelete, "/auth/sessions/"+decoyID)
	c.Params = gin.Params{{Key: "id", Value: decoyID}}
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}

	proxy.DeleteSession(c)

	if w.Code != http.StatusOK {
		t.Fatalf("decoy DELETE must mirror real-session 200, got %d: %s", w.Code, w.Body.String())
	}
	if zitadelHit {
		t.Errorf("decoy DELETE must NOT forward to Zitadel")
	}
	// Body must carry a `details` envelope to match Zitadel's shape.
	if !strings.Contains(w.Body.String(), `"details"`) {
		t.Errorf("decoy DELETE body must include `details`, got %s", w.Body.String())
	}
}

func TestFinalizeAuthRequest_DecoyShortCircuitsWith412(t *testing.T) {
	zitadelHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		zitadelHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	decoyID := "987654321098765432"
	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: decoyID, Token: "decoytoken", Decoy: true},
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/oidc/finalize",
		`{"authRequestId":"oidc_abc","sessionId":"`+decoyID+`","sessionToken":"decoytoken"}`)
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}

	proxy.FinalizeAuthRequest(c)

	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("decoy finalize must 412 (mirror loginName-only session), got %d: %s", w.Code, w.Body.String())
	}
	if zitadelHit {
		t.Errorf("decoy finalize must NOT forward to Zitadel (would 404 and leak)")
	}
	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoy finalize body must unmarshal: %v: %s", err, w.Body.String())
	}
	if resp.Code != 9 {
		t.Errorf("decoy finalize code: want 9 (FailedPrecondition), got %d", resp.Code)
	}
	if resp.Message == "" {
		t.Errorf("decoy finalize must carry a non-empty message")
	}
}

// --- Audit Round 21 ---

// TestUpdateSession_DecoyHitsLockoutAt429: Round 21 Finding 2.
// 5 wrong-password PATCHes against a decoy must produce 5x 400, then
// the 6th must 429 — mirroring the real-user lockout path. Without
// this parity, an attacker counting consecutive 400s vs (5x 400 + 429)
// has a single-bit oracle for "user exists".
func TestUpdateSession_DecoyHitsLockoutAt429(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Decoys must NEVER reach upstream — assert it doesn't here.
		t.Errorf("decoy PATCH must not forward to Zitadel")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL:        upstream.URL,
		PAT:                       "pat",
		LoginNameLockoutThreshold: 5,
		LoginNameLockoutWindow:    15 * time.Minute,
	})

	decoyID := "987654321098765432"
	loginName := "ghost@example.com"
	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: decoyID, Token: "tok", LoginName: loginName, Decoy: true},
	})

	patch := func() int {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequestWithBody(http.MethodPatch, "/auth/sessions/"+decoyID,
			`{"checks":{"password":{"password":"wrong"}}}`)
		c.Params = gin.Params{{Key: "id", Value: decoyID}}
		for _, ck := range seed.Result().Cookies() {
			c.Request.AddCookie(ck)
		}
		proxy.UpdateSession(c)
		return w.Code
	}
	for i := 1; i <= 5; i++ {
		if got := patch(); got != http.StatusBadRequest {
			t.Errorf("decoy attempt %d: want 400 (canonical password-invalid), got %d", i, got)
		}
	}
	// 6th attempt MUST 429 — same as a real user at threshold.
	if got := patch(); got != http.StatusTooManyRequests {
		t.Errorf("decoy attempt 6 (post-threshold): want 429, got %d", got)
	}
}

// TestSearchSessions_DecoyOnlyCookieReturnsSyntheticRow: Round 21
// Finding 3. A cookie carrying ONLY decoy entries must produce a
// SearchSessions response with one row per decoy (mirroring what a
// real-only cookie would produce); no upstream call needed.
func TestSearchSessions_DecoyOnlyCookieReturnsSyntheticRow(t *testing.T) {
	zitadelHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		zitadelHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: "111111111111111111", Token: "t1", LoginName: "ghost@a.com", Decoy: true},
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/sessions/search", `{}`)
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}

	proxy.SearchSessions(c)

	if zitadelHit {
		t.Errorf("decoy-only search must NOT hit Zitadel")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("decoy-only search must 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoy search body must unmarshal: %v", err)
	}
	if len(resp.Sessions) != 1 {
		t.Errorf("decoy-only search row count: want 1 (one per cookie decoy), got %d", len(resp.Sessions))
	}
}

// TestSearchSessions_MixedCookieSplicesDecoyRows: Round 21 Finding 3.
// Cookie has 1 real + 1 decoy. Upstream returns 1 row for the real
// session. Final response must show 2 rows so the client can't infer
// which entries are decoys by row-count divergence.
func TestSearchSessions_MixedCookieSplicesDecoyRows(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"sessions":[{"id":"realsession1234567","factors":{"user":{"id":"realuser1","loginName":"alice"}}}]}`))
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: "realsession1234567", Token: "rt", UserID: "realuser1"},
		{ID: "987654321098765432", Token: "dt", LoginName: "ghost@x.com", Decoy: true},
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/sessions/search", `{}`)
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}

	proxy.SearchSessions(c)

	if w.Code != http.StatusOK {
		t.Fatalf("mixed search must 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("mixed search body must unmarshal: %v", err)
	}
	if len(resp.Sessions) != 2 {
		t.Errorf("mixed search row count: want 2 (real + decoy spliced), got %d", len(resp.Sessions))
	}
}

// TestUpdateSession_MixedFactorBodyDoesNotConsumeSlot: Round 21
// Finding 4. A PATCH carrying `password + totp` (or any other
// multi-factor body) that 4xxs from Zitadel must NOT count as a
// password failure — the upstream rejection might be due to the
// other factor, not the password. Without this guard, an attacker
// (or transient SPA bug) can lock honest users by triggering 4xxs
// on a non-password branch.
func TestUpdateSession_MixedFactorBodyDoesNotConsumeSlot(t *testing.T) {
	// Upstream always 4xxs — simulating a server-side rejection that
	// might be password OR totp.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":7,"message":"some error","details":[]}`))
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL:        upstream.URL,
		PAT:                       "pat",
		LoginNameLockoutThreshold: 3,
		LoginNameLockoutWindow:    15 * time.Minute,
	})

	sessionID := "realsession1234567"
	userID := "realuser1"
	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: sessionID, Token: "tok", UserID: userID},
	})

	mixedPatch := func() int {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		// Multi-factor body — a plausible attack/bug shape.
		c.Request = newTestRequestWithBody(http.MethodPatch, "/auth/sessions/"+sessionID,
			`{"checks":{"password":{"password":"x"},"totp":{"code":"123"}}}`)
		c.Params = gin.Params{{Key: "id", Value: sessionID}}
		for _, ck := range seed.Result().Cookies() {
			c.Request.AddCookie(ck)
		}
		proxy.UpdateSession(c)
		return w.Code
	}
	// Send 10 multi-factor PATCHes. None should consume a lockout
	// slot (the body has factors other than password). Pre-fix, the
	// 4th would have 429'd.
	for i := 1; i <= 10; i++ {
		got := mixedPatch()
		if got == http.StatusTooManyRequests {
			t.Errorf("attempt %d: mixed-factor body must NOT consume a lockout slot (Round 21 Finding 4)", i)
			return
		}
	}
}

// TestUpdateSession_PureSinglePasswordCheckStillCounts: Round 21
// Finding 4 — inverse property. A pure password-only PATCH that 4xxs
// upstream must still consume the slot, otherwise F-sec-5/6 is broken.
func TestUpdateSession_PureSinglePasswordCheckStillCounts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":7,"message":"Password is invalid (COMMAND-3M9fs)","details":[]}`))
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL:        upstream.URL,
		PAT:                       "pat",
		LoginNameLockoutThreshold: 5,
		LoginNameLockoutWindow:    15 * time.Minute,
	})

	sessionID := "realsession1234567"
	userID := "realuser1"
	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: sessionID, Token: "tok", UserID: userID},
	})

	pwPatch := func() int {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequestWithBody(http.MethodPatch, "/auth/sessions/"+sessionID,
			`{"checks":{"password":{"password":"x"}}}`)
		c.Params = gin.Params{{Key: "id", Value: sessionID}}
		for _, ck := range seed.Result().Cookies() {
			c.Request.AddCookie(ck)
		}
		proxy.UpdateSession(c)
		return w.Code
	}
	for i := 1; i <= 5; i++ {
		if got := pwPatch(); got != http.StatusBadRequest {
			t.Errorf("attempt %d: want 400 (forwarded), got %d", i, got)
		}
	}
	if got := pwPatch(); got != http.StatusTooManyRequests {
		t.Errorf("attempt 6 (post-threshold): want 429, got %d — F-sec-5/6 lockout broken", got)
	}
}

// TestIsPureSinglePasswordCheck: unit test for the body-shape gate
// introduced in Round 21 Finding 4.
func TestIsPureSinglePasswordCheck(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"pure password", `{"checks":{"password":{"password":"abc"}}}`, true},
		{"empty body", `{}`, false},
		{"no checks key", `{"foo":"bar"}`, false},
		{"empty checks", `{"checks":{}}`, false},
		{"password + totp (mixed)", `{"checks":{"password":{"password":"x"},"totp":{"code":"y"}}}`, false},
		{"password + webAuthN (mixed)", `{"checks":{"password":{"password":"x"},"webAuthN":{}}}`, false},
		{"only totp (no password)", `{"checks":{"totp":{"code":"x"}}}`, false},
		{"empty password string", `{"checks":{"password":{"password":""}}}`, false},
		{"missing inner password", `{"checks":{"password":{}}}`, false},
		{"non-string password", `{"checks":{"password":{"password":1234}}}`, false},
		// Round 22 Finding 4: top-level keys alongside `checks` must
		// also disqualify the body — `lifetime`/`metadata` validation
		// failures upstream would otherwise count as password failures.
		{"top-level lifetime sibling", `{"checks":{"password":{"password":"x"}},"lifetime":"3600s"}`, false},
		{"top-level metadata sibling", `{"checks":{"password":{"password":"x"}},"metadata":{"foo":"bar"}}`, false},
		{"whitespace-only password", `{"checks":{"password":{"password":"   "}}}`, false},
		{"tab-only password", `{"checks":{"password":{"password":"\t"}}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body map[string]any
			if err := json.Unmarshal([]byte(tc.body), &body); err != nil {
				t.Fatalf("test fixture must unmarshal: %v", err)
			}
			got := isPureSinglePasswordCheck(body)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// --- Audit Round 22 ---

// TestUserScopedProxy_DecoyShortCircuitsAuthMethods: Round 22 Finding 1.
// A decoy session probed via GET /auth/users/{decoyUserId}/authentication_methods
// must NOT 403 (which is wire-distinguishable from the real loginName-only
// session's Zitadel response). The proxy detects the URL :id matching the
// decoy's hash-derived fake user id and synthesizes an empty
// `authMethodTypes` array.
func TestUserScopedProxy_DecoyShortCircuitsAuthMethods(t *testing.T) {
	zitadelHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		zitadelHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	loginName := "ghost@example.com"
	fakeUserID := deriveDecoySnowflake(proxy.decoySecret, "user:"+loginName)
	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: "111111111111111111", Token: "tok", LoginName: loginName, Decoy: true},
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/users/"+fakeUserID+"/authentication_methods")
	c.Params = gin.Params{{Key: "id", Value: fakeUserID}}
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}

	proxy.userScopedProxyWithMethod(c, http.MethodGet, "/v2/users/"+fakeUserID+"/authentication_methods")

	if w.Code != http.StatusOK {
		t.Fatalf("decoy authentication_methods must 200, got %d: %s", w.Code, w.Body.String())
	}
	if zitadelHit {
		t.Errorf("decoy must NOT forward to Zitadel (403/Zitadel divergence is the leak)")
	}
	var resp struct {
		AuthMethodTypes []string `json:"authMethodTypes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoy authentication_methods body must unmarshal: %v: %s", err, w.Body.String())
	}
	if resp.AuthMethodTypes == nil {
		t.Errorf("decoy authentication_methods must carry an empty authMethodTypes array")
	}
}

// TestBuildDecoyUserScopedResponse_GenericPathResourceOwner: Round 22
// Finding 6. The generic-path `details.resourceOwner` previously
// hardcoded "0", which is wire-distinguishable from a real Zitadel
// register-MFA response. Must now derive a stable fake snowflake
// matching the GetSession decoy's `factors.user.organizationId` for
// the same loginName.
func TestBuildDecoyUserScopedResponse_GenericPathResourceOwner(t *testing.T) {
	secret := []byte("test-decoy-secret-32-bytes-long!")
	loginName := "ghost@example.com"
	entry := &sessionEntry{LoginName: loginName, Decoy: true}

	body := buildDecoyUserScopedResponse("/v2/users/123/totp", entry, secret)

	var resp struct {
		Details struct {
			Sequence      string `json:"sequence"`
			ChangeDate    string `json:"changeDate"`
			ResourceOwner string `json:"resourceOwner"`
		} `json:"details"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("generic body must unmarshal: %v: %s", err, body)
	}
	if resp.Details.ResourceOwner == "0" || resp.Details.ResourceOwner == "" {
		t.Errorf("resourceOwner must be a derived snowflake, not %q (the leak)", resp.Details.ResourceOwner)
	}
	expected := deriveDecoySnowflake(secret, "org:"+loginName)
	if resp.Details.ResourceOwner != expected {
		t.Errorf("resourceOwner must match deriveDecoySnowflake; want %q got %q", expected, resp.Details.ResourceOwner)
	}
	// Must be stable: same loginName → same id (mirrors real-user
	// stability across probes; Round 21 Finding 1 invariant).
	body2 := buildDecoyUserScopedResponse("/v2/users/456/passkeys", entry, secret)
	var resp2 struct {
		Details struct {
			ResourceOwner string `json:"resourceOwner"`
		} `json:"details"`
	}
	if err := json.Unmarshal(body2, &resp2); err != nil {
		t.Fatalf("second generic body must unmarshal: %v: %s", err, body2)
	}
	if resp2.Details.ResourceOwner != resp.Details.ResourceOwner {
		t.Errorf("resourceOwner must be stable across endpoints for the same loginName; got %q vs %q", resp.Details.ResourceOwner, resp2.Details.ResourceOwner)
	}
}

// TestUserScopedProxy_RealUserStill403sCrossUser: regression check
// that Round 22's fix didn't break Round 17's cross-user gate. A real
// session A hitting userScopedProxy with user B's id must still 403.
func TestUserScopedProxy_RealUserStill403sCrossUser(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	// Cookie has user A's session bound to UserID="aaa".
	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: "session-a", Token: "ta", UserID: "aaa"},
	})

	// Caller asks for user B's authentication_methods.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/users/bbb/authentication_methods")
	c.Params = gin.Params{{Key: "id", Value: "bbb"}}
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}

	proxy.userScopedProxyWithMethod(c, http.MethodGet, "/v2/users/bbb/authentication_methods")

	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-user must 403, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSearchSessions_PreservesDetailsEnvelope: Round 22 Finding 2.
// Real Zitadel SearchSessions returns `{"details":{"totalResult":...,
// "timestamp":...}, "sessions":[...]}`. The splicer must preserve
// `details` AND update `totalResult` to match the merged row count.
func TestSearchSessions_PreservesDetailsEnvelope(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Real-shape upstream response.
		_, _ = w.Write([]byte(`{"details":{"totalResult":"1","timestamp":"2026-04-29T09:11:43Z"},"sessions":[{"id":"realsession1","factors":{"user":{"id":"realuser1"}}}]}`))
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: "realsession1", Token: "rt", UserID: "realuser1"},
		{ID: "decoysession2", Token: "dt", LoginName: "ghost@x.com", Decoy: true},
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/sessions/search", `{}`)
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}

	proxy.SearchSessions(c)

	if w.Code != http.StatusOK {
		t.Fatalf("search must 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Details struct {
			TotalResult string `json:"totalResult"`
			Timestamp   string `json:"timestamp"`
		} `json:"details"`
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("search body must unmarshal: %v: %s", err, w.Body.String())
	}
	if resp.Details.TotalResult != "2" {
		t.Errorf("details.totalResult: want \"2\" (merged count), got %q", resp.Details.TotalResult)
	}
	if resp.Details.Timestamp == "" {
		t.Errorf("details.timestamp: must be preserved from upstream (or synthesized for decoy-only path)")
	}
	if len(resp.Sessions) != 2 {
		t.Errorf("sessions row count: want 2, got %d", len(resp.Sessions))
	}
}

// TestSearchSessions_DecoyOnlyEmitsDetailsEnvelope: Round 22 Finding 2.
// Decoy-only cookie (no upstream call) must still produce a `details`
// envelope so the wire shape matches a real-only or mixed response.
func TestSearchSessions_DecoyOnlyEmitsDetailsEnvelope(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{
		{ID: "decoysession1", Token: "dt", LoginName: "ghost@x.com", Decoy: true},
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/sessions/search", `{}`)
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}

	proxy.SearchSessions(c)

	var resp struct {
		Details struct {
			TotalResult string `json:"totalResult"`
			Timestamp   string `json:"timestamp"`
		} `json:"details"`
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoy-only search body must unmarshal: %v: %s", err, w.Body.String())
	}
	if resp.Details.TotalResult != "1" {
		t.Errorf("decoy-only details.totalResult: want \"1\", got %q", resp.Details.TotalResult)
	}
	if resp.Details.Timestamp == "" {
		t.Errorf("decoy-only details.timestamp: must be synthesized")
	}
}

// TestSettingsProxy_DecoyOrgIDStripsCtxParam: Round 22 Finding 3.
// `GetLoginSettings ?ctx.orgId=<decoyOrgId>` must NOT forward the
// decoy orgId to Zitadel — Zitadel's per-org response (404 or
// instance-default fallback) is wire-distinguishable from a real
// org's customized policy. Strip the param so the upstream call is
// unscoped (instance-default).
func TestSettingsProxy_DecoyOrgIDStripsCtxParam(t *testing.T) {
	var receivedQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"settings":{"allowUsernamePassword":true}}`))
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	// Issue a decoy orgID by simulating the CreateSession decoy path.
	loginName := "ghost@example.com"
	decoyOrgID := deriveDecoySnowflake(proxy.decoySecret, "org:"+loginName)
	proxy.storeDecoyOrgID(decoyOrgID, time.Now().Add(decoyOrgTTL))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/settings/login?ctx.orgId="+decoyOrgID)

	proxy.GetLoginSettings(c)

	if w.Code != http.StatusOK {
		t.Fatalf("settings must 200, got %d: %s", w.Code, w.Body.String())
	}
	// Critical: the upstream call must NOT carry the decoy orgId.
	if strings.Contains(receivedQuery, "ctx.orgId") {
		t.Errorf("decoy orgId must be stripped before upstream call; got query %q", receivedQuery)
	}
}

// TestSettingsProxy_RealOrgIDPassesThrough: regression — a real org
// id that's NOT in the decoy set must still forward verbatim.
func TestSettingsProxy_RealOrgIDPassesThrough(t *testing.T) {
	var receivedQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"settings":{}}`))
	}))
	defer upstream.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// Real-looking org id NOT in the decoy set.
	c.Request = newTestRequest(http.MethodGet, "/auth/settings/login?ctx.orgId=367134438137596546")

	proxy.GetLoginSettings(c)

	if !strings.Contains(receivedQuery, "ctx.orgId=367134438137596546") {
		t.Errorf("non-decoy orgId must forward verbatim; got query %q", receivedQuery)
	}
}

// --- Audit Round 23 (PasswordReset / ChangePassword / VerifyEmail
// canonicalization — F-sec-7 from a different angle) ---

// TestPasswordReset_UnknownUserCanonicalizesToSuccess: Round 23
// Finding 2 (MODERATE). Direct probing of `/auth/users/<guess>/
// password-reset` with an unknown userId would reveal the user
// doesn't exist via the upstream 404. The proxy must canonicalize
// to a 200 + canonical details envelope so this leak isn't an
// enumeration oracle for F-sec-7 decoy userIds.
func TestPasswordReset_UnknownUserCanonicalizesToSuccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":5,"message":"Errors.User.NotFound (QUERY-3M9fs)"}`))
	}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/123456789/password-reset", `{}`)
	c.Params = gin.Params{{Key: "id", Value: "123456789"}}

	proxy.PasswordReset(c)

	if w.Code != http.StatusOK {
		t.Fatalf("unknown-user must canonicalize to 200, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "User.NotFound") {
		t.Errorf("response body must NOT leak User.NotFound: %s", w.Body.String())
	}
	// Sanity: response must include the canonical details envelope shape.
	if !strings.Contains(w.Body.String(), `"details"`) {
		t.Errorf("canonical response must contain a details envelope: %s", w.Body.String())
	}
}

// TestPasswordReset_KnownUserPassesThrough: regression — a real
// 200 response from Zitadel must forward verbatim (including any
// returnCode body in dev mode).
func TestPasswordReset_KnownUserPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"details":{"sequence":"42","changeDate":"2026-04-30T05:50:00Z","resourceOwner":"367134438137596546"},"verificationCode":"ABC123"}`))
	}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: upstream.URL,
		PAT:                "pat",
		NotificationMode:   NotificationModeReturnCode,
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/367134438137596547/password-reset", `{}`)
	c.Params = gin.Params{{Key: "id", Value: "367134438137596547"}}

	proxy.PasswordReset(c)

	if w.Code != http.StatusOK {
		t.Fatalf("known-user must 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"verificationCode":"ABC123"`) {
		t.Errorf("known-user response must preserve the verificationCode: %s", w.Body.String())
	}
}

// TestChangePassword_UnknownUserCanonicalizesToCodeInvalid: Round 23
// Finding 2 (MODERATE) for the change-password endpoint. Unknown
// userId 404 must canonicalize to a "code is invalid" 4xx — same
// shape Zitadel emits for a wrong verificationCode (reset flow) or
// wrong currentPassword (in-app change flow) on a real user.
func TestChangePassword_UnknownUserCanonicalizesToCodeInvalid(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":5,"message":"Errors.User.NotFound (QUERY-3M9fs)"}`))
	}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/123456789/password",
		`{"verificationCode":"BAD","newPassword":{"password":"NewPass1!"}}`)
	c.Params = gin.Params{{Key: "id", Value: "123456789"}}

	proxy.ChangePassword(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown-user must canonicalize to 400, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "User.NotFound") {
		t.Errorf("response body must NOT leak User.NotFound: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Code is invalid") {
		t.Errorf("response must use the canonical Code-invalid shape: %s", w.Body.String())
	}
}

// TestVerifyEmail_UnknownUserCanonicalizesToCodeInvalid: Round 23
// Finding 3 (MODERATE). Same canonicalization shape as
// ChangePassword — a wrong code on a real user 4xxs with the
// canonical shape, so an unknown user must produce the same shape
// to avoid the enumeration oracle.
//
// Round 25 Wave 6 (item 20 / R25b F1): VerifyEmail now requires a
// matching cookie session (cross-user gate). The test sets up a
// real-session entry for the target userID so the auth gate passes
// and the unknown-user canonicalization branch can be exercised.
func TestVerifyEmail_UnknownUserCanonicalizesToCodeInvalid(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":5,"message":"Errors.User.NotFound (QUERY-3M9fs)"}`))
	}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/123456789/email",
		`{"verificationCode":"BAD"}`)
	c.Params = gin.Params{{Key: "id", Value: "123456789"}}

	// Wave 6 (item 20): set up a real-session entry whose UserID
	// matches the URL :id so the cross-user gate passes. The test
	// exercises what happens when Zitadel returns 404 for a userID
	// the cookie says is real (timing race / deleted user).
	proxy.upsertSessionEntry(c, sessionEntry{
		ID:        "sess-real",
		Token:     "tok-real",
		UserID:    "123456789",
		LoginName: "real@example.com",
	})
	// Replay the cookie back into the request so readSessionCookie sees it.
	for _, ck := range w.Result().Cookies() {
		c.Request.AddCookie(ck)
	}

	proxy.VerifyEmail(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown-user must canonicalize to 400, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "User.NotFound") {
		t.Errorf("response body must NOT leak User.NotFound: %s", w.Body.String())
	}
}

// TestIsLikelyUnknownUserResponse covers the heuristic gate used by
// the three canonicalization sites. False positives (canonicalizing a
// non-User-NotFound 404) would break legitimate error reporting; false
// negatives would defeat the F-sec-7 anti-enumeration shield.
func TestIsLikelyUnknownUserResponse(t *testing.T) {
	cases := []struct {
		name string
		code int
		body string
		want bool
	}{
		{"Zitadel User.NotFound 404", http.StatusNotFound, `{"code":5,"message":"Errors.User.NotFound (X)"}`, true},
		{"NOT_FOUND text 404", http.StatusNotFound, `{"code":"NOT_FOUND","message":"x"}`, true},
		{"non-404 status (real user, wrong creds)", http.StatusBadRequest, `{"code":7,"message":"Password is invalid"}`, false},
		{"404 without User.NotFound marker (e.g. unknown route)", http.StatusNotFound, `{"code":5,"message":"some other 404"}`, false},
		{"500 (upstream outage)", http.StatusInternalServerError, `{"code":13,"message":"Internal"}`, false},
		{"200 (success)", http.StatusOK, `{"details":{}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isLikelyUnknownUserResponse(tc.code, []byte(tc.body))
			if got != tc.want {
				t.Errorf("isLikelyUnknownUserResponse(code=%d, body=%q) = %v, want %v", tc.code, tc.body, got, tc.want)
			}
		})
	}
}

// TestIsIssuedDecoyOrgID_PrunesExpired: the decoy orgId tracker
// expires entries after `decoyOrgTTL` and prunes inline on lookup.
func TestIsIssuedDecoyOrgID_PrunesExpired(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	// Seed a fresh entry → looked-up as live.
	proxy.storeDecoyOrgID("fresh", time.Now().Add(decoyOrgTTL))
	if !proxy.isIssuedDecoyOrgID("fresh") {
		t.Errorf("fresh decoy entry must report as issued")
	}
	// Seed an expired entry → looked-up as not-issued AND pruned.
	proxy.storeDecoyOrgID("stale", time.Now().Add(-1*time.Hour))
	if proxy.isIssuedDecoyOrgID("stale") {
		t.Errorf("stale decoy entry must NOT report as issued")
	}
	if _, ok := proxy.loadDecoyOrgIDExpiry("stale"); ok {
		t.Errorf("stale decoy entry must be pruned from the map after lookup")
	}
}

// Round 25 hardening (item 27 / R25b F6): deriveDecoySequence pins the
// determinism contract. Same secret + key MUST produce the same value
// on every call — otherwise an attacker probing the same loginName
// twice would see divergent decoy responses (a wire-distinguisher
// from real users, whose responses are stable across probes). Output
// must also be in the documented [1, 50] range.
func TestDeriveDecoySequence_DeterministicAndBounded(t *testing.T) {
	secret := []byte("test-secret-32-bytes-of-entropy!")
	keys := []string{"alice@example.com", "bob@example.com", "", "carol", "dave@x"}

	for _, k := range keys {
		got1 := deriveDecoySequence(secret, k)
		got2 := deriveDecoySequence(secret, k)
		if got1 != got2 {
			t.Errorf("deriveDecoySequence(%q) is non-deterministic: %q vs %q", k, got1, got2)
		}
		var n int
		if _, err := fmt.Sscanf(got1, "%d", &n); err != nil {
			t.Errorf("deriveDecoySequence(%q) = %q, not a valid integer: %v", k, got1, err)
			continue
		}
		if n < 1 || n > 50 {
			t.Errorf("deriveDecoySequence(%q) = %d, outside [1, 50]", k, n)
		}
	}
}

// Round 25 Wave 3 (item 24 / R25c H-3): the decoyOrgIDs map is now
// LRU-bounded. An attacker probing many distinct loginNames must NOT
// grow memory unbounded — overflow evicts the LRU entry.
func TestDecoyOrgIDs_LRUEvictionOnOverflow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	proxy.decoyOrgIDsCap = 3 // shrink for the test

	future := time.Now().Add(decoyOrgTTL)
	proxy.storeDecoyOrgID("a", future)
	proxy.storeDecoyOrgID("b", future)
	proxy.storeDecoyOrgID("c", future)
	proxy.storeDecoyOrgID("d", future) // evicts "a"

	if _, ok := proxy.decoyOrgIDsEntries["a"]; ok {
		t.Errorf("LRU should have evicted 'a' on overflow")
	}
	if proxy.decoyOrgIDsLRU.Len() != 3 {
		t.Errorf("LRU list length: want 3, got %d", proxy.decoyOrgIDsLRU.Len())
	}
	for _, k := range []string{"b", "c", "d"} {
		if _, ok := proxy.decoyOrgIDsEntries[k]; !ok {
			t.Errorf("expected %q to remain", k)
		}
	}
}

// Round 25 Wave 3 (item 24 / R25c H-3): the sweeper goroutine must
// prune entries past their expiry. Manually invoke sweepDecoyOrgIDs
// (deterministic — don't rely on the background ticker's timing).
func TestDecoyOrgIDs_SweeperPrunesExpired(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	// Mix of expired + fresh entries.
	proxy.storeDecoyOrgID("expired-1", time.Now().Add(-time.Minute))
	proxy.storeDecoyOrgID("fresh-1", time.Now().Add(decoyOrgTTL))
	proxy.storeDecoyOrgID("expired-2", time.Now().Add(-time.Hour))
	proxy.storeDecoyOrgID("fresh-2", time.Now().Add(decoyOrgTTL))

	proxy.sweepDecoyOrgIDs()

	for _, k := range []string{"expired-1", "expired-2"} {
		if _, ok := proxy.decoyOrgIDsEntries[k]; ok {
			t.Errorf("expected sweeper to prune %q", k)
		}
	}
	for _, k := range []string{"fresh-1", "fresh-2"} {
		if _, ok := proxy.decoyOrgIDsEntries[k]; !ok {
			t.Errorf("sweeper must NOT prune fresh entry %q", k)
		}
	}
}

// Round 25 Wave 3 (item 24 / R25c H-3): StopDecoyOrgIDsSweeper is
// idempotent (safe to call twice without panic).
func TestDecoyOrgIDs_StopSweeperIsIdempotent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	proxy.StopDecoyOrgIDsSweeper()
	proxy.StopDecoyOrgIDsSweeper() // must not panic on double-close
}

// Round 25 Wave 5 (item 5 / Round 23 Finding 5): allowPostLogoutRedirect
// must accept relative paths + the configured PublicFrontendURL host
// + extra-hosts list, and refuse anything else.
func TestAllowPostLogoutRedirect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL:     upstream.URL,
		PAT:                    "pat",
		PublicFrontendURL:      "https://app.example.com",
		PostLogoutAllowedHosts: []string{"alt.example.com", "another.test"},
	})
	defer proxy.StopDecoyOrgIDsSweeper()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"relative path", "/login/logout/done", true},
		{"relative with query", "/login/logout/done?reason=manual", true},
		{"absolute matches PublicFrontendURL", "https://app.example.com/done", true},
		{"absolute matches case-insensitive", "https://APP.EXAMPLE.COM/done", true},
		{"absolute matches extra host", "https://alt.example.com/done", true},
		{"absolute matches another extra host", "https://another.test/done", true},
		{"absolute mismatch refused", "https://evil.example/cb", false},
		{"empty refused", "", false},
		{"only-host (no path) but allowed", "https://app.example.com", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := proxy.allowPostLogoutRedirect(tc.in); got != tc.want {
				t.Errorf("allowPostLogoutRedirect(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// Round 25 Wave 5 (item 5 / Round 23 Finding 5): with no
// PublicFrontendURL configured AND no extra hosts, only relative paths
// are allowed. Any absolute redirect is refused, since we have no
// allowlist to match against.
func TestAllowPostLogoutRedirect_NoConfigDeniesAllAbsolute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	// Relative still allowed.
	if !proxy.allowPostLogoutRedirect("/login/logout/done") {
		t.Errorf("relative path must be allowed even with no config")
	}
	// Any absolute is refused.
	for _, in := range []string{"https://app.example.com/done", "https://attacker.example/cb"} {
		if proxy.allowPostLogoutRedirect(in) {
			t.Errorf("absolute %q must be refused with no allowlist configured", in)
		}
	}
}

// Round 25 Wave 6 (item 19 / R25a #3): the session cookie is signed
// with HMAC-SHA256. Round-trip property: a write+read returns the
// same entries.
func TestSessionCookie_SignAndVerifyRoundTrip(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	entries := []sessionEntry{
		{ID: "sess-1", Token: "tok-1", UserID: "u1", LoginName: "alice@x.com"},
		{ID: "sess-2", Token: "tok-2", UserID: "u2", LoginName: "bob@x.com"},
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/")
	proxy.writeSessionCookie(c, entries)

	// Replay the cookie into the request and read back.
	for _, ck := range w.Result().Cookies() {
		c.Request.AddCookie(ck)
	}
	got := proxy.readSessionCookie(c)
	if len(got) != 2 {
		t.Fatalf("round-trip: want 2 entries, got %d", len(got))
	}
	if got[0].ID != "sess-1" || got[1].ID != "sess-2" {
		t.Errorf("round-trip ids mismatch: got %+v", got)
	}
}

// Round 25 Wave 6 (item 19 / R25a #3): a tampered cookie (signature
// modified) MUST be treated as absent — caller silently re-authenticates
// rather than 4xx'ing.
func TestSessionCookie_TamperedSignatureTreatedAsAbsent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/")
	proxy.writeSessionCookie(c, []sessionEntry{{ID: "s", Token: "t", UserID: "u"}})

	// Tamper with the signature: flip a single character at the
	// front of the cookie value.
	cks := w.Result().Cookies()
	if len(cks) == 0 {
		t.Fatal("no cookie set")
	}
	tampered := *cks[0] //nolint:gosec // G124: copying a Set-Cookie struct from the response into the request for a verify-rejection test fixture; production cookies are written by writeSessionCookie with all the right attributes
	if tampered.Value[0] == 'A' {
		tampered.Value = "B" + tampered.Value[1:]
	} else {
		tampered.Value = "A" + tampered.Value[1:]
	}
	c.Request.AddCookie(&tampered)

	got := proxy.readSessionCookie(c)
	if len(got) != 0 {
		t.Errorf("tampered cookie must be treated as absent; got %d entries", len(got))
	}
}

// Round 25 Wave 6 (item 19 / R25a #3): an unsigned legacy cookie
// (raw JSON, no HMAC prefix) MUST be treated as absent. This is the
// rollout-cutover case: any user with a pre-Wave-6 cookie gets a
// silent re-authentication.
func TestSessionCookie_UnsignedLegacyCookieTreatedAsAbsent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/auth/")
	// Inject a raw-JSON cookie with no HMAC prefix.
	c.Request.AddCookie(&http.Cookie{ //nolint:gosec // G124: test fixture for the legacy-cookie rejection path; production cookies are written by writeSessionCookie with all the right attributes
		Name:  SessionCookieName,
		Value: `[{"id":"legacy","token":"t","userId":"u"}]`,
	})

	got := proxy.readSessionCookie(c)
	if len(got) != 0 {
		t.Errorf("unsigned legacy cookie must be treated as absent; got %d entries", len(got))
	}
}

// Round 25 Wave 6 (item 6 / Round 22 OOS): when a shared decoy secret
// is provided via config, two AuthProxy instances produce identical
// decoy ids for the same loginName — the contract HA replicas need.
func TestDecoySecret_SharedAcrossReplicas(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()

	shared := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	a := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat", DecoySecret: shared})
	b := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat", DecoySecret: shared})
	defer a.StopDecoyOrgIDsSweeper()
	defer b.StopDecoyOrgIDsSweeper()

	loginName := "ghost@example.com"
	idA := deriveDecoySnowflake(a.decoySecret, "user:"+loginName)
	idB := deriveDecoySnowflake(b.decoySecret, "user:"+loginName)
	if idA != idB {
		t.Errorf("shared decoy secret must produce identical ids across replicas; got %q vs %q", idA, idB)
	}
}

// Round 25 Wave 6 (item 6 / Round 22 OOS): without a shared secret,
// two AuthProxy instances generate divergent per-process decoy ids
// (the legacy single-replica behaviour, preserved for zero-config
// dev setups).
func TestDecoySecret_DivergesWithoutShared(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()

	a := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	b := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer a.StopDecoyOrgIDsSweeper()
	defer b.StopDecoyOrgIDsSweeper()

	loginName := "ghost@example.com"
	idA := deriveDecoySnowflake(a.decoySecret, "user:"+loginName)
	idB := deriveDecoySnowflake(b.decoySecret, "user:"+loginName)
	if idA == idB {
		t.Errorf("per-process secrets must produce divergent ids (probabilistically impossible to collide); got %q", idA)
	}
}

// Round 25 Wave 6 / Wave 14 revised contract for VerifyEmail:
//
//   - No session cookie → forward to Zitadel. The just-registered-user
//     flow (F7) lands here with no session because CreateUser doesn't
//     mint one. Security on this path comes from the per-userId rate
//     cap + Round 23 F3 unknown-user canonicalization.
//   - Session cookie present but doesn't match the URL :id → 403.
//     This is the cross-user attack the Round-25-Wave-6 gate was
//     written for and it still applies.
//
// The Wave-14 change unblocked F7 self-registration which had been
// silently 403'ing since the original Round-25 gate landed (caught
// 2026-05-10 by manual browser test).
func TestVerifyEmail_NoSessionForwardsToZitadel(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()
	defer proxy.LoginNameLimiter.Stop()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/9999/email", `{"verificationCode":"GOOD"}`)
	c.Params = gin.Params{{Key: "id", Value: "9999"}}

	proxy.VerifyEmail(c)

	if !upstreamCalled {
		t.Errorf("no-session caller (registration flow) MUST forward to Zitadel; upstream wasn't called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("no-session forward must surface Zitadel's status; got %d: %s", w.Code, w.Body.String())
	}
}

// Wave 14: cross-user attack must still 403. Pre-condition: session
// cookie exists, but its UserID doesn't match the URL :id.
func TestVerifyEmail_MismatchedSessionGets403(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("upstream must NOT be called when caller's session doesn't match URL :id")
	}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()
	defer proxy.LoginNameLimiter.Stop()

	// Seed an attacker session bound to user 1111, then probe /9999.
	seedW := httptest.NewRecorder()
	seedC, _ := gin.CreateTestContext(seedW)
	seedC.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/9999/email", `{"verificationCode":"BAD"}`)
	proxy.upsertSessionEntry(seedC, sessionEntry{ID: "s-atk", Token: "t", UserID: "1111"})
	setCks := seedW.Result().Cookies()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/9999/email", `{"verificationCode":"BAD"}`)
	c.Params = gin.Params{{Key: "id", Value: "9999"}}
	for _, ck := range setCks {
		c.Request.AddCookie(ck)
	}

	proxy.VerifyEmail(c)

	if w.Code != http.StatusForbidden {
		t.Errorf("mismatched-session probe must 403; got %d: %s", w.Code, w.Body.String())
	}
}

// Round 25 Wave 6 (item 30 / R25b F1 follow-on): per-userId rate cap
// on VerifyEmail. After enough failed attempts the user is locked
// and subsequent attempts return canonical "Code is invalid" without
// hitting Zitadel.
func TestVerifyEmail_RateLimitTriggersAfterThreshold(t *testing.T) {
	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":9,"message":"Code is invalid"}`))
	}))
	defer upstream.Close()

	// Threshold of 2 keeps the test small.
	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL:        upstream.URL,
		PAT:                       "pat",
		LoginNameLockoutThreshold: 2,
		LoginNameLockoutWindow:    5 * time.Minute,
	})
	defer proxy.StopDecoyOrgIDsSweeper()
	defer proxy.LoginNameLimiter.Stop()

	probeFn := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/uid-rl/email", `{"verificationCode":"BAD"}`)
		c.Params = gin.Params{{Key: "id", Value: "uid-rl"}}
		proxy.upsertSessionEntry(c, sessionEntry{ID: "s-rl", Token: "t", UserID: "uid-rl"})
		for _, ck := range w.Result().Cookies() {
			c.Request.AddCookie(ck)
		}
		// Rewind the writer for the actual call.
		w = httptest.NewRecorder()
		c, _ = gin.CreateTestContext(w)
		c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/uid-rl/email", `{"verificationCode":"BAD"}`)
		c.Params = gin.Params{{Key: "id", Value: "uid-rl"}}
		proxy.upsertSessionEntry(c, sessionEntry{ID: "s-rl", Token: "t", UserID: "uid-rl"})
		// Re-replay the cookie that just got set.
		setCks := w.Result().Cookies()
		w = httptest.NewRecorder()
		c, _ = gin.CreateTestContext(w)
		c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/uid-rl/email", `{"verificationCode":"BAD"}`)
		c.Params = gin.Params{{Key: "id", Value: "uid-rl"}}
		for _, ck := range setCks {
			c.Request.AddCookie(ck)
		}
		proxy.VerifyEmail(c)
		return w
	}

	// First two attempts go through to Zitadel.
	probeFn()
	probeFn()
	gotCalls := upstreamCalls
	if gotCalls < 1 {
		t.Errorf("expected at least one upstream call before rate-limit lock; got %d", gotCalls)
	}

	// Third attempt: rate-limited, must NOT hit upstream, must
	// return canonical 4xx.
	w := probeFn()
	if upstreamCalls > gotCalls {
		t.Errorf("rate-limited probe must NOT call upstream; was %d, now %d", gotCalls, upstreamCalls)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("rate-limited response must be canonical 400; got %d: %s", w.Code, w.Body.String())
	}
}

// Round 26 Wave 9 (HIGH-1): the decoy-path lockout key MUST be
// canonicalised (lowercased) before keying the LoginNameLimiter.
// Without this, an attacker probing `Admin@x.com`, `ADMIN@x.com`,
// `aDmin@x.com` (etc.) creates a separate counter per casing and
// bypasses the per-user lockout entirely.
//
// We can't directly observe the limiter key from outside, so we
// exercise the property: with a threshold of 2, three case-variant
// probes against the same logical user MUST trigger the lockout
// on the third probe (not three separate counters of 1 each that
// never lock). We use BeginAttempt directly with the canonicalised
// key shape this code path now generates.
func TestLoginNameLimiter_CanonicalisedDecoyKey(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL:        upstream.URL,
		PAT:                       "pat",
		LoginNameLockoutThreshold: 2,
		LoginNameLockoutWindow:    5 * time.Minute,
	})
	defer proxy.StopDecoyOrgIDsSweeper()
	defer proxy.LoginNameLimiter.Stop()

	// Three case-variant decoy keys for the SAME logical loginName.
	// Pre-fix, each would key a separate counter and never lock. With
	// canonicalisation, all three contribute to the same counter.
	got1 := proxy.LoginNameLimiter.BeginAttempt("decoy:" + strings.ToLower("Admin@example.com"))
	got2 := proxy.LoginNameLimiter.BeginAttempt("decoy:" + strings.ToLower("ADMIN@example.com"))
	got3 := proxy.LoginNameLimiter.BeginAttempt("decoy:" + strings.ToLower("aDmin@example.com"))

	if !got1 || !got2 {
		t.Fatalf("first two case-variant probes must be allowed under threshold; got %v %v", got1, got2)
	}
	if got3 {
		t.Errorf("third case-variant probe MUST be locked out (threshold=2 reached) — case canonicalisation regression")
	}
}

// Round 27 (CRITICAL, Round 27b): extractLoginNameFromCheck MUST
// canonicalise (lowercase) the loginName so all downstream HMAC
// derivations (decoy snowflakes, lockout keys, decoyOrgIDs, picker
// matching) see the same value regardless of casing the user typed.
// Pre-fix, `Alice@x.com` and `alice@x.com` produced DIFFERENT fake
// user/org ids on the decoy path while a real user with case-
// insensitive Zitadel resolution returned the SAME real ids — a
// real-vs-decoy oracle that re-opened F-sec-7 from a different angle.
func TestExtractLoginNameFromCheck_CanonicalisesCase(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want string
		ok   bool
	}{
		{"lowercase passes through", map[string]any{"checks": map[string]any{"user": map[string]any{"loginName": "alice@example.com"}}}, "alice@example.com", true},
		{"mixed case lowercased", map[string]any{"checks": map[string]any{"user": map[string]any{"loginName": "Alice@Example.COM"}}}, "alice@example.com", true},
		{"all-uppercase lowercased", map[string]any{"checks": map[string]any{"user": map[string]any{"loginName": "ALICE@EXAMPLE.COM"}}}, "alice@example.com", true},
		{"missing checks", map[string]any{}, "", false},
		{"missing user", map[string]any{"checks": map[string]any{}}, "", false},
		{"empty loginName", map[string]any{"checks": map[string]any{"user": map[string]any{"loginName": ""}}}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := extractLoginNameFromCheck(tc.in)
			if got != tc.want || ok != tc.ok {
				t.Errorf("extractLoginNameFromCheck = %q,%v; want %q,%v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// Round 27 (HIGH-4, Round 26 HIGH-4 re-confirmed): allowPostLogoutRedirect
// must reject backslash + leading-double-slash Location values.
// `url.Parse("/\\evil.com/x")` returns Scheme="" Host="" so the
// pre-fix relative-path branch accepted it; browsers then collapse
// `\` → `/` in Location and navigate scheme-relative cross-origin.
func TestAllowPostLogoutRedirect_RejectsBackslashAndProtocolRelative(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: upstream.URL,
		PAT:                "pat",
		PublicFrontendURL:  "https://app.example.com",
	})
	defer proxy.StopDecoyOrgIDsSweeper()

	cases := []string{
		"\\evil.com/path",
		"/\\evil.com/path",
		"//evil.com/path",
		"///evil.com/path",
		"/path\\evil.com",
		"https://app.example.com\\@evil.com/",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if proxy.allowPostLogoutRedirect(in) {
				t.Errorf("MUST reject %q (backslash / scheme-relative open-redirect bypass)", in)
			}
		})
	}
}
