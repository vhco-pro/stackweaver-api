// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// The origin allowlist and the browser-request check behind the session cookie
// (backend-for-frontend-session-plan.md, AC4, AC27, AC39).

// AC27: a default install sets STACKWEAVER_APP_URL and leaves CORS_EXTRA_ORIGINS empty, and its
// own origin must be allowed.
func TestOriginPolicyFromEnv_AllowsTheAppOriginWithNoExtraOrigins(t *testing.T) {
	t.Setenv("GIN_MODE", "release")
	t.Setenv("STACKWEAVER_APP_URL", "https://sw.example.com/some/path")
	t.Setenv("CORS_EXTRA_ORIGINS", "")
	p := OriginPolicyFromEnv()

	for origin, want := range map[string]bool{
		"https://sw.example.com":         true,
		"https://sw.example.com/":        true,
		"http://sw.example.com":          false, // another scheme is another origin
		"https://sw.example.com:8443":    false,
		"https://evil.example.com":       false,
		"http://localhost:5173":          false, // release mode trusts no localhost
		"https://sw.example.com.evil.io": false,
		"":                               false,
	} {
		if got := p.Allows(origin); got != want {
			t.Errorf("Allows(%q) = %v, want %v", origin, got, want)
		}
	}
}

func TestOriginPolicyFromEnv_ExtraOriginsAndLocalhostOutsideRelease(t *testing.T) {
	t.Setenv("GIN_MODE", "debug")
	t.Setenv("STACKWEAVER_APP_URL", "")
	t.Setenv("CORS_EXTRA_ORIGINS", " https://tunnel.example.com , https://other.example.com")
	p := OriginPolicyFromEnv()

	for origin, want := range map[string]bool{
		"https://tunnel.example.com":  true,
		"https://other.example.com":   true,
		"http://localhost:5173":       true,
		"http://localhost:5202":       true, // a worktree slot's Vite port
		"http://localhost.evil.com":   false,
		"https://unlisted.example.io": false,
	} {
		if got := p.Allows(origin); got != want {
			t.Errorf("Allows(%q) = %v, want %v", origin, got, want)
		}
	}
}

// AC4: the matrix for a request that rides on the session cookie.
func TestCheckBrowserRequest(t *testing.T) {
	p := NewOriginPolicy(false, "https://sw.example.com")
	cases := []struct {
		name    string
		method  string
		csrf    string
		origin  string
		referer string
		ok      bool
	}{
		{"GET with the header", http.MethodGet, "1", "", "", true},
		{"GET without the header", http.MethodGet, "", "", "", false},
		{"GET with a wrong header value", http.MethodGet, "yes", "", "", false},
		{"POST from the app origin", http.MethodPost, "1", "https://sw.example.com", "", true},
		{"POST with an app Referer", http.MethodPost, "1", "", "https://sw.example.com/workspaces/x", true},
		{"POST without the header", http.MethodPost, "", "https://sw.example.com", "", false},
		{"POST from a foreign origin", http.MethodPost, "1", "https://evil.example.com", "", false},
		{"POST with a foreign Referer", http.MethodPost, "1", "", "https://evil.example.com/page", false},
		{"POST with neither Origin nor Referer", http.MethodPost, "1", "", "", false},
		{"DELETE with neither Origin nor Referer", http.MethodDelete, "1", "", "", false},
		{"PATCH from the app origin", http.MethodPatch, "1", "https://sw.example.com", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), tc.method, "/api/v2/thing", nil)
			if tc.csrf != "" {
				req.Header.Set(CSRFHeader, tc.csrf)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			err := p.CheckBrowserRequest(req)
			if (err == nil) != tc.ok {
				t.Errorf("CheckBrowserRequest = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// The session endpoints carry the same check as a middleware, answering 403 with nothing run.
func TestRequireBrowserRequest(t *testing.T) {
	r := gin.New()
	reached := false
	r.POST("/auth/session", RequireBrowserRequest(NewOriginPolicy(false, "https://sw.example.com")), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusCreated)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/session", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://sw.example.com")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || reached {
		t.Fatalf("a POST without %s answered %d (handler reached: %v)", CSRFHeader, w.Code, reached)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/session", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://sw.example.com")
	req.Header.Set(CSRFHeader, "1")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated || !reached {
		t.Fatalf("a POST from the app with %s answered %d", CSRFHeader, w.Code)
	}
}

// AC39: Zitadel's back-channel logout POST carries no Origin, Referer or CSRF header, and the
// /auth group's own check still lets it through.
func TestCSRFProtection_BackChannelPostWithNoHeadersPasses(t *testing.T) {
	r := gin.New()
	r.Use(CSRFProtection(NewOriginPolicy(false, "https://sw.example.com")))
	r.POST("/auth/oidc/end-session", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/oidc/end-session", strings.NewReader("logout_token=x")))
	if w.Code != http.StatusOK {
		t.Fatalf("the back-channel POST answered %d", w.Code)
	}
}

// CORS answers per origin, so a shared cache must key on it, and the SPA's CSRF header must be
// allowed on a preflight or a split-host browser could never send it.
func TestCORSMiddleware_VaryAndCSRFHeader(t *testing.T) {
	t.Setenv("GIN_MODE", "release")
	t.Setenv("STACKWEAVER_APP_URL", "https://sw.example.com")
	t.Setenv("CORS_EXTRA_ORIGINS", "")
	cors := CORSMiddleware(OriginPolicyFromEnv())

	for _, method := range []string{http.MethodOptions, http.MethodGet} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequestWithContext(context.Background(), method, "/api/v2/organizations", nil)
		req.Header.Set("Origin", "https://sw.example.com")
		c.Request = req
		cors(c)
		if !strings.Contains(w.Header().Get("Vary"), "Origin") {
			t.Errorf("%s: Vary = %q, want it to name Origin", method, w.Header().Get("Vary"))
		}
		if !strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), CSRFHeader) {
			t.Errorf("%s: Access-Control-Allow-Headers = %q, want %s", method, w.Header().Get("Access-Control-Allow-Headers"), CSRFHeader)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://sw.example.com" {
			t.Errorf("%s: the app origin was not allowed with CORS_EXTRA_ORIGINS empty: %q", method, got)
		}
	}
}

// Sign-out is a form POST, which cannot carry the CSRF header, so it must come from a trusted
// origin: a page on another site, or on a sibling host of the same site, cannot sign anyone out,
// and neither can a GET link.
func TestCheckBrowserNavigation(t *testing.T) {
	p := NewOriginPolicy(false, "https://app.example.com")
	cases := []struct {
		name    string
		method  string
		headers map[string]string
		wantOK  bool
	}{
		{"form POST from the app", http.MethodPost, map[string]string{"Origin": "https://app.example.com"}, true},
		{"form POST with only a Referer from the app", http.MethodPost, map[string]string{"Referer": "https://app.example.com/dashboard"}, true},
		{"form POST from a sibling host of the same site", http.MethodPost, map[string]string{"Origin": "https://evil.example.com"}, false},
		{"form POST from another site", http.MethodPost, map[string]string{"Origin": "https://attacker.test"}, false},
		{"form POST with an opaque origin", http.MethodPost, map[string]string{"Origin": "null"}, false},
		{"form POST with neither Origin nor Referer", http.MethodPost, nil, false},
		{"a GET link, even from the app", http.MethodGet, map[string]string{"Origin": "https://app.example.com"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), tc.method, "/auth/session/end", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if err := p.CheckBrowserNavigation(r); (err == nil) != tc.wantOK {
				t.Fatalf("CheckBrowserNavigation = %v, want ok=%v", err, tc.wantOK)
			}
		})
	}
}
