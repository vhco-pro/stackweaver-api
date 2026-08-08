// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestIsLocalhostOrigin pins Round 24 Finding 2's host-boundary
// anchor - the previous prefix check (`origin[:16] == "http://
// localhost"`) accepted `http://localhost.evil.com` because there
// was no delimiter. Combined with `Allow-Credentials: true` an
// attacker who tricks a victim into navigating to a `localhost.<a>`
// host could pivot into the auth proxy with cookies attached. The
// fix anchors on a `:`/`/`/end-of-string boundary after the host.
func TestIsLocalhostOrigin(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		want   bool
	}{
		// Accepted shapes - exact host, host:port, host/path
		{"localhost no port", "http://localhost", true},
		{"localhost with port 5173", "http://localhost:5173", true},
		{"localhost with port 3000", "http://localhost:3000", true},
		{"localhost with path", "http://localhost/some-path", true},
		{"127.0.0.1 no port", "http://127.0.0.1", true},
		{"127.0.0.1 with port", "http://127.0.0.1:8080", true},
		{"IPv6 localhost no port", "http://[::1]", true},
		{"IPv6 localhost with port", "http://[::1]:5173", true},

		// THE FINDING - these used to be accepted, now rejected
		{"R24-2: localhost.evil.com", "http://localhost.evil.com", false},
		{"R24-2: localhost.evil.com:1234", "http://localhost.evil.com:1234", false},
		{"R24-2: localhostevil (no dot)", "http://localhostevil", false},
		{"R24-2: 127.0.0.1.evil.com", "http://127.0.0.1.evil.com", false},
		{"R24-2: [::1].evil.com", "http://[::1].evil.com", false},

		// Other shapes that should be rejected
		{"https localhost (we only allow http here)", "https://localhost", false},
		{"https localhost with port", "https://localhost:5173", false},
		{"localhost as path under another domain", "http://evil.com/localhost", false},
		{"empty origin", "", false},
		{"random domain", "http://example.com", false},
		{"trailing junk after host", "http://localhost?q=1", false}, // Origin headers don't carry queries; reject defensively
		{"trailing junk after host (#)", "http://localhost#frag", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isLocalhostOrigin(tc.origin)
			if got != tc.want {
				t.Errorf("isLocalhostOrigin(%q) = %v, want %v", tc.origin, got, tc.want)
			}
		})
	}
}

// TestCORSMiddleware_LocalhostGatedByProdMode covers AUD-070: a localhost Origin is credential-
// trusted only outside production. In GIN_MODE=release the middleware must NOT echo the localhost
// origin or set Allow-Credentials; outside release it must (dev convenience).
func TestCORSMiddleware_LocalhostGatedByProdMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const localhostOrigin = "http://localhost:5173"

	run := func(ginMode string) (allowOrigin, allowCreds string) {
		t.Setenv("GIN_MODE", ginMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v2/ping", nil)
		req.Header.Set("Origin", localhostOrigin)
		c.Request = req
		CORSMiddleware()(c)
		return w.Header().Get("Access-Control-Allow-Origin"), w.Header().Get("Access-Control-Allow-Credentials")
	}

	// Production: localhost must NOT be trusted.
	if o, cr := run("release"); o != "" || cr != "" {
		t.Errorf("release mode credential-trusted localhost: origin=%q creds=%q, want both empty", o, cr)
	}
	// Development: localhost trusted for convenience.
	if o, cr := run("debug"); o != localhostOrigin || cr != "true" {
		t.Errorf("debug mode did not trust localhost: origin=%q creds=%q, want %q/true", o, cr, localhostOrigin)
	}
}

// AUD-157: the OPTIONS preflight must reflect Access-Control-Allow-Origin (+ credentials) only for
// allowed origins - previously it reflected ANY origin before the allowed check.
func TestCORSPreflight_GatedOnAllowedOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("GIN_MODE", "release") // localhost not trusted; only CORS_EXTRA_ORIGINS allowed
	t.Setenv("CORS_EXTRA_ORIGINS", "https://app.example.com")

	preflight := func(origin string) (allowOrigin, allowCreds string, code int) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodOptions, "/api/v2/organizations", nil)
		req.Header.Set("Origin", origin)
		c.Request = req
		CORSMiddleware()(c)
		return w.Header().Get("Access-Control-Allow-Origin"), w.Header().Get("Access-Control-Allow-Credentials"), w.Code
	}

	// Disallowed origin: no credentialed CORS headers on the preflight (the bug).
	if o, cr, _ := preflight("https://evil.com"); o != "" || cr != "" {
		t.Errorf("preflight reflected disallowed origin: origin=%q creds=%q, want both empty", o, cr)
	}
	// Allowed origin: preflight still works.
	if o, cr, _ := preflight("https://app.example.com"); o != "https://app.example.com" || cr != "true" {
		t.Errorf("preflight did not honor allowed origin: origin=%q creds=%q, want app.example.com/true", o, cr)
	}
}
