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
// anchor — the previous prefix check (`origin[:16] == "http://
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
		// Accepted shapes — exact host, host:port, host/path
		{"localhost no port", "http://localhost", true},
		{"localhost with port 5173", "http://localhost:5173", true},
		{"localhost with port 3000", "http://localhost:3000", true},
		{"localhost with path", "http://localhost/some-path", true},
		{"127.0.0.1 no port", "http://127.0.0.1", true},
		{"127.0.0.1 with port", "http://127.0.0.1:8080", true},
		{"IPv6 localhost no port", "http://[::1]", true},
		{"IPv6 localhost with port", "http://[::1]:5173", true},

		// THE FINDING — these used to be accepted, now rejected
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
