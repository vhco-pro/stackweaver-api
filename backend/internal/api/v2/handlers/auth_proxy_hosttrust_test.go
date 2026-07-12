// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// AUD-113/AUD-071: the public host used to build the OIDC discovery doc and IdP redirect URLs must
// not be steerable by a forged X-Forwarded-Host / X-Zitadel-* header once a trusted-host allowlist is
// configured. Before the fix, getPublicHost returned any header value verbatim.

// newUnconfiguredProxy builds an AuthProxy with no public-URL allowlist — the dev/same-origin case
// where forwarding headers are trusted verbatim (legacy behavior).
func newUnconfiguredProxy() *AuthProxy {
	return NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: "http://localhost:8080"})
}

func hostReq(t *testing.T, headers map[string]string, host string) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequest(http.MethodGet, "/")
	if host != "" {
		c.Request.Host = host
	}
	for k, v := range headers {
		c.Request.Header.Set(k, v)
	}
	return c
}

func TestGetPublicHost_ForgedHeaderIgnoredWhenConfigured(t *testing.T) {
	// Split-domain production config: api on api.example.com, SPA on app.example.com.
	p := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: "http://localhost:8080",
		PublicAPIBaseURL:   "https://api.example.com",
		PublicFrontendURL:  "https://app.example.com",
		IsProduction:       true,
	})

	cases := []struct {
		name    string
		headers map[string]string
		host    string
		want    string
	}{
		{"forged X-Forwarded-Host is ignored → canonical", map[string]string{"X-Forwarded-Host": "evil.attacker.com"}, "api.example.com", "api.example.com"},
		{"forged X-Zitadel-Public-Host is ignored → canonical", map[string]string{"X-Zitadel-Public-Host": "evil.attacker.com"}, "api.example.com", "api.example.com"},
		{"forged header + forged Host → canonical, never attacker", map[string]string{"X-Forwarded-Host": "evil.attacker.com"}, "evil.attacker.com", "api.example.com"},
		{"trusted api host honored", map[string]string{"X-Forwarded-Host": "api.example.com"}, "api.example.com", "api.example.com"},
		{"trusted frontend host honored", map[string]string{"X-Forwarded-Host": "app.example.com"}, "api.example.com", "app.example.com"},
		{"trusted host with port normalizes", map[string]string{"X-Forwarded-Host": "api.example.com:443"}, "api.example.com", "api.example.com:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.getPublicHost(hostReq(t, tc.headers, tc.host)); got != tc.want {
				t.Fatalf("getPublicHost = %q, want %q", got, tc.want)
			}
			// And the derived base URL must never carry the attacker host.
			if base := p.getPublicBaseURL(hostReq(t, tc.headers, tc.host)); base == "https://evil.attacker.com" || base == "http://evil.attacker.com" {
				t.Fatalf("getPublicBaseURL leaked attacker host: %q", base)
			}
		})
	}
}

func TestGetPublicHost_UnconfiguredTrustsHeader(t *testing.T) {
	// Dev / same-origin: no public URLs configured → allowlist empty → legacy behavior (trust header),
	// so localhost same-origin deployments keep working.
	p := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: "http://localhost:8080",
		IsProduction:       false,
	})
	c := hostReq(t, map[string]string{"X-Forwarded-Host": "localhost:5173"}, "localhost:8022")
	if got := p.getPublicHost(c); got != "localhost:5173" {
		t.Fatalf("unconfigured getPublicHost = %q, want header value localhost:5173", got)
	}
}
