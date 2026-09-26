// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
)

// AUD-113/AUD-071: the public host used to build the OIDC discovery doc and IdP redirect URLs must
// not be steerable by a forged X-Forwarded-Host / X-Zitadel-* header once a trusted-host allowlist is
// configured. Before the fix, getPublicHost returned any header value verbatim.

// newUnconfiguredProxy builds an AuthProxy with no public-URL allowlist - the dev/same-origin case
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

// TestGetPublicBaseURL_MalformedHeadersCannotEscapeAllowlist is the AUD-113 residual:
// normalizeHost was a bare net.SplitHostPort, which splits on the last colon and
// validates neither side, so `localhost:1@evil.attacker.com` normalized to `localhost`,
// passed the allowlist, and getPublicHost returned the RAW value - which a URL parser
// reads as userinfo `localhost:1` on host `evil.attacker.com`. X-Forwarded-Proto was
// likewise concatenated verbatim. Every derived base URL must parse to a trusted host.
func TestGetPublicBaseURL_MalformedHeadersCannotEscapeAllowlist(t *testing.T) {
	p := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: "http://localhost:8080",
		PublicAPIBaseURL:   "https://api.example.com",
		PublicFrontendURL:  "http://localhost:5173",
		IsProduction:       true,
	})
	trusted := map[string]bool{"api.example.com": true, "localhost": true}

	cases := []struct {
		name    string
		headers map[string]string
	}{
		{"userinfo smuggled past the trusted host", map[string]string{"X-Forwarded-Host": "localhost:1@evil.attacker.com"}},
		{"userinfo on the api host", map[string]string{"X-Zitadel-Public-Host": "api.example.com:443@evil.attacker.com"}},
		{"path after the trusted host", map[string]string{"X-Forwarded-Host": "api.example.com/@evil.attacker.com"}},
		{"fragment after the trusted host", map[string]string{"X-Forwarded-Host": "api.example.com#@evil.attacker.com"}},
		{"backslash authority confusion", map[string]string{"X-Forwarded-Host": "api.example.com\\@evil.attacker.com"}},
		{"forged scheme rewrites the origin", map[string]string{"X-Forwarded-Proto": "https://evil.attacker.com/#", "X-Forwarded-Host": "api.example.com"}},
		{"forged scheme with a trailing proxy hop", map[string]string{"X-Forwarded-Proto": "javascript, https"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := p.getPublicBaseURL(hostReq(t, tc.headers, "api.example.com"))
			u, err := url.Parse(base)
			if err != nil {
				t.Fatalf("base URL %q does not parse: %v", base, err)
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				t.Fatalf("base URL %q has scheme %q, want http or https", base, u.Scheme)
			}
			if u.User != nil || u.Path != "" || u.Fragment != "" || u.RawQuery != "" {
				t.Fatalf("base URL %q carries more than scheme://host[:port]", base)
			}
			if !trusted[u.Hostname()] {
				t.Fatalf("base URL %q resolves to untrusted host %q", base, u.Hostname())
			}
		})
	}
}

func TestGetPublicHost_UnconfiguredRejectsMalformedHeader(t *testing.T) {
	// Trust-all (no allowlist) still only echoes a syntactically plain authority.
	p := newUnconfiguredProxy()
	c := hostReq(t, map[string]string{"X-Forwarded-Host": "evil.attacker.com/phish?x=@a"}, "localhost:8022")
	if got := p.getPublicHost(c); got != "localhost:8022" {
		t.Fatalf("unconfigured getPublicHost = %q, want the valid Host localhost:8022", got)
	}
}

func TestCanonicalHost(t *testing.T) {
	cases := map[string]string{
		"api.example.com":               "api.example.com",
		"API.Example.com:8443":          "api.example.com:8443",
		"stackweaver_api:8022":          "stackweaver_api:8022",
		"10.0.0.1:80":                   "10.0.0.1:80",
		"[::1]:8080":                    "[::1]:8080",
		"[::1]":                         "[::1]",
		"::1":                           "[::1]",
		"":                              "",
		"localhost:1@evil.attacker.com": "",
		"localhost:":                    "",
		"localhost:0":                   "",
		"localhost:65536":               "",
		"localhost:080":                 "",
		"a..b":                          "",
		"host/path":                     "",
		"user@host":                     "",
		"[1.2.3.4]:80":                  "",
		"[::1]:8080@evil.com":           "",
	}
	for in, want := range cases {
		if got := canonicalHost(in); got != want {
			t.Errorf("canonicalHost(%q) = %q, want %q", in, got, want)
		}
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
