// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestSecurityHeaders_SetsBaseHeaders(t *testing.T) {
	w := runThroughSecurityHeaders(t, false, "")

	wantHeaders := map[string]string{
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "origin-when-cross-origin",
		"X-XSS-Protection":        "0",
		"Permissions-Policy":      "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
		"Content-Security-Policy": "default-src 'self'; connect-src 'self'; frame-ancestors 'none'",
	}
	for k, want := range wantHeaders {
		if got := w.Header().Get(k); got != want {
			t.Errorf("header %s: got %q, want %q", k, got, want)
		}
	}
}

func TestSecurityHeaders_HSTSOnlyOnTLS(t *testing.T) {
	// Plain HTTP: HSTS must NOT be set (would wedge dev against localhost).
	plain := runThroughSecurityHeaders(t, false, "")
	if hsts := plain.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS must not be set on plain HTTP, got %q", hsts)
	}

	// Direct TLS termination at the server.
	direct := runThroughSecurityHeaders(t, true, "")
	if hsts := direct.Header().Get("Strict-Transport-Security"); hsts == "" {
		t.Error("HSTS must be set on direct TLS")
	}

	// Reverse proxy (TLS terminated upstream, forwarded as HTTP).
	fwd := runThroughSecurityHeaders(t, false, "https")
	if hsts := fwd.Header().Get("Strict-Transport-Security"); hsts == "" {
		t.Error("HSTS must be set when X-Forwarded-Proto=https")
	}

	// X-Forwarded-Proto=http must NOT turn HSTS on.
	fwdHTTP := runThroughSecurityHeaders(t, false, "http")
	if hsts := fwdHTTP.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS must not be set for X-Forwarded-Proto=http, got %q", hsts)
	}
}

// runThroughSecurityHeaders exercises the middleware with the given TLS state
// and X-Forwarded-Proto header and returns the recorded response.
func runThroughSecurityHeaders(t *testing.T, directTLS bool, forwardedProto string) *httptest.ResponseRecorder {
	t.Helper()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/oidc/discovery", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if directTLS {
		req.TLS = &tls.ConnectionState{}
	}
	if forwardedProto != "" {
		req.Header.Set("X-Forwarded-Proto", forwardedProto)
	}
	c.Request = req

	handler := SecurityHeaders()
	handler(c)
	return w
}
