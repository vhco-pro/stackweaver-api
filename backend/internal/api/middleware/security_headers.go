// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders sets conservative security headers on responses from the
// auth proxy. Mirrors the set enforced by the official Zitadel login UI in
// its next.config.mjs so behaviour is identical after the cutover. Plan
// reference: A10.1.
//
//   - X-Frame-Options: DENY prevents login pages from being framed by a
//     malicious parent (clickjacking).
//   - X-Content-Type-Options: nosniff keeps browsers from MIME-sniffing
//     JSON responses into executable types.
//   - Referrer-Policy: origin-when-cross-origin prevents query strings
//     (auth_request, tokens in URLs) from leaking on outbound navigation.
//   - X-XSS-Protection: 0 disables the legacy, buggy XSS auditor (CSP is the
//     modern replacement). Mirrors the frontend nginx set.
//   - Permissions-Policy: deny browser features the API never uses. Mirrors
//     the frontend nginx set.
//   - Content-Security-Policy: connect-src 'self' — tight default so the
//     login SPA can only talk to the same origin. Harmless on JSON
//     responses (browsers apply CSP to the document that initiated the
//     request, not to this response directly), but kept for parity and so
//     reverse proxies that forward the header see a consistent policy.
//   - Strict-Transport-Security: only set when the incoming request is
//     TLS-terminated (direct TLS or an X-Forwarded-Proto=https hop). HSTS
//     on plain HTTP is a no-op, and setting it on dev (localhost, http)
//     can wedge the browser into refusing subsequent plain-http sessions
//     for that host.
//
// Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy are deliberately
// NOT set here. They are document/window isolation headers meant for the HTML
// app shell (the frontend nginx layer sets them); CORP: same-origin on the JSON
// API would break legitimate cross-origin consumers (the SPA on a split-host
// deployment, and browser-based API clients that rely on CORS).
//
// This middleware does NOT honour getSecuritySettings().iframe_enabled yet;
// iframe-embed support is tracked in AC-39 and requires relaxing
// X-Frame-Options + switching the session cookie to SameSite=None.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "origin-when-cross-origin")
		h.Set("X-XSS-Protection", "0")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		h.Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; frame-ancestors 'none'")

		if isTLS(c.Request) {
			// 1 year, include subdomains. Don't set preload — that's an opt-in
			// registry commitment the operator should make deliberately.
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}

// isTLS reports whether the request arrived over TLS, accounting for the
// common case of a reverse proxy terminating TLS and forwarding via HTTP.
func isTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" {
		return true
	}
	return false
}
