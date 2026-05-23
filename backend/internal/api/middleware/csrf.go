// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// CSRFProtection validates Origin and Referer headers on mutating requests
// to /auth/* endpoints. Required because SameSite=Lax alone is not sufficient
// for SPA-to-API CSRF protection (see plan D6).
//
// For non-mutating methods (GET, HEAD, OPTIONS) this is a no-op.
func CSRFProtection(allowedOrigins []string) gin.HandlerFunc {
	// Build a set for O(1) lookup
	originSet := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[strings.TrimRight(o, "/")] = struct{}{}
	}

	return func(c *gin.Context) {
		// Only validate mutating methods
		method := c.Request.Method
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			c.Next()
			return
		}

		// Check Origin header first (preferred, always present in CORS requests)
		origin := c.GetHeader("Origin")
		if origin != "" {
			if _, ok := originSet[strings.TrimRight(origin, "/")]; ok {
				c.Next()
				return
			}
			// Origin present but not in allowlist — reject
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "cross-origin request blocked",
			})
			c.Abort()
			return
		}

		// No Origin header — fall back to Referer
		referer := c.GetHeader("Referer")
		if referer != "" {
			parsed, err := url.Parse(referer)
			if err == nil {
				refererOrigin := parsed.Scheme + "://" + parsed.Host
				if _, ok := originSet[strings.TrimRight(refererOrigin, "/")]; ok {
					c.Next()
					return
				}
			}
			// Referer present but not from allowed origin — reject
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "cross-origin request blocked",
			})
			c.Abort()
			return
		}

		// No Origin AND no Referer — this can happen with direct API calls (curl, etc.)
		// or same-origin requests in some browsers. Allow it — the session cookie
		// provides the authorization, and SameSite=Lax prevents cross-site attachment.
		c.Next()
	}
}
