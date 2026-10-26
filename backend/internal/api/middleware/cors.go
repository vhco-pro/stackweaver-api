// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// corsAllowHeaders are the request headers a cross-origin caller may send. CSRFHeader is among
// them, or a split-host browser could never send it.
const corsAllowHeaders = "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, " + CSRFHeader

// CORSMiddleware answers cross-origin requests for the origins p trusts: the app's own origin,
// CORS_EXTRA_ORIGINS, and localhost outside release mode (AUD-070, see OriginPolicyFromEnv).
//
// Round 24 Finding 2 (HIGH): a localhost origin is matched on the host boundary, so
// `http://localhost.evil.com` is not localhost (isLocalhostOrigin).
func CORSMiddleware(p OriginPolicy) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		allowed := p.Allows(origin)

		// The answer depends on the Origin, so a shared cache must not serve one origin's answer
		// to another.
		c.Writer.Header().Add("Vary", "Origin")

		// For OPTIONS requests (preflight), reflect the origin only when it is allowed.
		// AUD-157: the preflight previously set Access-Control-Allow-Origin + Allow-Credentials
		// for ANY origin before consulting `allowed`, so an arbitrary origin got a credentialed
		// 204. The preflight must match the gate on real requests.
		if c.Request.Method == http.MethodOptions {
			if allowed {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			c.Writer.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		if allowed {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		c.Writer.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		c.Next()
	}
}

// isLocalhostOrigin reports whether the given Origin header value is
// a localhost variant on any port. Round 24 Finding 2: anchored on
// the host boundary so `http://localhost.evil.com` does NOT match.
//
// Accepted shapes:
//   - http://localhost            (no port, no path - exact match)
//   - http://localhost:NNNN       (any port)
//   - http://localhost/path        (defensive - Origin headers don't carry paths in practice but be tolerant)
//   - same for http://127.0.0.1 and http://[::1]
//
// Rejected:
//   - http://localhost.evil.com   (the dot is not a host boundary)
//   - http://localhostevil        (no separator)
//   - https://localhost           (we only allow http for the dev allowlist)
func isLocalhostOrigin(origin string) bool {
	for _, host := range []string{"http://localhost", "http://127.0.0.1", "http://[::1]"} {
		if origin == host {
			return true
		}
		if len(origin) > len(host) && origin[:len(host)] == host {
			next := origin[len(host)]
			if next == ':' || next == '/' {
				return true
			}
		}
	}
	return false
}
