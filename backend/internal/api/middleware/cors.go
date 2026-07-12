// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func CORSMiddleware() gin.HandlerFunc {
	// AUD-070: only credential-trust localhost origins outside production. In production
	// (GIN_MODE=release, the same gate the rest of the app uses) the real frontend origin is
	// configured via CORS_EXTRA_ORIGINS, so trusting any localhost variant there is pure attack
	// surface — a page a victim was tricked into loading from their own localhost could otherwise
	// pivot into the API with credentials.
	allowLocalhost := os.Getenv("GIN_MODE") != "release"

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		var allowedOrigins []string
		// Allowed localhost dev origins (non-production only).
		if allowLocalhost {
			allowedOrigins = append(allowedOrigins,
				"http://localhost:5173", // Vite dev server
				"http://localhost:3000", // Alternative frontend port
				"http://localhost:5174", // Alternative Vite port
				"http://127.0.0.1:5173", // IPv4 localhost
				"http://127.0.0.1:3000", // IPv4 localhost
				"http://127.0.0.1:5174", // IPv4 localhost
				"http://[::1]:5173",     // IPv6 localhost
				"http://[::1]:3000",     // IPv6 localhost
				"http://[::1]:5174",     // IPv6 localhost
			)
		}
		// Extra origins for Cloudflare Tunnel or other public frontend URLs (comma-separated).
		if extra := os.Getenv("CORS_EXTRA_ORIGINS"); extra != "" {
			for _, o := range strings.Split(extra, ",") {
				if o = strings.TrimSpace(o); o != "" {
					allowedOrigins = append(allowedOrigins, o)
				}
			}
		}

		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				allowed = true
				break
			}
		}

		// Also allow if origin is empty (same-origin request) or if it's a localhost variant.
		// This handles cases where the browser sends different localhost formats.
		//
		// Round 24 Finding 2 (HIGH): the previous prefix check
		// (`origin[:16] == "http://localhost"`) matched
		// `http://localhost.evil.com:1234` because there was no
		// host-boundary delimiter — combined with
		// `Allow-Credentials: true` an attacker who tricks a victim
		// into navigating to a `localhost.<attacker>` host could
		// pivot into the auth proxy with cookies attached. The fix:
		// after the literal host prefix, require the next byte to
		// be `:` (port), `/` (path), or end-of-string, anchoring the
		// match to the actual hostname.
		if !allowed && origin != "" && allowLocalhost {
			allowed = isLocalhostOrigin(origin)
		}

		// For OPTIONS requests (preflight), always set CORS headers if origin is present
		// This ensures the browser can complete the preflight check
		if c.Request.Method == "OPTIONS" {
			// Set CORS headers BEFORE checking if origin is allowed
			// This ensures preflight requests succeed even if origin check fails
			if origin != "" {
				// Use the origin (both allowed and development cases use the same origin)
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")
			c.AbortWithStatus(204)
			return
		}

		// For actual requests, set CORS headers if origin is allowed or if it's a localhost variant
		if allowed || origin == "" {
			if origin != "" {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}

		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		c.Next()
	}
}

// isLocalhostOrigin reports whether the given Origin header value is
// a localhost variant on any port. Round 24 Finding 2: anchored on
// the host boundary so `http://localhost.evil.com` does NOT match.
//
// Accepted shapes:
//   - http://localhost            (no port, no path — exact match)
//   - http://localhost:NNNN       (any port)
//   - http://localhost/path        (defensive — Origin headers don't carry paths in practice but be tolerant)
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
