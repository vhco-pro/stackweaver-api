// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// MaxBodyBytes wraps the request body in an http.MaxBytesReader so any
// downstream call to ShouldBindJSON / io.ReadAll fails fast with a 413
// once `limit` bytes have been consumed.
//
// Round 25c Finding C-2 (CRITICAL): the auth proxy handlers all call
// `c.ShouldBindJSON` with no upstream cap. The /auth/* surface is
// unauthenticated by design (the user hasn't logged in yet), so a
// single attacker streaming a multi-GB body to /auth/sessions can
// exhaust API memory before any handler-level validation runs.
//
// 64KiB is the chosen default — every legitimate auth body fits in a
// few KB (loginName, password, TOTP code, passkey assertion). The cap
// is generous enough that no real flow trips it but tight enough that
// a flood of the maximum size is bounded at ~6.4MB per 100 in-flight
// connections (vs. unbounded today).
func MaxBodyBytes(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil && c.Request.ContentLength > limit {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "request body too large",
			})
			return
		}
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		}
		c.Next()
	}
}
