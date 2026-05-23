// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build e2e

// This file is only compiled into binaries built with the `e2e` build tag.
// The companion `testing_noop.go` provides a production-safe stub so the
// call site in setupAuthProxyRoutes compiles unconditionally.
//
// Double-gated per plan A14:
//   - build tag: file only present in e2e binaries.
//   - runtime env: handler returns 404 unless STACKWEAVER_ENV=e2e-test.

package routes

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	v2handlers "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
)

// testingE2EEnvValue is the exact value STACKWEAVER_ENV must have for the
// reset endpoint to serve. Anything else (unset, "production", "staging",
// typos like "e2e") returns 404 as if the route did not exist.
const testingE2EEnvValue = "e2e-test"

func registerTestingRoutes(r *gin.RouterGroup, limiter *middleware.IPRateLimiter, proxy *v2handlers.AuthProxy) {
	r.POST("/testing/reset", testingResetHandler(limiter, proxy))
}

func testingResetHandler(limiter *middleware.IPRateLimiter, proxy *v2handlers.AuthProxy) gin.HandlerFunc {
	return func(c *gin.Context) {
		if os.Getenv("STACKWEAVER_ENV") != testingE2EEnvValue {
			// Deliberately indistinguishable from an unregistered route so a
			// misbuilt production binary behaves like a production binary.
			// AbortWithStatus — c.Status alone is buffered until handler return,
			// which test recorders read as the default 200.
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		cleared := []string{}
		if limiter != nil {
			limiter.Reset()
			cleared = append(cleared, "rate_limit")
		}
		// F-sec-5/6: also clear the per-loginName lockout state so
		// tests that intentionally trip lockout don't leak failures
		// into subsequent specs.
		if proxy != nil && proxy.LoginNameLimiter != nil {
			proxy.LoginNameLimiter.ResetAll()
			cleared = append(cleared, "loginname_lockout")
		}

		// Fixture user cleanup is tracked separately (F-pre-2) — it requires
		// calling Zitadel's user management API with a dedicated fixtures PAT.
		// This handler is the hook the helper will grow into.
		c.JSON(http.StatusOK, gin.H{
			"reset":     true,
			"cleared":   cleared,
			"todo":      []string{"fixture_users"},
			"e2e_build": true,
		})
	}
}
