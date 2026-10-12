// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
)

// InteractiveOnly admits a caller who signed in interactively and refuses every programmatic
// token. It runs after AuthMiddleware, on routes where a person manages their own account and
// credentials: the settings surface, the user-token routes and the browser half of
// `terraform login`.
//
// AuthMiddleware resolves a `tfe-` token to the user who owns it, and a handler that then asks
// "who is the caller?" gets that owner back with none of the token's limits attached: not its
// organization binding, not its scopes, not its kind. On an account route that is the whole
// authorization, so a key bound read-only to one organization could mint itself a key with any
// scope on any organization its owner belongs to, or a user-bound token for all of them, list
// and revoke the owner's other credentials, and rewrite the owner's profile. The org wall cannot
// help, because these routes carry no target organization for it to resolve. Managing
// credentials and identity is something a person does while signed in, so the route refuses the
// token instead of trying to scope it.
//
// The check is an allow-list on purpose. A caller is admitted only when AuthMiddleware recorded
// a verified JWT, so an authentication method added later is refused here until someone decides
// it belongs, which is the same fail-closed default the org wall takes for unclassified routes.
func InteractiveOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		if method, _ := c.Get("auth_method"); method != "jwt" {
			logger.Warnf("interactive-only: denying %v identity on %s %s", method, c.Request.Method, c.FullPath())
			jsonapi.AbortError(c, http.StatusForbidden, jsonapi.TitleForbidden,
				"this endpoint requires an interactive sign-in and cannot be used with an API token")
			return
		}
		c.Next()
	}
}
