// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
)

// AccountHandlerV2 serves the TFE-compatible current-account endpoint (`/api/v2/account/details`),
// the target of go-tfe's Users.ReadCurrent and the tfe_current_user data source. It returns the
// authenticated caller as a JSON:API `users` resource. It is account-level (no target organization),
// so the org-wall classifies it as agnostic.
type AccountHandlerV2 struct {
	authService *auth.Service
}

func NewAccountHandlerV2(authService *auth.Service) *AccountHandlerV2 {
	return &AccountHandlerV2{authService: authService}
}

// Details returns the authenticated user's account (tfe_current_user).
// GET /api/v2/account/details
func (h *AccountHandlerV2) Details(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonAPIError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	// TFE requires a username; fall back to the email local-part when the profile has none.
	username := user.Username
	if username == "" {
		username = user.Email
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"id":   user.ID,
			"type": "users",
			"attributes": gin.H{
				"username":           username,
				"email":              user.Email,
				"is-service-account": false,
				"avatar-url":         "",
				"v2-only":            true,
			},
		},
	})
}
