// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
)

// PlatformSettingsHandlerV2 serves `GET /api/v2/platform/settings` (#132, D4): the deployment's
// platform policy, read-only because it is deployment configuration. Every authenticated
// identity may read it; the values are policy, not secrets, and an ordinary user's Organizations
// page needs them.
type PlatformSettingsHandlerV2 struct {
	admins      *platformadmin.Service
	authService *auth.Service
}

// NewPlatformSettingsHandlerV2 creates the handler.
func NewPlatformSettingsHandlerV2(admins *platformadmin.Service, authService *auth.Service) *PlatformSettingsHandlerV2 {
	return &PlatformSettingsHandlerV2{admins: admins, authService: authService}
}

// PlatformSettingsAttributes is the platform-settings resource.
type PlatformSettingsAttributes struct {
	OrganizationCreation string `json:"organization-creation"`
}

// Show returns the platform settings.
// GET /api/v2/platform/settings
func (h *PlatformSettingsHandlerV2) Show(c *gin.Context) {
	if user, err := h.authService.GetUserFromContext(c); err != nil || user == nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, jsonapi.Resource[PlatformSettingsAttributes]{
		ID:   "platform",
		Type: "platform-settings",
		Attributes: PlatformSettingsAttributes{
			OrganizationCreation: string(h.admins.OrganizationCreation()),
		},
	})
}
