// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// OrganizationTokenHandlerV2 serves the TFE-compatible organization authentication token endpoints
// (`/api/v2/organizations/:name/authentication-token`). Each org has at most one such token - the
// org-admin credential CI/automation uses (tfe_organization_token). It is backed by the unified
// api_keys table (an org-scoped key flagged IsOrgToken) via the shared apikey.Service.
type OrganizationTokenHandlerV2 struct {
	apiKeyService *apikey.Service
	authService   *auth.Service
	rbacService   *rbac.Service
	orgRepo       *repository.OrganizationRepository
}

func NewOrganizationTokenHandlerV2(
	apiKeyService *apikey.Service,
	authService *auth.Service,
	rbacService *rbac.Service,
	orgRepo *repository.OrganizationRepository,
) *OrganizationTokenHandlerV2 {
	return &OrganizationTokenHandlerV2{
		apiKeyService: apiKeyService,
		authService:   authService,
		rbacService:   rbacService,
		orgRepo:       orgRepo,
	}
}

// jsonAPIError writes a single-error JSON:API error response (status as the numeric code string).
func jsonAPIError(c *gin.Context, status int, title, detail string) {
	c.JSON(status, gin.H{
		"errors": []gin.H{
			{"status": strconv.Itoa(status), "title": title, "detail": detail},
		},
	})
}

// orgTokenCreateRequest is the JSON:API body go-tfe sends: an optional iso8601 `expired-at`.
type orgTokenCreateRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			ExpiredAt *time.Time `json:"expired-at"`
		} `json:"attributes"`
	} `json:"data"`
}

// resolveOrgOwner loads the org named in the URL and verifies the caller is an org owner. On any
// failure it writes the JSON:API error and returns ok=false.
func (h *OrganizationTokenHandlerV2) resolveOrgOwner(c *gin.Context) (*models.Organization, bool) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonAPIError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}

	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		jsonAPIError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return nil, false
	}

	owner, err := h.rbacService.IsOrgOwner(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return nil, false
	}
	if !owner {
		jsonAPIError(c, http.StatusForbidden, "Forbidden", "Only organization owners can manage the organization token")
		return nil, false
	}
	return org, true
}

// orgTokenResource builds the JSON:API resource for an org token. token is the plaintext, included only
// on create (empty on read).
func orgTokenResource(key *models.APIKey, token string) gin.H {
	attrs := gin.H{
		"created-at":   key.CreatedAt,
		"last-used-at": key.LastUsedAt,
		"expired-at":   key.ExpiresAt,
	}
	if token != "" {
		attrs["token"] = token
	}
	return gin.H{
		"data": gin.H{
			"id":         key.ID,
			"type":       "authentication-tokens",
			"attributes": attrs,
		},
	}
}

// Create mints (or regenerates) the organization token.
// POST /api/v2/organizations/:name/authentication-token
func (h *OrganizationTokenHandlerV2) Create(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonAPIError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	org, ok := h.resolveOrgOwner(c)
	if !ok {
		return
	}

	// Body is optional; a bare POST (no body) mints a non-expiring token.
	var req orgTokenCreateRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			jsonAPIError(c, http.StatusBadRequest, "Bad Request", err.Error())
			return
		}
	}

	key, token, err := h.apiKeyService.CreateOrganizationToken(user.ID, org.ID, req.Data.Attributes.ExpiredAt)
	if err != nil {
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create organization token")
		return
	}

	c.JSON(http.StatusCreated, orgTokenResource(key, token))
}

// Read returns the organization token's metadata (no plaintext).
// GET /api/v2/organizations/:name/authentication-token
func (h *OrganizationTokenHandlerV2) Read(c *gin.Context) {
	org, ok := h.resolveOrgOwner(c)
	if !ok {
		return
	}

	key, err := h.apiKeyService.GetOrganizationToken(org.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			jsonAPIError(c, http.StatusNotFound, "Not Found", "Organization token not found")
			return
		}
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to read organization token")
		return
	}

	c.JSON(http.StatusOK, orgTokenResource(key, ""))
}

// Delete revokes the organization token.
// DELETE /api/v2/organizations/:name/authentication-token
func (h *OrganizationTokenHandlerV2) Delete(c *gin.Context) {
	org, ok := h.resolveOrgOwner(c)
	if !ok {
		return
	}

	if err := h.apiKeyService.DeleteOrganizationToken(org.ID); err != nil {
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete organization token")
		return
	}

	c.Status(http.StatusNoContent)
}
