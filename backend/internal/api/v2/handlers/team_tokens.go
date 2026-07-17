// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// TeamTokenHandlerV2 serves the TFE-compatible team authentication token endpoints
// (`/api/v2/teams/:id/authentication-token`). Each team has at most one such token - the credential
// CI/automation uses to act as the team (tfe_team_token). It is backed by the unified api_keys table
// (a team-scoped key flagged IsTeamToken) via the shared apikey.Service.
//
// Only the legacy (descriptionless) single-token-per-team behavior is implemented; the provider's BETA
// descriptioned/multiple-tokens-per-team path is an intentional divergence (see the spec doc).
type TeamTokenHandlerV2 struct {
	apiKeyService *apikey.Service
	authService   *auth.Service
	rbacService   *rbac.Service
	teamRepo      *repository.TeamRepository
}

func NewTeamTokenHandlerV2(
	apiKeyService *apikey.Service,
	authService *auth.Service,
	rbacService *rbac.Service,
	teamRepo *repository.TeamRepository,
) *TeamTokenHandlerV2 {
	return &TeamTokenHandlerV2{
		apiKeyService: apiKeyService,
		authService:   authService,
		rbacService:   rbacService,
		teamRepo:      teamRepo,
	}
}

// teamTokenCreateRequest is the JSON:API body go-tfe sends: an optional iso8601 `expired-at`.
type teamTokenCreateRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			ExpiredAt *time.Time `json:"expired-at"`
		} `json:"attributes"`
	} `json:"data"`
}

// resolveTeamOwner loads the team named in the URL (:id, a UUID) and verifies the caller is an owner
// of the team's organization. On any failure it writes the JSON:API error and returns ok=false.
func (h *TeamTokenHandlerV2) resolveTeamOwner(c *gin.Context) (*models.Team, bool) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonAPIError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}

	teamID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonAPIError(c, http.StatusNotFound, "Not Found", "Team not found")
		return nil, false
	}

	team, err := h.teamRepo.GetByID(teamID)
	if err != nil {
		jsonAPIError(c, http.StatusNotFound, "Not Found", "Team not found")
		return nil, false
	}

	owner, err := h.rbacService.IsOrgOwner(c.Request.Context(), user.ID, team.OrganizationID)
	if err != nil {
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return nil, false
	}
	if !owner {
		jsonAPIError(c, http.StatusForbidden, "Forbidden", "Only organization owners can manage team tokens")
		return nil, false
	}
	return team, true
}

// teamTokenResource builds the JSON:API resource for a team token. token is the plaintext, included
// only on create (empty on read). Legacy team tokens carry no description, so it is always null.
func teamTokenResource(key *models.APIKey, token string) gin.H {
	attrs := gin.H{
		"created-at":   key.CreatedAt,
		"last-used-at": key.LastUsedAt,
		"expired-at":   key.ExpiresAt,
		"description":  nil,
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

// Create mints (or regenerates) the team token.
// POST /api/v2/teams/:id/authentication-token
func (h *TeamTokenHandlerV2) Create(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonAPIError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	team, ok := h.resolveTeamOwner(c)
	if !ok {
		return
	}

	// Body is optional; a bare POST (no body) mints a non-expiring token.
	var req teamTokenCreateRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			jsonAPIError(c, http.StatusBadRequest, "Bad Request", err.Error())
			return
		}
	}

	key, token, err := h.apiKeyService.CreateTeamToken(user.ID, team.ID, team.OrganizationID, req.Data.Attributes.ExpiredAt)
	if err != nil {
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create team token")
		return
	}

	c.JSON(http.StatusCreated, teamTokenResource(key, token))
}

// Read returns the team token's metadata (no plaintext).
// GET /api/v2/teams/:id/authentication-token
func (h *TeamTokenHandlerV2) Read(c *gin.Context) {
	team, ok := h.resolveTeamOwner(c)
	if !ok {
		return
	}

	key, err := h.apiKeyService.GetTeamToken(team.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			jsonAPIError(c, http.StatusNotFound, "Not Found", "Team token not found")
			return
		}
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to read team token")
		return
	}

	c.JSON(http.StatusOK, teamTokenResource(key, ""))
}

// Delete revokes the team token.
// DELETE /api/v2/teams/:id/authentication-token
func (h *TeamTokenHandlerV2) Delete(c *gin.Context) {
	team, ok := h.resolveTeamOwner(c)
	if !ok {
		return
	}

	if err := h.apiKeyService.DeleteTeamToken(team.ID); err != nil {
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete team token")
		return
	}

	c.Status(http.StatusNoContent)
}
