// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// AgentTokenHandlerV2 serves the TFE-compatible agent token endpoints (tfe_agent_token): pool-scoped
// registration credentials an agent presents to register into an agent pool. A pool may have many.
// They are backed by the unified api_keys table (a Kind=org key carrying org:<id>:runner:register,
// bound to AgentPoolID and flagged IsAgentToken) via the shared apikey.Service, so a minted token is a
// real credential the runner registration path already understands.
type AgentTokenHandlerV2 struct {
	apiKeyService *apikey.Service
	authService   *auth.Service
	rbacService   *rbac.Service
	poolRepo      *repository.AgentPoolRepository
}

func NewAgentTokenHandlerV2(
	apiKeyService *apikey.Service,
	authService *auth.Service,
	rbacService *rbac.Service,
	poolRepo *repository.AgentPoolRepository,
) *AgentTokenHandlerV2 {
	return &AgentTokenHandlerV2{
		apiKeyService: apiKeyService,
		authService:   authService,
		rbacService:   rbacService,
		poolRepo:      poolRepo,
	}
}

// agentTokenCreateRequest is the JSON:API body go-tfe sends: a required `description`.
type agentTokenCreateRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Description string `json:"description"`
		} `json:"attributes"`
	} `json:"data"`
}

// requireManageAgentPools verifies the caller may manage the org's agent pools (the same permission
// that gates agent-pool CRUD). On failure it writes the JSON:API error and returns false.
func (h *AgentTokenHandlerV2) requireManageAgentPools(c *gin.Context, orgID uuid.UUID) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonAPIError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return false
	}
	ok, err := h.rbacService.CheckOrgManageAgentPools(c.Request.Context(), user.ID, orgID)
	if err != nil {
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return false
	}
	if !ok {
		jsonAPIError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage agent pools")
		return false
	}
	return true
}

// resolvePool loads the pool named by the :id path param. On failure it writes the JSON:API error.
func (h *AgentTokenHandlerV2) resolvePool(c *gin.Context) (*models.AgentPool, bool) {
	poolID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonAPIError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
		return nil, false
	}
	pool, err := h.poolRepo.GetByID(poolID, false)
	if err != nil {
		jsonAPIError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
		return nil, false
	}
	return pool, true
}

// agentTokenResource builds the JSON:API resource for an agent token. token is the plaintext, included
// only on create (empty on read). The description is stored as the key name.
func agentTokenResource(key *models.APIKey, token string) gin.H {
	attrs := gin.H{
		"created-at":   key.CreatedAt,
		"last-used-at": key.LastUsedAt,
		"description":  key.Name,
	}
	if token != "" {
		attrs["token"] = token
	}
	return gin.H{
		"id":         key.ID,
		"type":       "authentication-tokens",
		"attributes": attrs,
	}
}

// Create mints a new agent token for a pool.
// POST /api/v2/agent-pools/:id/authentication-tokens
func (h *AgentTokenHandlerV2) Create(c *gin.Context) {
	pool, ok := h.resolvePool(c)
	if !ok {
		return
	}
	if !h.requireManageAgentPools(c, pool.OrganizationID) {
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonAPIError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	var req agentTokenCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonAPIError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	description := strings.TrimSpace(req.Data.Attributes.Description)
	if description == "" {
		jsonAPIError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "description is required")
		return
	}

	key, token, err := h.apiKeyService.CreateAgentToken(user.ID, pool.ID, pool.OrganizationID, description)
	if err != nil {
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create agent token")
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": agentTokenResource(key, token)})
}

// List returns a pool's agent tokens (metadata only).
// GET /api/v2/agent-pools/:id/authentication-tokens
func (h *AgentTokenHandlerV2) List(c *gin.Context) {
	pool, ok := h.resolvePool(c)
	if !ok {
		return
	}
	if !h.requireManageAgentPools(c, pool.OrganizationID) {
		return
	}

	keys, err := h.apiKeyService.ListAgentTokens(pool.ID)
	if err != nil {
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list agent tokens")
		return
	}

	data := make([]gin.H, 0, len(keys))
	for _, k := range keys {
		data = append(data, agentTokenResource(k, ""))
	}
	c.JSON(http.StatusOK, gin.H{
		"data": data,
		"meta": gin.H{
			"pagination": gin.H{
				"current-page": 1,
				"prev-page":    nil,
				"next-page":    nil,
				"total-pages":  1,
				"total-count":  len(keys),
			},
		},
	})
}

// ReadByID returns a single agent token's metadata.
// GET /api/v2/authentication-tokens/:id
func (h *AgentTokenHandlerV2) ReadByID(c *gin.Context) {
	key, ok := h.resolveTokenByID(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": agentTokenResource(key, "")})
}

// DeleteByID revokes a single agent token.
// DELETE /api/v2/authentication-tokens/:id
func (h *AgentTokenHandlerV2) DeleteByID(c *gin.Context) {
	key, ok := h.resolveTokenByID(c)
	if !ok {
		return
	}
	deleted, err := h.apiKeyService.DeleteAgentToken(key.ID)
	if err != nil {
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete agent token")
		return
	}
	if !deleted {
		jsonAPIError(c, http.StatusNotFound, "Not Found", "Agent token not found")
		return
	}
	c.Status(http.StatusNoContent)
}

// resolveTokenByID loads the agent token named by the :id path param and enforces manage-agent-pools
// on its organization. On any failure it writes the JSON:API error and returns false.
func (h *AgentTokenHandlerV2) resolveTokenByID(c *gin.Context) (*models.APIKey, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonAPIError(c, http.StatusNotFound, "Not Found", "Agent token not found")
		return nil, false
	}
	key, err := h.apiKeyService.GetAgentToken(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			jsonAPIError(c, http.StatusNotFound, "Not Found", "Agent token not found")
			return nil, false
		}
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to read agent token")
		return nil, false
	}
	if key.OrganizationID == nil || !h.requireManageAgentPools(c, *key.OrganizationID) {
		return nil, false
	}
	return key, true
}
