// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/helpers"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/activity"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/models"
)

type APIKeyHandler struct {
	apiKeyService   *apikey.Service
	authService     *auth.Service
	activityService *activity.Service
}

func NewAPIKeyHandler(apiKeyService *apikey.Service, authService *auth.Service, activityService *activity.Service) *APIKeyHandler {
	return &APIKeyHandler{
		apiKeyService:   apiKeyService,
		authService:     authService,
		activityService: activityService,
	}
}

// CreateAPIKeyRequest is the api-keys document a personal API key is created from (#858, D8).
type CreateAPIKeyRequest struct {
	Data *struct {
		Type       string `json:"type"`
		Attributes struct {
			Name      string   `json:"name" binding:"required"`
			Scopes    []string `json:"scopes,omitempty"`
			ExpiresAt *string  `json:"expires-at,omitempty"` // ISO 8601 date string
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

// PrimaryType reports data.type and whether data was sent (jsonapi.TypedDocument).
func (r *CreateAPIKeyRequest) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
}

// APIKeyAttributes describe one of the caller's API keys. Key is the plaintext key, present only
// in the answer to the create, the one time it is shown.
type APIKeyAttributes struct {
	Name       string     `json:"name"`
	Key        string     `json:"key,omitempty"`
	KeyPrefix  string     `json:"key-prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires-at"`
	LastUsedAt *time.Time `json:"last-used-at"`
	CreatedAt  time.Time  `json:"created-at"`
}

// APIKeyRelationships name the organization or project a scoped key is limited to.
type APIKeyRelationships struct {
	Organization *jsonapi.Relationship `json:"organization,omitempty"`
	Project      *jsonapi.Relationship `json:"project,omitempty"`
}

// apiKeyResource is one key as the api-keys resource; plainKey is set only on create.
func apiKeyResource(key *models.APIKey, plainKey string) jsonapi.Resource[APIKeyAttributes] {
	res := jsonapi.Resource[APIKeyAttributes]{
		ID:   key.ID.String(),
		Type: "api-keys",
		Attributes: APIKeyAttributes{
			Name: key.Name, Key: plainKey, KeyPrefix: key.KeyPrefix, Scopes: []string(key.Scopes),
			ExpiresAt: key.ExpiresAt, LastUsedAt: key.LastUsedAt, CreatedAt: key.CreatedAt,
		},
	}
	if res.Attributes.Scopes == nil {
		res.Attributes.Scopes = []string{}
	}
	var rels APIKeyRelationships
	if key.OrganizationID != nil {
		r := jsonapi.ToOne(key.OrganizationID.String(), "organizations")
		rels.Organization = &r
	}
	if key.ProjectID != nil {
		r := jsonapi.ToOne(key.ProjectID.String(), "projects")
		rels.Project = &r
	}
	if rels.Organization != nil || rels.Project != nil {
		res.Relationships = rels
	}
	return res
}

// CreateAPIKey creates a new API key
// POST /api/v2/settings/api-keys
func (h *APIKeyHandler) CreateAPIKey(c *gin.Context) {
	var body CreateAPIKeyRequest
	if !jsonapi.BindDocument(c, &body, "api-keys") {
		return
	}
	req := body.Data.Attributes

	// Get user from context
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized")
		return
	}

	// Parse expiration date if provided
	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "invalid expires-at format, use ISO 8601 (RFC3339)")
			return
		}
		expiresAt = &parsed
	}

	// Create the API key with scopes
	apiKey, plainKey, err := h.apiKeyService.CreateAPIKey(user.ID, req.Name, req.Scopes, expiresAt)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "failed to create API key"+": "+err.Error())
		return
	}

	// Log activity (non-blocking)
	if h.activityService != nil {
		activityCtx := helpers.GetActivityContext(c)
		if apiKey.OrganizationID != nil {
			activityCtx.OrganizationID = apiKey.OrganizationID
		}
		if apiKey.ProjectID != nil {
			activityCtx.ProjectID = apiKey.ProjectID
		}
		_ = h.activityService.LogAPIKeyCreate(c.Request.Context(), apiKey.ID, apiKey.Name, activityCtx)
	}

	// Format response
	// The only time the plaintext key is shown.
	jsonapi.WriteDocument(c, http.StatusCreated, apiKeyResource(apiKey, plainKey))
}

// ListAPIKeys lists all API keys for the current user
// GET /api/v2/settings/api-keys
func (h *APIKeyHandler) ListAPIKeys(c *gin.Context) {
	// Get user from context
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized")
		return
	}

	// List API keys
	apiKeys, err := h.apiKeyService.ListAPIKeys(user.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "failed to list API keys"+": "+err.Error())
		return
	}

	// Convert to response format
	data := make([]jsonapi.Resource[APIKeyAttributes], 0, len(apiKeys))
	for _, key := range apiKeys {
		data = append(data, apiKeyResource(key, ""))
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewFullPageMeta(len(data)))
}

// DeleteAPIKey deletes an API key
// DELETE /api/v2/settings/api-keys/:id
func (h *APIKeyHandler) DeleteAPIKey(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "invalid API key ID")
		return
	}

	// Get user from context
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized")
		return
	}

	// A key that is not the caller's, or does not exist, is not found.
	apiKey, err := h.apiKeyService.GetAPIKey(id, user.ID)
	if err != nil || apiKey == nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "API key not found")
		return
	}

	// Delete the API key
	if err := h.apiKeyService.DeleteAPIKey(id, user.ID); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "failed to delete API key"+": "+err.Error())
		return
	}

	// Log activity (non-blocking)
	if h.activityService != nil && apiKey != nil {
		activityCtx := helpers.GetActivityContext(c)
		if apiKey.OrganizationID != nil {
			activityCtx.OrganizationID = apiKey.OrganizationID
		}
		if apiKey.ProjectID != nil {
			activityCtx.ProjectID = apiKey.ProjectID
		}
		_ = h.activityService.LogAPIKeyDelete(c.Request.Context(), apiKey.ID, apiKey.Name, activityCtx)
	}

	c.Status(http.StatusNoContent)
}
