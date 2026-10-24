// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
)

// TokenHandlerV2 serves the TFE-compatible token endpoints (`/api/v2/tokens`).
// These mint **user-bound** tokens - the `terraform login` / personal access
// token. They are now backed by the unified api_keys table (kind="user") via
// the shared apikey.Service, not the legacy tfe_tokens table.
type TokenHandlerV2 struct {
	apiKeyService *apikey.Service
	authService   *auth.Service
	// admins decides who may mint a platform admin token; nil refuses every such request.
	admins *platformadmin.Service
}

// SetPlatformAdmin lets a platform administrator mint a platform admin token (#132, D5).
func (h *TokenHandlerV2) SetPlatformAdmin(admins *platformadmin.Service) {
	h.admins = admins
}

func NewTokenHandlerV2(
	apiKeyService *apikey.Service,
	authService *auth.Service,
) *TokenHandlerV2 {
	return &TokenHandlerV2{
		apiKeyService: apiKeyService,
		authService:   authService,
	}
}

// CreateTokenRequestV2 is the tokens document a personal token is minted from (#858, D6). Its
// attributes keep the snake_case spelling the tokens resource answers with (D3).
type CreateTokenRequestV2 struct {
	Data *struct {
		Type       string `json:"type"`
		Attributes struct {
			Description string     `json:"description"`
			ExpiresAt   *time.Time `json:"expires_at,omitempty"`
			// PlatformAdminToken asks for a platform admin token: a user token carrying the
			// platform:admin scope, which only a platform administrator may mint (#132).
			PlatformAdminToken bool `json:"platform_admin,omitempty"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

// PrimaryType reports data.type and whether data was sent (jsonapi.TypedDocument).
func (r *CreateTokenRequestV2) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
}

// Create creates a new user-bound token for the authenticated user
// POST /api/v2/tokens
func (h *TokenHandlerV2) Create(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "User not authenticated")
		return
	}

	var body CreateTokenRequestV2
	if !jsonapi.BindDocument(c, &body, "tokens") {
		return
	}
	req := body.Data.Attributes

	// Mint a user-bound token (kind="user") via the unified apikey service.
	// The description is stored as the key name. A platform admin token additionally carries the
	// platform:admin scope; the route is interactive-only, so only a signed-in holder mints one.
	var scopes []string
	if req.PlatformAdminToken {
		isAdmin := false
		if h.admins != nil {
			if isAdmin, err = h.admins.IsPlatformAdmin(c.Request.Context(), user.ID); err != nil {
				jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create token")
				return
			}
		}
		if !isAdmin {
			jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "only a platform administrator can mint a platform admin token")
			return
		}
		scopes = []string{apikey.PlatformAdminScope}
	}
	apiKey, tokenString, err := h.apiKeyService.CreateUserTokenWithScopes(user.ID, req.Description, req.ExpiresAt, scopes)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create token")
		return
	}

	// Return token with plaintext token (only time it's shown)
	// TFE-compatible response format
	jsonapi.WriteDocument(c, http.StatusCreated, jsonapi.Resource[UserTokenCreateAttributes]{
		ID:   apiKey.ID.String(),
		Type: "tokens",
		Attributes: UserTokenCreateAttributes{
			Token:              tokenString, // Plaintext token (only shown once)
			Description:        apiKey.Name,
			ExpiresAt:          apiKey.ExpiresAt,
			CreatedAt:          apiKey.CreatedAt,
			PlatformAdminToken: carriesPlatformAdmin(apiKey.Scopes),
		},
	})
}

// List lists all user-bound tokens for the authenticated user
// GET /api/v2/tokens
func (h *TokenHandlerV2) List(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "User not authenticated")
		return
	}

	tokens, err := h.apiKeyService.ListUserTokens(user.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list tokens")
		return
	}

	// Convert to response format (without plaintext tokens)
	responseData := make([]jsonapi.Resource[UserTokenListAttributes], 0, len(tokens))
	for _, token := range tokens {
		responseData = append(responseData, jsonapi.Resource[UserTokenListAttributes]{
			ID:   token.ID.String(),
			Type: "tokens",
			Attributes: UserTokenListAttributes{
				Description:        token.Name,
				LastUsedAt:         token.LastUsedAt,
				ExpiresAt:          token.ExpiresAt,
				CreatedAt:          token.CreatedAt,
				PlatformAdminToken: carriesPlatformAdmin(token.Scopes),
			},
		})
	}

	// TFE-compatible response format
	jsonapi.WriteDocumentMeta(c, http.StatusOK, responseData, jsonapi.NewFullPageMeta(len(responseData)))
}

// Delete deletes a user-bound token
// DELETE /api/v2/tokens/:id
func (h *TokenHandlerV2) Delete(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "User not authenticated")
		return
	}

	tokenID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid token ID")
		return
	}

	// DeleteAPIKey verifies ownership (key belongs to the authenticated user).
	if err := h.apiKeyService.DeleteAPIKey(tokenID, user.ID); err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Token not found")
		return
	}

	c.Status(http.StatusNoContent)
}

// carriesPlatformAdmin reports whether a token's scopes include platform:admin.
func carriesPlatformAdmin(scopes []string) bool {
	checker, err := apikey.NewScopeChecker(scopes)
	return err == nil && checker.HasPlatformAdmin()
}
