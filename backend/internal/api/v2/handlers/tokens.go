// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
)

// TokenHandlerV2 serves the TFE-compatible token endpoints (`/api/v2/tokens`).
// These mint **user-bound** tokens — the `terraform login` / personal access
// token. They are now backed by the unified api_keys table (kind="user") via
// the shared apikey.Service, not the legacy tfe_tokens table.
type TokenHandlerV2 struct {
	apiKeyService *apikey.Service
	authService   *auth.Service
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

type CreateTokenRequestV2 struct {
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type TokenResponseV2 struct {
	ID          uuid.UUID  `json:"id"`
	Token       string     `json:"token"` // Only returned on creation
	Description string     `json:"description"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Create creates a new user-bound token for the authenticated user
// POST /api/v2/tokens
func (h *TokenHandlerV2) Create(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "User not authenticated",
				},
			},
		})
		return
	}

	var req CreateTokenRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": err.Error(),
				},
			},
		})
		return
	}

	// Mint a user-bound token (kind="user") via the unified apikey service.
	// The description is stored as the key name.
	apiKey, tokenString, err := h.apiKeyService.CreateUserToken(user.ID, req.Description, req.ExpiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to create token",
				},
			},
		})
		return
	}

	// Return token with plaintext token (only time it's shown)
	// TFE-compatible response format
	c.JSON(http.StatusCreated, gin.H{
		"data": gin.H{
			"id":   apiKey.ID,
			"type": "tokens",
			"attributes": gin.H{
				"token":       tokenString, // Plaintext token (only shown once)
				"description": apiKey.Name,
				"expires_at":  apiKey.ExpiresAt,
				"created_at":  apiKey.CreatedAt,
			},
		},
	})
}

// List lists all user-bound tokens for the authenticated user
// GET /api/v2/tokens
func (h *TokenHandlerV2) List(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "User not authenticated",
				},
			},
		})
		return
	}

	tokens, err := h.apiKeyService.ListUserTokens(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to list tokens",
				},
			},
		})
		return
	}

	// Convert to response format (without plaintext tokens)
	responseData := make([]gin.H, 0, len(tokens))
	for _, token := range tokens {
		responseData = append(responseData, gin.H{
			"id":   token.ID,
			"type": "tokens",
			"attributes": gin.H{
				"description":  token.Name,
				"last_used_at": token.LastUsedAt,
				"expires_at":   token.ExpiresAt,
				"created_at":   token.CreatedAt,
			},
		})
	}

	// TFE-compatible response format
	c.JSON(http.StatusOK, gin.H{
		"data": responseData,
	})
}

// Delete deletes a user-bound token
// DELETE /api/v2/tokens/:id
func (h *TokenHandlerV2) Delete(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "User not authenticated",
				},
			},
		})
		return
	}

	tokenID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Invalid token ID",
				},
			},
		})
		return
	}

	// DeleteAPIKey verifies ownership (key belongs to the authenticated user).
	if err := h.apiKeyService.DeleteAPIKey(tokenID, user.ID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Token not found",
				},
			},
		})
		return
	}

	c.Status(http.StatusNoContent)
}
