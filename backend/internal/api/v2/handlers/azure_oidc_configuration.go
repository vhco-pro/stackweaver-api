// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// azureOIDCConfigType is the JSON:API resource type expected by go-tfe/terraform-provider-tfe.
const azureOIDCConfigType = "azure-oidc-configurations"

// AzureOIDCConfigurationHandlerV2 handles TFE-compatible Azure OIDC configuration API.
// Reference: go-tfe/azure_oidc_configuration.go
type AzureOIDCConfigurationHandlerV2 struct {
	configRepo  *repository.AzureOIDCConfigurationRepository
	orgRepo     *repository.OrganizationRepository
	authService *auth.Service
	rbacService *rbac.Service
}

// NewAzureOIDCConfigurationHandlerV2 creates an AzureOIDCConfigurationHandlerV2.
func NewAzureOIDCConfigurationHandlerV2(
	configRepo *repository.AzureOIDCConfigurationRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *AzureOIDCConfigurationHandlerV2 {
	return &AzureOIDCConfigurationHandlerV2{
		configRepo:  configRepo,
		orgRepo:     orgRepo,
		authService: authService,
		rbacService: rbacService,
	}
}

// CreateAzureOIDCConfigRequest is the JSON:API request for creating an Azure OIDC configuration.
type CreateAzureOIDCConfigRequest struct {
	Data struct {
		Type       string `json:"type" binding:"required"`
		Attributes struct {
			ClientID       string `json:"client-id"`
			SubscriptionID string `json:"subscription-id"`
			TenantID       string `json:"tenant-id"`
		} `json:"attributes" binding:"required"`
	} `json:"data" binding:"required"`
}

// UpdateAzureOIDCConfigRequest is the JSON:API request for updating an Azure OIDC configuration.
type UpdateAzureOIDCConfigRequest struct {
	Data struct {
		Type       string `json:"type" binding:"required"`
		Attributes struct {
			ClientID       *string `json:"client-id,omitempty"`
			SubscriptionID *string `json:"subscription-id,omitempty"`
			TenantID       *string `json:"tenant-id,omitempty"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

// formatAzureOIDCConfigResponse formats an Azure OIDC configuration as a JSON:API response.
func formatAzureOIDCConfigResponse(config *models.AzureOIDCConfiguration) gin.H {
	orgName := ""
	if config.Organization != nil {
		orgName = config.Organization.Name
	}

	return gin.H{
		"id":   config.ID,
		"type": azureOIDCConfigType,
		"attributes": gin.H{
			"client-id":       config.ClientID,
			"subscription-id": config.SubscriptionID,
			"tenant-id":       config.TenantID,
		},
		"relationships": gin.H{
			"organization": gin.H{
				"data": gin.H{"id": orgName, "type": "organizations"},
			},
		},
		"links": gin.H{
			"self": "/api/v2/oidc-configurations/" + config.ID,
		},
	}
}

// listData returns the org's Azure OIDC configs formatted as JSON:API resource objects (used by the
// dispatcher's merged List across providers).
func (h *AzureOIDCConfigurationHandlerV2) listData(orgID uuid.UUID) ([]gin.H, error) {
	configs, err := h.configRepo.GetByOrganization(orgID)
	if err != nil {
		return nil, err
	}
	out := make([]gin.H, 0, len(configs))
	for i := range configs {
		out = append(out, formatAzureOIDCConfigResponse(&configs[i]))
	}
	return out, nil
}

// Create creates a new Azure OIDC configuration.
// POST /api/v2/organizations/:name/oidc-configurations
func (h *AzureOIDCConfigurationHandlerV2) Create(c *gin.Context) {
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	// RBAC: user must be in the organization
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	ok, err := h.rbacService.CheckOrgManageVCSSettings(c.Request.Context(), user.ID, org.ID)
	if err != nil || !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage OIDC configurations")
		return
	}

	var req CreateAzureOIDCConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	if req.Data.Type != azureOIDCConfigType {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "data.type must be 'azure-oidc-configurations'")
		return
	}

	// Validate required fields
	if req.Data.Attributes.ClientID == "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "client-id is required")
		return
	}
	if req.Data.Attributes.SubscriptionID == "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "subscription-id is required")
		return
	}
	if req.Data.Attributes.TenantID == "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "tenant-id is required")
		return
	}

	config := &models.AzureOIDCConfiguration{
		ClientID:       req.Data.Attributes.ClientID,
		SubscriptionID: req.Data.Attributes.SubscriptionID,
		TenantID:       req.Data.Attributes.TenantID,
		OrganizationID: org.ID,
	}

	if err := h.configRepo.Create(config); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create Azure OIDC configuration")
		return
	}

	// Reload with organization preloaded
	config, err = h.configRepo.GetByID(config.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to reload Azure OIDC configuration")
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, formatAzureOIDCConfigResponse(config))
}

// Read returns an Azure OIDC configuration by ID.
// GET /api/v2/oidc-configurations/:id
func (h *AzureOIDCConfigurationHandlerV2) Read(c *gin.Context) {
	configID := c.Param("id")

	config, err := h.configRepo.GetByID(configID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "OIDC configuration not found")
			return
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to get OIDC configuration")
		return
	}

	// RBAC: user must be in the organization
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	ok, err := h.rbacService.CheckOrgManageVCSSettings(c.Request.Context(), user.ID, config.OrganizationID)
	if err != nil || !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to read OIDC configurations")
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatAzureOIDCConfigResponse(config))
}

// Update updates an Azure OIDC configuration (partial update).
// PATCH /api/v2/oidc-configurations/:id
func (h *AzureOIDCConfigurationHandlerV2) Update(c *gin.Context) {
	configID := c.Param("id")

	config, err := h.configRepo.GetByID(configID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "OIDC configuration not found")
			return
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to get OIDC configuration")
		return
	}

	// RBAC: user must be in the organization
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	ok, err := h.rbacService.CheckOrgManageVCSSettings(c.Request.Context(), user.ID, config.OrganizationID)
	if err != nil || !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage OIDC configurations")
		return
	}

	var req UpdateAzureOIDCConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	if req.Data.Type != azureOIDCConfigType {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "data.type must be 'azure-oidc-configurations'")
		return
	}

	// Build update map with only non-nil fields (partial update)
	updates := make(map[string]interface{})
	if req.Data.Attributes.ClientID != nil {
		updates["client_id"] = *req.Data.Attributes.ClientID
	}
	if req.Data.Attributes.SubscriptionID != nil {
		updates["subscription_id"] = *req.Data.Attributes.SubscriptionID
	}
	if req.Data.Attributes.TenantID != nil {
		updates["tenant_id"] = *req.Data.Attributes.TenantID
	}

	if len(updates) > 0 {
		config, err = h.configRepo.Update(configID, updates)
		if err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update OIDC configuration")
			return
		}
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatAzureOIDCConfigResponse(config))
}

// Delete deletes an Azure OIDC configuration.
// DELETE /api/v2/oidc-configurations/:id
func (h *AzureOIDCConfigurationHandlerV2) Delete(c *gin.Context) {
	configID := c.Param("id")

	config, err := h.configRepo.GetByID(configID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "OIDC configuration not found")
			return
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to get OIDC configuration")
		return
	}

	// RBAC: user must be in the organization
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	ok, err := h.rbacService.CheckOrgManageVCSSettings(c.Request.Context(), user.ID, config.OrganizationID)
	if err != nil || !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage OIDC configurations")
		return
	}

	if err := h.configRepo.Delete(configID); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete OIDC configuration")
		return
	}

	c.Status(http.StatusNoContent)
}
