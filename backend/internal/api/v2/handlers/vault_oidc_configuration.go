// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// vaultOIDCConfigType is the JSON:API resource type expected by go-tfe/terraform-provider-tfe.
const vaultOIDCConfigType = "vault-oidc-configurations"

// VaultOIDCConfigurationHandlerV2 handles TFE-compatible Vault OIDC configuration API.
// Reference: go-tfe/vault_oidc_configuration.go. It shares the /oidc-configurations routes with the
// other providers via OIDCConfigDispatchHandler (dispatch by data.type on create, by ID prefix on
// the by-id routes).
type VaultOIDCConfigurationHandlerV2 struct {
	configRepo  *repository.VaultOIDCConfigurationRepository
	orgRepo     *repository.OrganizationRepository
	authService *auth.Service
	rbacService *rbac.Service
}

// NewVaultOIDCConfigurationHandlerV2 creates a VaultOIDCConfigurationHandlerV2.
func NewVaultOIDCConfigurationHandlerV2(
	configRepo *repository.VaultOIDCConfigurationRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *VaultOIDCConfigurationHandlerV2 {
	return &VaultOIDCConfigurationHandlerV2{
		configRepo:  configRepo,
		orgRepo:     orgRepo,
		authService: authService,
		rbacService: rbacService,
	}
}

// CreateVaultOIDCConfigRequest is the JSON:API request for creating a Vault OIDC configuration.
type CreateVaultOIDCConfigRequest struct {
	Data struct {
		Type       string `json:"type" binding:"required"`
		Attributes struct {
			Address       string `json:"address"`
			RoleName      string `json:"role"`
			Namespace     string `json:"namespace"`
			JWTAuthPath   string `json:"auth-path"`
			EncodedCACert string `json:"encoded-cacert"`
		} `json:"attributes" binding:"required"`
	} `json:"data" binding:"required"`
}

// UpdateVaultOIDCConfigRequest is the JSON:API request for updating a Vault OIDC configuration.
type UpdateVaultOIDCConfigRequest struct {
	Data struct {
		Type       string `json:"type" binding:"required"`
		Attributes struct {
			Address       *string `json:"address,omitempty"`
			RoleName      *string `json:"role,omitempty"`
			Namespace     *string `json:"namespace,omitempty"`
			JWTAuthPath   *string `json:"auth-path,omitempty"`
			EncodedCACert *string `json:"encoded-cacert,omitempty"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

// formatVaultOIDCConfigResponse formats a Vault OIDC configuration as a JSON:API response.
func formatVaultOIDCConfigResponse(config *models.VaultOIDCConfiguration) gin.H {
	orgName := ""
	if config.Organization != nil {
		orgName = config.Organization.Name
	}

	return gin.H{
		"id":   config.ID,
		"type": vaultOIDCConfigType,
		"attributes": gin.H{
			"address":        config.Address,
			"role":           config.RoleName,
			"namespace":      config.Namespace,
			"auth-path":      config.JWTAuthPath,
			"encoded-cacert": config.TLSCACertificate,
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

// Create creates a new Vault OIDC configuration.
// POST /api/v2/organizations/:name/oidc-configurations (dispatched by data.type)
func (h *VaultOIDCConfigurationHandlerV2) Create(c *gin.Context) {
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Organization not found"}}})
		return
	}

	// RBAC: user must be able to manage the organization's VCS/OIDC settings
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return
	}
	ok, err := h.rbacService.CheckOrgManageVCSSettings(c.Request.Context(), user.ID, org.ID)
	if err != nil || !ok {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to manage OIDC configurations"}}})
		return
	}

	var req CreateVaultOIDCConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}}})
		return
	}

	if req.Data.Type != vaultOIDCConfigType {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "data.type must be '" + vaultOIDCConfigType + "'"}}})
		return
	}

	if req.Data.Attributes.Address == "" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": []gin.H{{"status": "422", "title": "Unprocessable Entity", "detail": "address is required"}}})
		return
	}
	if req.Data.Attributes.RoleName == "" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": []gin.H{{"status": "422", "title": "Unprocessable Entity", "detail": "role is required"}}})
		return
	}

	config := &models.VaultOIDCConfiguration{
		Address:          req.Data.Attributes.Address,
		RoleName:         req.Data.Attributes.RoleName,
		Namespace:        req.Data.Attributes.Namespace,
		JWTAuthPath:      req.Data.Attributes.JWTAuthPath,
		TLSCACertificate: req.Data.Attributes.EncodedCACert,
		OrganizationID:   org.ID,
	}

	if err := h.configRepo.Create(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to create Vault OIDC configuration"}}})
		return
	}

	// Reload with organization preloaded
	config, err = h.configRepo.GetByID(config.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to reload Vault OIDC configuration"}}})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": formatVaultOIDCConfigResponse(config)})
}

// Read returns a Vault OIDC configuration by ID.
// GET /api/v2/oidc-configurations/:id (dispatched by ID prefix)
func (h *VaultOIDCConfigurationHandlerV2) Read(c *gin.Context) {
	config, ok := h.loadAuthorized(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatVaultOIDCConfigResponse(config)})
}

// Update updates a Vault OIDC configuration (partial update).
// PATCH /api/v2/oidc-configurations/:id (dispatched by ID prefix)
func (h *VaultOIDCConfigurationHandlerV2) Update(c *gin.Context) {
	config, ok := h.loadAuthorized(c)
	if !ok {
		return
	}

	var req UpdateVaultOIDCConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}}})
		return
	}

	if req.Data.Type != vaultOIDCConfigType {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "data.type must be '" + vaultOIDCConfigType + "'"}}})
		return
	}

	updates := make(map[string]any)
	if req.Data.Attributes.Address != nil {
		updates["address"] = *req.Data.Attributes.Address
	}
	if req.Data.Attributes.RoleName != nil {
		updates["role_name"] = *req.Data.Attributes.RoleName
	}
	if req.Data.Attributes.Namespace != nil {
		updates["namespace"] = *req.Data.Attributes.Namespace
	}
	if req.Data.Attributes.JWTAuthPath != nil {
		updates["jwt_auth_path"] = *req.Data.Attributes.JWTAuthPath
	}
	if req.Data.Attributes.EncodedCACert != nil {
		updates["tls_ca_certificate"] = *req.Data.Attributes.EncodedCACert
	}

	if len(updates) > 0 {
		updated, err := h.configRepo.Update(config.ID, updates)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to update OIDC configuration"}}})
			return
		}
		config = updated
	}

	c.JSON(http.StatusOK, gin.H{"data": formatVaultOIDCConfigResponse(config)})
}

// Delete deletes a Vault OIDC configuration.
// DELETE /api/v2/oidc-configurations/:id (dispatched by ID prefix)
func (h *VaultOIDCConfigurationHandlerV2) Delete(c *gin.Context) {
	config, ok := h.loadAuthorized(c)
	if !ok {
		return
	}
	if err := h.configRepo.Delete(config.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to delete OIDC configuration"}}})
		return
	}
	c.Status(http.StatusNoContent)
}

// loadAuthorized fetches the config by :id and enforces org VCS-settings permission. It writes the
// error response and returns ok=false on any failure.
func (h *VaultOIDCConfigurationHandlerV2) loadAuthorized(c *gin.Context) (*models.VaultOIDCConfiguration, bool) {
	config, err := h.configRepo.GetByID(c.Param("id"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "OIDC configuration not found"}}})
			return nil, false
		}
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to get OIDC configuration"}}})
		return nil, false
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return nil, false
	}
	ok, err := h.rbacService.CheckOrgManageVCSSettings(c.Request.Context(), user.ID, config.OrganizationID)
	if err != nil || !ok {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to manage OIDC configurations"}}})
		return nil, false
	}
	return config, true
}

// listData returns the org's Vault OIDC configs formatted as JSON:API resource objects (used by the
// dispatcher's merged List).
func (h *VaultOIDCConfigurationHandlerV2) listData(orgID uuid.UUID) ([]gin.H, error) {
	configs, err := h.configRepo.GetByOrganization(orgID)
	if err != nil {
		return nil, err
	}
	out := make([]gin.H, 0, len(configs))
	for i := range configs {
		out = append(out, formatVaultOIDCConfigResponse(&configs[i]))
	}
	return out, nil
}
