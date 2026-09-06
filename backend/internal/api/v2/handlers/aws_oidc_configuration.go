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

// awsOIDCConfigType is the JSON:API resource type expected by go-tfe/terraform-provider-tfe.
const awsOIDCConfigType = "aws-oidc-configurations"

// AWSOIDCConfigurationHandlerV2 handles TFE-compatible AWS OIDC configuration API.
// Reference: go-tfe/aws_oidc_configuration.go. It shares the /oidc-configurations routes with the
// other providers via OIDCConfigDispatchHandler (dispatch by data.type on create, by ID prefix on
// the by-id routes).
type AWSOIDCConfigurationHandlerV2 struct {
	configRepo  *repository.AWSOIDCConfigurationRepository
	orgRepo     *repository.OrganizationRepository
	authService *auth.Service
	rbacService *rbac.Service
}

// NewAWSOIDCConfigurationHandlerV2 creates an AWSOIDCConfigurationHandlerV2.
func NewAWSOIDCConfigurationHandlerV2(
	configRepo *repository.AWSOIDCConfigurationRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *AWSOIDCConfigurationHandlerV2 {
	return &AWSOIDCConfigurationHandlerV2{
		configRepo:  configRepo,
		orgRepo:     orgRepo,
		authService: authService,
		rbacService: rbacService,
	}
}

// CreateAWSOIDCConfigRequest is the JSON:API request for creating an AWS OIDC configuration.
type CreateAWSOIDCConfigRequest struct {
	Data struct {
		Type       string `json:"type" binding:"required"`
		Attributes struct {
			RoleARN string `json:"role-arn"`
		} `json:"attributes" binding:"required"`
	} `json:"data" binding:"required"`
}

// UpdateAWSOIDCConfigRequest is the JSON:API request for updating an AWS OIDC configuration.
type UpdateAWSOIDCConfigRequest struct {
	Data struct {
		Type       string `json:"type" binding:"required"`
		Attributes struct {
			RoleARN *string `json:"role-arn,omitempty"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

// formatAWSOIDCConfigResponse formats an AWS OIDC configuration as a JSON:API response.
func formatAWSOIDCConfigResponse(config *models.AWSOIDCConfiguration) gin.H {
	orgName := ""
	if config.Organization != nil {
		orgName = config.Organization.Name
	}

	return gin.H{
		"id":   config.ID,
		"type": awsOIDCConfigType,
		"attributes": gin.H{
			"role-arn": config.RoleARN,
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

// Create creates a new AWS OIDC configuration.
// POST /api/v2/organizations/:name/oidc-configurations (dispatched by data.type)
func (h *AWSOIDCConfigurationHandlerV2) Create(c *gin.Context) {
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	// RBAC: user must be able to manage the organization's VCS/OIDC settings
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

	var req CreateAWSOIDCConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	if req.Data.Type != awsOIDCConfigType {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "data.type must be '"+awsOIDCConfigType+"'")
		return
	}

	if req.Data.Attributes.RoleARN == "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "role-arn is required")
		return
	}

	config := &models.AWSOIDCConfiguration{
		RoleARN:        req.Data.Attributes.RoleARN,
		OrganizationID: org.ID,
	}

	if err := h.configRepo.Create(config); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create AWS OIDC configuration")
		return
	}

	// Reload with organization preloaded
	config, err = h.configRepo.GetByID(config.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to reload AWS OIDC configuration")
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, formatAWSOIDCConfigResponse(config))
}

// Read returns an AWS OIDC configuration by ID.
// GET /api/v2/oidc-configurations/:id (dispatched by ID prefix)
func (h *AWSOIDCConfigurationHandlerV2) Read(c *gin.Context) {
	config, ok := h.loadAuthorized(c)
	if !ok {
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, formatAWSOIDCConfigResponse(config))
}

// Update updates an AWS OIDC configuration (partial update).
// PATCH /api/v2/oidc-configurations/:id (dispatched by ID prefix)
func (h *AWSOIDCConfigurationHandlerV2) Update(c *gin.Context) {
	config, ok := h.loadAuthorized(c)
	if !ok {
		return
	}

	var req UpdateAWSOIDCConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	if req.Data.Type != awsOIDCConfigType {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "data.type must be '"+awsOIDCConfigType+"'")
		return
	}

	updates := make(map[string]any)
	if req.Data.Attributes.RoleARN != nil {
		updates["role_arn"] = *req.Data.Attributes.RoleARN
	}

	if len(updates) > 0 {
		updated, err := h.configRepo.Update(config.ID, updates)
		if err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update OIDC configuration")
			return
		}
		config = updated
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatAWSOIDCConfigResponse(config))
}

// Delete deletes an AWS OIDC configuration.
// DELETE /api/v2/oidc-configurations/:id (dispatched by ID prefix)
func (h *AWSOIDCConfigurationHandlerV2) Delete(c *gin.Context) {
	config, ok := h.loadAuthorized(c)
	if !ok {
		return
	}
	if err := h.configRepo.Delete(config.ID); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete OIDC configuration")
		return
	}
	c.Status(http.StatusNoContent)
}

// loadAuthorized fetches the config by :id and enforces org VCS-settings permission. It writes the
// error response and returns ok=false on any failure.
func (h *AWSOIDCConfigurationHandlerV2) loadAuthorized(c *gin.Context) (*models.AWSOIDCConfiguration, bool) {
	config, err := h.configRepo.GetByID(c.Param("id"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "OIDC configuration not found")
			return nil, false
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to get OIDC configuration")
		return nil, false
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	ok, err := h.rbacService.CheckOrgManageVCSSettings(c.Request.Context(), user.ID, config.OrganizationID)
	if err != nil || !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage OIDC configurations")
		return nil, false
	}
	return config, true
}

// listData returns the org's AWS OIDC configs formatted as JSON:API resource objects (used by the
// dispatcher's merged List).
func (h *AWSOIDCConfigurationHandlerV2) listData(orgID uuid.UUID) ([]gin.H, error) {
	configs, err := h.configRepo.GetByOrganization(orgID)
	if err != nil {
		return nil, err
	}
	out := make([]gin.H, 0, len(configs))
	for i := range configs {
		out = append(out, formatAWSOIDCConfigResponse(&configs[i]))
	}
	return out, nil
}
