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

// gcpOIDCConfigType is the JSON:API resource type expected by go-tfe/terraform-provider-tfe.
const gcpOIDCConfigType = "gcp-oidc-configurations"

// GCPOIDCConfigurationHandlerV2 handles TFE-compatible GCP OIDC configuration API.
// Reference: go-tfe/gcp_oidc_configuration.go. It shares the /oidc-configurations routes with the
// other providers via OIDCConfigDispatchHandler (dispatch by data.type on create, by ID prefix on
// the by-id routes).
type GCPOIDCConfigurationHandlerV2 struct {
	configRepo  *repository.GCPOIDCConfigurationRepository
	orgRepo     *repository.OrganizationRepository
	authService *auth.Service
	rbacService *rbac.Service
}

// NewGCPOIDCConfigurationHandlerV2 creates a GCPOIDCConfigurationHandlerV2.
func NewGCPOIDCConfigurationHandlerV2(
	configRepo *repository.GCPOIDCConfigurationRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *GCPOIDCConfigurationHandlerV2 {
	return &GCPOIDCConfigurationHandlerV2{
		configRepo:  configRepo,
		orgRepo:     orgRepo,
		authService: authService,
		rbacService: rbacService,
	}
}

// CreateGCPOIDCConfigRequest is the JSON:API request for creating a GCP OIDC configuration.
type CreateGCPOIDCConfigRequest struct {
	Data struct {
		Type       string `json:"type" binding:"required"`
		Attributes struct {
			ServiceAccountEmail  string `json:"service-account-email"`
			ProjectNumber        string `json:"project-number"`
			WorkloadProviderName string `json:"workload-provider-name"`
		} `json:"attributes" binding:"required"`
	} `json:"data" binding:"required"`
}

// UpdateGCPOIDCConfigRequest is the JSON:API request for updating a GCP OIDC configuration.
type UpdateGCPOIDCConfigRequest struct {
	Data struct {
		Type       string `json:"type" binding:"required"`
		Attributes struct {
			ServiceAccountEmail  *string `json:"service-account-email,omitempty"`
			ProjectNumber        *string `json:"project-number,omitempty"`
			WorkloadProviderName *string `json:"workload-provider-name,omitempty"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

// formatGCPOIDCConfigResponse formats a GCP OIDC configuration as a JSON:API response.
func formatGCPOIDCConfigResponse(config *models.GCPOIDCConfiguration) jsonapi.Resource[GCPOIDCConfigAttributes] {
	orgName := ""
	if config.Organization != nil {
		orgName = config.Organization.Name
	}

	return jsonapi.Resource[GCPOIDCConfigAttributes]{
		ID:   config.ID,
		Type: gcpOIDCConfigType,
		Attributes: GCPOIDCConfigAttributes{
			ServiceAccountEmail:  config.ServiceAccountEmail,
			ProjectNumber:        config.ProjectNumber,
			WorkloadProviderName: config.WorkloadProviderName,
		},
		Relationships: WorkspaceOnlyRelationshipsNamed{
			Organization: jsonapi.ToOne(orgName, "organizations"),
		},
		Links: jsonapi.SelfLink{
			Self: "/api/v2/oidc-configurations/" + config.ID,
		},
	}
}

// Create creates a new GCP OIDC configuration.
// POST /api/v2/organizations/:name/oidc-configurations (dispatched by data.type)
func (h *GCPOIDCConfigurationHandlerV2) Create(c *gin.Context) {
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

	var req CreateGCPOIDCConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	if req.Data.Type != gcpOIDCConfigType {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "data.type must be '"+gcpOIDCConfigType+"'")
		return
	}

	if req.Data.Attributes.ServiceAccountEmail == "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "service-account-email is required")
		return
	}
	if req.Data.Attributes.ProjectNumber == "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "project-number is required")
		return
	}
	if req.Data.Attributes.WorkloadProviderName == "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "workload-provider-name is required")
		return
	}

	config := &models.GCPOIDCConfiguration{
		ServiceAccountEmail:  req.Data.Attributes.ServiceAccountEmail,
		ProjectNumber:        req.Data.Attributes.ProjectNumber,
		WorkloadProviderName: req.Data.Attributes.WorkloadProviderName,
		OrganizationID:       org.ID,
	}

	if err := h.configRepo.Create(config); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create GCP OIDC configuration")
		return
	}

	// Reload with organization preloaded
	config, err = h.configRepo.GetByID(config.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to reload GCP OIDC configuration")
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, formatGCPOIDCConfigResponse(config))
}

// Read returns a GCP OIDC configuration by ID.
// GET /api/v2/oidc-configurations/:id (dispatched by ID prefix)
func (h *GCPOIDCConfigurationHandlerV2) Read(c *gin.Context) {
	config, ok := h.loadAuthorized(c)
	if !ok {
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, formatGCPOIDCConfigResponse(config))
}

// Update updates a GCP OIDC configuration (partial update).
// PATCH /api/v2/oidc-configurations/:id (dispatched by ID prefix)
func (h *GCPOIDCConfigurationHandlerV2) Update(c *gin.Context) {
	config, ok := h.loadAuthorized(c)
	if !ok {
		return
	}

	var req UpdateGCPOIDCConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	if req.Data.Type != gcpOIDCConfigType {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "data.type must be '"+gcpOIDCConfigType+"'")
		return
	}

	updates := make(map[string]any)
	if req.Data.Attributes.ServiceAccountEmail != nil {
		updates["service_account_email"] = *req.Data.Attributes.ServiceAccountEmail
	}
	if req.Data.Attributes.ProjectNumber != nil {
		updates["project_number"] = *req.Data.Attributes.ProjectNumber
	}
	if req.Data.Attributes.WorkloadProviderName != nil {
		updates["workload_provider_name"] = *req.Data.Attributes.WorkloadProviderName
	}

	if len(updates) > 0 {
		updated, err := h.configRepo.Update(config.ID, updates)
		if err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update OIDC configuration")
			return
		}
		config = updated
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatGCPOIDCConfigResponse(config))
}

// Delete deletes a GCP OIDC configuration.
// DELETE /api/v2/oidc-configurations/:id (dispatched by ID prefix)
func (h *GCPOIDCConfigurationHandlerV2) Delete(c *gin.Context) {
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
func (h *GCPOIDCConfigurationHandlerV2) loadAuthorized(c *gin.Context) (*models.GCPOIDCConfiguration, bool) {
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

// listData returns the org's GCP OIDC configs formatted as JSON:API resource objects (used by the
// dispatcher's merged List).
func (h *GCPOIDCConfigurationHandlerV2) listData(orgID uuid.UUID) ([]jsonapi.Resource[GCPOIDCConfigAttributes], error) {
	configs, err := h.configRepo.GetByOrganization(orgID)
	if err != nil {
		return nil, err
	}
	out := make([]jsonapi.Resource[GCPOIDCConfigAttributes], 0, len(configs))
	for i := range configs {
		out = append(out, formatGCPOIDCConfigResponse(&configs[i]))
	}
	return out, nil
}
