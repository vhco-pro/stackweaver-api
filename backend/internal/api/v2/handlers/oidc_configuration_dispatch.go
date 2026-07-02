// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/repository"
)

// OIDCConfigDispatchHandler serves the TFE-compatible OIDC configuration routes that are shared by all
// cloud providers (Azure, AWS, GCP, Vault). terraform-provider-tfe uses a single set of URLs —
// POST/GET /organizations/:name/oidc-configurations and GET/PATCH/DELETE /oidc-configurations/:id —
// and distinguishes providers by the JSON:API `data.type` on create and by the ID prefix on the by-id
// routes. This handler owns those routes and delegates to the per-provider handler:
//   - create:  by `data.type`  (azure-oidc-configurations | aws-oidc-configurations)
//   - by-id:   by ID prefix    (azoidc- | awsoidc-)
//   - list:    merged across all providers for the organization.
type OIDCConfigDispatchHandler struct {
	azure       *AzureOIDCConfigurationHandlerV2
	aws         *AWSOIDCConfigurationHandlerV2
	orgRepo     *repository.OrganizationRepository
	authService *auth.Service
	rbacService *rbac.Service
}

// NewOIDCConfigDispatchHandler creates an OIDCConfigDispatchHandler.
func NewOIDCConfigDispatchHandler(
	azure *AzureOIDCConfigurationHandlerV2,
	aws *AWSOIDCConfigurationHandlerV2,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *OIDCConfigDispatchHandler {
	return &OIDCConfigDispatchHandler{
		azure:       azure,
		aws:         aws,
		orgRepo:     orgRepo,
		authService: authService,
		rbacService: rbacService,
	}
}

// List returns all OIDC configurations (every provider) for an organization, merged.
// GET /api/v2/organizations/:name/oidc-configurations
func (h *OIDCConfigDispatchHandler) List(c *gin.Context) {
	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Organization not found"}}})
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return
	}
	ok, err := h.rbacService.CheckOrgManageVCSSettings(c.Request.Context(), user.ID, org.ID)
	if err != nil || !ok {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to read OIDC configurations"}}})
		return
	}

	data := make([]gin.H, 0)
	azureData, err := h.azure.listData(org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to list OIDC configurations"}}})
		return
	}
	data = append(data, azureData...)
	awsData, err := h.aws.listData(org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to list OIDC configurations"}}})
		return
	}
	data = append(data, awsData...)

	c.JSON(http.StatusOK, gin.H{"data": data})
}

// Create dispatches to the provider handler named by the request's data.type.
// POST /api/v2/organizations/:name/oidc-configurations
func (h *OIDCConfigDispatchHandler) Create(c *gin.Context) {
	// Peek data.type without consuming the body, then restore it for the delegate's ShouldBindJSON.
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Failed to read request body"}}})
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	var peek struct {
		Data struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	_ = json.Unmarshal(body, &peek)

	switch peek.Data.Type {
	case azureOIDCConfigType:
		h.azure.Create(c)
	case awsOIDCConfigType:
		h.aws.Create(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "data.type must be one of: " + azureOIDCConfigType + ", " + awsOIDCConfigType}}})
	}
}

// Read dispatches a by-id read to the provider handler named by the ID prefix.
// GET /api/v2/oidc-configurations/:id
func (h *OIDCConfigDispatchHandler) Read(c *gin.Context) {
	switch h.providerForID(c.Param("id")) {
	case h.azure:
		h.azure.Read(c)
	case h.aws:
		h.aws.Read(c)
	default:
		oidcUnknownID(c)
	}
}

// Update dispatches a by-id update.
// PATCH /api/v2/oidc-configurations/:id
func (h *OIDCConfigDispatchHandler) Update(c *gin.Context) {
	switch h.providerForID(c.Param("id")) {
	case h.azure:
		h.azure.Update(c)
	case h.aws:
		h.aws.Update(c)
	default:
		oidcUnknownID(c)
	}
}

// Delete dispatches a by-id delete.
// DELETE /api/v2/oidc-configurations/:id
func (h *OIDCConfigDispatchHandler) Delete(c *gin.Context) {
	switch h.providerForID(c.Param("id")) {
	case h.azure:
		h.azure.Delete(c)
	case h.aws:
		h.aws.Delete(c)
	default:
		oidcUnknownID(c)
	}
}

// providerForID returns the provider handler matching the ID prefix (azoidc- / awsoidc-), or nil.
func (h *OIDCConfigDispatchHandler) providerForID(id string) any {
	switch {
	case strings.HasPrefix(id, "azoidc-"):
		return h.azure
	case strings.HasPrefix(id, "awsoidc-"):
		return h.aws
	default:
		return nil
	}
}

func oidcUnknownID(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "OIDC configuration not found"}}})
}
