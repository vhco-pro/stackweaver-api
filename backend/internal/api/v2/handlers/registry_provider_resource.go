// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/storage"
)

// RegistryProviderResourceHandler implements the tfe_registry_provider resource, TFE-compatible
// with terraform-provider-tfe / go-tfe RegistryProviders. It manages the provider *shell*
// (name + namespace + registry_name); versions and platforms are published separately (see
// RegistryProviderPublishingHandler). The wire surface mirrors go-tfe: JSON:API type
// "registry-providers", kebab-case attributes, addressed by the composite
// {organization}/{registry_name}/{namespace}/{name}.
type RegistryProviderResourceHandler struct {
	providerRepo *repository.ProviderRepository
	orgRepo      *repository.OrganizationRepository
	authService  *auth.Service
	rbacService  *rbac.Service
	storage      storage.Client
}

func NewRegistryProviderResourceHandler(
	providerRepo *repository.ProviderRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	storageClient storage.Client,
) *RegistryProviderResourceHandler {
	return &RegistryProviderResourceHandler{
		providerRepo: providerRepo,
		orgRepo:      orgRepo,
		authService:  authService,
		rbacService:  rbacService,
		storage:      storageClient,
	}
}

// requireManageProviders authorizes the caller to manage the org's provider
// registry (create/delete providers, publish binaries). AUD-103. Returns false and
// writes the error when unauthorized.
func (h *RegistryProviderResourceHandler) requireManageProviders(c *gin.Context, orgID uuid.UUID) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		regProvErr(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return false
	}
	ok, err := h.rbacService.CheckOrgManageProviders(c.Request.Context(), user.ID, orgID)
	if err != nil || !ok {
		regProvErr(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this organization's registry")
		return false
	}
	return true
}

// requireMember authorizes the caller as a member of the org (provider reads). AUD-103.
func (h *RegistryProviderResourceHandler) requireMember(c *gin.Context, orgID uuid.UUID) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		regProvErr(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return false
	}
	inOrg, err := h.orgRepo.UserInOrg(user.ID, orgID)
	if err != nil || !inOrg {
		regProvErr(c, http.StatusForbidden, "Forbidden", "You are not a member of this organization")
		return false
	}
	return true
}

const registryProviderType = "registry-providers"

func regProvErr(c *gin.Context, status int, title, detail string) {
	c.JSON(status, gin.H{
		"errors": []gin.H{{"status": fmt.Sprintf("%d", status), "title": title, "detail": detail}},
	})
}

// formatRegistryProviderResponse renders a provider as a go-tfe-compatible JSON:API resource.
func formatRegistryProviderResponse(p *models.Provider) gin.H {
	return gin.H{
		"id":   p.ID.String(),
		"type": registryProviderType,
		"attributes": gin.H{
			"name":          p.Name,
			"namespace":     p.Namespace,
			"registry-name": p.RegistryName,
			"created-at":    p.CreatedAt.UTC().Format(time.RFC3339),
			"updated-at":    p.UpdatedAt.UTC().Format(time.RFC3339),
			"permissions": gin.H{
				"can-delete": true,
			},
		},
		"relationships": gin.H{
			"organization": gin.H{
				"data": gin.H{"id": p.Organization.Name, "type": "organizations"},
			},
		},
	}
}

// CreateProvider handles POST /api/v2/organizations/:name/registry-providers.
// Body: { data: { type: "registry-providers", attributes: { name, namespace, registry-name } } }.
func (h *RegistryProviderResourceHandler) CreateProvider(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		regProvErr(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		regProvErr(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	if !h.requireManageProviders(c, org.ID) {
		return
	}

	var req struct {
		Data struct {
			Type       string `json:"type"`
			Attributes struct {
				Name         string `json:"name"`
				Namespace    string `json:"namespace"`
				RegistryName string `json:"registry-name"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		regProvErr(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	name := req.Data.Attributes.Name
	if name == "" {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "name is required")
		return
	}

	registryName := req.Data.Attributes.RegistryName
	if registryName == "" {
		registryName = "private"
	}
	if registryName != "private" && registryName != "public" {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "registry-name must be 'private' or 'public'")
		return
	}

	// Namespace rules mirror the provider: private providers are namespaced by their org (the
	// client omits namespace); public providers require an explicit upstream namespace.
	namespace := req.Data.Attributes.Namespace
	switch registryName {
	case "private":
		if namespace != "" && namespace != org.Name {
			regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "private providers are namespaced by the organization; namespace must be omitted or equal the organization name")
			return
		}
		namespace = org.Name
	case "public":
		if namespace == "" {
			regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "namespace is required for public registry providers")
			return
		}
	}

	if existing, err := h.providerRepo.GetByComposite(org.ID, registryName, namespace, name); err == nil && existing != nil {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", fmt.Sprintf("provider %s/%s/%s already exists", registryName, namespace, name))
		return
	}

	provider := &models.Provider{
		OrganizationID: org.ID,
		Name:           name,
		RegistryName:   registryName,
		Namespace:      namespace,
		PublishedBy:    user.ID,
	}
	if err := h.providerRepo.Create(provider); err != nil {
		regProvErr(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	provider.Organization = *org

	c.JSON(http.StatusCreated, gin.H{"data": formatRegistryProviderResponse(provider)})
}

// ListProviders handles GET /api/v2/organizations/:name/registry-providers?filter[registry_name]=private.
func (h *RegistryProviderResourceHandler) ListProviders(c *gin.Context) {
	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		regProvErr(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	if !h.requireMember(c, org.ID) {
		return
	}

	registryName := c.Query("filter[registry_name]")
	providers, _, err := h.providerRepo.ListByOrganization(org.ID, registryName, 100, 0)
	if err != nil {
		regProvErr(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	data := make([]gin.H, 0, len(providers))
	for i := range providers {
		data = append(data, formatRegistryProviderResponse(&providers[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

// GetProvider handles GET /api/v2/organizations/:name/registry-providers/:registry_name/:namespace/:provider_name.
func (h *RegistryProviderResourceHandler) GetProvider(c *gin.Context) {
	provider, ok := h.resolveComposite(c)
	if !ok {
		return
	}
	if !h.requireMember(c, provider.OrganizationID) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatRegistryProviderResponse(provider)})
}

// DeleteProvider handles DELETE /api/v2/organizations/:name/registry-providers/:registry_name/:namespace/:provider_name.
func (h *RegistryProviderResourceHandler) DeleteProvider(c *gin.Context) {
	provider, ok := h.resolveComposite(c)
	if !ok {
		return
	}
	if !h.requireManageProviders(c, provider.OrganizationID) {
		return
	}
	if err := h.providerRepo.Delete(provider.ID); err != nil {
		regProvErr(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	h.gcProviderStorage(c.Request.Context(), provider)
	c.Status(http.StatusNoContent)
}

// GetProviderByID handles GET /api/v2/registry-providers/:id (go-tfe read-by-id form).
func (h *RegistryProviderResourceHandler) GetProviderByID(c *gin.Context) {
	provider, ok := h.resolveByID(c)
	if !ok {
		return
	}
	if !h.requireMember(c, provider.OrganizationID) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatRegistryProviderResponse(provider)})
}

// DeleteProviderByID handles DELETE /api/v2/registry-providers/:id.
func (h *RegistryProviderResourceHandler) DeleteProviderByID(c *gin.Context) {
	provider, ok := h.resolveByID(c)
	if !ok {
		return
	}
	if !h.requireManageProviders(c, provider.OrganizationID) {
		return
	}
	if err := h.providerRepo.Delete(provider.ID); err != nil {
		regProvErr(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	h.gcProviderStorage(c.Request.Context(), provider)
	c.Status(http.StatusNoContent)
}

// gcProviderStorage best-effort deletes a deleted provider's artifacts (binaries, SHA256SUMS,
// signatures) from object storage. The DB cascade has already removed the rows, so any failure here
// only leaves orphaned objects — it is logged, never fatal. Objects live under
// providers/{org}/{name}/... ; the trailing slash keeps "foo" from also matching "foobar".
func (h *RegistryProviderResourceHandler) gcProviderStorage(ctx context.Context, provider *models.Provider) {
	if h.storage == nil {
		return
	}
	prefix := fmt.Sprintf("providers/%s/%s/", provider.Organization.Name, provider.Name)
	objs, err := h.storage.List(ctx, prefix)
	if err != nil {
		logger.Warnf("registry provider delete: failed to list storage for GC (%s): %v", prefix, err)
		return
	}
	removed := 0
	for _, o := range objs {
		if err := h.storage.Delete(ctx, o.Key); err != nil {
			logger.Warnf("registry provider delete: failed to GC storage object %s: %v", o.Key, err)
			continue
		}
		removed++
	}
	if len(objs) > 0 {
		logger.Infof("registry provider delete: GC'd %d/%d storage objects under %s", removed, len(objs), prefix)
	}
}

// resolveComposite authenticates, resolves the org from :name, and loads the provider by the
// composite :registry_name/:namespace/:provider_name. Writes the error response on failure.
func (h *RegistryProviderResourceHandler) resolveComposite(c *gin.Context) (*models.Provider, bool) {
	if _, err := h.authService.GetUserFromContext(c); err != nil {
		regProvErr(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		regProvErr(c, http.StatusNotFound, "Not Found", "Organization not found")
		return nil, false
	}
	provider, err := h.providerRepo.GetByComposite(org.ID, c.Param("registry_name"), c.Param("namespace"), c.Param("provider_name"))
	if err != nil {
		regProvErr(c, http.StatusNotFound, "Not Found", "Registry provider not found")
		return nil, false
	}
	return provider, true
}

// resolveByID authenticates and loads the provider by its UUID (:id).
func (h *RegistryProviderResourceHandler) resolveByID(c *gin.Context) (*models.Provider, bool) {
	if _, err := h.authService.GetUserFromContext(c); err != nil {
		regProvErr(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		regProvErr(c, http.StatusNotFound, "Not Found", "Registry provider not found")
		return nil, false
	}
	provider, err := h.providerRepo.GetByID(id)
	if err != nil {
		regProvErr(c, http.StatusNotFound, "Not Found", "Registry provider not found")
		return nil, false
	}
	return provider, true
}
