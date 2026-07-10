// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// GPGKeyHandler handles private-registry GPG key management, TFE-compatible with
// terraform-provider-tfe's tfe_registry_gpg_key resource. The wire surface mirrors
// go-tfe's GPGKeys API: JSON:API with kebab-case attributes, served under
// /api/registry/:registry/v2/gpg-keys, addressed by {namespace}/{key_id} where the
// namespace is the organization name and the resource id IS the GPG key id.
type GPGKeyHandler struct {
	gpgKeyRepo  *repository.GPGKeyRepository
	orgRepo     *repository.OrganizationRepository
	authService *auth.Service
	rbacService *rbac.Service
	gpgService  *registry.GPGService
}

func NewGPGKeyHandler(
	gpgKeyRepo *repository.GPGKeyRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *GPGKeyHandler {
	return &GPGKeyHandler{
		gpgKeyRepo:  gpgKeyRepo,
		orgRepo:     orgRepo,
		authService: authService,
		rbacService: rbacService,
		gpgService:  registry.NewGPGService(),
	}
}

// requireOrgManageProviders authorizes the caller to manage the org's registry
// trust plane (create/delete GPG keys). AUD-103: these endpoints previously
// authenticated but never checked membership or role, so any authenticated user
// could register or delete any org's trust anchors. Returns false (and writes the
// error) when unauthorized.
func (h *GPGKeyHandler) requireOrgManageProviders(c *gin.Context, org *models.Organization) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		gpgError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return false
	}
	ok, err := h.rbacService.CheckOrgManageProviders(c.Request.Context(), user.ID, org.ID)
	if err != nil || !ok {
		gpgError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this organization's registry")
		return false
	}
	return true
}

// requireOrgMember authorizes the caller as a member of org (GPG key reads).
func (h *GPGKeyHandler) requireOrgMember(c *gin.Context, org *models.Organization) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		gpgError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return false
	}
	inOrg, err := h.orgRepo.UserInOrg(user.ID, org.ID)
	if err != nil || !inOrg {
		gpgError(c, http.StatusForbidden, "Forbidden", "You are not a member of this organization")
		return false
	}
	return true
}

// gpgKeyType is the JSON:API primary type for GPG keys (matches go-tfe).
const gpgKeyType = "gpg-keys"

// privateRegistry is the only registry name the GPG key API supports (go-tfe hardcodes it).
const privateRegistry = "private"

// formatGPGKeyResponse renders a GPG key as a TFE-compatible JSON:API resource object.
// The resource id is the GPG key id (the provider addresses reads/deletes by
// {namespace}/{key_id} and stores key-id as the Terraform state id), and namespace is
// the owning organization's name.
func formatGPGKeyResponse(key *models.GPGKey, namespace string) gin.H {
	return gin.H{
		"id":   key.KeyID,
		"type": gpgKeyType,
		"attributes": gin.H{
			"ascii-armor":     key.ASCIIArmor,
			"created-at":      key.CreatedAt.UTC().Format(time.RFC3339),
			"updated-at":      key.UpdatedAt.UTC().Format(time.RFC3339),
			"key-id":          key.KeyID,
			"namespace":       namespace,
			"source":          "",
			"source-url":      nil,
			"trust-signature": "",
		},
	}
}

func gpgError(c *gin.Context, status int, title, detail string) {
	c.JSON(status, gin.H{
		"errors": []gin.H{{"status": fmt.Sprintf("%d", status), "title": title, "detail": detail}},
	})
}

// CreateGPGKey handles POST /api/registry/:registry/v2/gpg-keys.
// Body: { data: { type: "gpg-keys", attributes: { namespace, ascii-armor } } }.
func (h *GPGKeyHandler) CreateGPGKey(c *gin.Context) {
	if c.Param("registry") != privateRegistry {
		gpgError(c, http.StatusNotFound, "Not Found", "only the private registry supports GPG keys")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		gpgError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	var req struct {
		Data struct {
			Type       string `json:"type"`
			Attributes struct {
				Namespace  string `json:"namespace"`
				ASCIIArmor string `json:"ascii-armor"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		gpgError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	namespace := req.Data.Attributes.Namespace
	if namespace == "" {
		gpgError(c, http.StatusBadRequest, "Bad Request", "namespace is required")
		return
	}
	if req.Data.Attributes.ASCIIArmor == "" {
		gpgError(c, http.StatusBadRequest, "Bad Request", "ascii-armor is required")
		return
	}

	org, err := h.orgRepo.GetByName(namespace)
	if err != nil {
		gpgError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	if !h.requireOrgManageProviders(c, org) {
		return
	}

	keyID, err := h.gpgService.ParseGPGKey(req.Data.Attributes.ASCIIArmor)
	if err != nil {
		gpgError(c, http.StatusBadRequest, "Bad Request", fmt.Sprintf("Invalid GPG key: %v", err))
		return
	}

	if existing, err := h.gpgKeyRepo.GetByKeyID(org.ID, keyID); err == nil && existing != nil {
		gpgError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", fmt.Sprintf("GPG key %s already exists", keyID))
		return
	}

	gpgKey := &models.GPGKey{
		OrganizationID: org.ID,
		KeyID:          keyID,
		ASCIIArmor:     req.Data.Attributes.ASCIIArmor,
		CreatedBy:      user.ID,
	}
	if err := h.gpgKeyRepo.Create(gpgKey); err != nil {
		gpgError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": formatGPGKeyResponse(gpgKey, org.Name)})
}

// ListGPGKeys handles GET /api/registry/:registry/v2/gpg-keys?filter[namespace]=org1&filter[namespace]=org2.
func (h *GPGKeyHandler) ListGPGKeys(c *gin.Context) {
	if c.Param("registry") != privateRegistry {
		gpgError(c, http.StatusNotFound, "Not Found", "only the private registry supports GPG keys")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		gpgError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	namespaces := c.QueryArray("filter[namespace]")
	if len(namespaces) == 0 {
		gpgError(c, http.StatusBadRequest, "Bad Request", "at least one filter[namespace] is required")
		return
	}

	data := make([]gin.H, 0)
	for _, namespace := range namespaces {
		org, err := h.orgRepo.GetByName(namespace)
		if err != nil {
			// Skip namespaces that don't resolve rather than failing the whole list.
			continue
		}
		// AUD-103: only disclose keys for orgs the caller is a member of.
		if inOrg, err := h.orgRepo.UserInOrg(user.ID, org.ID); err != nil || !inOrg {
			continue
		}
		keys, err := h.gpgKeyRepo.GetByOrganization(org.ID)
		if err != nil {
			gpgError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
			return
		}
		for i := range keys {
			data = append(data, formatGPGKeyResponse(&keys[i], org.Name))
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": data})
}

// GetGPGKey handles GET /api/registry/:registry/v2/gpg-keys/:namespace/:key_id.
func (h *GPGKeyHandler) GetGPGKey(c *gin.Context) {
	key, org, ok := h.resolveKey(c)
	if !ok {
		return
	}
	if !h.requireOrgMember(c, org) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatGPGKeyResponse(key, org.Name)})
}

// UpdateGPGKey handles PATCH /api/registry/:registry/v2/gpg-keys/:namespace/:key_id.
// go-tfe only updates the namespace; terraform-provider-tfe never calls it (ascii_armor
// and organization both force replacement), so this is a minimal, faithful no-op that
// returns the current key.
func (h *GPGKeyHandler) UpdateGPGKey(c *gin.Context) {
	key, org, ok := h.resolveKey(c)
	if !ok {
		return
	}
	if !h.requireOrgMember(c, org) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatGPGKeyResponse(key, org.Name)})
}

// DeleteGPGKey handles DELETE /api/registry/:registry/v2/gpg-keys/:namespace/:key_id.
func (h *GPGKeyHandler) DeleteGPGKey(c *gin.Context) {
	key, org, ok := h.resolveKey(c)
	if !ok {
		return
	}
	if !h.requireOrgManageProviders(c, org) {
		return
	}
	if err := h.gpgKeyRepo.Delete(key.ID); err != nil {
		gpgError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// resolveKey validates the registry, authenticates, resolves the org from the :namespace
// path param, and loads the key by :key_id. It writes the appropriate error response and
// returns ok=false on any failure.
func (h *GPGKeyHandler) resolveKey(c *gin.Context) (*models.GPGKey, *models.Organization, bool) {
	if c.Param("registry") != privateRegistry {
		gpgError(c, http.StatusNotFound, "Not Found", "only the private registry supports GPG keys")
		return nil, nil, false
	}
	if _, err := h.authService.GetUserFromContext(c); err != nil {
		gpgError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, nil, false
	}

	org, err := h.orgRepo.GetByName(c.Param("namespace"))
	if err != nil {
		gpgError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return nil, nil, false
	}
	key, err := h.gpgKeyRepo.GetByKeyID(org.ID, c.Param("key_id"))
	if err != nil {
		gpgError(c, http.StatusNotFound, "Not Found", "GPG key not found")
		return nil, nil, false
	}
	return key, org, true
}
