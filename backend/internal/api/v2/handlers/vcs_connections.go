// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/pagination"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/ansiblefiles"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"gorm.io/gorm"
)

type VCSConnectionHandlerV2 struct {
	vcsConnectionRepo *repository.VCSConnectionRepository
	orgRepo           *repository.OrganizationRepository
	authService       *auth.Service
	vcsRegistry       *vcs.ProviderRegistry
	rbacService       *rbac.Service
}

func NewVCSConnectionHandlerV2(
	vcsConnectionRepo *repository.VCSConnectionRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	vcsRegistry *vcs.ProviderRegistry,
	rbacService *rbac.Service,
) *VCSConnectionHandlerV2 {
	return &VCSConnectionHandlerV2{
		vcsConnectionRepo: vcsConnectionRepo,
		orgRepo:           orgRepo,
		authService:       authService,
		vcsRegistry:       vcsRegistry,
		rbacService:       rbacService,
	}
}

type CreateVCSConnectionRequestV2 struct {
	Provider       string `json:"provider" binding:"required"` // "github", "gitlab", "bitbucket", "azure_devops"
	InstallationID string `json:"installation_id,omitempty"`
	AccessToken    string `json:"access_token" binding:"required"` //nolint:gosec // G117: token field, encrypted before storage
	RefreshToken   string `json:"refresh_token,omitempty"`         //nolint:gosec // G117: token field
	TokenExpiresAt string `json:"token_expires_at,omitempty"`      // ISO 8601 format
	AccountName    string `json:"account_name" binding:"required"`
	AccountType    string `json:"account_type" binding:"required"` // "organization" or "user"
}

// List lists all VCS connections for an organization
// GET /api/v2/organizations/:name/vcs-connections
func (h *VCSConnectionHandlerV2) List(c *gin.Context) {
	orgName := c.Param("name")

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	// AUD-138: gate the connection roster on org membership (JWT callers bypass the wall).
	if !h.requireOrgMembership(c, org.ID) {
		return
	}

	connections, err := h.vcsConnectionRepo.ListByOrganization(org.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list VCS connections")
		return
	}

	responseData := make([]jsonapi.Resource[VCSConnectionAttributes], 0, len(connections))
	for i := range connections {
		responseData = append(responseData, vcsConnectionResource(&connections[i], org.ID))
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, responseData, jsonapi.NewFullPageMeta(len(responseData)))
}

// Create creates a new VCS connection
// POST /api/v2/organizations/:name/vcs-connections
func (h *VCSConnectionHandlerV2) Create(c *gin.Context) {
	orgName := c.Param("name")

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	if !authorizeManageVCSSettings(c, h.authService, h.rbacService, org.ID) {
		return
	}

	var req CreateVCSConnectionRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	provider := models.VCSProvider(req.Provider)
	if provider != models.VCSProviderGitHub &&
		provider != models.VCSProviderGitLab &&
		provider != models.VCSProviderBitbucket &&
		provider != models.VCSProviderAzureDevOps {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid provider. Must be 'github', 'gitlab', 'bitbucket', or 'azure_devops'")
		return
	}

	// One connection per provider. Only "not found" means there is none: any other error leaves
	// the question unanswered, and answering it either way would be a guess.
	_, err = h.vcsConnectionRepo.GetByOrganizationAndProvider(org.ID, provider)
	if err == nil {
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", "VCS connection for this provider already exists")
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check for an existing VCS connection")
		return
	}

	var tokenExpiresAt *time.Time
	if req.TokenExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, req.TokenExpiresAt)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid token_expires_at format. Use ISO 8601 format (RFC3339)")
			return
		}
		tokenExpiresAt = &parsed
	}

	connection := &models.VCSConnection{
		OrganizationID: org.ID,
		Provider:       provider,
		InstallationID: req.InstallationID,
		AccessToken:    req.AccessToken,
		RefreshToken:   req.RefreshToken,
		TokenExpiresAt: tokenExpiresAt,
		AccountName:    req.AccountName,
		AccountType:    req.AccountType,
	}

	// Encrypt tokens at rest (#95) before persisting. No-op when encryption is disabled.
	if h.vcsRegistry != nil {
		if err := h.vcsRegistry.EncryptTokens(connection); err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to encrypt VCS tokens")
			return
		}
	}

	if err := h.vcsConnectionRepo.Create(connection); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create VCS connection")
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, vcsConnectionResource(connection, org.ID))
}

// Get returns a VCS connection by ID
// GET /api/v2/vcs-connections/:id
func (h *VCSConnectionHandlerV2) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid VCS connection ID")
		return
	}

	connection, err := h.vcsConnectionRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "VCS connection not found")
		return
	}

	// AUD-138: gate metadata read on org membership.
	if !h.authorizeVCSConnectionRead(c, connection) {
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, vcsConnectionResource(connection, connection.OrganizationID))
}

// Delete deletes a VCS connection
// DELETE /api/v2/vcs-connections/:id
func (h *VCSConnectionHandlerV2) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid VCS connection ID")
		return
	}

	connection, err := h.vcsConnectionRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "VCS connection not found")
		return
	}

	org, err := h.orgRepo.GetByID(connection.OrganizationID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to retrieve organization")
		return
	}

	if !authorizeManageVCSSettings(c, h.authService, h.rbacService, org.ID) {
		return
	}

	if err := h.vcsConnectionRepo.Delete(id); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete VCS connection")
		return
	}

	c.Status(http.StatusNoContent)
}

// authorizeManageVCSSettings gates an action on the caller holding the organization-level
// manage-vcs-settings permission in orgID. It writes the JSON:API error and returns false when
// the caller may not proceed: 401 without an identity, 403 without the permission.
//
// Every handler that creates, re-points or removes an organization's VCS connection calls it,
// and so does every handler that starts a flow ending in one: the GitHub App installation, and
// the Azure DevOps authorization whose signed state the callback later accepts in place of a
// caller. One function, so that those handlers hold the same rule and cannot drift apart. Call
// it once the organization is known and before anything is fetched from the provider or
// written.
//
// It answers what the caller's USER may do. What an API token may do is the org wall's
// question, and the wall asks it before any of these handlers runs (wallRegistry in
// middleware/org_wall_registry.go). A token the wall refused never reaches this, so the check
// only ever narrows what a token may do and is never a second way in for one.
func authorizeManageVCSSettings(c *gin.Context, authService *auth.Service, rbacService *rbac.Service, orgID uuid.UUID) bool {
	user, err := authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return false
	}
	// A handler wired without the service cannot answer the question, and must not answer yes.
	if rbacService == nil {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", manageVCSSettingsRefusal)
		return false
	}
	hasPermission, err := rbacService.CheckOrgManageVCSSettings(c.Request.Context(), user.ID, orgID)
	if err != nil || !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", manageVCSSettingsRefusal)
		return false
	}
	return true
}

// manageVCSSettingsRefusal is the one answer a caller without the permission gets, whichever
// handler refused them.
const manageVCSSettingsRefusal = "You do not have permission to manage VCS connections. This requires organization-level manage-vcs-settings permission via team membership."

// requireOrgMembership gates an action on the caller being a member of orgID.
// Writes the JSON:API error and returns false when unauthorized - 401 (no auth),
// 403 (not a member). JWT/browser identities bypass the org-resolution wall, so
// this per-handler check is the only defense for them.
func (h *VCSConnectionHandlerV2) requireOrgMembership(c *gin.Context, orgID uuid.UUID) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return false
	}
	inOrg, err := h.orgRepo.UserInOrg(user.ID, orgID)
	if err != nil || !inOrg {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You must be a member of this organization (via team membership)")
		return false
	}
	return true
}

// authorizeVCSConnectionRead gates a read of a VCS connection on organization
// membership. AUD-138: the repository/branch/file-content read endpoints operate
// the connection's org's *decrypted* OAuth token server-side, so an unauthorized
// caller could exfiltrate another tenant's private source. It writes the JSON:API
// error and returns false when unauthorized.
func (h *VCSConnectionHandlerV2) authorizeVCSConnectionRead(c *gin.Context, connection *models.VCSConnection) bool {
	return h.requireOrgMembership(c, connection.OrganizationID)
}

// getProvider resolves the ProviderService for a connection and handles error responses.
// Returns nil if an error was written to c. It first enforces org membership
// (AUD-138) - every provider-backed read goes through here, so this is the single
// choke point that gates repository/branch/file-content listing.
func (h *VCSConnectionHandlerV2) getProvider(c *gin.Context, connection *models.VCSConnection) vcs.ProviderService {
	if !h.authorizeVCSConnectionRead(c, connection) {
		return nil
	}
	provider, err := h.vcsRegistry.GetProvider(connection)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", fmt.Sprintf("Failed to resolve VCS provider: %v", err))
		return nil
	}
	return provider
}

// isNotImplemented reports whether an error from a provider indicates "not implemented".
func isNotImplemented(err error) bool {
	return strings.Contains(err.Error(), "not implemented")
}

// isIdentityNotMaterialized reports whether an Azure DevOps error is the "identity not materialized" error.
func isIdentityNotMaterialized(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "azure_devops_identity_not_materialized") ||
		strings.Contains(msg, "AadUserStateException") ||
		strings.Contains(msg, "not been materialized")
}

// ListRepositories lists repositories for a VCS connection
// GET /api/v2/vcs-connections/:id/repositories
func (h *VCSConnectionHandlerV2) ListRepositories(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid VCS connection ID")
		return
	}

	connection, err := h.vcsConnectionRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "VCS connection not found")
		return
	}

	page, perPage := pagination.Parse(c, 30)
	if perPage > 100 {
		perPage = 100
	}

	provider := h.getProvider(c, connection)
	if provider == nil {
		return
	}

	project := c.Query("project")
	var repos []vcs.Repository
	if scoped, ok := provider.(vcs.ProjectScopedRepoLister); ok && project != "" {
		repos, err = scoped.ListRepositoriesByProject(c.Request.Context(), connection, project, page, perPage)
	} else {
		repos, err = provider.ListRepositories(c.Request.Context(), connection, page, perPage)
	}
	if err != nil {
		switch {
		case isNotImplemented(err):
			jsonapi.WriteError(c, http.StatusNotImplemented, "Not Implemented", fmt.Sprintf("Repository listing is not yet supported for %s", connection.Provider))
		case isIdentityNotMaterialized(err):
			jsonapi.WriteError(c, http.StatusForbidden, "Identity Not Materialized", "Your Azure DevOps identity has not been activated in this organization. "+
				"Open https://dev.azure.com/ in a browser, sign in with the same Microsoft account you used to authorize Stackweaver, "+
				"then delete this VCS connection and reconnect.")
		default:
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", fmt.Sprintf("Failed to list repositories: %v", err))
		}
		return
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, repos, LegacyPageMeta{Pagination: LegacyPage{Page: page, PerPage: perPage}})
}

// ListProjects lists projects for a VCS connection.
// Only providers with a project layer (Azure DevOps) support this; others return 501.
// GET /api/v2/vcs-connections/:id/projects
func (h *VCSConnectionHandlerV2) ListProjects(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid VCS connection ID")
		return
	}

	connection, err := h.vcsConnectionRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "VCS connection not found")
		return
	}

	page, perPage := pagination.Parse(c, 100)
	if perPage > 100 {
		perPage = 100
	}

	provider := h.getProvider(c, connection)
	if provider == nil {
		return
	}

	lister, ok := provider.(vcs.ProjectLister)
	if !ok {
		jsonapi.WriteError(c, http.StatusNotImplemented, "Not Implemented", fmt.Sprintf("Project listing is not supported for %s", connection.Provider))
		return
	}

	projects, err := lister.ListProjects(c.Request.Context(), connection, page, perPage)
	if err != nil {
		switch {
		case isIdentityNotMaterialized(err):
			jsonapi.WriteError(c, http.StatusForbidden, "Identity Not Materialized", "Your Azure DevOps identity has not been activated in this organization. "+
				"Open https://dev.azure.com/ in a browser, sign in with the same Microsoft account you used to authorize Stackweaver, "+
				"then delete this VCS connection and reconnect.")
		default:
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", fmt.Sprintf("Failed to list projects: %v", err))
		}
		return
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, projects, LegacyPageMeta{Pagination: LegacyPage{Page: page, PerPage: perPage}})
}

// ListBranches lists branches for a repository
// GET /api/v2/vcs-connections/:id/repositories/:owner/:repo/branches
func (h *VCSConnectionHandlerV2) ListBranches(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid VCS connection ID")
		return
	}

	connection, err := h.vcsConnectionRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "VCS connection not found")
		return
	}

	owner := c.Param("owner")
	repo := c.Param("repo")

	page, perPage := pagination.Parse(c, 30)
	if perPage > 100 {
		perPage = 100
	}

	provider := h.getProvider(c, connection)
	if provider == nil {
		return
	}

	branches, err := provider.ListBranches(c.Request.Context(), connection, owner, repo, page, perPage)
	if err != nil {
		if isNotImplemented(err) {
			jsonapi.WriteError(c, http.StatusNotImplemented, "Not Implemented", fmt.Sprintf("Branch listing is not yet supported for %s", connection.Provider))
		} else {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", fmt.Sprintf("Failed to list branches: %v", err))
		}
		return
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, branches, LegacyPageMeta{Pagination: LegacyPage{Page: page, PerPage: perPage}})
}

// GetFileContent retrieves file content from a repository
// GET /api/v2/vcs-connections/:id/repositories/:owner/:repo/contents/*path
func (h *VCSConnectionHandlerV2) GetFileContent(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid VCS connection ID")
		return
	}

	connection, err := h.vcsConnectionRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "VCS connection not found")
		return
	}

	owner := c.Param("owner")
	repo := c.Param("repo")
	path := c.Param("path")
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	ref := c.Query("ref")

	provider := h.getProvider(c, connection)
	if provider == nil {
		return
	}

	content, err := provider.GetFileContent(c.Request.Context(), connection, owner, repo, path, ref)
	if err != nil {
		if isNotImplemented(err) {
			jsonapi.WriteError(c, http.StatusNotImplemented, "Not Implemented", fmt.Sprintf("File content retrieval is not yet supported for %s", connection.Provider))
		} else {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", fmt.Sprintf("Failed to get file content: %v", err))
		}
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, VCSFileContentResponse{Content: content, Path: path, Ref: ref})
}

// ListYamlFiles lists all .yaml and .yml files in a repository
// GET /api/v2/vcs-connections/:id/repositories/:owner/:repo/yaml-files
func (h *VCSConnectionHandlerV2) ListYamlFiles(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid VCS connection ID")
		return
	}

	connection, err := h.vcsConnectionRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "VCS connection not found")
		return
	}

	owner := c.Param("owner")
	repo := c.Param("repo")
	ref := c.Query("ref")

	provider := h.getProvider(c, connection)
	if provider == nil {
		return
	}

	files, err := provider.ListFiles(c.Request.Context(), connection, owner, repo, ref, []string{".yaml", ".yml"})
	if err != nil {
		if isNotImplemented(err) {
			jsonapi.WriteError(c, http.StatusNotImplemented, "Not Implemented", fmt.Sprintf("YAML file listing is not yet supported for %s", connection.Provider))
		} else {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", fmt.Sprintf("Failed to list YAML files: %v", err))
		}
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, files)
}

// ListInventoryFiles lists the inventory candidate files in a repository: the
// .ini, .yaml, .yml and .json files outside conventional non-inventory
// locations (playbooks, roles, group_vars/host_vars, CI and tooling files), see
// ansiblefiles.Inventories. The optional path query parameter scopes the
// listing to a repository directory.
// GET /api/v2/vcs-connections/:id/repositories/:owner/:repo/inventory-files?ref=&path=
func (h *VCSConnectionHandlerV2) ListInventoryFiles(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid VCS connection ID")
		return
	}

	connection, err := h.vcsConnectionRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "VCS connection not found")
		return
	}

	owner := c.Param("owner")
	repo := c.Param("repo")
	ref := c.Query("ref")

	provider := h.getProvider(c, connection)
	if provider == nil {
		return
	}

	files, err := listInventoryCandidates(c.Request.Context(), provider, connection, owner, repo, ref, c.Query("path"))
	if err != nil {
		if isNotImplemented(err) {
			jsonapi.WriteError(c, http.StatusNotImplemented, "Not Implemented", fmt.Sprintf("Inventory file listing is not yet supported for %s", connection.Provider))
		} else {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", fmt.Sprintf("Failed to list inventory files: %v", err))
		}
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, files)
}

// inventoryExtensions are the file types ansible-inventory parses through its
// ini and yaml plugins (the yaml plugin also reads .json).
var inventoryExtensions = []string{".ini", ".yaml", ".yml", ".json"}

// fileLister is the part of a VCS provider the inventory listing needs.
type fileLister interface {
	ListFiles(ctx context.Context, conn *models.VCSConnection, owner, repo, ref string, extensions []string) ([]string, error)
}

// listInventoryCandidates lists a repository's inventory-extension files and
// narrows them to inventory candidates under scopePath.
func listInventoryCandidates(ctx context.Context, lister fileLister, conn *models.VCSConnection, owner, repo, ref, scopePath string) ([]string, error) {
	files, err := lister.ListFiles(ctx, conn, owner, repo, ref, inventoryExtensions)
	if err != nil {
		return nil, err
	}
	candidates := ansiblefiles.Inventories(files, scopePath)
	if candidates == nil {
		// Encode an empty listing as [] rather than null.
		candidates = []string{}
	}
	return candidates, nil
}
