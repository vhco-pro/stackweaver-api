// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/security/gitargs"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// RegistryPublishingHandler handles module publishing operations
type RegistryPublishingHandler struct {
	moduleRepo        *repository.ModuleRepository
	moduleVersionRepo *repository.ModuleVersionRepository
	orgRepo           *repository.OrganizationRepository
	vcsConnectionRepo *repository.VCSConnectionRepository
	authService       *auth.Service
	rbacService       *rbac.Service
	githubAppManager  *vcs.GitHubAppManager
	publisher         *registry.ModulePublisher
}

func NewRegistryPublishingHandler(
	moduleRepo *repository.ModuleRepository,
	moduleVersionRepo *repository.ModuleVersionRepository,
	orgRepo *repository.OrganizationRepository,
	vcsConnectionRepo *repository.VCSConnectionRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	githubAppManager *vcs.GitHubAppManager,
	publisher *registry.ModulePublisher,
) *RegistryPublishingHandler {
	return &RegistryPublishingHandler{
		moduleRepo:        moduleRepo,
		moduleVersionRepo: moduleVersionRepo,
		orgRepo:           orgRepo,
		vcsConnectionRepo: vcsConnectionRepo,
		authService:       authService,
		rbacService:       rbacService,
		githubAppManager:  githubAppManager,
		publisher:         publisher,
	}
}

// requireModuleManage gates registry-module mutations (AUD-004): only a caller with
// org manage-modules permission may create/publish/delete modules. Returns the
// authenticated user + org on success; writes the JSON:API error and returns ok=false
// otherwise. JWT identities bypass the org wall, so this per-handler check is what
// actually enforces tenant isolation on the publish plane.
func (h *RegistryPublishingHandler) requireModuleManage(c *gin.Context, orgName string) (*models.User, *models.Organization, bool) {
	user, org, ok := h.resolveUserAndOrg(c, orgName)
	if !ok {
		return nil, nil, false
	}
	hasPermission, err := h.rbacService.CheckOrgManageModules(c.Request.Context(), user.ID, org.ID)
	if err != nil || !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to manage modules in this organization"}},
		})
		return nil, nil, false
	}
	return user, org, true
}

// requireModuleRead gates registry-module reads on org membership (AUD-004): module
// listings expose VCS repo wiring and publish topology, so a non-member of the org
// must not read them.
func (h *RegistryPublishingHandler) requireModuleRead(c *gin.Context, orgName string) (*models.User, *models.Organization, bool) {
	user, org, ok := h.resolveUserAndOrg(c, orgName)
	if !ok {
		return nil, nil, false
	}
	inOrg, err := h.orgRepo.UserInOrg(user.ID, org.ID)
	if err != nil || !inOrg {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You are not a member of this organization"}},
		})
		return nil, nil, false
	}
	return user, org, true
}

// resolveUserAndOrg fetches the authenticated user and the named organization,
// writing the appropriate 401/404 on failure.
func (h *RegistryPublishingHandler) resolveUserAndOrg(c *gin.Context, orgName string) (*models.User, *models.Organization, bool) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}},
		})
		return nil, nil, false
	}
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Organization not found"}},
		})
		return nil, nil, false
	}
	return user, org, true
}

// CreateModule handles POST /api/v2/organizations/:name/registry/modules
func (h *RegistryPublishingHandler) CreateModule(c *gin.Context) {
	orgName := c.Param("name")

	// AUD-004: creating a module requires org manage-modules permission.
	user, org, ok := h.requireModuleManage(c, orgName)
	if !ok {
		return
	}

	// Parse request body
	var req struct {
		Name            string     `json:"name" binding:"required"`
		Provider        string     `json:"provider" binding:"required"`
		Description     string     `json:"description"`
		VCSConnectionID *uuid.UUID `json:"vcs_connection_id,omitempty"`
		VCSRepository   string     `json:"vcs_repository,omitempty"`
		AutoPublishTags bool       `json:"auto_publish_tags"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}},
		})
		return
	}

	// Validate VCS connection if provided
	if req.VCSConnectionID != nil {
		vcsConn, err := h.vcsConnectionRepo.GetByID(*req.VCSConnectionID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "VCS connection not found"}},
			})
			return
		}
		if vcsConn.OrganizationID != org.ID {
			c.JSON(http.StatusForbidden, gin.H{
				"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "VCS connection does not belong to this organization"}},
			})
			return
		}
	}

	// Create module
	module, err := h.publisher.CreateModule(
		org.ID,
		req.Name,
		req.Provider,
		req.Description,
		req.VCSConnectionID,
		req.VCSRepository,
		req.AutoPublishTags,
		user.ID,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}},
		})
		return
	}

	// If VCS-connected, try to fetch and publish the latest version from GitHub
	if req.VCSConnectionID != nil && req.VCSRepository != "" && h.githubAppManager != nil && h.githubAppManager.IsEnabled() {
		// Get VCS connection
		vcsConn, err := h.vcsConnectionRepo.GetByID(*req.VCSConnectionID)
		if err == nil && vcsConn.InstallationID != "" {
			// Parse repository owner and name
			parts := strings.Split(req.VCSRepository, "/")
			if len(parts) == 2 {
				owner, repoName := parts[0], parts[1]

				// Get GitHub service
				githubService := h.githubAppManager.GetService()

				// Fetch latest tag
				ctx := c.Request.Context()
				latestTag, err := githubService.GetLatestTag(ctx, vcsConn.InstallationID, owner, repoName)
				if err == nil && latestTag != nil {
					tagName := latestTag.GetName()

					// Extract version from tag
					version := registry.ExtractVersionFromTag(tagName)

					// Validate version
					if err := registry.ValidateSemanticVersion(version); err == nil {
						// Check if version already exists
						if !h.moduleVersionRepo.Exists(module.ID, version) {
							// Publish the latest version in background
							go func() {
								if err := h.PublishFromGitTag(ctx, module.ID, tagName, req.VCSRepository); err != nil {
									logger.Infof("Failed to auto-publish latest version %s for module %s: %v", version, module.Name, err)
								} else {
									logger.Infof("Auto-published latest version %s for module %s from tag %s", version, module.Name, tagName)
								}
							}()
						}
					}
				}
			}
		}
	}

	// Create webhook if VCS-connected and auto-publish enabled
	// TODO: Create webhook for tag push events
	// This will be implemented when we extend the webhook handler
	_ = req.VCSConnectionID != nil && req.AutoPublishTags && h.githubAppManager != nil && h.githubAppManager.IsEnabled()

	// Format response (TFE-compatible)
	c.JSON(http.StatusCreated, gin.H{
		"data": gin.H{
			"id":   module.ID.String(),
			"type": "registry-modules",
			"attributes": gin.H{
				"name":              module.Name,
				"provider":          module.Provider,
				"description":       module.Description,
				"vcs_repository":    module.VCSRepository,
				"auto_publish_tags": module.AutoPublishTags,
			},
		},
	})
}

// DeleteModule handles DELETE /api/v2/organizations/:name/registry/modules/:module_name/:provider
func (h *RegistryPublishingHandler) DeleteModule(c *gin.Context) {
	orgName := c.Param("name")
	moduleName := c.Param("module_name")
	provider := c.Param("provider")

	// AUD-004: publishing/deleting a module requires org manage-modules permission.
	_, org, ok := h.requireModuleManage(c, orgName)
	if !ok {
		return
	}

	// Get module
	module, err := h.moduleRepo.GetByOrganizationAndName(org.ID, moduleName, provider)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Module not found"}},
		})
		return
	}

	// Delete module (cascade will delete versions)
	if err := h.moduleRepo.Delete(module.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": err.Error()}},
		})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// DeleteAllModules handles DELETE /api/v2/organizations/:name/registry/modules
func (h *RegistryPublishingHandler) DeleteAllModules(c *gin.Context) {
	orgName := c.Param("name")

	// AUD-004: wiping an org's module registry requires org manage-modules permission.
	_, org, ok := h.requireModuleManage(c, orgName)
	if !ok {
		return
	}

	// Get all modules for organization
	modules, _, err := h.moduleRepo.List(&org.ID, "", nil, 1000, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": err.Error()}},
		})
		return
	}

	// Delete all modules
	for _, module := range modules {
		if err := h.moduleRepo.Delete(module.ID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": fmt.Sprintf("Failed to delete module %s: %v", module.Name, err)}},
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Deleted %d module(s)", len(modules)),
	})
}

// ListModules handles GET /api/v2/organizations/:name/registry/modules
func (h *RegistryPublishingHandler) ListModules(c *gin.Context) {
	orgName := c.Param("name")

	// AUD-004: module listings expose VCS wiring — require org membership.
	_, org, ok := h.requireModuleRead(c, orgName)
	if !ok {
		return
	}

	modules, _, err := h.moduleRepo.List(&org.ID, "", nil, 100, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": err.Error()}},
		})
		return
	}

	// Format response
	data := make([]gin.H, len(modules))
	for i, m := range modules {
		// Get latest version for this module
		var latestVersion string
		var publishedAt time.Time
		var downloads int

		// Load versions for this module
		versions, err := h.moduleVersionRepo.ListByModule(m.ID)
		if err == nil && len(versions) > 0 {
			// Versions are already sorted by published_at DESC in the repository
			latestVersion = versions[0].Version
			publishedAt = versions[0].PublishedAt
			downloads = versions[0].Downloads
		}

		listAttrs := gin.H{
			"name":              m.Name,
			"provider":          m.Provider,
			"description":       m.Description,
			"vcs_repository":    m.VCSRepository,
			"auto_publish_tags": m.AutoPublishTags,
			"latest_version":    latestVersion,
			"published_at":      publishedAt.Format("2006-01-02T15:04:05Z"),
			"downloads":         downloads,
		}
		if m.VCSConnection != nil {
			listAttrs["vcs_provider"] = string(m.VCSConnection.Provider)
			listAttrs["vcs_account_name"] = m.VCSConnection.AccountName
		}
		data[i] = gin.H{
			"id":         m.ID.String(),
			"type":       "registry-modules",
			"attributes": listAttrs,
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": data})
}

// GetModule handles GET /api/v2/organizations/:name/registry/modules/:name/:provider
func (h *RegistryPublishingHandler) GetModule(c *gin.Context) {
	orgName := c.Param("name")
	moduleName := c.Param("module_name")
	provider := c.Param("provider")

	// AUD-004: module detail exposes VCS wiring — require org membership.
	_, org, ok := h.requireModuleRead(c, orgName)
	if !ok {
		return
	}

	module, err := h.moduleRepo.GetByOrganizationAndName(org.ID, moduleName, provider)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Module not found"}},
		})
		return
	}

	attrs := gin.H{
		"name":              module.Name,
		"provider":          module.Provider,
		"description":       module.Description,
		"vcs_repository":    module.VCSRepository,
		"auto_publish_tags": module.AutoPublishTags,
	}
	if module.VCSConnection != nil {
		attrs["vcs_provider"] = string(module.VCSConnection.Provider)
		attrs["vcs_account_name"] = module.VCSConnection.AccountName
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"id":         module.ID.String(),
			"type":       "registry-modules",
			"attributes": attrs,
		},
	})
}

// ListModuleVersions handles GET /api/v2/organizations/:name/registry/modules/:module_name/:provider/versions
func (h *RegistryPublishingHandler) ListModuleVersions(c *gin.Context) {
	orgName := c.Param("name")
	moduleName := c.Param("module_name")
	provider := c.Param("provider")

	// AUD-004: module version listings are tenant data — require org membership.
	_, org, ok := h.requireModuleRead(c, orgName)
	if !ok {
		return
	}

	// Get module
	module, err := h.moduleRepo.GetByOrganizationAndName(org.ID, moduleName, provider)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Module not found"}},
		})
		return
	}

	// Get versions
	versions, err := h.moduleVersionRepo.ListByModule(module.ID)
	if err != nil {
		logger.Errorf("Error listing versions for module %s/%s/%s: %v", orgName, moduleName, provider, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": err.Error()}},
		})
		return
	}

	logger.Infof("ListModuleVersions: Found %d version(s) for module %s/%s/%s", len(versions), orgName, moduleName, provider)

	// Format response (sort by published_at DESC - latest first)
	data := make([]gin.H, len(versions))
	for i, v := range versions {
		// Convert JSONB fields to proper format
		var inputs, outputs, dependencies, resources, submodules interface{}
		if v.Inputs != nil {
			inputs = v.Inputs
		}
		if v.Outputs != nil {
			outputs = v.Outputs
		}
		if v.Dependencies != nil {
			dependencies = v.Dependencies
		}
		if v.Resources != nil {
			resources = v.Resources
		}
		if v.Submodules != nil {
			submodules = v.Submodules
		}

		data[i] = gin.H{
			"id":   v.ID.String(),
			"type": "module-versions",
			"attributes": gin.H{
				"version":      v.Version,
				"source":       v.Source,
				"readme":       v.Readme, // Return raw markdown for frontend Shiki rendering
				"published_at": v.PublishedAt.Format("2006-01-02T15:04:05Z"),
				"downloads":    v.Downloads,
				"inputs":       inputs,
				"outputs":      outputs,
				"dependencies": dependencies,
				"resources":    resources,
				"submodules":   submodules,
				"tarball_size": v.TarballSize,
			},
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": data})
}

// PublishVersion handles POST /api/v2/organizations/:name/registry/modules/:name/:provider/versions
func (h *RegistryPublishingHandler) PublishVersion(c *gin.Context) {
	orgName := c.Param("name")
	moduleName := c.Param("module_name")
	provider := c.Param("provider")

	// AUD-004: publishing/deleting a module requires org manage-modules permission.
	_, org, ok := h.requireModuleManage(c, orgName)
	if !ok {
		return
	}

	// Get module
	module, err := h.moduleRepo.GetByOrganizationAndName(org.ID, moduleName, provider)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Module not found"}},
		})
		return
	}

	// Check if storage_path is provided (direct S3/MinIO upload)
	storagePath := c.PostForm("storage_path")
	if storagePath != "" {
		// TODO: Implement direct storage path registration
		c.JSON(http.StatusNotImplemented, gin.H{
			"errors": []gin.H{{"status": "501", "title": "Not Implemented", "detail": "Direct storage path registration not yet implemented"}},
		})
		return
	}

	// Get version from form
	version := c.PostForm("version")
	if version == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "version is required"}},
		})
		return
	}

	// Get tarball file
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "file is required"}},
		})
		return
	}

	// Open uploaded file
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": err.Error()}},
		})
		return
	}
	defer func() {
		if err := src.Close(); err != nil {
			logger.Warnf("Failed to close source file: %v", err)
		}
	}()

	// Publish version
	moduleVersion, err := h.publisher.PublishVersionFromTarball(
		c.Request.Context(),
		module.ID,
		version,
		src,
		file.Size,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}},
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"data": gin.H{
			"id":   moduleVersion.ID.String(),
			"type": "registry-module-versions",
			"attributes": gin.H{
				"version":      moduleVersion.Version,
				"published_at": moduleVersion.PublishedAt.Format("2006-01-02T15:04:05Z"),
			},
		},
	})
}

// PublishFromGitTag publishes a module version from a Git tag (called by webhook handler)
func (h *RegistryPublishingHandler) PublishFromGitTag(
	ctx context.Context,
	moduleID uuid.UUID,
	tagName string,
	repositoryFullName string,
) error {
	// Sanitise via regex rebind. Without this, a tag named
	// "--upload-pack=evil" or a repo name containing shell metacharacters
	// could subvert the git invocations below (Wave 8 / D1).
	tagName = gitargs.RefNameRe.FindString(tagName)
	if tagName == "" {
		return fmt.Errorf("invalid tag name")
	}
	repositoryFullName = gitargs.RepoFullNameRe.FindString(repositoryFullName)
	if repositoryFullName == "" {
		return fmt.Errorf("invalid repository name")
	}

	// Get module to access VCS connection
	module, err := h.moduleRepo.GetByID(moduleID)
	if err != nil {
		return fmt.Errorf("failed to get module: %w", err)
	}

	// Extract version from tag
	version := registry.ExtractVersionFromTag(tagName)

	// Validate version
	if err := registry.ValidateSemanticVersion(version); err != nil {
		return fmt.Errorf("invalid version in tag %s: %w", tagName, err)
	}

	// Check if version already exists
	if h.moduleVersionRepo.Exists(moduleID, version) {
		return fmt.Errorf("version %s already exists", version)
	}

	// Clone repository at tag
	tempDir, err := os.MkdirTemp("", "module-clone-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			logger.Warnf("Failed to remove temp directory %s: %v", tempDir, err)
		}
	}()

	// Clone using git command with installation token if available
	var cloneURL string
	if module.VCSConnectionID != nil && h.githubAppManager != nil && h.githubAppManager.IsEnabled() {
		// Get VCS connection to get installation ID
		vcsConn, err := h.vcsConnectionRepo.GetByID(*module.VCSConnectionID)
		if err == nil && vcsConn.InstallationID != "" {
			// Generate installation token
			githubService := h.githubAppManager.GetService()
			installToken, err := githubService.GenerateInstallationToken(ctx, vcsConn.InstallationID)
			if err == nil {
				// Use token for authentication
				cloneURL = fmt.Sprintf("https://x-access-token:%s@github.com/%s.git", installToken, repositoryFullName)
			} else {
				logger.Warnf("Failed to generate installation token, using public clone: %v", err)
				cloneURL = fmt.Sprintf("https://github.com/%s.git", repositoryFullName)
			}
		} else {
			cloneURL = fmt.Sprintf("https://github.com/%s.git", repositoryFullName)
		}
	} else {
		cloneURL = fmt.Sprintf("https://github.com/%s.git", repositoryFullName)
	}

	// Clone repository at specific tag
	// First, clone shallow with the tag
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--branch", tagName, cloneURL, tempDir) //nolint:gosec // intentional: executing git command
	if err := cmd.Run(); err != nil {
		// If that fails, clone and checkout tag
		cmd = exec.CommandContext(ctx, "git", "clone", "--depth", "1", cloneURL, tempDir) //nolint:gosec // intentional: executing git command
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to clone repository: %w", err)
		}
		// Checkout tag
		cmd = exec.CommandContext(ctx, "git", "checkout", tagName) //nolint:gosec // G204: tagName is validated git tag from webhook
		cmd.Dir = tempDir
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to checkout tag %s: %w", tagName, err)
		}
	}

	// Publish version from directory
	_, err = h.publisher.PublishVersionFromDirectory(ctx, moduleID, version, tempDir)
	if err != nil {
		return fmt.Errorf("failed to publish version from directory: %w", err)
	}

	logger.Infof("Successfully published module %s version %s from tag %s", module.Name, version, tagName)
	return nil
}

// DeleteModuleVersion handles DELETE /api/v2/organizations/:name/registry/modules/:module_name/:provider/versions/:version
func (h *RegistryPublishingHandler) DeleteModuleVersion(c *gin.Context) {
	orgName := c.Param("name")
	moduleName := c.Param("module_name")
	provider := c.Param("provider")
	versionStr := c.Param("version")

	// AUD-004: publishing/deleting a module requires org manage-modules permission.
	_, org, ok := h.requireModuleManage(c, orgName)
	if !ok {
		return
	}

	// Get module
	module, err := h.moduleRepo.GetByOrganizationAndName(org.ID, moduleName, provider)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Module not found"}},
		})
		return
	}

	// Get version
	version, err := h.moduleVersionRepo.GetByModuleAndVersion(module.ID, versionStr)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Version not found"}},
		})
		return
	}

	// Delete version
	if err := h.moduleVersionRepo.Delete(version.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": err.Error()}},
		})
		return
	}

	logger.Infof("Deleted module version %s/%s/%s@%s", orgName, moduleName, provider, versionStr)
	c.JSON(http.StatusNoContent, nil)
}
