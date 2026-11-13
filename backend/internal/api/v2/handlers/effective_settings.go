// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/settings"
)

// effectiveSettingsType is the JSON:API type of an effective-settings read.
const effectiveSettingsType = "effective-settings"

// EffectiveSetting is one resolved setting: its value and the level it came from (workspace,
// job-template, inventory-source, project, organization or deployment). Every setting resolves; the
// OpenTofu version's deployment level is the installation default (#1069, D2).
type EffectiveSetting[T any] struct {
	Value T       `json:"value"`
	Level *string `json:"level"`
}

// EffectiveSettingsAttributes are the multi-level settings of one launching object, each resolved by
// the level rule (core/settings). A setting that does not apply to the object's kind is omitted.
type EffectiveSettingsAttributes struct {
	ExecutionMode *EffectiveSetting[string]  `json:"execution-mode,omitempty"`
	AgentPoolID   *EffectiveSetting[*string] `json:"agent-pool-id,omitempty"`
	TofuVersion   *EffectiveSetting[string]  `json:"tofu-version,omitempty"`
	RunTimeout    *EffectiveSetting[int]     `json:"run-timeout,omitempty"`
	// RunImageID is the run image the object's jobs run in, null at deployment level for the
	// platform image (#933, D6); IdentityBindingID the identity binding, null for the platform
	// identity (D8).
	RunImageID        *EffectiveSetting[*string] `json:"run-image-id,omitempty"`
	IdentityBindingID *EffectiveSetting[*string] `json:"identity-binding-id,omitempty"`
}

func idSetting(r settings.Resolved[*uuid.UUID]) *EffectiveSetting[*string] {
	return &EffectiveSetting[*string]{Value: poolString(r.Value), Level: levelOf(r.Level)}
}

func levelOf(l settings.Level) *string {
	s := string(l)
	return &s
}

func poolString(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

// workspaceEffectiveSettings resolves a workspace's settings; installation is the installation
// default OpenTofu version (repository.InstallationTofuVersion). The workspace must be loaded with
// its Project and the Project's Organization.
func workspaceEffectiveSettings(ws *models.Workspace, deploymentTimeout int, installation string) EffectiveSettingsAttributes {
	exec := settings.EffectiveExecution(ws)
	v := settings.EffectiveTofuVersion(ws, installation)
	version := &EffectiveSetting[string]{Value: v.Value, Level: levelOf(v.Level)}
	timeout := settings.EffectiveWorkspaceRunTimeout(ws, deploymentTimeout)
	return EffectiveSettingsAttributes{
		ExecutionMode:     &EffectiveSetting[string]{Value: exec.Value.Mode, Level: levelOf(exec.Level)},
		AgentPoolID:       &EffectiveSetting[*string]{Value: poolString(exec.Value.PoolID), Level: levelOf(exec.Level)},
		TofuVersion:       version,
		RunTimeout:        &EffectiveSetting[int]{Value: timeout.Value, Level: levelOf(timeout.Level)},
		RunImageID:        idSetting(settings.EffectiveWorkspaceRunImage(ws)),
		IdentityBindingID: idSetting(settings.EffectiveWorkspaceIdentity(ws)),
	}
}

// jobTemplateEffectiveSettings resolves a job template's settings. The project must be loaded with
// its Organization.
func jobTemplateEffectiveSettings(tpl *models.AnsibleJobTemplate, project *models.Project, deploymentTimeout int) EffectiveSettingsAttributes {
	pool := settings.EffectiveJobPool(tpl, project)
	timeout := settings.EffectiveRunTimeout(settings.LevelJobTemplate, tpl.TimeoutSeconds, project.RunTimeout, project.Organization.RunTimeout, deploymentTimeout)
	return EffectiveSettingsAttributes{
		AgentPoolID:       &EffectiveSetting[*string]{Value: poolString(pool.Value), Level: levelOf(pool.Level)},
		RunTimeout:        &EffectiveSetting[int]{Value: timeout.Value, Level: levelOf(timeout.Level)},
		RunImageID:        idSetting(settings.EffectiveTemplateRunImage(tpl, project, &project.Organization)),
		IdentityBindingID: idSetting(settings.EffectiveTemplateIdentity(tpl, project, &project.Organization)),
	}
}

// inventorySourceEffectiveSettings resolves an inventory source's settings: the source's own, then
// its project (nil for an organization-scoped inventory), then its organization, then the deployment
// default. The timeout is the one its syncs run under (WorkItemService.RequestSourceSync): the
// source's sync timeout, then the project's and organization's run timeout, then syncTimeout, the
// deployment's sync_timeout.
func inventorySourceEffectiveSettings(src *models.AnsibleInventorySource, project *models.Project, org *models.Organization, syncTimeout int) EffectiveSettingsAttributes {
	projectSeconds := 0
	if project != nil {
		projectSeconds = project.RunTimeout
	}
	timeout := settings.EffectiveRunTimeout(settings.LevelInventorySource, src.TimeoutSeconds, projectSeconds, org.RunTimeout, syncTimeout)
	return EffectiveSettingsAttributes{
		RunTimeout:        &EffectiveSetting[int]{Value: timeout.Value, Level: levelOf(timeout.Level)},
		RunImageID:        idSetting(settings.EffectiveSourceRunImage(src, project, org)),
		IdentityBindingID: idSetting(settings.EffectiveSourceIdentity(src, project, org)),
	}
}

func effectiveSettingsResource(id string, attrs EffectiveSettingsAttributes) jsonapi.Resource[EffectiveSettingsAttributes] {
	return jsonapi.Resource[EffectiveSettingsAttributes]{ID: id, Type: effectiveSettingsType, Attributes: attrs}
}

// EffectiveSettingsHandlerV2 serves the effective-settings reads (#933, D0, D15):
//
//	GET /workspaces/:id/effective-settings
//	GET /ansible/job-templates/:id/effective-settings
//	GET /ansible/inventory-sources/:source_id/effective-settings
//
// Each answers with the resolved value of every multi-level setting and the level it came from, so
// the UI and the provider show where a value is inherited from. Reading needs read access to the
// object itself.
type EffectiveSettingsHandlerV2 struct {
	workspaceRepo *repository.WorkspaceRepository
	templateRepo  *repository.AnsibleJobTemplateRepository
	sourceRepo    *repository.AnsibleInventorySourceRepository
	inventoryRepo *repository.AnsibleInventoryRepository
	projectRepo   *repository.ProjectRepository
	orgRepo       *repository.OrganizationRepository
	authService   *auth.Service
	rbacService   *rbac.Service
	// deploymentTimeout is the deployment default run timeout in seconds, the last level of a
	// workspace's and a job template's walk.
	deploymentTimeout int
	// syncTimeout is the deployment's sync_timeout in seconds, the last level of an inventory
	// source's walk.
	syncTimeout int
}

// NewEffectiveSettingsHandlerV2 builds the handler; the deployment default run timeout and
// sync_timeout are read from the environment once, as every other process reads them.
func NewEffectiveSettingsHandlerV2(
	workspaceRepo *repository.WorkspaceRepository,
	templateRepo *repository.AnsibleJobTemplateRepository,
	sourceRepo *repository.AnsibleInventorySourceRepository,
	inventoryRepo *repository.AnsibleInventoryRepository,
	projectRepo *repository.ProjectRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *EffectiveSettingsHandlerV2 {
	return &EffectiveSettingsHandlerV2{
		workspaceRepo: workspaceRepo, templateRepo: templateRepo, sourceRepo: sourceRepo,
		inventoryRepo: inventoryRepo, projectRepo: projectRepo, orgRepo: orgRepo,
		authService: authService, rbacService: rbacService,
		deploymentTimeout: settings.DeploymentRunTimeout(os.Getenv),
		syncTimeout:       settings.SyncTimeout(os.Getenv),
	}
}

// GetWorkspace - GET /workspaces/:id/effective-settings
func (h *EffectiveSettingsHandlerV2) GetWorkspace(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	ws, err := h.workspaceRepo.GetByID(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}
	ok, err := h.rbacService.CheckResourcePermission(c.Request.Context(), user.ID, rbac.ResourceTypeTerraformWorkspace, ws.ID, rbac.PermissionWorkspaceRead, &ws.ProjectID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to read this workspace")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, effectiveSettingsResource(ws.ID, workspaceEffectiveSettings(ws, h.deploymentTimeout, repository.InstallationTofuVersion(h.workspaceRepo.DB()))))
}

// GetJobTemplate - GET /ansible/job-templates/:id/effective-settings
func (h *EffectiveSettingsHandlerV2) GetJobTemplate(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid job template ID")
		return
	}
	tpl, err := h.templateRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Job template not found")
		return
	}
	ok, err := h.rbacService.CheckResourcePermission(c.Request.Context(), user.ID, rbac.ResourceTypeAnsibleJobTemplate, tpl.ID.String(), rbac.PermissionAnsibleJobTemplateRead, &tpl.ProjectID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to read this job template")
		return
	}
	project, err := h.projectRepo.GetByID(tpl.ProjectID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to load the job template's project")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, effectiveSettingsResource(tpl.ID.String(), jobTemplateEffectiveSettings(tpl, project, h.deploymentTimeout)))
}

// GetInventorySource - GET /ansible/inventory-sources/:source_id/effective-settings
func (h *EffectiveSettingsHandlerV2) GetInventorySource(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	id, err := uuid.Parse(c.Param("source_id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory source ID")
		return
	}
	source, err := h.sourceRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory source not found")
		return
	}
	inventory, err := h.inventoryRepo.GetByID(source.InventoryID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return
	}
	// The source inherits its inventory's scope, as every inventory sub-resource does
	// (handlers/ansible authorizeInventoryResource).
	var allowed bool
	if inventory.ProjectID != nil {
		allowed, err = h.rbacService.CheckAnsibleResourcePermission(c.Request.Context(), user.ID, rbac.ResourceTypeAnsibleInventory, inventory.ID.String(), rbac.PermissionAnsibleInventoryRead, inventory.ProjectID)
	} else {
		allowed, err = h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, inventory.OrganizationID)
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !allowed {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to access this inventory")
		return
	}

	var project *models.Project
	if inventory.ProjectID != nil {
		if project, err = h.projectRepo.GetByID(*inventory.ProjectID); err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to load the inventory's project")
			return
		}
	}
	org, err := h.orgRepo.GetByID(inventory.OrganizationID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to load the inventory's organization")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, effectiveSettingsResource(source.ID.String(), inventorySourceEffectiveSettings(source, project, org, h.syncTimeout)))
}
