// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/response"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

// AdHocHandler serves AWX-style ad hoc commands: run a single module against
// an inventory through the normal job pipeline (transient generated playbook).
type AdHocHandler struct {
	inventoryRepo  *repository.AnsibleInventoryRepository
	orgRepo        *repository.OrganizationRepository
	credentialRepo *repository.AnsibleCredentialRepository
	projectRepo    *repository.ProjectRepository
	agentPoolRepo  *repository.AgentPoolRepository
	jobService     *ansible.JobService
	authService    *auth.Service
	rbacService    *rbac.Service
}

// NewAdHocHandler creates an ad hoc command handler.
func NewAdHocHandler(
	inventoryRepo *repository.AnsibleInventoryRepository,
	orgRepo *repository.OrganizationRepository,
	credentialRepo *repository.AnsibleCredentialRepository,
	projectRepo *repository.ProjectRepository,
	agentPoolRepo *repository.AgentPoolRepository,
	jobService *ansible.JobService,
	authService *auth.Service,
	rbacService *rbac.Service,
) *AdHocHandler {
	return &AdHocHandler{
		inventoryRepo:  inventoryRepo,
		orgRepo:        orgRepo,
		credentialRepo: credentialRepo,
		projectRepo:    projectRepo,
		agentPoolRepo:  agentPoolRepo,
		jobService:     jobService,
		authService:    authService,
		rbacService:    rbacService,
	}
}

// AdHocModules returns the effective module allowlist for an organization
// (its configured comma-separated list, or the AWX default). Thin wrapper over
// the core resolver so the HTTP allowlist and the launch-time allowlist stay
// identical.
func AdHocModules(org *models.Organization) []string {
	return ansible.ResolveAdHocModules(org.AnsibleAdHocModules)
}

// RunCommand launches an ad hoc command against an inventory.
// POST /api/v2/ansible/inventories/:id/actions/run-command
func (h *AdHocHandler) RunCommand(c *gin.Context) {
	inventoryID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid inventory ID")
		return
	}

	var req struct {
		Data struct {
			Attributes struct {
				Module        string              `json:"module" binding:"required"`
				ModuleArgs    string              `json:"module-args"`
				Limit         string              `json:"limit"`
				ProjectID     string              `json:"project-id"`
				CredentialID  string              `json:"credential-id"`
				AgentPoolID   string              `json:"agent-pool-id"`
				Verbosity     int                 `json:"verbosity"`
				Forks         int                 `json:"forks"`
				BecomeEnabled bool                `json:"become-enabled"`
				ExtraVars     models.JobExtraVars `json:"extra-vars"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	attrs := req.Data.Attributes

	inventory, err := h.inventoryRepo.GetByID(inventoryID)
	if err != nil {
		response.NotFound(c, "Inventory not found")
		return
	}

	// Resolve the project the job runs under: explicit attribute, else the
	// inventory's own project scope.
	var projectID uuid.UUID
	switch {
	case attrs.ProjectID != "":
		projectID, err = uuid.Parse(attrs.ProjectID)
		if err != nil {
			response.BadRequest(c, "Invalid project-id")
			return
		}
	case inventory.ProjectID != nil:
		projectID = *inventory.ProjectID
	default:
		// Org-scoped inventory: run under the org's default project (mirrors
		// how inventory creation resolves a project).
		defaultProject, err := h.projectRepo.GetByOrganizationAndName(inventory.OrganizationID, "default")
		if err != nil {
			response.BadRequest(c, "project-id is required: this inventory is org-scoped and the organization has no default project")
			return
		}
		projectID = defaultProject.ID
	}

	// RBAC: dedicated ad hoc permission (AWX adhoc_role), distinct from
	// template execute.
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return
	}
	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(),
		user.ID,
		rbac.ResourceTypeAnsibleJob,
		"",
		rbac.PermissionAnsibleAdHocExecute,
		&projectID,
	)
	if err != nil {
		response.InternalError(c, "Failed to check permissions")
		return
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You don't have permission to run ad hoc commands in this project"}}})
		return
	}

	// Enforce the org module allowlist server-side.
	org, err := h.orgRepo.GetByID(inventory.OrganizationID)
	if err != nil {
		response.InternalError(c, "Failed to load organization")
		return
	}
	allowed := false
	for _, m := range AdHocModules(org) {
		if m == attrs.Module {
			allowed = true
			break
		}
	}
	if !allowed {
		response.BadRequest(c, "Module "+attrs.Module+" is not in the organization's ad hoc module allowlist")
		return
	}

	var credentialID *uuid.UUID
	if attrs.CredentialID != "" {
		id, err := uuid.Parse(attrs.CredentialID)
		if err != nil {
			response.BadRequest(c, "Invalid credential-id")
			return
		}
		// Org boundary: the credential must belong to the inventory's org —
		// otherwise a foreign credential could be exfiltrated against
		// attacker-controlled hosts.
		cred, err := h.credentialRepo.GetByID(id)
		if err != nil || cred.OrganizationID != inventory.OrganizationID {
			response.BadRequest(c, "Credential not found in this organization")
			return
		}
		credentialID = &id
	}

	var agentPoolID *uuid.UUID
	if attrs.AgentPoolID != "" {
		id, err := uuid.Parse(attrs.AgentPoolID)
		if err != nil {
			response.BadRequest(c, "Invalid agent-pool-id")
			return
		}
		// Org boundary: the pool must belong to the inventory's org, or the
		// command would be routed to another organization's runners.
		pool, err := h.agentPoolRepo.GetByID(id, false)
		if err != nil || pool.OrganizationID != inventory.OrganizationID {
			response.BadRequest(c, "Agent pool not found in this organization")
			return
		}
		agentPoolID = &id
	}

	job, err := h.jobService.LaunchAdHoc(c.Request.Context(), ansible.LaunchAdHocInput{
		ProjectID:     projectID,
		InventoryID:   inventoryID,
		Module:        attrs.Module,
		ModuleArgs:    attrs.ModuleArgs,
		Limit:         attrs.Limit,
		Verbosity:     attrs.Verbosity,
		Forks:         attrs.Forks,
		CredentialID:  credentialID,
		AgentPoolID:   agentPoolID,
		BecomeEnabled: attrs.BecomeEnabled,
		ExtraVars:     attrs.ExtraVars,
		CreatedBy:     &user.ID,
	})
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": formatJobResponse(job)})
}

// ListModules returns the effective ad hoc module allowlist of an organization.
// GET /api/v2/organizations/:name/ansible/adhoc-modules
func (h *AdHocHandler) ListModules(c *gin.Context) {
	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		response.NotFound(c, "Organization not found")
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return
	}
	hasPermission, err := h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		response.InternalError(c, "Failed to check permissions")
		return
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You don't have permission to view this organization's ad hoc modules"}}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"type": "adhoc-modules",
		"id":   org.ID.String(),
		"attributes": gin.H{
			"modules": AdHocModules(org),
		},
	}})
}
