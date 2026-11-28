// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/levelrefs"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
	vcs "github.com/michielvha/stackweaver/core/services/vcs"
)

// InventoryHandler handles Ansible inventory API endpoints
type InventoryHandler struct {
	inventoryService  *ansible.InventoryService
	inventoryRepo     *repository.AnsibleInventoryRepository
	orgRepo           *repository.OrganizationRepository
	projectRepo       *repository.ProjectRepository
	authService       *auth.Service
	rbacService       *rbac.Service
	workItems         *ansible.WorkItemService
	vcsRegistry       *vcs.ProviderRegistry
	vcsConnectionRepo *repository.VCSConnectionRepository
	levelRefs         *levelrefs.Checker
}

// SetLevelRefs sets the checker of the identity binding a VCS inventory selects (#1113, D1).
func (h *InventoryHandler) SetLevelRefs(c *levelrefs.Checker) { h.levelRefs = c }

// identityBinding checks the identity-binding-id a create or update sends for an inventory of
// typ in org (#1113, D1): absent leaves the selection, null or empty inherits, an id must name a
// binding of the organization or the hosted binding. Only a VCS inventory may select one, because
// only its file syncs run with it. It writes the error and returns false when the request must
// stop.
func (h *InventoryHandler) identityBinding(c *gin.Context, typ models.InventoryType, org uuid.UUID, attr jsonapi.Nullable[string]) (id *uuid.UUID, set, ok bool) {
	if !attr.Present {
		return nil, false, true
	}
	if typ != models.InventoryTypeVCS {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "identity-binding-id applies to a VCS inventory only: its file syncs are what run with the binding")
		return nil, false, false
	}
	if h.levelRefs == nil {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "identity bindings are not configured")
		return nil, false, false
	}
	raw := attr.Value
	id, set, err := h.levelRefs.IdentityBinding(org, &raw)
	if errors.Is(err, levelrefs.ErrInvalid) {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return nil, false, false
	}
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return nil, false, false
	}
	return id, set, true
}

// identityRefusal is the reason a refused identity binding is reported with, without the wrapping
// of the layers it passed through.
func identityRefusal(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ansible.ErrIdentityBindingRefused.Error()+": "); i >= 0 {
		return msg[i+len(ansible.ErrIdentityBindingRefused.Error())+2:]
	}
	return msg
}

// NewInventoryHandler creates a new inventory handler
func NewInventoryHandler(
	inventoryService *ansible.InventoryService,
	inventoryRepo *repository.AnsibleInventoryRepository,
	orgRepo *repository.OrganizationRepository,
	projectRepo *repository.ProjectRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	workItems *ansible.WorkItemService,
	vcsRegistry *vcs.ProviderRegistry,
	vcsConnectionRepo *repository.VCSConnectionRepository,
) *InventoryHandler {
	return &InventoryHandler{
		inventoryService:  inventoryService,
		inventoryRepo:     inventoryRepo,
		orgRepo:           orgRepo,
		projectRepo:       projectRepo,
		authService:       authService,
		rbacService:       rbacService,
		workItems:         workItems,
		vcsRegistry:       vcsRegistry,
		vcsConnectionRepo: vcsConnectionRepo,
	}
}

// storedVCSConnection loads the connection a stored inventory names, within the inventory's
// organization (ansible.InventoryVCSConnection). It is nil when the inventory names none or
// names one outside its organization, which a row stored before the write path checked may.
func (h *InventoryHandler) storedVCSConnection(ctx context.Context, inventory *models.AnsibleInventory) *models.VCSConnection {
	if inventory.VCSConnectionID == nil || h.vcsConnectionRepo == nil {
		return nil
	}
	scope := h.vcsConnectionRepo.OrganizationScope().WithContext(ctx)
	conn, err := ansible.InventoryVCSConnection(scope, inventory.OrganizationID, *inventory.VCSConnectionID)
	if err != nil {
		if !errors.Is(err, ansible.ErrInvalidInput) {
			logger.Warnf("Inventory %s: loading its VCS connection failed: %v", inventory.ID, err)
		}
		return nil
	}
	return conn
}

// maybeRegisterADOWebhook registers Azure DevOps service hook subscriptions for a specific repo
// in a background goroutine (vcs.RegisterRepoWebhooksInBackground). A registration it cannot make,
// such as one without STACKWEAVER_WEBHOOK_BASE_URL, is logged as a warning.
//
// It takes the connection, not its identifier: the registration is made with the connection's
// token, so the caller hands over a connection held to the inventory's organization
// (storedVCSConnection).
func (h *InventoryHandler) maybeRegisterADOWebhook(conn *models.VCSConnection, repoPath string) {
	vcs.RegisterRepoWebhooksInBackground(h.vcsRegistry, conn, repoPath, "inventory")
}

// CreateInventoryRequest represents the request to create an inventory
type CreateInventoryRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name          string                    `json:"name" binding:"required"`
			Description   string                    `json:"description"`
			Type          string                    `json:"inventory-type"`
			Source        string                    `json:"source"`
			Variables     models.InventoryVariables `json:"variables"`
			VCSRepository string                    `json:"vcs_repository"`
			VCSBranch     string                    `json:"vcs_branch"`
			InventoryPath string                    `json:"inventory_path"`
			// Constructed inventory fields
			SourceVars              string   `json:"source-vars"`
			ConstructedLimit        string   `json:"constructed-limit"`
			ConstructedCacheTimeout int      `json:"constructed-cache-timeout"`
			InputInventoryIDs       []string `json:"input-inventory-ids"`
			// IdentityBindingID is a VCS inventory's identity binding (#1113, D1).
			IdentityBindingID jsonapi.Nullable[string] `json:"identity-binding-id"`
		} `json:"attributes"`
		Relationships struct {
			VCSConnection struct {
				Data *struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"vcs_connection"`
			Project struct {
				Data *struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"project"`
		} `json:"relationships"`
	} `json:"data"`
}

// UpdateInventoryRequest represents the request to update an inventory
type UpdateInventoryRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name          *string                    `json:"name"`
			Description   *string                    `json:"description"`
			Source        *string                    `json:"source"`
			Variables     *models.InventoryVariables `json:"variables"`
			VCSRepository *string                    `json:"vcs_repository"`
			VCSBranch     *string                    `json:"vcs_branch"`
			InventoryPath *string                    `json:"inventory_path"`
			// Constructed inventory fields
			SourceVars              *string   `json:"source-vars"`
			ConstructedLimit        *string   `json:"constructed-limit"`
			ConstructedCacheTimeout *int      `json:"constructed-cache-timeout"`
			InputInventoryIDs       *[]string `json:"input-inventory-ids"`
			// IdentityBindingID is a VCS inventory's identity binding: null or empty inherits
			// (#1113, D1).
			IdentityBindingID jsonapi.Nullable[string] `json:"identity-binding-id"`
		} `json:"attributes"`
		Relationships struct {
			VCSConnection struct {
				Data *struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"vcs_connection"`
			Project struct {
				Data *struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"project"`
		} `json:"relationships"`
	} `json:"data"`
}

// List lists all inventories for an organization
// GET /api/v2/organizations/:name/ansible/inventories
func (h *InventoryHandler) List(c *gin.Context) {
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	// RBAC: check org-level read permission
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	hasPermission, err := h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to list inventories in this organization")
		return
	}

	page, perPage := jsonapi.PageParams(c, 20, 100)
	offset := (page - 1) * perPage

	inventories, total, err := h.inventoryService.ListInventories(org.ID, perPage, offset)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list inventories")
		return
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, formatInventoriesResponse(inventories), jsonapi.NewPaginationMeta(page, perPage, total))
}

// getOrCreateDefaultProject gets or creates the default project for an organization
func (h *InventoryHandler) getOrCreateDefaultProject(orgID uuid.UUID) (*uuid.UUID, error) {
	// Try to get existing default project
	defaultProject, err := h.projectRepo.GetByOrganizationAndName(orgID, "default")
	if err == nil && defaultProject != nil {
		return &defaultProject.ID, nil
	}

	// Create default project if it doesn't exist
	defaultProject = &models.Project{
		OrganizationID: orgID,
		Name:           "default",
		Description:    "Default project for your organization",
	}
	if err := h.projectRepo.Create(defaultProject); err != nil {
		return nil, fmt.Errorf("failed to create default project: %w", err)
	}
	return &defaultProject.ID, nil
}

// Create creates a new inventory
// POST /api/v2/organizations/:name/ansible/inventories
func (h *InventoryHandler) Create(c *gin.Context) {
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	// RBAC: check org-level write permission
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	hasPermission, err := h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to create inventories in this organization")
		return
	}

	var req CreateInventoryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	// Parse inventory type
	invType := models.InventoryTypeStatic
	switch req.Data.Attributes.Type {
	case "static":
		invType = models.InventoryTypeStatic
	case "dynamic":
		invType = models.InventoryTypeDynamic
	case "vcs":
		invType = models.InventoryTypeVCS
	case "constructed":
		invType = models.InventoryTypeConstructed
	}

	// Constructed inventories need at least one valid input
	if invType == models.InventoryTypeConstructed {
		if len(req.Data.Attributes.InputInventoryIDs) == 0 {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Constructed inventories need at least one input inventory")
			return
		}
	}

	// Parse VCS connection ID if provided
	var vcsConnectionID *uuid.UUID
	if req.Data.Relationships.VCSConnection.Data != nil {
		vid, err := uuid.Parse(req.Data.Relationships.VCSConnection.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid VCS connection ID")
			return
		}
		vcsConnectionID = &vid
	}

	// Parse project ID if provided, otherwise use default project
	var projectID *uuid.UUID
	if req.Data.Relationships.Project.Data != nil {
		pid, err := uuid.Parse(req.Data.Relationships.Project.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid project ID")
			return
		}
		// Verify project belongs to organization
		project, err := h.projectRepo.GetByID(pid)
		if err != nil || project.OrganizationID != org.ID {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Project not found or does not belong to organization")
			return
		}
		projectID = &pid
	} else {
		// Use default project
		defaultProjectID, err := h.getOrCreateDefaultProject(org.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to get default project")
			return
		}
		projectID = defaultProjectID
	}

	identityID, identitySet, ok := h.identityBinding(c, invType, org.ID, req.Data.Attributes.IdentityBindingID)
	if !ok {
		return
	}

	inventory, err := h.inventoryService.CreateInventory(
		org.ID,
		projectID,
		req.Data.Attributes.Name,
		req.Data.Attributes.Description,
		invType,
		req.Data.Attributes.Source,
		req.Data.Attributes.Variables,
		vcsConnectionID,
		req.Data.Attributes.VCSRepository,
		req.Data.Attributes.VCSBranch,
		req.Data.Attributes.InventoryPath,
		// The binding is inserted with the inventory, in the transaction that locks and checks
		// it, before the first sync is requested (#1113, D1, D2).
		ansible.IdentityChange{Set: identitySet, ID: identityID},
	)
	if errors.Is(err, ansible.ErrIdentityBindingRefused) {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", identityRefusal(err))
		return
	}
	if errors.Is(err, ansible.ErrInvalidInput) {
		// A VCS connection the inventory may not name: one of another organization and one
		// that does not exist get this same answer.
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
		return
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	// Register ADO webhooks if this inventory is linked to an Azure DevOps repository
	h.maybeRegisterADOWebhook(h.storedVCSConnection(c.Request.Context(), inventory), inventory.VCSRepository)

	// Constructed inventories: persist rules + ordered inputs, then request the
	// initial build.
	if inventory.Type == models.InventoryTypeConstructed {
		inventory.SourceVars = req.Data.Attributes.SourceVars
		inventory.ConstructedLimit = req.Data.Attributes.ConstructedLimit
		inventory.ConstructedCacheTimeout = req.Data.Attributes.ConstructedCacheTimeout
		if !h.setConstructedInputs(c, org.ID, inventory, req.Data.Attributes.InputInventoryIDs) {
			return
		}
		if err := h.inventoryRepo.Update(inventory); err != nil {
			logger.Warnf("Failed to persist constructed inventory fields: %v", err)
		}
		h.setSyncStatus(inventory, "syncing", "")
		if h.workItems != nil {
			if _, err := h.workItems.RequestInventorySync(c.Request.Context(), inventory, "manual"); err != nil {
				logger.Warnf("Failed to request the initial constructed inventory build: %v", err)
				h.setSyncStatus(inventory, "pending", inventory.LastSyncError)
			}
		}
		jsonapi.WriteDocument(c, http.StatusCreated, formatInventoryResponse(inventory))
		return
	}

	// Auto-trigger sync for VCS-backed inventories. The inventory is already created, so the
	// request answers 201 whatever happens to its first sync: a refusal or a database error is
	// recorded as the inventory's last sync, only when no file sync of it exists yet (#1113, D2).
	if inventory.VCSConnectionID != nil && inventory.VCSRepository != "" && inventory.InventoryPath != "" && h.workItems != nil {
		if _, err := h.workItems.RequestInventorySync(c.Request.Context(), inventory, "manual"); err != nil {
			reason, refused := ansible.FileSyncRefusal(err)
			if !refused {
				logger.Warnf("requesting the first sync of inventory %s: %v", inventory.ID, err)
				reason = ansible.FirstSyncRetryReason
			}
			if recErr := h.workItems.RecordFileSyncFailure(c.Request.Context(), inventory.ID, reason, ansible.FirstSyncFailure); recErr != nil {
				logger.Warnf("recording the failed first sync of inventory %s: %v", inventory.ID, recErr)
			}
			if stored, getErr := h.inventoryRepo.GetByID(inventory.ID); getErr == nil {
				inventory.LastSyncStatus, inventory.LastSyncError = stored.LastSyncStatus, stored.LastSyncError
			}
		} else {
			inventory.LastSyncStatus, inventory.LastSyncError = "syncing", ""
		}
	}

	jsonapi.WriteDocument(c, http.StatusCreated, formatInventoryResponse(inventory))
}

// Get retrieves an inventory by ID
// GET /api/v2/ansible/inventories/:id
func (h *InventoryHandler) Get(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory ID")
		return
	}

	inventory, err := h.inventoryService.GetInventory(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return
	}

	// RBAC: check resource-level read permission
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	var hasPermission bool
	if inventory.ProjectID != nil {
		hasPermission, err = h.rbacService.CheckAnsibleResourcePermission(
			c.Request.Context(),
			user.ID,
			rbac.ResourceTypeAnsibleInventory,
			inventory.ID.String(),
			rbac.PermissionAnsibleInventoryRead,
			inventory.ProjectID,
		)
	} else {
		hasPermission, err = h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, inventory.OrganizationID)
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to access this inventory")
		return
	}

	resp := formatInventoryResponse(inventory)
	// Constructed inventories also list their ordered inputs
	if inventory.Type == models.InventoryTypeConstructed {
		if inputs, err := h.inventoryRepo.ListConstructedInputs(inventory.ID); err == nil {
			inputList := make([]ConstructedInputEntry, 0, len(inputs))
			for i := range inputs {
				inputList = append(inputList, ConstructedInputEntry{ID: inputs[i].ID.String(), Name: inputs[i].Name})
			}
			resp.Attributes.InputInventories = &inputList
		}
	}
	jsonapi.WriteDocument(c, http.StatusOK, resp)
}

// Update updates an inventory
// PATCH /api/v2/ansible/inventories/:id
func (h *InventoryHandler) Update(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory ID")
		return
	}

	// RBAC: fetch inventory and check resource-level write permission
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	rbacInventory, err := h.inventoryRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return
	}
	var hasPermission bool
	if rbacInventory.ProjectID != nil {
		hasPermission, err = h.rbacService.CheckAnsibleResourcePermission(
			c.Request.Context(),
			user.ID,
			rbac.ResourceTypeAnsibleInventory,
			rbacInventory.ID.String(),
			rbac.PermissionAnsibleInventoryWrite,
			rbacInventory.ProjectID,
		)
	} else {
		hasPermission, err = h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, rbacInventory.OrganizationID)
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to update this inventory")
		return
	}

	var req UpdateInventoryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	identityID, identitySet, ok := h.identityBinding(c, rbacInventory.Type, rbacInventory.OrganizationID, req.Data.Attributes.IdentityBindingID)
	if !ok {
		return
	}

	// Parse VCS connection ID if provided
	var vcsConnectionID *uuid.UUID
	if req.Data.Relationships.VCSConnection.Data != nil {
		vid, err := uuid.Parse(req.Data.Relationships.VCSConnection.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid VCS connection ID")
			return
		}
		vcsConnectionID = &vid
	}

	// Parse project ID if provided
	var projectID *uuid.UUID
	if req.Data.Relationships.Project.Data != nil {
		pid, err := uuid.Parse(req.Data.Relationships.Project.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid project ID")
			return
		}
		// Get existing inventory to verify organization
		existingInventory, err := h.inventoryRepo.GetByID(id)
		if err != nil {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
			return
		}
		// Verify project belongs to same organization
		project, err := h.projectRepo.GetByID(pid)
		if err != nil || project.OrganizationID != existingInventory.OrganizationID {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Project not found or does not belong to organization")
			return
		}
		projectID = &pid
	}

	inventory, err := h.inventoryService.UpdateInventory(
		id,
		projectID,
		req.Data.Attributes.Name,
		req.Data.Attributes.Description,
		req.Data.Attributes.Source,
		req.Data.Attributes.Variables,
		vcsConnectionID,
		req.Data.Attributes.VCSRepository,
		req.Data.Attributes.VCSBranch,
		req.Data.Attributes.InventoryPath,
		// Every attribute the update changes, the binding included, is written in one transaction
		// on the locked row; the binding only when the request sends it (#1113, D1).
		ansible.IdentityChange{Set: identitySet, ID: identityID},
	)
	if errors.Is(err, ansible.ErrIdentityBindingRefused) {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", identityRefusal(err))
		return
	}
	if errors.Is(err, ansible.ErrInvalidInput) {
		// As on create: the one answer for a VCS connection the inventory may not name.
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
		return
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	// Constructed inventories: apply rule/limit/input changes
	if inventory.Type == models.InventoryTypeConstructed {
		changed := false
		if req.Data.Attributes.SourceVars != nil {
			inventory.SourceVars = *req.Data.Attributes.SourceVars
			changed = true
		}
		if req.Data.Attributes.ConstructedLimit != nil {
			inventory.ConstructedLimit = *req.Data.Attributes.ConstructedLimit
			changed = true
		}
		if req.Data.Attributes.ConstructedCacheTimeout != nil {
			inventory.ConstructedCacheTimeout = *req.Data.Attributes.ConstructedCacheTimeout
			changed = true
		}
		if changed {
			if err := h.inventoryRepo.Update(inventory); err != nil {
				logger.Warnf("Failed to persist constructed inventory fields: %v", err)
			}
		}
		if req.Data.Attributes.InputInventoryIDs != nil {
			if !h.setConstructedInputs(c, inventory.OrganizationID, inventory, *req.Data.Attributes.InputInventoryIDs) {
				return
			}
		}
	}

	// Register ADO webhooks if this inventory is linked to an Azure DevOps repository
	h.maybeRegisterADOWebhook(h.storedVCSConnection(c.Request.Context(), inventory), inventory.VCSRepository)

	jsonapi.WriteDocument(c, http.StatusOK, formatInventoryResponse(inventory))
}

// setConstructedInputs validates and persists the ordered input list of a
// constructed inventory. On failure it writes the error response and returns
// false. Inputs must belong to the same organization and cannot themselves be
// constructed (no nesting in v1).
func (h *InventoryHandler) setConstructedInputs(c *gin.Context, orgID uuid.UUID, inventory *models.AnsibleInventory, inputIDs []string) bool {
	if len(inputIDs) == 0 {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Constructed inventories need at least one input inventory")
		return false
	}
	ids := make([]uuid.UUID, 0, len(inputIDs))
	for _, raw := range inputIDs {
		inputID, err := uuid.Parse(raw)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid input inventory ID "+raw)
			return false
		}
		input, err := h.inventoryRepo.GetByID(inputID)
		if err != nil || input.OrganizationID != orgID {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Input inventory "+raw+" not found in this organization")
			return false
		}
		if input.Type == models.InventoryTypeConstructed {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Constructed inventories cannot be inputs of other constructed inventories")
			return false
		}
		if input.ID == inventory.ID {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "An inventory cannot be its own input")
			return false
		}
		ids = append(ids, inputID)
	}
	if err := h.inventoryRepo.SetConstructedInputs(inventory.ID, ids); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to save input inventories")
		return false
	}
	return true
}

// Delete deletes an inventory
// DELETE /api/v2/ansible/inventories/:id
func (h *InventoryHandler) Delete(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory ID")
		return
	}

	// RBAC: fetch inventory and check resource-level write permission
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	inventoryForRBAC, err := h.inventoryRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return
	}
	var hasPermission bool
	if inventoryForRBAC.ProjectID != nil {
		hasPermission, err = h.rbacService.CheckAnsibleResourcePermission(
			c.Request.Context(),
			user.ID,
			rbac.ResourceTypeAnsibleInventory,
			inventoryForRBAC.ID.String(),
			rbac.PermissionAnsibleInventoryWrite,
			inventoryForRBAC.ProjectID,
		)
	} else {
		hasPermission, err = h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, inventoryForRBAC.OrganizationID)
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to delete this inventory")
		return
	}

	// ?force=true cascades over every dependent resource (templates, jobs,
	// schedules, workflow nodes, sources). It deletes resources well beyond the
	// inventory itself, so it additionally requires org-level Ansible manage.
	if c.Query("force") == "true" {
		canManage, err := h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, inventoryForRBAC.OrganizationID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
			return
		}
		if !canManage {
			jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Force delete requires organization-level Ansible management permission")
			return
		}
		if err := h.inventoryService.ForceDeleteInventory(id); err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
			return
		}
		c.Status(http.StatusNoContent)
		return
	}

	if err := h.inventoryService.DeleteInventory(id); err != nil {
		// Check if it's a dependency error (contains "cannot delete" or "referenced")
		errStr := err.Error()
		if strings.Contains(errStr, "cannot delete") || strings.Contains(errStr, "referenced") {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
			return
		}

		// A template or job that appeared after the dependency count is refused by its foreign key.
		if detail, ok := deleteConflictDetail(err, inventoryConflicts); ok {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", detail)
			return
		}

		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	c.Status(http.StatusNoContent)
}

// GetInventoryINI returns the inventory in INI format
// GET /api/v2/ansible/inventories/:id/ini
func (h *InventoryHandler) GetInventoryINI(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory ID")
		return
	}

	// RBAC: fetch inventory and check resource-level read permission
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	inventory, err := h.inventoryRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return
	}
	var hasPermission bool
	if inventory.ProjectID != nil {
		hasPermission, err = h.rbacService.CheckAnsibleResourcePermission(
			c.Request.Context(),
			user.ID,
			rbac.ResourceTypeAnsibleInventory,
			inventory.ID.String(),
			rbac.PermissionAnsibleInventoryRead,
			inventory.ProjectID,
		)
	} else {
		hasPermission, err = h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, inventory.OrganizationID)
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to access this inventory")
		return
	}

	content, err := h.inventoryService.GenerateInventoryINI(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	c.Header("Content-Type", "text/plain")
	c.String(http.StatusOK, content)
}

// GetInventoryJSON returns the inventory in JSON format
// GET /api/v2/ansible/inventories/:id/json
func (h *InventoryHandler) GetInventoryJSON(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory ID")
		return
	}

	// RBAC: fetch inventory and check resource-level read permission
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	inventory, err := h.inventoryRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return
	}
	var hasPermission bool
	if inventory.ProjectID != nil {
		hasPermission, err = h.rbacService.CheckAnsibleResourcePermission(
			c.Request.Context(),
			user.ID,
			rbac.ResourceTypeAnsibleInventory,
			inventory.ID.String(),
			rbac.PermissionAnsibleInventoryRead,
			inventory.ProjectID,
		)
	} else {
		hasPermission, err = h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, inventory.OrganizationID)
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to access this inventory")
		return
	}

	content, err := h.inventoryService.GenerateInventoryJSON(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, content)
}

// SyncInventory syncs a VCS inventory from repository
// POST /api/v2/ansible/inventories/:id/actions/sync
func (h *InventoryHandler) SyncInventory(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory ID")
		return
	}

	inventory, err := h.inventoryRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return
	}

	// RBAC: check resource-level write permission
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	var hasPermission bool
	if inventory.ProjectID != nil {
		hasPermission, err = h.rbacService.CheckAnsibleResourcePermission(
			c.Request.Context(),
			user.ID,
			rbac.ResourceTypeAnsibleInventory,
			inventory.ID.String(),
			rbac.PermissionAnsibleInventoryWrite,
			inventory.ProjectID,
		)
	} else {
		hasPermission, err = h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, inventory.OrganizationID)
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to sync this inventory")
		return
	}

	// Constructed inventories rebuild from their inputs; VCS inventories need
	// their VCS configuration.
	if inventory.Type != models.InventoryTypeConstructed &&
		(inventory.VCSConnectionID == nil || inventory.VCSRepository == "" || inventory.InventoryPath == "") {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Inventory has no VCS connection configured")
		return
	}

	if inventory.Type == models.InventoryTypeConstructed {
		// A constructed rebuild is marked syncing first, as before (#1113 leaves rebuilds as they are).
		if err := h.inventoryRepo.SetSyncStatus(inventory.ID, "syncing", ""); err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update sync status")
			return
		}
		inventory.LastSyncStatus, inventory.LastSyncError = "syncing", ""
		if h.workItems != nil {
			if _, err := h.workItems.RequestInventorySync(c.Request.Context(), inventory, "manual"); err != nil {
				h.setSyncStatus(inventory, "failed", "Failed to request the sync: "+err.Error())
				jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to request the sync")
				return
			}
		}
		jsonapi.WriteDocument(c, http.StatusAccepted, formatInventoryResponse(inventory))
		return
	}

	// A file sync request is checked before anything is written: it marks the inventory syncing in
	// the transaction that queues the work item, so a refusal or a failure leaves the status as it
	// was, and nothing this request writes later can overwrite a fast completion (#1113, D2).
	if h.workItems != nil {
		if _, err := h.workItems.RequestInventorySync(c.Request.Context(), inventory, "manual"); err != nil {
			if reason, refused := ansible.FileSyncRefusal(err); refused {
				jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", reason)
				return
			}
			logger.Warnf("requesting a sync of inventory %s: %v", inventory.ID, err)
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to request the sync")
			return
		}
		inventory.LastSyncStatus, inventory.LastSyncError = "syncing", ""
	}

	jsonapi.WriteDocument(c, http.StatusAccepted, formatInventoryResponse(inventory))
}

// setSyncStatus records a sync status on the inventory row and on the struct the response is
// written from. The row is written by identifier: the struct may have been loaded with its hosts
// and groups, and only the status columns are this write's to change (#927). A failure is logged,
// because the request the status belongs to has already succeeded or failed on its own.
func (h *InventoryHandler) setSyncStatus(inventory *models.AnsibleInventory, status, syncError string) {
	if err := h.inventoryRepo.SetSyncStatus(inventory.ID, status, syncError); err != nil {
		logger.Warnf("Failed to set the sync status of inventory %s: %v", inventory.ID, err)
		return
	}
	inventory.LastSyncStatus, inventory.LastSyncError = status, syncError
}

// formatInventoryResponse formats an inventory for JSON:API response
func formatInventoryResponse(inv *models.AnsibleInventory) *jsonapi.Resource[InventoryAttributes] {
	attributes := InventoryAttributes{
		Name:                    inv.Name,
		Description:             inv.Description,
		InventoryType:           inv.Type,
		Source:                  inv.Source,
		Variables:               inv.Variables,
		LastSyncAt:              jsonapi.FormatTimePtr(inv.LastSyncAt),
		LastSyncStatus:          inv.LastSyncStatus,
		LastSyncError:           inv.LastSyncError,
		LastSyncHostsDiscovered: inv.LastSyncHostsDiscovered,
		LastSyncLog:             inv.LastSyncLog,
		SourceVars:              inv.SourceVars,
		ConstructedLimit:        inv.ConstructedLimit,
		ConstructedCacheTimeout: inv.ConstructedCacheTimeout,
		CreatedAt:               jsonapi.FormatTime(inv.CreatedAt),
		UpdatedAt:               jsonapi.FormatTime(inv.UpdatedAt),
	}

	// Add VCS fields if present
	if inv.VCSConnectionID != nil {
		attributes.VCSConnectionID = inv.VCSConnectionID.String()
	}
	attributes.VCSRepository = inv.VCSRepository
	attributes.VCSBranch = inv.VCSBranch
	attributes.InventoryPath = inv.InventoryPath
	attributes.IdentityBindingID = levelrefs.UUIDString(inv.IdentityBindingID)

	relationships := InventoryRelationships{
		Organization: jsonapi.ToOne(inv.OrganizationID.String(), "organizations"),
	}

	// Add VCS connection relationship if present
	if inv.VCSConnectionID != nil {
		r := jsonapi.ToOne(inv.VCSConnectionID.String(), "vcs-connections")
		relationships.VCSConnection = &r
	}

	return &jsonapi.Resource[InventoryAttributes]{
		ID:            inv.ID.String(),
		Type:          "ansible-inventories",
		Attributes:    attributes,
		Relationships: relationships,
	}
}

// formatInventoriesResponse formats multiple inventories for JSON:API response
func formatInventoriesResponse(inventories []models.AnsibleInventory) []*jsonapi.Resource[InventoryAttributes] {
	result := make([]*jsonapi.Resource[InventoryAttributes], len(inventories))
	for i, inv := range inventories {
		result[i] = formatInventoryResponse(&inv)
	}
	return result
}
