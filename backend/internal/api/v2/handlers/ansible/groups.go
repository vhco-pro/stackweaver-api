// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

// GroupHandler handles Ansible inventory group API endpoints
type GroupHandler struct {
	inventoryService *ansible.InventoryService
	inventoryRepo    *repository.AnsibleInventoryRepository
	authService      *auth.Service
	rbacService      *rbac.Service
}

// NewGroupHandler creates a new group handler
func NewGroupHandler(
	inventoryService *ansible.InventoryService,
	inventoryRepo *repository.AnsibleInventoryRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *GroupHandler {
	return &GroupHandler{
		inventoryService: inventoryService,
		inventoryRepo:    inventoryRepo,
		authService:      authService,
		rbacService:      rbacService,
	}
}

// authorizeGroup resolves the group's parent inventory and gates the caller against
// it (AUD-100). Returns the group and true when authorized; writes the JSON:API
// error and returns false otherwise.
func (h *GroupHandler) authorizeGroup(c *gin.Context, groupID uuid.UUID, write bool) (*models.AnsibleInventoryGroup, bool) {
	group, err := h.inventoryService.GetGroup(groupID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Group not found")
		return nil, false
	}
	inventory, err := h.inventoryService.GetInventory(group.InventoryID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return nil, false
	}
	if !authorizeInventoryResource(c, h.authService, h.rbacService, inventory, write) {
		return nil, false
	}
	return group, true
}

// authorizeInventoryByID loads the inventory named by the :id path param and gates
// the caller against it (used by the collection routes List/Create). AUD-100.
func (h *GroupHandler) authorizeInventoryByID(c *gin.Context, inventoryID uuid.UUID, write bool) bool {
	inventory, err := h.inventoryService.GetInventory(inventoryID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return false
	}
	return authorizeInventoryResource(c, h.authService, h.rbacService, inventory, write)
}

// CreateGroupRequest represents the request to create a group
type CreateGroupRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name        string                    `json:"name" binding:"required"`
			Description string                    `json:"description"`
			Variables   models.InventoryVariables `json:"variables"`
		} `json:"attributes"`
		Relationships struct {
			Parent struct {
				Data *struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"parent,omitempty"`
		} `json:"relationships,omitempty"`
	} `json:"data"`
}

// UpdateGroupRequest represents the request to update a group
type UpdateGroupRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name        *string                    `json:"name"`
			Description *string                    `json:"description"`
			Variables   *models.InventoryVariables `json:"variables"`
		} `json:"attributes"`
		Relationships struct {
			Parent struct {
				Data *struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"parent,omitempty"`
		} `json:"relationships,omitempty"`
	} `json:"data"`
}

// List lists all groups in an inventory
// GET /api/v2/ansible/inventories/:id/groups
func (h *GroupHandler) List(c *gin.Context) {
	inventoryIDStr := c.Param("id")
	inventoryID, err := uuid.Parse(inventoryIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory ID")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page[number]", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("page[size]", "20"))
	if perPage > 100 {
		perPage = 100
	}
	offset := (page - 1) * perPage

	if !h.authorizeInventoryByID(c, inventoryID, false) {
		return
	}

	groups, total, err := h.inventoryService.ListGroups(inventoryID, perPage, offset)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list groups")
		return
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, formatGroupsResponse(groups), jsonapi.NewPaginationMeta(page, perPage, total))
}

// Create creates a new group in an inventory
// POST /api/v2/ansible/inventories/:id/groups
func (h *GroupHandler) Create(c *gin.Context) {
	inventoryIDStr := c.Param("id")
	inventoryID, err := uuid.Parse(inventoryIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory ID")
		return
	}

	if !h.authorizeInventoryByID(c, inventoryID, true) {
		return
	}

	var req CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	var parentID *uuid.UUID
	if req.Data.Relationships.Parent.Data != nil {
		pid, err := uuid.Parse(req.Data.Relationships.Parent.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid parent group ID")
			return
		}
		parentID = &pid
	}

	group, err := h.inventoryService.CreateGroup(
		inventoryID,
		req.Data.Attributes.Name,
		req.Data.Attributes.Description,
		req.Data.Attributes.Variables,
		parentID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, formatGroupResponse(group))
}

// Get retrieves a group by ID
// GET /api/v2/ansible/groups/:id
func (h *GroupHandler) Get(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid group ID")
		return
	}

	group, ok := h.authorizeGroup(c, id, false)
	if !ok {
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatGroupResponse(group))
}

// Update updates a group
// PATCH /api/v2/ansible/groups/:id
func (h *GroupHandler) Update(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid group ID")
		return
	}

	if _, ok := h.authorizeGroup(c, id, true); !ok {
		return
	}

	var req UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	var parentID *uuid.UUID
	if req.Data.Relationships.Parent.Data != nil {
		pid, err := uuid.Parse(req.Data.Relationships.Parent.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid parent group ID")
			return
		}
		parentID = &pid
	}

	group, err := h.inventoryService.UpdateGroup(
		id,
		req.Data.Attributes.Name,
		req.Data.Attributes.Description,
		req.Data.Attributes.Variables,
		parentID,
		false, // Don't clear parent unless explicitly requested
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatGroupResponse(group))
}

// Delete deletes a group
// DELETE /api/v2/ansible/groups/:id
func (h *GroupHandler) Delete(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid group ID")
		return
	}

	if _, ok := h.authorizeGroup(c, id, true); !ok {
		return
	}

	if err := h.inventoryService.DeleteGroup(id); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	c.Status(http.StatusNoContent)
}

// formatGroupResponse formats a group for JSON:API response
func formatGroupResponse(group *models.AnsibleInventoryGroup) gin.H {
	hosts := make([]gin.H, len(group.Hosts))
	for i, host := range group.Hosts {
		hosts[i] = gin.H{
			"id":   host.ID.String(),
			"type": "ansible-hosts",
		}
	}

	children := make([]gin.H, len(group.Children))
	for i, child := range group.Children {
		children[i] = gin.H{
			"id":   child.ID.String(),
			"type": "ansible-groups",
		}
	}

	relationships := gin.H{
		"inventory": gin.H{
			"data": gin.H{
				"id":   group.InventoryID.String(),
				"type": "ansible-inventories",
			},
		},
		"hosts": gin.H{
			"data": hosts,
		},
		"children": gin.H{
			"data": children,
		},
	}

	if group.ParentID != nil {
		relationships["parent"] = gin.H{
			"data": gin.H{
				"id":   group.ParentID.String(),
				"type": "ansible-groups",
			},
		}
	}

	return gin.H{
		"id":   group.ID.String(),
		"type": "ansible-groups",
		"attributes": gin.H{
			"name":        group.Name,
			"description": group.Description,
			"variables":   group.Variables,
			"created-at":  group.CreatedAt.Format("2006-01-02T15:04:05Z"),
			"updated-at":  group.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		},
		"relationships": relationships,
	}
}

// formatGroupsResponse formats multiple groups for JSON:API response
func formatGroupsResponse(groups []models.AnsibleInventoryGroup) []gin.H {
	result := make([]gin.H, len(groups))
	for i, group := range groups {
		result[i] = formatGroupResponse(&group)
	}
	return result
}
