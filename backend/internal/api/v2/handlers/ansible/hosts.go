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

// HostHandler handles Ansible inventory host API endpoints
type HostHandler struct {
	inventoryService *ansible.InventoryService
	inventoryRepo    *repository.AnsibleInventoryRepository
	authService      *auth.Service
	rbacService      *rbac.Service
}

// NewHostHandler creates a new host handler
func NewHostHandler(
	inventoryService *ansible.InventoryService,
	inventoryRepo *repository.AnsibleInventoryRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *HostHandler {
	return &HostHandler{
		inventoryService: inventoryService,
		inventoryRepo:    inventoryRepo,
		authService:      authService,
		rbacService:      rbacService,
	}
}

// authorizeHost resolves the host's parent inventory and gates the caller against
// it (AUD-100). Returns the host and true when authorized; writes the JSON:API
// error and returns false otherwise (404 host/inventory not found, else the
// authorizeInventoryResource verdict).
func (h *HostHandler) authorizeHost(c *gin.Context, hostID uuid.UUID, write bool) (*models.AnsibleInventoryHost, bool) {
	host, err := h.inventoryService.GetHost(hostID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Host not found")
		return nil, false
	}
	inventory, err := h.inventoryService.GetInventory(host.InventoryID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return nil, false
	}
	if !authorizeInventoryResource(c, h.authService, h.rbacService, inventory, write) {
		return nil, false
	}
	return host, true
}

// authorizeInventoryByID loads the inventory named by the :id path param and gates
// the caller against it (used by the collection routes List/Create). AUD-100.
func (h *HostHandler) authorizeInventoryByID(c *gin.Context, inventoryID uuid.UUID, write bool) bool {
	inventory, err := h.inventoryService.GetInventory(inventoryID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return false
	}
	return authorizeInventoryResource(c, h.authService, h.rbacService, inventory, write)
}

// CreateHostRequest represents the request to create a host
type CreateHostRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name        string                    `json:"name" binding:"required"`
			Description string                    `json:"description"`
			Hostname    string                    `json:"hostname"`
			Port        int                       `json:"port"`
			Variables   models.InventoryVariables `json:"variables"`
			Enabled     *bool                     `json:"enabled"`
		} `json:"attributes"`
	} `json:"data"`
}

// UpdateHostRequest represents the request to update a host
type UpdateHostRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name        *string                    `json:"name"`
			Description *string                    `json:"description"`
			Hostname    *string                    `json:"hostname"`
			Port        *int                       `json:"port"`
			Variables   *models.InventoryVariables `json:"variables"`
			Enabled     *bool                      `json:"enabled"`
		} `json:"attributes"`
	} `json:"data"`
}

// List lists all hosts in an inventory
// GET /api/v2/ansible/inventories/:id/hosts
func (h *HostHandler) List(c *gin.Context) {
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

	hosts, total, err := h.inventoryService.ListHosts(inventoryID, perPage, offset)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list hosts")
		return
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, formatHostsResponse(hosts), jsonapi.NewPaginationMeta(page, perPage, total))
}

// Create creates a new host in an inventory
// POST /api/v2/ansible/inventories/:id/hosts
func (h *HostHandler) Create(c *gin.Context) {
	inventoryIDStr := c.Param("id")
	inventoryID, err := uuid.Parse(inventoryIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory ID")
		return
	}

	if !h.authorizeInventoryByID(c, inventoryID, true) {
		return
	}

	var req CreateHostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	enabled := true
	if req.Data.Attributes.Enabled != nil {
		enabled = *req.Data.Attributes.Enabled
	}

	port := req.Data.Attributes.Port
	if port == 0 {
		port = 22
	}

	host, err := h.inventoryService.CreateHost(
		inventoryID,
		req.Data.Attributes.Name,
		req.Data.Attributes.Description,
		req.Data.Attributes.Hostname,
		port,
		req.Data.Attributes.Variables,
		enabled,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, formatHostResponse(host))
}

// Get retrieves a host by ID
// GET /api/v2/ansible/hosts/:id
func (h *HostHandler) Get(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid host ID")
		return
	}

	host, ok := h.authorizeHost(c, id, false)
	if !ok {
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatHostResponse(host))
}

// Update updates a host
// PATCH /api/v2/ansible/hosts/:id
func (h *HostHandler) Update(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid host ID")
		return
	}

	if _, ok := h.authorizeHost(c, id, true); !ok {
		return
	}

	var req UpdateHostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	host, err := h.inventoryService.UpdateHost(
		id,
		req.Data.Attributes.Name,
		req.Data.Attributes.Description,
		req.Data.Attributes.Hostname,
		req.Data.Attributes.Port,
		req.Data.Attributes.Variables,
		req.Data.Attributes.Enabled,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatHostResponse(host))
}

// Delete deletes a host
// DELETE /api/v2/ansible/hosts/:id
func (h *HostHandler) Delete(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid host ID")
		return
	}

	if _, ok := h.authorizeHost(c, id, true); !ok {
		return
	}

	if err := h.inventoryService.DeleteHost(id); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	c.Status(http.StatusNoContent)
}

// AddToGroup adds a host to a group
// POST /api/v2/ansible/hosts/:id/groups/:group_id
func (h *HostHandler) AddToGroup(c *gin.Context) {
	hostIDStr := c.Param("id")
	hostID, err := uuid.Parse(hostIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid host ID")
		return
	}

	groupIDStr := c.Param("group_id")
	groupID, err := uuid.Parse(groupIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid group ID")
		return
	}

	if _, ok := h.authorizeHost(c, hostID, true); !ok {
		return
	}

	if err := h.inventoryService.AddHostToGroup(hostID, groupID); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	c.Status(http.StatusNoContent)
}

// RemoveFromGroup removes a host from a group
// DELETE /api/v2/ansible/hosts/:id/groups/:group_id
func (h *HostHandler) RemoveFromGroup(c *gin.Context) {
	hostIDStr := c.Param("id")
	hostID, err := uuid.Parse(hostIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid host ID")
		return
	}

	groupIDStr := c.Param("group_id")
	groupID, err := uuid.Parse(groupIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid group ID")
		return
	}

	if _, ok := h.authorizeHost(c, hostID, true); !ok {
		return
	}

	if err := h.inventoryService.RemoveHostFromGroup(hostID, groupID); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	c.Status(http.StatusNoContent)
}

// formatHostResponse formats a host for JSON:API response
func formatHostResponse(host *models.AnsibleInventoryHost) jsonapi.Resource[HostAttributes] {
	groups := make([]jsonapi.ResourceID, len(host.Groups))
	for i, group := range host.Groups {
		groups[i] = jsonapi.ResourceID{ID: group.ID.String(), Type: "ansible-groups"}
	}

	return jsonapi.Resource[HostAttributes]{
		ID:   host.ID.String(),
		Type: "ansible-hosts",
		Attributes: HostAttributes{
			Name:        host.Name,
			Description: host.Description,
			Hostname:    host.Hostname,
			Port:        host.Port,
			Variables:   host.Variables,
			Enabled:     host.Enabled,
			CreatedAt:   host.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:   host.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		},
		Relationships: HostRelationships{
			Inventory: jsonapi.ToOne(host.InventoryID.String(), "ansible-inventories"),
			Groups:    jsonapi.ManyRelationship{Data: groups},
		},
	}
}

// formatHostsResponse formats multiple hosts for JSON:API response
func formatHostsResponse(hosts []models.AnsibleInventoryHost) []jsonapi.Resource[HostAttributes] {
	result := make([]jsonapi.Resource[HostAttributes], len(hosts))
	for i, host := range hosts {
		result[i] = formatHostResponse(&host)
	}
	return result
}
