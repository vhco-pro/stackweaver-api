// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/response"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// InventorySyncHandler serves inventory sync run history (AWX's inventory
// update jobs): list per inventory, detail with captured output.
type InventorySyncHandler struct {
	syncRepo      *repository.AnsibleInventorySyncRepository
	inventoryRepo *repository.AnsibleInventoryRepository
	authService   *auth.Service
	rbacService   *rbac.Service
}

// NewInventorySyncHandler creates a new inventory sync handler.
func NewInventorySyncHandler(
	syncRepo *repository.AnsibleInventorySyncRepository,
	inventoryRepo *repository.AnsibleInventoryRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *InventorySyncHandler {
	return &InventorySyncHandler{
		syncRepo:      syncRepo,
		inventoryRepo: inventoryRepo,
		authService:   authService,
		rbacService:   rbacService,
	}
}

// authorizeInventoryRead verifies the caller can read Ansible resources in
// the inventory's organization. Writes the error response and returns false
// on denial — sync output can contain host variables and connection details.
func (h *InventorySyncHandler) authorizeInventoryRead(c *gin.Context, inventoryID uuid.UUID) bool {
	inventory, err := h.inventoryRepo.GetByID(inventoryID)
	if err != nil {
		response.NotFound(c, "Inventory not found")
		return false
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return false
	}
	hasPermission, err := h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, inventory.OrganizationID)
	if err != nil {
		response.InternalError(c, "Failed to check permissions")
		return false
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You don't have permission to view this inventory's sync history"}}})
		return false
	}
	return true
}

// List returns the sync history of an inventory, newest first (no output).
// GET /api/v2/ansible/inventories/:id/syncs
func (h *InventorySyncHandler) List(c *gin.Context) {
	inventoryID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid inventory_id")
		return
	}

	if !h.authorizeInventoryRead(c, inventoryID) {
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	syncs, total, err := h.syncRepo.ListByInventory(inventoryID, limit, offset)
	if err != nil {
		response.InternalError(c, "Failed to list inventory syncs")
		return
	}

	data := make([]gin.H, 0, len(syncs))
	for i := range syncs {
		data = append(data, formatInventorySyncResponse(&syncs[i], false))
	}
	c.JSON(http.StatusOK, gin.H{"data": data, "meta": gin.H{"total": total}})
}

// Get returns one sync run including its captured output.
// GET /api/v2/ansible/inventory-syncs/:sync_id
func (h *InventorySyncHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("sync_id"))
	if err != nil {
		response.BadRequest(c, "Invalid inventory sync ID")
		return
	}

	sync, err := h.syncRepo.GetByID(id)
	if err != nil {
		response.NotFound(c, "Inventory sync not found")
		return
	}
	if !h.authorizeInventoryRead(c, sync.InventoryID) {
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": formatInventorySyncResponse(sync, true)})
}

// formatInventorySyncResponse formats a sync run for JSON:API responses.
// Output is only included on detail fetches.
func formatInventorySyncResponse(sync *models.AnsibleInventorySync, includeOutput bool) gin.H {
	attrs := gin.H{
		"status":            string(sync.Status),
		"triggered-by":      sync.TriggeredBy,
		"hosts-discovered":  sync.HostsDiscovered,
		"groups-discovered": sync.GroupsDiscovered,
		"error":             sync.Error,
		"started-at":        sync.StartedAt,
		"finished-at":       sync.FinishedAt,
		"created-at":        sync.CreatedAt,
	}
	if sync.Source != nil {
		attrs["source-name"] = sync.Source.Name
	}
	if includeOutput {
		attrs["output"] = sync.Output
	}
	resp := gin.H{
		"id":         sync.ID.String(),
		"type":       "inventory-syncs",
		"attributes": attrs,
		"relationships": gin.H{
			"inventory": gin.H{
				"data": gin.H{"id": sync.InventoryID.String(), "type": "inventories"},
			},
		},
	}
	if sync.SourceID != nil {
		resp["relationships"].(gin.H)["source"] = gin.H{
			"data": gin.H{"id": sync.SourceID.String(), "type": "inventory-sources"},
		}
	}
	return resp
}
