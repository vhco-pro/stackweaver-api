// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
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
// on denial - sync output can contain host variables and connection details.
func (h *InventorySyncHandler) authorizeInventoryRead(c *gin.Context, inventoryID uuid.UUID) bool {
	inventory, err := h.inventoryRepo.GetByID(inventoryID)
	if err != nil {
		response.NotFound(c, "Inventory not found")
		return false
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return false
	}
	hasPermission, err := h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, inventory.OrganizationID)
	if err != nil {
		response.InternalError(c, "Failed to check permissions")
		return false
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You don't have permission to view this inventory's sync history")
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

	data := make([]jsonapi.Resource[InventorySyncAttributes], 0, len(syncs))
	for i := range syncs {
		data = append(data, formatInventorySyncResponse(&syncs[i], false))
	}
	// limit/offset paging, reported as pages so this collection reads like every other one.
	// It previously emitted a bare {"total": n} with no page information at all, so a client
	// could not tell which page it had received.
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(offset/max(limit, 1)+1, limit, total))
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

	jsonapi.WriteDocument(c, http.StatusOK, formatInventorySyncResponse(sync, true))
}

// formatInventorySyncResponse formats a sync run for JSON:API responses.
// Output is only included on detail fetches.
func formatInventorySyncResponse(sync *models.AnsibleInventorySync, includeOutput bool) jsonapi.Resource[InventorySyncAttributes] {
	attrs := InventorySyncAttributes{
		Status:           string(sync.Status),
		TriggeredBy:      sync.TriggeredBy,
		HostsDiscovered:  sync.HostsDiscovered,
		GroupsDiscovered: sync.GroupsDiscovered,
		Error:            sync.Error,
		StartedAt:        sync.StartedAt,
		FinishedAt:       sync.FinishedAt,
		CreatedAt:        sync.CreatedAt,
	}
	if sync.Source != nil {
		attrs.SourceName = sync.Source.Name
	}
	if includeOutput {
		attrs.Output = &sync.Output
	}
	relationships := InventorySyncRelationships{
		Inventory: jsonapi.ToOne(sync.InventoryID.String(), "inventories"),
	}
	if sync.SourceID != nil {
		r := jsonapi.ToOne(sync.SourceID.String(), "inventory-sources")
		relationships.Source = &r
	}
	return jsonapi.Resource[InventorySyncAttributes]{
		ID:            sync.ID.String(),
		Type:          "inventory-syncs",
		Attributes:    attrs,
		Relationships: relationships,
	}
}
