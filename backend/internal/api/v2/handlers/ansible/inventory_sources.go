// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/response"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/queue"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

// InventorySourceSyncMessage represents a request to sync a dynamic inventory source
type InventorySourceSyncMessage struct {
	SourceID uuid.UUID `json:"source_id"`
	// TriggeredBy records what started the sync; recorded in the sync history.
	TriggeredBy string `json:"triggered_by,omitempty"`
}

// InventorySourceHandler handles inventory source API requests
type InventorySourceHandler struct {
	sourceService    *ansible.InventorySourceService
	inventoryService *ansible.InventoryService
	authService      *auth.Service
	rbacService      *rbac.Service
	queue            queue.Queue
}

// NewInventorySourceHandler creates a new inventory source handler
func NewInventorySourceHandler(
	sourceService *ansible.InventorySourceService,
	inventoryService *ansible.InventoryService,
	authService *auth.Service,
	rbacService *rbac.Service,
	redisQueue queue.Queue,
) *InventorySourceHandler {
	return &InventorySourceHandler{
		sourceService:    sourceService,
		inventoryService: inventoryService,
		authService:      authService,
		rbacService:      rbacService,
		queue:            redisQueue,
	}
}

// authorizeInventoryByID loads the inventory named by the :id path param and gates
// the caller against it (collection routes Create/List). AUD-100.
func (h *InventorySourceHandler) authorizeInventoryByID(c *gin.Context, inventoryID uuid.UUID, write bool) bool {
	inventory, err := h.inventoryService.GetInventory(inventoryID)
	if err != nil {
		response.NotFound(c, "Inventory not found")
		return false
	}
	return authorizeInventoryResource(c, h.authService, h.rbacService, inventory, write)
}

// authorizeSource resolves the source's parent inventory and gates the caller
// against it (item routes Get/Update/Delete/Sync). Returns the source and true
// when authorized. AUD-100.
func (h *InventorySourceHandler) authorizeSource(c *gin.Context, sourceID uuid.UUID, write bool) (*models.AnsibleInventorySource, bool) {
	source, err := h.sourceService.GetInventorySource(sourceID)
	if err != nil {
		response.NotFound(c, "Inventory source not found")
		return nil, false
	}
	inventory, err := h.inventoryService.GetInventory(source.InventoryID)
	if err != nil {
		response.NotFound(c, "Inventory not found")
		return nil, false
	}
	if !authorizeInventoryResource(c, h.authService, h.rbacService, inventory, write) {
		return nil, false
	}
	return source, true
}

// CreateInventorySourceRequest represents the JSON:API request to create an inventory source
type CreateInventorySourceRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name               string                       `json:"name" binding:"required,min=1,max=255"`
			Description        string                       `json:"description"`
			SourceType         models.InventorySourceType   `json:"source-type" binding:"required,oneof=aws azure gcp vmware custom"`
			CredentialID       *string                      `json:"credential-id"`
			Config             models.InventorySourceConfig `json:"config"`
			SyncSchedule       string                       `json:"sync-schedule"`
			UpdateOnLaunch     *bool                        `json:"update-on-launch"`
			UpdateCacheTimeout *int                         `json:"update-cache-timeout"`
			Overwrite          *bool                        `json:"overwrite"`
			OverwriteVars      *bool                        `json:"overwrite-vars"`
			Verbosity          *int                         `json:"verbosity"`
			GroupByInstanceID  *bool                        `json:"group-by-instance-id"`
			GroupByRegion      *bool                        `json:"group-by-region"`
			GroupByAZ          *bool                        `json:"group-by-availability-zone"`
			GroupByTag         string                       `json:"group-by-tag"`
			HostnameVar        string                       `json:"hostname-var"`
			InstanceFilters    string                       `json:"instance-filters"`
			Enabled            *bool                        `json:"enabled"`
		} `json:"attributes"`
	} `json:"data"`
}

// UpdateInventorySourceRequest represents the JSON:API request to update an inventory source
type UpdateInventorySourceRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name               *string                       `json:"name"`
			Description        *string                       `json:"description"`
			SourceType         *string                       `json:"source-type"`
			CredentialID       *string                       `json:"credential-id"`
			Config             *models.InventorySourceConfig `json:"config"`
			Enabled            *bool                         `json:"enabled"`
			SyncSchedule       *string                       `json:"sync-schedule"`
			UpdateOnLaunch     *bool                         `json:"update-on-launch"`
			UpdateCacheTimeout *int                          `json:"update-cache-timeout"`
			Overwrite          *bool                         `json:"overwrite"`
			OverwriteVars      *bool                         `json:"overwrite-vars"`
			Verbosity          *int                          `json:"verbosity"`
			GroupByInstanceID  *bool                         `json:"group-by-instance-id"`
			GroupByRegion      *bool                         `json:"group-by-region"`
			GroupByAZ          *bool                         `json:"group-by-availability-zone"`
			GroupByTag         *string                       `json:"group-by-tag"`
			HostnameVar        *string                       `json:"hostname-var"`
			InstanceFilters    *string                       `json:"instance-filters"`
		} `json:"attributes"`
	} `json:"data"`
}

// Create creates a new inventory source
// @Summary Create inventory source
// @Description Create a new dynamic inventory source
// @Tags Ansible Inventory Sources
// @Accept json
// @Produce json
// @Param id path string true "Inventory ID"
// @Param request body CreateInventorySourceRequest true "Inventory source details"
// @Success 201 {object} models.AnsibleInventorySource
// @Failure 400 {object} response.ErrorResponse
// @Failure 500 {object} response.ErrorResponse
// @Router /api/v2/ansible/inventories/{id}/sources [post]
func (h *InventorySourceHandler) Create(c *gin.Context) {
	// Get inventory_id from path parameter (route: /ansible/inventories/:id/sources)
	inventoryIDStr := c.Param("id")
	if inventoryIDStr == "" {
		response.BadRequest(c, "inventory_id is required in path")
		return
	}

	inventoryID, err := uuid.Parse(inventoryIDStr)
	if err != nil {
		response.BadRequest(c, "Invalid inventory_id")
		return
	}

	if !h.authorizeInventoryByID(c, inventoryID, true) {
		return
	}

	var req CreateInventorySourceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	attrs := req.Data.Attributes

	var credentialID *uuid.UUID
	if attrs.CredentialID != nil && *attrs.CredentialID != "" {
		id, err := uuid.Parse(*attrs.CredentialID)
		if err != nil {
			response.BadRequest(c, "Invalid credential_id")
			return
		}
		credentialID = &id
	}

	source, err := h.sourceService.CreateInventorySource(
		inventoryID,
		attrs.Name,
		attrs.Description,
		attrs.SourceType,
		credentialID,
		attrs.Config,
	)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	// Apply the sync-behavior attributes the constructor doesn't take, so
	// create requests don't silently fall back to model defaults.
	syncOpts := ansible.UpdateInventorySourceOptions{
		UpdateOnLaunch:     attrs.UpdateOnLaunch,
		UpdateCacheTimeout: attrs.UpdateCacheTimeout,
		Overwrite:          attrs.Overwrite,
		OverwriteVars:      attrs.OverwriteVars,
		Verbosity:          attrs.Verbosity,
		Enabled:            attrs.Enabled,
		GroupByInstanceID:  attrs.GroupByInstanceID,
		GroupByRegion:      attrs.GroupByRegion,
		GroupByAZ:          attrs.GroupByAZ,
	}
	if attrs.SyncSchedule != "" {
		syncOpts.SyncSchedule = &attrs.SyncSchedule
	}
	if attrs.GroupByTag != "" {
		syncOpts.GroupByTag = &attrs.GroupByTag
	}
	if attrs.HostnameVar != "" {
		syncOpts.HostnameVar = &attrs.HostnameVar
	}
	if attrs.InstanceFilters != "" {
		syncOpts.InstanceFilters = &attrs.InstanceFilters
	}
	if syncOpts != (ansible.UpdateInventorySourceOptions{}) {
		if updated, optErr := h.sourceService.UpdateInventorySource(source.ID, syncOpts); optErr != nil {
			logger.Warnf("Inventory source %s created but sync options not applied: %v", source.ID, optErr)
		} else {
			source = updated
		}
	}

	c.JSON(http.StatusCreated, gin.H{"data": formatInventorySourceResponse(source)})
}

// Get retrieves an inventory source by ID
// @Summary Get inventory source
// @Description Get an inventory source by ID
// @Tags Ansible Inventory Sources
// @Produce json
// @Param id path string true "Inventory Source ID"
// @Success 200 {object} models.AnsibleInventorySource
// @Failure 400 {object} response.ErrorResponse
// @Failure 404 {object} response.ErrorResponse
// @Router /api/v2/ansible/inventory-sources/{id} [get]
func (h *InventorySourceHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("source_id"))
	if err != nil {
		response.BadRequest(c, "Invalid inventory source ID")
		return
	}

	source, ok := h.authorizeSource(c, id, false)
	if !ok {
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": formatInventorySourceResponse(source)})
}

// List lists inventory sources for an inventory
// @Summary List inventory sources
// @Description List all inventory sources for a given inventory
// @Tags Ansible Inventory Sources
// @Produce json
// @Param id path string true "Inventory ID"
// @Param limit query int false "Limit" default(20)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} response.PaginatedResponse
// @Failure 400 {object} response.ErrorResponse
// @Router /api/v2/ansible/inventories/{id}/sources [get]
func (h *InventorySourceHandler) List(c *gin.Context) {
	// Get inventory_id from path parameter (route: /ansible/inventories/:id/sources)
	inventoryIDStr := c.Param("id")
	if inventoryIDStr == "" {
		response.BadRequest(c, "inventory_id is required")
		return
	}

	inventoryID, err := uuid.Parse(inventoryIDStr)
	if err != nil {
		response.BadRequest(c, "Invalid inventory_id")
		return
	}

	if !h.authorizeInventoryByID(c, inventoryID, false) {
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	sources, total, err := h.sourceService.ListInventorySources(inventoryID, limit, offset)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	page := offset/limit + 1
	totalPages := (total + int64(limit) - 1) / int64(limit)

	c.JSON(http.StatusOK, gin.H{
		"data": formatInventorySourcesResponse(sources),
		"meta": gin.H{
			"pagination": gin.H{
				"current-page": page,
				"page-size":    limit,
				"total-count":  total,
				"total-pages":  totalPages,
			},
		},
	})
}

// Update updates an inventory source
// @Summary Update inventory source
// @Description Update an inventory source
// @Tags Ansible Inventory Sources
// @Accept json
// @Produce json
// @Param id path string true "Inventory Source ID"
// @Param request body UpdateInventorySourceRequest true "Update details"
// @Success 200 {object} models.AnsibleInventorySource
// @Failure 400 {object} response.ErrorResponse
// @Failure 404 {object} response.ErrorResponse
// @Router /api/v2/ansible/inventory-sources/{id} [patch]
func (h *InventorySourceHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("source_id"))
	if err != nil {
		response.BadRequest(c, "Invalid inventory source ID")
		return
	}

	if _, ok := h.authorizeSource(c, id, true); !ok {
		return
	}

	var req UpdateInventorySourceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	attrs := req.Data.Attributes

	opts := ansible.UpdateInventorySourceOptions{
		Name:               attrs.Name,
		Description:        attrs.Description,
		Config:             attrs.Config,
		Enabled:            attrs.Enabled,
		HostnameVar:        attrs.HostnameVar,
		GroupByRegion:      attrs.GroupByRegion,
		GroupByAZ:          attrs.GroupByAZ,
		GroupByInstanceID:  attrs.GroupByInstanceID,
		GroupByTag:         attrs.GroupByTag,
		InstanceFilters:    attrs.InstanceFilters,
		UpdateOnLaunch:     attrs.UpdateOnLaunch,
		UpdateCacheTimeout: attrs.UpdateCacheTimeout,
		SyncSchedule:       attrs.SyncSchedule,
		Overwrite:          attrs.Overwrite,
		OverwriteVars:      attrs.OverwriteVars,
		Verbosity:          attrs.Verbosity,
	}

	// Handle credential: empty string = clear credential (switch to OIDC), non-empty = set credential
	if attrs.CredentialID != nil {
		if *attrs.CredentialID == "" {
			opts.ClearCredential = true
		} else {
			credID, err := uuid.Parse(*attrs.CredentialID)
			if err != nil {
				response.BadRequest(c, "Invalid credential_id")
				return
			}
			opts.CredentialID = &credID
		}
	}

	source, err := h.sourceService.UpdateInventorySource(id, opts)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": formatInventorySourceResponse(source)})
}

// Delete deletes an inventory source
// @Summary Delete inventory source
// @Description Delete an inventory source
// @Tags Ansible Inventory Sources
// @Param id path string true "Inventory Source ID"
// @Success 204
// @Failure 400 {object} response.ErrorResponse
// @Failure 500 {object} response.ErrorResponse
// @Router /api/v2/ansible/inventory-sources/{id} [delete]
func (h *InventorySourceHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("source_id"))
	if err != nil {
		response.BadRequest(c, "Invalid inventory source ID")
		return
	}

	if _, ok := h.authorizeSource(c, id, true); !ok {
		return
	}

	if err := h.sourceService.DeleteInventorySource(id); err != nil {
		response.InternalError(c, err.Error())
		return
	}

	c.Status(http.StatusNoContent)
}

// Sync triggers a sync for an inventory source
// @Summary Sync inventory source
// @Description Trigger a sync for an inventory source
// @Tags Ansible Inventory Sources
// @Produce json
// @Param id path string true "Inventory Source ID"
// @Success 200 {object} ansible.SyncResult
// @Failure 400 {object} response.ErrorResponse
// @Failure 500 {object} response.ErrorResponse
// @Router /api/v2/ansible/inventory-sources/{id}/sync [post]
func (h *InventorySourceHandler) Sync(c *gin.Context) {
	id, err := uuid.Parse(c.Param("source_id"))
	if err != nil {
		response.BadRequest(c, "Invalid inventory source ID")
		return
	}

	// Verify source exists, authorize the caller, and mark as syncing
	source, ok := h.authorizeSource(c, id, true)
	if !ok {
		return
	}

	if !source.Enabled {
		response.BadRequest(c, "Inventory source is disabled")
		return
	}

	// Mark as syncing
	if markErr := h.sourceService.MarkSyncing(id); markErr != nil {
		logger.Warnf("Failed to mark source as syncing: %v", markErr)
	}
	// Reflect the syncing status in the response
	source.Status = models.InventorySourceStatusSyncing

	// Queue sync job to ansible-runner via Redis
	if h.queue != nil {
		syncMsg := InventorySourceSyncMessage{
			SourceID:    id,
			TriggeredBy: "manual",
		}
		if err := h.queue.Enqueue(context.Background(), "ansible_sync", syncMsg); err != nil {
			// Revert status
			if markErr := h.sourceService.MarkSyncFailed(id, "Failed to queue sync job: "+err.Error()); markErr != nil {
				logger.Warnf("Failed to update source after queue error: %v", markErr)
			}
			response.InternalError(c, "Failed to queue sync job")
			return
		}
	} else {
		response.InternalError(c, "Sync queue not available")
		return
	}

	c.JSON(http.StatusAccepted, gin.H{"data": formatInventorySourceResponse(source)})
}

// formatInventorySourceResponse formats a source for JSON:API response
func formatInventorySourceResponse(source *models.AnsibleInventorySource) gin.H {
	resp := gin.H{
		"id":   source.ID.String(),
		"type": "inventory-sources",
		"attributes": gin.H{
			"name":                       source.Name,
			"description":                source.Description,
			"source-type":                string(source.Type),
			"config":                     source.Config,
			"update-on-launch":           source.UpdateOnLaunch,
			"update-cache-timeout":       source.UpdateCacheTimeout,
			"overwrite":                  source.Overwrite,
			"overwrite-vars":             source.OverwriteVars,
			"verbosity":                  source.Verbosity,
			"group-by-instance-id":       source.GroupByInstanceID,
			"group-by-region":            source.GroupByRegion,
			"group-by-availability-zone": source.GroupByAvailabilityZone,
			"group-by-tag":               source.GroupByTag,
			"hostname-var":               source.HostnameVar,
			"instance-filters":           source.InstanceFilters,
			"sync-schedule":              source.SyncSchedule,
			"status":                     string(source.Status),
			"last-sync-at":               source.LastSyncAt,
			"last-sync-error":            source.LastSyncError,
			"last-sync-log":              source.LastSyncLog,
			"hosts-count":                source.HostsCount,
			"enabled":                    source.Enabled,
			"created-at":                 source.CreatedAt.Format("2006-01-02T15:04:05Z"),
			"updated-at":                 source.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		},
		"relationships": gin.H{
			"inventory": gin.H{
				"data": gin.H{
					"id":   source.InventoryID.String(),
					"type": "ansible-inventories",
				},
			},
		},
	}

	if source.CredentialID != nil {
		resp["relationships"].(gin.H)["credential"] = gin.H{
			"data": gin.H{
				"id":   source.CredentialID.String(),
				"type": "ansible-credentials",
			},
		}
	}

	return resp
}

// formatInventorySourcesResponse formats multiple sources for JSON:API response
func formatInventorySourcesResponse(sources []models.AnsibleInventorySource) []gin.H {
	result := make([]gin.H, len(sources))
	for i := range sources {
		result[i] = formatInventorySourceResponse(&sources[i])
	}
	return result
}
