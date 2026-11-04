// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/apierror"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/levelrefs"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

// InventorySourceHandler handles inventory source API requests
type InventorySourceHandler struct {
	sourceService    *ansible.InventorySourceService
	inventoryService *ansible.InventoryService
	authService      *auth.Service
	rbacService      *rbac.Service
	workItems        *ansible.WorkItemService
	levelRefs        *levelrefs.Checker
}

// NewInventorySourceHandler creates a new inventory source handler
func NewInventorySourceHandler(
	sourceService *ansible.InventorySourceService,
	inventoryService *ansible.InventoryService,
	authService *auth.Service,
	rbacService *rbac.Service,
	workItems *ansible.WorkItemService,
) *InventorySourceHandler {
	return &InventorySourceHandler{
		sourceService:    sourceService,
		inventoryService: inventoryService,
		authService:      authService,
		rbacService:      rbacService,
		workItems:        workItems,
	}
}

// authorizeInventoryByID loads the inventory named by the :id path param and gates
// the caller against it (collection routes Create/List). AUD-100.
func (h *InventorySourceHandler) authorizeInventoryByID(c *gin.Context, inventoryID uuid.UUID, write bool) bool {
	inventory, err := h.inventoryService.GetInventory(inventoryID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return false
	}
	return authorizeInventoryResource(c, h.authService, h.rbacService, inventory, write)
}

// SetLevelRefs sets the checker of the run image and identity binding a source selects.
func (h *InventorySourceHandler) SetLevelRefs(c *levelrefs.Checker) { h.levelRefs = c }

// levelRefOptions checks the run image (an Ansible one) and identity binding a source selects
// against its inventory's organization and sets them on opts, writing the 422 and returning false on
// an invalid one (#933, D0, D6, D8).
func (h *InventorySourceHandler) levelRefOptions(c *gin.Context, inventoryID uuid.UUID, opts *ansible.UpdateInventorySourceOptions, runImage, binding *string) bool {
	if runImage == nil && binding == nil {
		return true
	}
	inventory, err := h.inventoryService.GetInventory(inventoryID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
		return false
	}
	if h.levelRefs == nil {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "run images and identity bindings are not configured")
		return false
	}
	img, set, err := h.levelRefs.RunImage(inventory.OrganizationID, models.RunImageKindAnsible, runImage)
	if err == nil {
		opts.SetRunImage, opts.RunImageID = set, img
		var b *uuid.UUID
		if b, set, err = h.levelRefs.IdentityBinding(inventory.OrganizationID, binding); err == nil {
			opts.SetIdentityBinding, opts.IdentityBindingID = set, b
		}
	}
	if err != nil {
		if errors.Is(err, levelrefs.ErrInvalid) {
			jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return false
	}
	return true
}

// authorizeSource resolves the source's parent inventory and gates the caller
// against it (item routes Get/Update/Delete/Sync). Returns the source and true
// when authorized. AUD-100.
func (h *InventorySourceHandler) authorizeSource(c *gin.Context, sourceID uuid.UUID, write bool) (*models.AnsibleInventorySource, bool) {
	source, err := h.sourceService.GetInventorySource(sourceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory source not found")
		return nil, false
	}
	inventory, err := h.inventoryService.GetInventory(source.InventoryID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Inventory not found")
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
			SyncTimeout        *int                         `json:"sync-timeout"`
			RunImageID         *string                      `json:"run-image-id"`
			IdentityBindingID  *string                      `json:"identity-binding-id"`
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
			SyncTimeout        *int                          `json:"sync-timeout"`
			RunImageID         *string                       `json:"run-image-id"`
			IdentityBindingID  *string                       `json:"identity-binding-id"`
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
func (h *InventorySourceHandler) Create(c *gin.Context) {
	// Get inventory_id from path parameter (route: /ansible/inventories/:id/sources)
	inventoryIDStr := c.Param("id")
	if inventoryIDStr == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "inventory_id is required in path")
		return
	}

	inventoryID, err := uuid.Parse(inventoryIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory_id")
		return
	}

	if !h.authorizeInventoryByID(c, inventoryID, true) {
		return
	}

	var req CreateInventorySourceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	attrs := req.Data.Attributes

	var credentialID *uuid.UUID
	if attrs.CredentialID != nil && *attrs.CredentialID != "" {
		id, err := uuid.Parse(*attrs.CredentialID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid credential_id")
			return
		}
		credentialID = &id
	}

	// The sync attributes the caller sent. One left out stays nil and the service supplies the
	// create default, so the row is written once with its final values.
	syncOpts := ansible.UpdateInventorySourceOptions{
		UpdateOnLaunch:     attrs.UpdateOnLaunch,
		UpdateCacheTimeout: attrs.UpdateCacheTimeout,
		Overwrite:          attrs.Overwrite,
		OverwriteVars:      attrs.OverwriteVars,
		Verbosity:          attrs.Verbosity,
		TimeoutSeconds:     attrs.SyncTimeout,
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
	if !h.levelRefOptions(c, inventoryID, &syncOpts, attrs.RunImageID, attrs.IdentityBindingID) {
		return
	}

	source, err := h.sourceService.CreateInventorySourceWithOptions(
		inventoryID,
		attrs.Name,
		attrs.Description,
		attrs.SourceType,
		credentialID,
		attrs.Config,
		syncOpts,
	)
	// The service validates the caller's input (the credential and its type, the Azure
	// configuration) in the same call that writes the row. Input errors keep their sentence and
	// answer 400; anything else is logged and answered with an operator-authored message. A
	// constructed inventory takes no source, because its build would remove what a sync adds.
	if writeConstructedRefusal(c, err) {
		return
	}
	if errors.Is(err, ansible.ErrInvalidInput) {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if err != nil {
		apierror.Internal(c, "Failed to create inventory source", err)
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, formatInventorySourceResponse(source))
}

// Get retrieves an inventory source by ID
func (h *InventorySourceHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("source_id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory source ID")
		return
	}

	source, ok := h.authorizeSource(c, id, false)
	if !ok {
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatInventorySourceResponse(source))
}

// List lists inventory sources for an inventory
func (h *InventorySourceHandler) List(c *gin.Context) {
	// Get inventory_id from path parameter (route: /ansible/inventories/:id/sources)
	inventoryIDStr := c.Param("id")
	if inventoryIDStr == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "inventory_id is required")
		return
	}

	inventoryID, err := uuid.Parse(inventoryIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory_id")
		return
	}

	if !h.authorizeInventoryByID(c, inventoryID, false) {
		return
	}

	// page[number]/page[size], not limit/offset. This handler already emitted correct pagination
	// meta, which made the mismatch worse rather than harmless: fetchAllPages
	// (frontend/src/lib/pagination.ts) believed the total-pages it was told, asked for page 2,
	// and got page 1 back because the offset it sent was never read - so the Sources tab listed
	// every row twice and never reached the ones past the first page.
	page, perPage := jsonapi.PageParams(c, 20, 100)
	offset := (page - 1) * perPage

	sources, total, err := h.sourceService.ListInventorySources(inventoryID, perPage, offset)
	if err != nil {
		apierror.Internal(c, "Failed to list inventory sources", err)
		return
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, formatInventorySourcesResponse(sources), jsonapi.NewPaginationMeta(page, perPage, total))
}

// Update updates an inventory source
func (h *InventorySourceHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("source_id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory source ID")
		return
	}

	source, ok := h.authorizeSource(c, id, true)
	if !ok {
		return
	}

	var req UpdateInventorySourceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
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
		TimeoutSeconds:     attrs.SyncTimeout,
	}

	if !h.levelRefOptions(c, source.InventoryID, &opts, attrs.RunImageID, attrs.IdentityBindingID) {
		return
	}

	// Handle credential: empty string = clear credential (switch to OIDC), non-empty = set credential
	if attrs.CredentialID != nil {
		if *attrs.CredentialID == "" {
			opts.ClearCredential = true
		} else {
			credID, err := uuid.Parse(*attrs.CredentialID)
			if err != nil {
				jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid credential_id")
				return
			}
			opts.CredentialID = &credID
		}
	}

	source, err = h.sourceService.UpdateInventorySource(id, opts)
	if errors.Is(err, ansible.ErrInvalidInput) {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if err != nil {
		apierror.Internal(c, "Failed to update inventory source", err)
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatInventorySourceResponse(source))
}

// Delete deletes an inventory source
func (h *InventorySourceHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("source_id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory source ID")
		return
	}

	if _, ok := h.authorizeSource(c, id, true); !ok {
		return
	}

	if err := h.sourceService.DeleteInventorySource(id); err != nil {
		apierror.Internal(c, "Failed to delete inventory source", err)
		return
	}

	c.Status(http.StatusNoContent)
}

// Sync triggers a sync for an inventory source
func (h *InventorySourceHandler) Sync(c *gin.Context) {
	id, err := uuid.Parse(c.Param("source_id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid inventory source ID")
		return
	}

	// Verify source exists, authorize the caller, and mark as syncing
	source, ok := h.authorizeSource(c, id, true)
	if !ok {
		return
	}

	if !source.Enabled {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Inventory source is disabled")
		return
	}

	// Mark as syncing
	if markErr := h.sourceService.MarkSyncing(id); markErr != nil {
		logger.Warnf("Failed to mark source as syncing: %v", markErr)
	}
	// Reflect the syncing status in the response
	source.Status = models.InventorySourceStatusSyncing

	// Request the sync work item; a launcher of the source's pool runs it (#933, D2).
	if h.workItems != nil {
		if _, err := h.workItems.RequestSourceSync(c.Request.Context(), source, "manual"); err != nil {
			// Revert status
			if markErr := h.sourceService.MarkSyncFailed(id, "Failed to request the sync: "+err.Error()); markErr != nil {
				logger.Warnf("Failed to update source after the sync request error: %v", markErr)
			}
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to request the sync")
			return
		}
	} else {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Syncs are not available")
		return
	}

	jsonapi.WriteDocument(c, http.StatusAccepted, formatInventorySourceResponse(source))
}

// formatInventorySourceResponse formats a source for JSON:API response
func formatInventorySourceResponse(source *models.AnsibleInventorySource) jsonapi.Resource[InventorySourceAttributes] {
	relationships := InventorySourceRelationships{
		Inventory: jsonapi.ToOne(source.InventoryID.String(), "ansible-inventories"),
	}
	if source.CredentialID != nil {
		r := jsonapi.ToOne(source.CredentialID.String(), "ansible-credentials")
		relationships.Credential = &r
	}

	return jsonapi.Resource[InventorySourceAttributes]{
		ID:   source.ID.String(),
		Type: "inventory-sources",
		Attributes: InventorySourceAttributes{
			Name:                    source.Name,
			Description:             source.Description,
			SourceType:              string(source.Type),
			Config:                  source.Config,
			UpdateOnLaunch:          source.UpdateOnLaunch,
			UpdateCacheTimeout:      source.UpdateCacheTimeout,
			Overwrite:               source.Overwrite,
			OverwriteVars:           source.OverwriteVars,
			Verbosity:               source.Verbosity,
			SyncTimeout:             source.TimeoutSeconds,
			RunImageID:              levelrefs.UUIDString(source.RunImageID),
			IdentityBindingID:       levelrefs.UUIDString(source.IdentityBindingID),
			GroupByInstanceID:       source.GroupByInstanceID,
			GroupByRegion:           source.GroupByRegion,
			GroupByAvailabilityZone: source.GroupByAvailabilityZone,
			GroupByTag:              source.GroupByTag,
			HostnameVar:             source.HostnameVar,
			InstanceFilters:         source.InstanceFilters,
			SyncSchedule:            source.SyncSchedule,
			Status:                  string(source.Status),
			LastSyncAt:              source.LastSyncAt,
			LastSyncError:           source.LastSyncError,
			LastSyncLog:             source.LastSyncLog,
			HostsCount:              source.HostsCount,
			Enabled:                 source.Enabled,
			CreatedAt:               source.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:               source.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		},
		Relationships: relationships,
	}
}

// formatInventorySourcesResponse formats multiple sources for JSON:API response
func formatInventorySourcesResponse(sources []models.AnsibleInventorySource) []jsonapi.Resource[InventorySourceAttributes] {
	result := make([]jsonapi.Resource[InventorySourceAttributes], len(sources))
	for i := range sources {
		result[i] = formatInventorySourceResponse(&sources[i])
	}
	return result
}
