// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/notification"
)

// NotificationConfigurationHandlerV2 serves the TFE-compatible workspace notification-configuration
// endpoints (tfe_notification_configuration). Delivery is handled by the orchestrator poll; this handler
// owns CRUD + the verify action.
type NotificationConfigurationHandlerV2 struct {
	repo          *repository.NotificationConfigurationRepository
	workspaceRepo *repository.WorkspaceRepository
	authService   *auth.Service
	rbacService   *rbac.Service
	cryptoService *crypto.CryptoService
	notifier      *notification.Service
}

func NewNotificationConfigurationHandlerV2(
	repo *repository.NotificationConfigurationRepository,
	workspaceRepo *repository.WorkspaceRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	cryptoService *crypto.CryptoService,
	notifier *notification.Service,
) *NotificationConfigurationHandlerV2 {
	return &NotificationConfigurationHandlerV2{
		repo:          repo,
		workspaceRepo: workspaceRepo,
		authService:   authService,
		rbacService:   rbacService,
		cryptoService: cryptoService,
		notifier:      notifier,
	}
}

func ncError(c *gin.Context, status int, title, detail string) {
	c.JSON(status, gin.H{"errors": []gin.H{{"status": strconv.Itoa(status), "title": title, "detail": detail}}})
}

// ncRequest is the JSON:API create/update body (type: notification-configurations).
type ncRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name            *string  `json:"name"`
			DestinationType *string  `json:"destination-type"`
			URL             *string  `json:"url"`
			Token           *string  `json:"token"`
			Enabled         *bool    `json:"enabled"`
			Triggers        []string `json:"triggers"`
			EmailAddresses  []string `json:"email-addresses"`
		} `json:"attributes"`
	} `json:"data"`
}

// formatNotificationConfig renders a config as JSON:API (never includes the token).
func formatNotificationConfig(nc *models.NotificationConfiguration) gin.H {
	triggers := []string(nc.Triggers)
	if triggers == nil {
		triggers = []string{}
	}
	emails := []string(nc.EmailAddresses)
	if emails == nil {
		emails = []string{}
	}
	return gin.H{
		"id":   nc.ID,
		"type": "notification-configurations",
		"attributes": gin.H{
			"name":             nc.Name,
			"destination-type": string(nc.Destination),
			"url":              nc.URL,
			"enabled":          nc.Enabled,
			"triggers":         triggers,
			"email-addresses":  emails,
			"created-at":       nc.CreatedAt.Format(time.RFC3339),
			"updated-at":       nc.UpdatedAt.Format(time.RFC3339),
		},
		"relationships": gin.H{
			"subscribable": gin.H{"data": gin.H{"id": nc.WorkspaceID, "type": "workspaces"}},
		},
	}
}

// authWorkspace loads a workspace and checks the caller's permission (read or write).
func (h *NotificationConfigurationHandlerV2) authWorkspace(c *gin.Context, workspaceID string, write bool) (*models.Workspace, bool) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		ncError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	ws, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		ncError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return nil, false
	}
	perm := rbac.PermissionWorkspaceRead
	if write {
		perm = rbac.PermissionWorkspaceWrite
	}
	ok, err := h.rbacService.CheckWorkspacePermission(c.Request.Context(), user.ID, ws.ID, perm, ws.ProjectID)
	if err != nil || !ok {
		ncError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this workspace's notifications")
		return nil, false
	}
	return ws, true
}

// applyAttributes copies request attributes onto a config, encrypting the token. isCreate seeds defaults.
func (h *NotificationConfigurationHandlerV2) applyAttributes(nc *models.NotificationConfiguration, req *ncRequest, isCreate bool) error {
	a := req.Data.Attributes
	if a.Name != nil {
		nc.Name = *a.Name
	}
	if a.DestinationType != nil {
		nc.Destination = models.NotificationDestinationType(*a.DestinationType)
	}
	if a.URL != nil {
		nc.URL = *a.URL
	}
	if a.Triggers != nil {
		nc.Triggers = models.StringArray(a.Triggers)
	}
	if a.EmailAddresses != nil {
		nc.EmailAddresses = models.StringArray(a.EmailAddresses)
	}
	if a.Enabled != nil {
		nc.Enabled = *a.Enabled
	} else if isCreate {
		nc.Enabled = true
	}
	// Token is write-only: encrypt when provided; leave untouched on update when omitted.
	if a.Token != nil && *a.Token != "" {
		if h.cryptoService == nil {
			return errors.New("token encryption unavailable")
		}
		enc, err := h.cryptoService.Encrypt(*a.Token)
		if err != nil {
			return err
		}
		nc.Token = enc
	}
	return nil
}

// Create handles POST /workspaces/:id/notification-configurations
func (h *NotificationConfigurationHandlerV2) Create(c *gin.Context) {
	ws, ok := h.authWorkspace(c, c.Param("id"), true)
	if !ok {
		return
	}
	var req ncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ncError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if req.Data.Attributes.Name == nil || *req.Data.Attributes.Name == "" {
		ncError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "name is required")
		return
	}
	if req.Data.Attributes.DestinationType == nil {
		ncError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "destination-type is required")
		return
	}
	nc := &models.NotificationConfiguration{WorkspaceID: ws.ID}
	if err := h.applyAttributes(nc, &req, true); err != nil {
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to prepare notification configuration")
		return
	}
	if err := h.repo.Create(nc); err != nil {
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create notification configuration")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": formatNotificationConfig(nc)})
}

// List handles GET /workspaces/:id/notification-configurations
func (h *NotificationConfigurationHandlerV2) List(c *gin.Context) {
	ws, ok := h.authWorkspace(c, c.Param("id"), false)
	if !ok {
		return
	}
	configs, err := h.repo.ListByWorkspace(ws.ID)
	if err != nil {
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list notification configurations")
		return
	}
	data := make([]gin.H, 0, len(configs))
	for i := range configs {
		data = append(data, formatNotificationConfig(&configs[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

// loadForCaller loads a config by id and checks workspace permission.
func (h *NotificationConfigurationHandlerV2) loadForCaller(c *gin.Context, write bool) (*models.NotificationConfiguration, *models.Workspace, bool) {
	nc, err := h.repo.GetByID(c.Param("id"))
	if err != nil {
		ncError(c, http.StatusNotFound, "Not Found", "Notification configuration not found")
		return nil, nil, false
	}
	ws, ok := h.authWorkspace(c, nc.WorkspaceID, write)
	if !ok {
		return nil, nil, false
	}
	return nc, ws, true
}

// Read handles GET /notification-configurations/:id
func (h *NotificationConfigurationHandlerV2) Read(c *gin.Context) {
	nc, _, ok := h.loadForCaller(c, false)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatNotificationConfig(nc)})
}

// Update handles PATCH /notification-configurations/:id
func (h *NotificationConfigurationHandlerV2) Update(c *gin.Context) {
	nc, _, ok := h.loadForCaller(c, true)
	if !ok {
		return
	}
	var req ncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ncError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if err := h.applyAttributes(nc, &req, false); err != nil {
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to prepare notification configuration")
		return
	}
	if err := h.repo.Update(nc); err != nil {
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update notification configuration")
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatNotificationConfig(nc)})
}

// Delete handles DELETE /notification-configurations/:id
func (h *NotificationConfigurationHandlerV2) Delete(c *gin.Context) {
	nc, _, ok := h.loadForCaller(c, true)
	if !ok {
		return
	}
	if err := h.repo.Delete(nc.ID); err != nil {
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete notification configuration")
		return
	}
	c.Status(http.StatusNoContent)
}

// Verify handles POST /notification-configurations/:id/actions/verify (sends a test delivery).
func (h *NotificationConfigurationHandlerV2) Verify(c *gin.Context) {
	nc, ws, ok := h.loadForCaller(c, true)
	if !ok {
		return
	}
	// Project + Organization are preloaded by workspaceRepo.GetByID; Name is "" if unavailable.
	orgName := ws.Project.Organization.Name
	rc := notification.RunContext{
		RunID:         "run-verify",
		WorkspaceID:   ws.ID,
		WorkspaceName: ws.Name,
		Organization:  orgName,
		Status:        models.RunStatusPending,
		Operation:     models.RunOperationPlanAndApply,
		Message:       "Verification notification from Stackweaver",
		UpdatedAt:     time.Now(),
	}
	if err := h.notifier.Verify(c.Request.Context(), nc, rc); err != nil {
		ncError(c, http.StatusBadGateway, "Delivery Failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatNotificationConfig(nc)})
}
