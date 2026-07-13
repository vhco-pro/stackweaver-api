// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// RunTriggerHandlerV2 implements the TFE-compatible run-triggers API (tfe_run_trigger). A run trigger
// links a source workspace to a target workspace so a successful apply in the source auto-queues a run
// in the target; the auto-queue itself runs in the orchestrator's run-trigger worker.
type RunTriggerHandlerV2 struct {
	runTriggerRepo *repository.RunTriggerRepository
	workspaceRepo  *repository.WorkspaceRepository
	authService    *auth.Service
	rbacService    *rbac.Service
}

func NewRunTriggerHandlerV2(
	runTriggerRepo *repository.RunTriggerRepository,
	workspaceRepo *repository.WorkspaceRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *RunTriggerHandlerV2 {
	return &RunTriggerHandlerV2{
		runTriggerRepo: runTriggerRepo,
		workspaceRepo:  workspaceRepo,
		authService:    authService,
		rbacService:    rbacService,
	}
}

func rtError(c *gin.Context, status int, title, detail string) {
	c.JSON(status, gin.H{"errors": []gin.H{{"status": itoa(status), "title": title, "detail": detail}}})
}

func itoa(n int) string {
	switch n {
	case http.StatusBadRequest:
		return "400"
	case http.StatusUnauthorized:
		return "401"
	case http.StatusForbidden:
		return "403"
	case http.StatusNotFound:
		return "404"
	case http.StatusUnprocessableEntity:
		return "422"
	default:
		return "500"
	}
}

// checkWorkspacePermission returns true if the caller holds `perm` on the workspace.
func (h *RunTriggerHandlerV2) checkWorkspacePermission(c *gin.Context, ws *models.Workspace, perm rbac.Permission) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		rtError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return false
	}
	ok, err := h.rbacService.CheckResourcePermission(
		c.Request.Context(), user.ID, rbac.ResourceTypeTerraformWorkspace, ws.ID, perm, &ws.ProjectID,
	)
	if err != nil {
		rtError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return false
	}
	if !ok {
		rtError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage run triggers on this workspace")
		return false
	}
	return true
}

func formatRunTriggerResponse(rt *models.RunTrigger) gin.H {
	return gin.H{
		"id":   rt.ID,
		"type": "run-triggers",
		"attributes": gin.H{
			"workspace-name":  rt.Workspace.Name,
			"sourceable-name": rt.Sourceable.Name,
			"created-at":      rt.CreatedAt.UTC().Format(time.RFC3339),
		},
		"relationships": gin.H{
			// workspace = the TARGET (whose runs are triggered); sourceable = the SOURCE.
			"workspace":  gin.H{"data": gin.H{"id": rt.WorkspaceID, "type": "workspaces"}},
			"sourceable": gin.H{"data": gin.H{"id": rt.SourceableID, "type": "workspaces"}},
		},
	}
}

// Create handles POST /api/v2/workspaces/:workspace_id/run-triggers. The path workspace is the TARGET;
// the body carries the source as a `sourceable` relationship.
// Reference: https://developer.hashicorp.com/terraform/cloud-docs/api-docs/run-triggers#create-a-run-trigger
func (h *RunTriggerHandlerV2) Create(c *gin.Context) {
	targetID := c.Param("id")
	target, err := h.workspaceRepo.GetByID(targetID)
	if err != nil {
		rtError(c, http.StatusNotFound, "Not Found", "Target workspace not found")
		return
	}

	// Managing run triggers on the target requires write on the target workspace.
	if !h.checkWorkspacePermission(c, target, rbac.PermissionWorkspaceWrite) {
		return
	}

	var req struct {
		Data struct {
			Type          string `json:"type"`
			Relationships struct {
				Sourceable struct {
					Data struct {
						Type string `json:"type"`
						ID   string `json:"id"`
					} `json:"data"`
				} `json:"sourceable"`
			} `json:"relationships"`
		} `json:"data"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		rtError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	sourceID := req.Data.Relationships.Sourceable.Data.ID
	if sourceID == "" {
		rtError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "a sourceable workspace relationship is required")
		return
	}
	if sourceID == targetID {
		rtError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "a workspace cannot trigger itself")
		return
	}

	source, err := h.workspaceRepo.GetByID(sourceID)
	if err != nil {
		rtError(c, http.StatusNotFound, "Not Found", "Source (sourceable) workspace not found")
		return
	}
	// The source must belong to the same organization as the target (tenant safety + TFE semantics).
	if source.Project.OrganizationID != target.Project.OrganizationID {
		rtError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "the source and target workspaces must belong to the same organization")
		return
	}
	// The caller must at least be able to read the source workspace (you can't wire a trigger from a
	// workspace you can't see).
	if !h.checkWorkspacePermission(c, source, rbac.PermissionWorkspaceRead) {
		return
	}

	// The source→target pair is unique.
	if exists, err := h.runTriggerRepo.ExistsForPair(targetID, sourceID); err == nil && exists {
		rtError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "a run trigger already exists for this source and target")
		return
	}

	rt := &models.RunTrigger{WorkspaceID: targetID, SourceableID: sourceID}
	if err := h.runTriggerRepo.Create(rt); err != nil {
		rtError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create run trigger")
		return
	}
	created, err := h.runTriggerRepo.GetByID(rt.ID)
	if err != nil {
		rtError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to load created run trigger")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": formatRunTriggerResponse(created)})
}

// GetByID handles GET /api/v2/run-triggers/:id.
func (h *RunTriggerHandlerV2) GetByID(c *gin.Context) {
	rt, err := h.runTriggerRepo.GetByID(c.Param("id"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			rtError(c, http.StatusNotFound, "Not Found", "Run trigger not found")
			return
		}
		rtError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to retrieve run trigger")
		return
	}
	// Reading requires read on the target workspace.
	target, err := h.workspaceRepo.GetByID(rt.WorkspaceID)
	if err != nil {
		rtError(c, http.StatusNotFound, "Not Found", "Target workspace not found")
		return
	}
	if !h.checkWorkspacePermission(c, target, rbac.PermissionWorkspaceRead) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatRunTriggerResponse(rt)})
}

// Delete handles DELETE /api/v2/run-triggers/:id.
func (h *RunTriggerHandlerV2) Delete(c *gin.Context) {
	rt, err := h.runTriggerRepo.GetByID(c.Param("id"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// Already gone — idempotent for destroy.
			c.Status(http.StatusNoContent)
			return
		}
		rtError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to retrieve run trigger")
		return
	}
	target, err := h.workspaceRepo.GetByID(rt.WorkspaceID)
	if err != nil {
		rtError(c, http.StatusNotFound, "Not Found", "Target workspace not found")
		return
	}
	if !h.checkWorkspacePermission(c, target, rbac.PermissionWorkspaceWrite) {
		return
	}
	if err := h.runTriggerRepo.Delete(rt.ID); err != nil {
		rtError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete run trigger")
		return
	}
	c.Status(http.StatusNoContent)
}

// ListByWorkspace handles GET /api/v2/workspaces/:workspace_id/run-triggers.
// TFE filters by direction: filter[run-trigger][type] = inbound (default) or outbound.
// Reference: https://developer.hashicorp.com/terraform/cloud-docs/api-docs/run-triggers#list-run-triggers
func (h *RunTriggerHandlerV2) ListByWorkspace(c *gin.Context) {
	workspaceID := c.Param("id")
	ws, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		rtError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}
	if !h.checkWorkspacePermission(c, ws, rbac.PermissionWorkspaceRead) {
		return
	}

	// go-tfe sends filter[run-trigger][type]; gin exposes it as "filter[run-trigger][type]".
	filterType := c.Query("filter[run-trigger][type]")
	var triggers []models.RunTrigger
	if filterType == "outbound" {
		triggers, err = h.runTriggerRepo.ListOutbound(workspaceID)
	} else {
		// Default (and explicit "inbound"): triggers targeting this workspace.
		triggers, err = h.runTriggerRepo.ListInbound(workspaceID)
	}
	if err != nil {
		rtError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list run triggers")
		return
	}

	data := make([]gin.H, 0, len(triggers))
	for i := range triggers {
		data = append(data, formatRunTriggerResponse(&triggers[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}
