// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// WorkspaceRunTaskHandlerV2 serves workspace run-task attachments (tfe_workspace_run_task, JSON:API
// type "workspace-tasks"): an org run task bound to one workspace at one or more stages with an
// enforcement level.
type WorkspaceRunTaskHandlerV2 struct {
	repo          *repository.WorkspaceTaskRepository
	taskRepo      *repository.RunTaskRepository
	workspaceRepo *repository.WorkspaceRepository
	authService   *auth.Service
	rbacService   *rbac.Service
}

func NewWorkspaceRunTaskHandlerV2(
	repo *repository.WorkspaceTaskRepository,
	taskRepo *repository.RunTaskRepository,
	workspaceRepo *repository.WorkspaceRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *WorkspaceRunTaskHandlerV2 {
	return &WorkspaceRunTaskHandlerV2{
		repo:          repo,
		taskRepo:      taskRepo,
		workspaceRepo: workspaceRepo,
		authService:   authService,
		rbacService:   rbacService,
	}
}

// workspaceTaskAttributes on write. `stage` (singular) is deprecated upstream: internally Stages is
// the only source of truth; a request carrying only `stage` is normalized into a one-element Stages
// (wire compat, per the never-implement-deprecated rule).
type workspaceTaskAttributes struct {
	EnforcementLevel *string  `json:"enforcement-level"`
	Stage            *string  `json:"stage"`
	Stages           []string `json:"stages"`
}

type workspaceTaskRequest struct {
	Data struct {
		Type          string                  `json:"type"`
		Attributes    workspaceTaskAttributes `json:"attributes"`
		Relationships struct {
			Task struct {
				Data struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"task"`
		} `json:"relationships"`
	} `json:"data"`
}

// formatWorkspaceTask renders an attachment as JSON:API. BOTH `stage` (deprecated, = stages[0]) and
// `stages` are emitted: the provider stores both and go-tfe decodes both.
func formatWorkspaceTask(wt *models.WorkspaceTask) gin.H {
	stages := wt.Stages
	if len(stages) == 0 {
		stages = models.StringArray{models.TaskStagePostPlan}
	}
	return gin.H{
		"id":   wt.ID,
		"type": "workspace-tasks",
		"attributes": gin.H{
			"enforcement-level": wt.EnforcementLevel,
			"stage":             stages[0],
			"stages":            stages,
			"created-at":        wt.CreatedAt.Format(time.RFC3339),
			"updated-at":        wt.UpdatedAt.Format(time.RFC3339),
		},
		"relationships": gin.H{
			"task":      gin.H{"data": gin.H{"id": wt.TaskID, "type": "tasks"}},
			"workspace": gin.H{"data": gin.H{"id": wt.WorkspaceID, "type": "workspaces"}},
		},
	}
}

// authWorkspace checks run-task access on a workspace: write requires the run_tasks permission
// (granted by workspace admin/write access, the project WorkspaceRunTasks bit, or the workspace
// RunTasks bit), read requires workspace read. Org owners pass via the IsOrgOwner fallback
// (CheckWorkspacePermission has no owners bypass).
func (h *WorkspaceRunTaskHandlerV2) authWorkspace(c *gin.Context, workspaceID string, write bool) (*models.Workspace, bool) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		taskError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	ws, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		taskError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return nil, false
	}
	perm := rbac.PermissionWorkspaceRead
	if write {
		perm = rbac.PermissionRunTasks
	}
	ok, err := h.rbacService.CheckWorkspacePermission(c.Request.Context(), user.ID, ws.ID, perm, ws.ProjectID)
	if err == nil && ok {
		return ws, true
	}
	if owner, oerr := h.rbacService.IsOrgOwner(c.Request.Context(), user.ID, ws.Project.OrganizationID); oerr == nil && owner {
		return ws, true
	}
	taskError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this workspace's run tasks")
	return nil, false
}

// loadForCaller loads an attachment by :tid, verifies it belongs to the :id workspace, and
// authorizes the caller.
func (h *WorkspaceRunTaskHandlerV2) loadForCaller(c *gin.Context, write bool) (*models.WorkspaceTask, bool) {
	wt, err := h.repo.GetByID(c.Param("tid"))
	if err != nil || wt.WorkspaceID != c.Param("id") {
		taskError(c, http.StatusNotFound, "Not Found", "Workspace run task not found")
		return nil, false
	}
	if _, ok := h.authWorkspace(c, wt.WorkspaceID, write); !ok {
		return nil, false
	}
	return wt, true
}

// normalizeStages resolves the stages of a write: explicit `stages` wins, else a singular `stage`
// becomes a one-element list, else the fallback. Returns nil on invalid input.
func normalizeStages(a workspaceTaskAttributes, fallback []string) []string {
	switch {
	case a.Stages != nil:
		if len(a.Stages) == 0 || !validTaskStages(a.Stages) {
			return nil
		}
		return a.Stages
	case a.Stage != nil:
		one := []string{*a.Stage}
		if !validTaskStages(one) {
			return nil
		}
		return one
	default:
		return fallback
	}
}

// Create handles POST /workspaces/:id/tasks.
func (h *WorkspaceRunTaskHandlerV2) Create(c *gin.Context) {
	ws, ok := h.authWorkspace(c, c.Param("id"), true)
	if !ok {
		return
	}
	var req workspaceTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		taskError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	a := req.Data.Attributes
	if a.EnforcementLevel == nil || !validEnforcementLevel(*a.EnforcementLevel) {
		taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "enforcement-level must be advisory or mandatory")
		return
	}
	taskID := req.Data.Relationships.Task.Data.ID
	if taskID == "" {
		taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "a task relationship is required")
		return
	}
	task, err := h.taskRepo.GetByID(taskID)
	if err != nil || task.OrganizationID != ws.Project.OrganizationID {
		// Cross-org tasks 404 (not 403) to avoid confirming another tenant's task ids.
		taskError(c, http.StatusNotFound, "Not Found", "Run task not found in this workspace's organization")
		return
	}
	stages := normalizeStages(a, []string{models.TaskStagePostPlan})
	if stages == nil {
		taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "stages must be unique values of pre_plan, post_plan, pre_apply, post_apply")
		return
	}

	wt := &models.WorkspaceTask{
		WorkspaceID:      ws.ID,
		TaskID:           task.ID,
		EnforcementLevel: *a.EnforcementLevel,
		Stages:           stages,
	}
	if err := h.repo.Create(wt); err != nil {
		if isDuplicateKey(err) {
			taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "this task is already attached to the workspace")
			return
		}
		taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to attach run task")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": formatWorkspaceTask(wt)})
}

// List handles GET /workspaces/:id/tasks.
func (h *WorkspaceRunTaskHandlerV2) List(c *gin.Context) {
	ws, ok := h.authWorkspace(c, c.Param("id"), false)
	if !ok {
		return
	}
	page, pageSize, offset := paginate(c)
	wts, total, err := h.repo.ListByWorkspace(ws.ID, pageSize, offset)
	if err != nil {
		taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list workspace run tasks")
		return
	}
	data := make([]gin.H, 0, len(wts))
	for i := range wts {
		data = append(data, formatWorkspaceTask(&wts[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": data, "meta": fullPaginationMeta(page, pageSize, total)})
}

// Read handles GET /workspaces/:id/tasks/:tid.
func (h *WorkspaceRunTaskHandlerV2) Read(c *gin.Context) {
	wt, ok := h.loadForCaller(c, false)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatWorkspaceTask(wt)})
}

// Update handles PATCH /workspaces/:id/tasks/:tid.
func (h *WorkspaceRunTaskHandlerV2) Update(c *gin.Context) {
	wt, ok := h.loadForCaller(c, true)
	if !ok {
		return
	}
	var req workspaceTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		taskError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	a := req.Data.Attributes
	if a.EnforcementLevel != nil {
		if !validEnforcementLevel(*a.EnforcementLevel) {
			taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "enforcement-level must be advisory or mandatory")
			return
		}
		wt.EnforcementLevel = *a.EnforcementLevel
	}
	stages := normalizeStages(a, wt.Stages)
	if stages == nil {
		taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "stages must be unique values of pre_plan, post_plan, pre_apply, post_apply")
		return
	}
	wt.Stages = stages

	if err := h.repo.Update(wt); err != nil {
		taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update workspace run task")
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatWorkspaceTask(wt)})
}

// Delete handles DELETE /workspaces/:id/tasks/:tid.
func (h *WorkspaceRunTaskHandlerV2) Delete(c *gin.Context) {
	wt, ok := h.loadForCaller(c, true)
	if !ok {
		return
	}
	if err := h.repo.Delete(wt.ID); err != nil {
		taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to detach run task")
		return
	}
	c.Status(http.StatusNoContent)
}
