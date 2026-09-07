// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/services/runtask"
)

// Task stages and results (TFE run-tasks read API + the override action). These are RunHandlerV2
// methods: everything here is scoped to a run, authorized through the same authorizeRun/
// CheckRunPermission path as the rest of the run surface. The provider itself never reads these
// endpoints, but go-tfe does (tfe_workspace_run lists a run's task stages to pick its plan-terminal
// status) and the run UI renders them.

// formatTimestamp renders a nullable time for status-timestamps.
func phaseTimestamps(runningAt, passedAt, failedAt, erroredAt, canceledAt *time.Time) TaskPhaseTimestamps {
	fmtT := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.Format(time.RFC3339)
	}
	return TaskPhaseTimestamps{
		RunningAt:  fmtT(runningAt),
		PassedAt:   fmtT(passedAt),
		FailedAt:   fmtT(failedAt),
		ErroredAt:  fmtT(erroredAt),
		CanceledAt: fmtT(canceledAt),
	}
}

// formatTaskStage renders a task stage as JSON:API (type "task-stages"). permissions/actions
// reflect the CALLER: canOverride is their apply permission on the run's workspace, and
// is-overridable additionally requires the stage to actually await an override.
func formatTaskStage(ts *models.TaskStage, canOverride bool) jsonapi.Resource[TaskStageAttributes] {
	results := make([]jsonapi.ResourceID, 0, len(ts.TaskResults))
	for i := range ts.TaskResults {
		results = append(results, jsonapi.ResourceID{ID: ts.TaskResults[i].ID, Type: "task-results"})
	}
	return jsonapi.Resource[TaskStageAttributes]{
		ID:   ts.ID,
		Type: "task-stages",
		Attributes: TaskStageAttributes{
			Stage:            ts.Stage,
			Status:           ts.Status,
			StatusTimestamps: phaseTimestamps(ts.RunningAt, ts.PassedAt, ts.FailedAt, ts.ErroredAt, ts.CanceledAt),
			CreatedAt:        ts.CreatedAt.Format(time.RFC3339),
			UpdatedAt:        ts.UpdatedAt.Format(time.RFC3339),
			Permissions: TaskStagePermissions{
				CanOverrideTasks: canOverride,
				CanOverride:      canOverride,
			},
			Actions: TaskStageActions{IsOverridable: ts.Status == models.TaskStageStatusAwaitingOverride},
		},
		Relationships: TaskStageRelationships{
			Run:         jsonapi.ToOne(ts.RunID, "runs"),
			TaskResults: jsonapi.ManyRelationship{Data: results},
			// Emitted empty: Stackweaver has no policy evaluations (documented divergence).
			PolicyEvaluations: jsonapi.ManyRelationship{Data: []jsonapi.ResourceID{}},
		},
	}
}

// formatTaskResult renders a task result as JSON:API (type "task-results"). The task-stage relation
// key is `task_stage` with an UNDERSCORE: that is what go-tfe v1 decodes (v1.go TaskResult struct),
// even though TFE's v2 OpenAPI spec spells it with a hyphen; we emit both to satisfy either reader.
func formatTaskResult(tr *models.TaskResult) jsonapi.Resource[TaskResultAttributes] {
	taskID := ""
	if tr.TaskID != nil {
		taskID = *tr.TaskID
	}
	wstaskID := ""
	if tr.WorkspaceTaskID != nil {
		wstaskID = *tr.WorkspaceTaskID
	}
	stageRel := jsonapi.ToOne(tr.TaskStageID, "task-stages")
	return jsonapi.Resource[TaskResultAttributes]{
		ID:   tr.ID,
		Type: "task-results",
		Attributes: TaskResultAttributes{
			Status:                        tr.Status,
			Message:                       tr.Message,
			URL:                           tr.URL,
			StatusTimestamps:              phaseTimestamps(tr.RunningAt, tr.PassedAt, tr.FailedAt, tr.ErroredAt, tr.CanceledAt),
			TaskID:                        taskID,
			TaskName:                      tr.TaskName,
			TaskURL:                       tr.TaskURL,
			WorkspaceTaskID:               wstaskID,
			WorkspaceTaskEnforcementLevel: tr.EnforcementLevel,
			CreatedAt:                     tr.CreatedAt.Format(time.RFC3339),
			UpdatedAt:                     tr.UpdatedAt.Format(time.RFC3339),
		},
		Relationships: TaskResultRelationships{
			TaskStageUnderscore: stageRel,
			TaskStage:           stageRel,
		},
	}
}

// formatTaskResultOutcome renders an outcome (type "task-result-outcomes").
func formatTaskResultOutcome(o *models.TaskResultOutcome) jsonapi.Resource[TaskResultOutcomeAttributes] {
	return jsonapi.Resource[TaskResultOutcomeAttributes]{
		ID:   o.ID,
		Type: "task-result-outcomes",
		Attributes: TaskResultOutcomeAttributes{
			OutcomeID:   o.OutcomeID,
			Description: o.Description,
			Body:        o.Body,
			URL:         o.URL,
			Tags:        o.Tags,
			CreatedAt:   o.CreatedAt.Format(time.RFC3339),
			UpdatedAt:   o.UpdatedAt.Format(time.RFC3339),
		},
		Relationships: TaskResultOutcomeRelationships{TaskResult: jsonapi.ToOne(o.TaskResultID, "task-results")},
	}
}

// callerCanOverride quietly checks the caller's apply permission on the run (no error responses).
func (h *RunHandlerV2) callerCanOverride(c *gin.Context, run *models.Run) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		return false
	}
	ws, err := h.workspaceRepo.GetByID(run.WorkspaceID)
	if err != nil {
		return false
	}
	allowed, err := h.rbacService.CheckRunPermission(c.Request.Context(), user.ID, run.WorkspaceID, ws.ProjectID, "apply")
	return err == nil && allowed
}

// ListTaskStages handles GET /runs/:id/task-stages (replaces the pre-run-tasks empty stub).
func (h *RunHandlerV2) ListTaskStages(c *gin.Context) {
	run, ok := h.authorizeRun(c, c.Param("id"), "read")
	if !ok {
		return
	}
	stages, err := h.taskStageRepo.ListByRun(run.ID)
	if err != nil {
		taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list task stages")
		return
	}
	canOverride := false
	if len(stages) > 0 {
		canOverride = h.callerCanOverride(c, run)
	}
	page, pageSize, _ := paginate(c)
	data := make([]jsonapi.Resource[TaskStageAttributes], 0, len(stages))
	for i := range stages {
		data = append(data, formatTaskStage(&stages[i], canOverride))
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(page, pageSize, int64(len(stages))))
}

// GetTaskStage handles GET /task-stages/:id (?include=task_results).
func (h *RunHandlerV2) GetTaskStage(c *gin.Context) {
	ts, err := h.taskStageRepo.GetByID(c.Param("id"))
	if err != nil {
		taskError(c, http.StatusNotFound, "Not Found", "Task stage not found")
		return
	}
	run, ok := h.authorizeRun(c, ts.RunID, "read")
	if !ok {
		return
	}
	resp := jsonapi.Document{Data: formatTaskStage(ts, h.callerCanOverride(c, run))}
	if inc := c.Query("include"); inc == "task_results" || inc == "task-results" {
		included := make([]jsonapi.Resource[TaskResultAttributes], 0, len(ts.TaskResults))
		for i := range ts.TaskResults {
			included = append(included, formatTaskResult(&ts.TaskResults[i]))
		}
		resp.Included = included
	}
	c.JSON(http.StatusOK, resp)
}

// OverrideTaskStage handles POST /task-stages/:id/actions/override (plain JSON {"comment"}): a
// human with apply rights passes a failed mandatory stage and the run continues.
func (h *RunHandlerV2) OverrideTaskStage(c *gin.Context) {
	ts, err := h.taskStageRepo.GetByID(c.Param("id"))
	if err != nil {
		taskError(c, http.StatusNotFound, "Not Found", "Task stage not found")
		return
	}
	if _, ok := h.authorizeRun(c, ts.RunID, "apply"); !ok {
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		taskError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	// TFE sends {"comment": "..."} as plain JSON (not JSON:API).
	var body struct {
		Comment string `json:"comment"`
	}
	_ = c.ShouldBindJSON(&body) // body optional

	ok, err := h.taskStageRepo.Override(ts.ID, user.ID, body.Comment)
	if err != nil {
		taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to override task stage")
		return
	}
	if !ok {
		taskError(c, http.StatusConflict, "Conflict", "Task stage is not awaiting an override")
		return
	}
	if err := runtask.NewEngine(h.runRepo, h.taskStageRepo).ContinueRun(ts); err != nil {
		// The stage IS overridden; the orchestrator's finalize backstop will retry the run
		// continuation, so report success with a warning rather than a misleading error.
		logger.Warnf("override of stage %s recorded but run continuation failed (backstop will retry): %v", ts.ID, err)
	}

	reloaded, err := h.taskStageRepo.GetByID(ts.ID)
	if err != nil {
		reloaded = ts
	}
	jsonapi.WriteDocument(c, http.StatusOK, formatTaskStage(reloaded, true))
}

// GetTaskResult handles GET /task-results/:id.
func (h *RunHandlerV2) GetTaskResult(c *gin.Context) {
	tr, err := h.taskResultRepo.GetByID(c.Param("id"))
	if err != nil || tr.TaskStage == nil {
		taskError(c, http.StatusNotFound, "Not Found", "Task result not found")
		return
	}
	if _, ok := h.authorizeRun(c, tr.TaskStage.RunID, "read"); !ok {
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, formatTaskResult(tr))
}

// ListTaskResultOutcomes handles GET /task-results/:id/outcomes.
func (h *RunHandlerV2) ListTaskResultOutcomes(c *gin.Context) {
	tr, err := h.taskResultRepo.GetByID(c.Param("id"))
	if err != nil || tr.TaskStage == nil {
		taskError(c, http.StatusNotFound, "Not Found", "Task result not found")
		return
	}
	if _, ok := h.authorizeRun(c, tr.TaskStage.RunID, "read"); !ok {
		return
	}
	outcomes, err := h.taskResultRepo.ListOutcomes(tr.ID)
	if err != nil {
		taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list outcomes")
		return
	}
	page, pageSize, _ := paginate(c)
	data := make([]jsonapi.Resource[TaskResultOutcomeAttributes], 0, len(outcomes))
	for i := range outcomes {
		data = append(data, formatTaskResultOutcome(&outcomes[i]))
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(page, pageSize, int64(len(outcomes))))
}

// GetTaskResultOutcome handles GET /task-result-outcomes/:id.
func (h *RunHandlerV2) GetTaskResultOutcome(c *gin.Context) {
	o, err := h.taskResultRepo.GetOutcomeByID(c.Param("id"))
	if err != nil {
		taskError(c, http.StatusNotFound, "Not Found", "Outcome not found")
		return
	}
	tr, err := h.taskResultRepo.GetByID(o.TaskResultID)
	if err != nil || tr.TaskStage == nil {
		taskError(c, http.StatusNotFound, "Not Found", "Outcome not found")
		return
	}
	if _, ok := h.authorizeRun(c, tr.TaskStage.RunID, "read"); !ok {
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, formatTaskResultOutcome(o))
}
