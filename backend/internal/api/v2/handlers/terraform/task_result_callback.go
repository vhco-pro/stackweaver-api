// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/services/runtask"
)

// TaskResultCallback handles PATCH /task-results/:id/callback — the endpoint an external run-task
// service PATCHes with its verdict, authenticated by the webhook's `access_token` (a stateless
// run-scoped bearer; see task_result_token.go). Registered on the ROOT router (like the ansible
// provisioning callback) with a body cap, since it is outside the normal auth middleware.
//
// Contract (TFE run-tasks integration API): JSON:API type `task-results` (TFE also accepts the
// escaped spelling `task_results`; so do we), attrs `status` restricted to passed|failed|running,
// optional `message` and `url`, and an optional `outcomes` relationship carrying
// `task-result-outcomes` documents inline in `included`. `running` is a progress heartbeat: it
// refreshes the 10-minute no-progress deadline without finalizing anything.

// maxOutcomeBodyBytes caps one outcome's markdown body. Documented divergence: TFE allows 5MB per
// outcome; 1MB is plenty for findings and keeps a hostile callback from bloating the DB.
const maxOutcomeBodyBytes = 1 << 20

type taskCallbackDocument struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			URL     string `json:"url"`
		} `json:"attributes"`
	} `json:"data"`
	Included []struct {
		Type       string `json:"type"`
		Attributes struct {
			OutcomeID   string          `json:"outcome-id"`
			Description string          `json:"description"`
			Body        string          `json:"body"`
			URL         string          `json:"url"`
			Tags        json.RawMessage `json:"tags"`
		} `json:"attributes"`
	} `json:"included"`
}

func (h *RunHandlerV2) TaskResultCallback(c *gin.Context) {
	// Authenticate: the Bearer must be a valid task token minted for THIS task result.
	tok := taskTokenFromAuthHeader(c.GetHeader("Authorization"))
	if tok == "" {
		taskError(c, http.StatusUnauthorized, "Unauthorized", "A run task access token is required")
		return
	}
	tokenResultID, _, ok := verifyTaskResultToken(tok)
	if !ok || tokenResultID != c.Param("id") {
		taskError(c, http.StatusUnauthorized, "Unauthorized", "Invalid, expired, or mismatched run task access token")
		return
	}

	tr, err := h.taskResultRepo.GetByID(tokenResultID)
	if err != nil || tr.TaskStage == nil {
		taskError(c, http.StatusNotFound, "Not Found", "Task result not found")
		return
	}

	var doc taskCallbackDocument
	if err := c.ShouldBindJSON(&doc); err != nil {
		taskError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	// TFE accepts both spellings of the type (its own SDKs disagree).
	if t := doc.Data.Type; t != "task-results" && t != "task_results" && t != "" {
		taskError(c, http.StatusUnprocessableEntity, "Invalid Type", "type must be task-results")
		return
	}
	status := doc.Data.Attributes.Status
	if status != models.TaskResultStatusPassed && status != models.TaskResultStatusFailed && status != models.TaskResultStatusRunning {
		taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "status must be one of passed, failed, running")
		return
	}

	// Every callback (including heartbeats) refreshes the stage's no-progress deadline.
	if err := h.taskStageRepo.BumpProgress(tr.TaskStageID); err != nil {
		logger.Warnf("failed to bump progress for stage %s: %v", tr.TaskStageID, err)
	}

	// Outcomes replace wholesale on every callback that carries them (last write wins, as TFE).
	if len(doc.Included) > 0 {
		outcomes := make([]*models.TaskResultOutcome, 0, len(doc.Included))
		for _, inc := range doc.Included {
			if inc.Type != "task-result-outcomes" && inc.Type != "task_result_outcomes" {
				continue
			}
			if len(inc.Attributes.Body) > maxOutcomeBodyBytes {
				taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "an outcome body exceeds the 1MB limit")
				return
			}
			tags := models.JSONB{}
			if len(inc.Attributes.Tags) > 0 {
				if err := json.Unmarshal(inc.Attributes.Tags, &tags); err != nil {
					taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "outcome tags must be an object of label arrays")
					return
				}
			}
			outcomes = append(outcomes, &models.TaskResultOutcome{
				OutcomeID:   inc.Attributes.OutcomeID,
				Description: inc.Attributes.Description,
				Body:        inc.Attributes.Body,
				URL:         inc.Attributes.URL,
				Tags:        tags,
			})
		}
		if err := h.taskResultRepo.ReplaceOutcomes(tr.ID, outcomes); err != nil {
			taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to store outcomes")
			return
		}
	}

	// Write the verdict. Guarded from non-terminal statuses only: a late callback after the sweep
	// already errored/canceled the result must not resurrect it (the service gets a 409).
	from := []string{models.TaskResultStatusPending, models.TaskResultStatusRunning}
	wrote, err := h.taskResultRepo.SetStatus(tr.ID, from, status, doc.Data.Attributes.Message, doc.Data.Attributes.URL)
	if err != nil {
		taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update task result")
		return
	}
	if !wrote {
		taskError(c, http.StatusConflict, "Conflict", "Task result is already in a terminal state")
		return
	}

	// A terminal verdict may finish the stage: reload it with fresh results and let the shared
	// engine fold the outcome and continue (or block) the run. Errors here are logged, not
	// returned — the orchestrator's finalize backstop retries within a tick.
	if status != models.TaskResultStatusRunning {
		stage, serr := h.taskStageRepo.GetByID(tr.TaskStageID)
		if serr == nil {
			if ferr := runtask.NewEngine(h.runRepo, h.taskStageRepo).FinalizeStage(stage); ferr != nil {
				logger.Warnf("stage finalize after callback for %s failed (backstop will retry): %v", tr.ID, ferr)
			}
		}
	}

	reloaded, err := h.taskResultRepo.GetByID(tr.ID)
	if err != nil {
		reloaded = tr
	}
	c.JSON(http.StatusOK, gin.H{"data": formatTaskResult(reloaded)})
}
