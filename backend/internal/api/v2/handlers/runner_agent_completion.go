// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/logbuffer"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	errCompletionAnswered = errors.New("completion refusal already answered")
	errCompletionMissing  = errors.New("completion job absent")
)

// completedClaim captures the phase whose SQL outcome won. External finalization
// uses this value after commit, even if another launcher has already claimed apply.
type completedClaim struct {
	kind         models.JobType
	id           string
	phase        string
	cancelMarker bool
	organization uuid.UUID
	pool         *uuid.UUID
}

func refuseCompletedClaim(c *gin.Context) error {
	jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the original claim has finished")
	return errCompletionAnswered
}

// completeReportedClaim serializes outcome, credential cleanup and release with
// start and token issuance on the authoritative parent row.
func (h *RunnerAgentHandler) completeReportedClaim(c *gin.Context, id string, req JobCompleteRequest) (completedClaim, error) {
	effect := completedClaim{kind: models.JobTypeAnsibleJob, id: id}
	switch {
	case isWorkItem(id):
		effect.kind = models.JobTypeWorkItem
	case strings.HasPrefix(id, "run-"):
		effect.kind = models.JobTypeTofuRun
	default:
		if _, err := uuid.Parse(id); err != nil {
			return effect, errInvalidRunnerJobID
		}
	}
	principal, ok := callingJob(c)
	if !ok || principal.Kind != effect.kind || principal.JobID != id {
		writeRunnerForbidden(c, "this job token is for a different job")
		return effect, errCompletionAnswered
	}
	if req.Attempt != 0 && req.Attempt != principal.Attempt {
		return effect, repository.ErrInvalidClaim
	}
	if effect.kind != models.JobTypeTofuRun && req.Phase != "" {
		return effect, repository.ErrInvalidClaim
	}
	if h.db == nil {
		return effect, errors.New("completion storage unavailable")
	}
	if effect.kind == models.JobTypeWorkItem && h.beforeWorkItemFinish != nil {
		item, loaded := h.loadWorkItem(c, id)
		if !loaded || !h.authorizeRunnerForWorkItem(c, item, true) {
			return effect, errCompletionAnswered
		}
		h.beforeWorkItemFinish(id)
	}
	err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		scoped := *h
		scoped.db = tx
		scoped.jobExecRepo = repository.NewRunnerJobExecutionRepository(tx)
		scoped.ansibleJobRepo = repository.NewAnsibleJobRepository(tx)
		var err error
		switch effect.kind {
		case models.JobTypeAnsibleJob:
			err = scoped.completeAnsibleClaim(c, principal, req, &effect)
		case models.JobTypeTofuRun:
			err = scoped.completeRunClaim(c, principal, req, &effect)
		case models.JobTypeWorkItem:
			err = scoped.completeWorkItemClaim(c, principal, req, &effect)
		default:
			return repository.ErrInvalidClaim
		}
		if err != nil {
			return err
		}
		if req.Status == "completed" && req.CacheManifest != nil && !effect.cancelMarker && effect.kind != models.JobTypeWorkItem {
			if err := scoped.recordCachePromotions(c, effect.kind, id, effect.organization, effect.pool, req.CacheManifest); err != nil {
				return err
			}
		}
		keys := apikey.NewService(repository.NewAPIKeyRepository(tx), nil, nil, nil)
		if err := keys.RevokeJobTokens(effect.kind, id); err != nil {
			return err
		}
		return updateRunnerAfterClaim(tx, principal.RunnerID)
	})
	return effect, err
}

func (h *RunnerAgentHandler) completeAnsibleClaim(c *gin.Context, principal apikey.JobPrincipal, req JobCompleteRequest, effect *completedClaim) error {
	var job models.AnsibleJob
	if err := h.db.Clauses(clause.Locking{Strength: "UPDATE"}).First(&job, "id = ?", effect.id).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		// A deleted job keeps its established missing result only after the
		// surviving execution has been checked against this authenticated owner.
		execution, lookup := h.jobExecRepo.GetByJobID(uuid.MustParse(effect.id))
		if lookup != nil && !errors.Is(lookup, gorm.ErrRecordNotFound) {
			return lookup
		}
		if lookup == nil && execution.RunnerID != principal.RunnerID {
			writeRunnerForbidden(c, "the execution belongs to a different launcher")
			return errCompletionAnswered
		}
		return errCompletionMissing
	}
	if !authorizeJobPrincipal(c, principal, effect.kind, effect.id, job.RunnerID, job.Attempt, false) || !h.authorizeRunnerForAnsibleJobReport(c, &job) {
		return errCompletionAnswered
	}
	if job.Status != models.AnsibleJobStatusRunning && job.Status != models.AnsibleJobStatusCanceled {
		return refuseCompletedClaim(c)
	}
	execution, err := h.jobExecRepo.GetByJobID(job.ID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return errCompletionMissing
	}
	if err != nil {
		return err
	}
	if execution.RunnerID != principal.RunnerID {
		writeRunnerForbidden(c, "the execution belongs to a different launcher")
		return errCompletionAnswered
	}
	if execution.FinishedAt != nil || execution.Status == models.JobExecutionStatusCompleted || execution.Status == models.JobExecutionStatusFailed || execution.Status == models.JobExecutionStatusCanceled {
		return refuseCompletedClaim(c)
	}
	if execution.Status != models.JobExecutionStatusRunning {
		return errors.New("active execution state unavailable")
	}
	events, _, err := h.ansibleJobRepo.ListEventsByJob(job.ID, 10000, 0)
	if err != nil {
		return err
	}
	effect.organization, effect.pool, err = h.ansibleJobOrgAndPool(&job)
	if err != nil {
		return err
	}
	status := models.JobExecutionStatusCompleted
	if req.Status == "failed" {
		status = models.JobExecutionStatusFailed
	}
	if req.Status == "canceled" {
		status = models.JobExecutionStatusCanceled
	}
	if err := h.jobExecRepo.UpdateStatus(execution.ID, status, req.ErrorMessage); err != nil {
		return err
	}
	now := time.Now()
	effect.cancelMarker = job.Status == models.AnsibleJobStatusCanceled
	if effect.cancelMarker {
		if err := h.ansibleJobRepo.CreateEventNextCounter(&models.AnsibleJobEvent{JobID: job.ID, Event: "runner_output", Stdout: jobCancelMarker}); err != nil {
			return err
		}
		if job.FinishedAt == nil {
			job.FinishedAt = &now
		}
	} else {
		job.FinishedAt = &now
		switch req.Status {
		case "completed":
			job.Status = models.AnsibleJobStatusSuccessful
		case "failed":
			job.Status = models.AnsibleJobStatusFailed
			if req.ErrorMessage != "" {
				job.ErrorMessage = req.ErrorMessage
			}
			if job.HostsFailed == 0 && job.HostsUnreachable == 0 {
				job.HostsFailed = 1
			}
		case "canceled":
			job.Status = models.AnsibleJobStatusCanceled
		}
		warnings := 0
		for _, event := range events {
			warnings += strings.Count(event.Stderr, "[WARNING]:") + strings.Count(event.Stderr, "[DEPRECATION WARNING]:")
		}
		if warnings > 0 {
			job.HasWarnings, job.WarningsCount = true, warnings
		}
	}
	return h.ansibleJobRepo.UpdateColumns(&job, "finished_at", "status", "error_message", "hosts_failed", "has_warnings", "warnings_count")
}

func (h *RunnerAgentHandler) completeRunClaim(c *gin.Context, principal apikey.JobPrincipal, req JobCompleteRequest, effect *completedClaim) error {
	var run models.Run
	if err := h.db.Clauses(clause.Locking{Strength: "UPDATE"}).First(&run, "id = ?", effect.id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errCompletionMissing
		}
		return err
	}
	if !authorizeJobPrincipal(c, principal, effect.kind, effect.id, run.RunnerID, run.Attempt, false) || !h.authorizeRunnerForRunReport(c, &run) {
		return errCompletionAnswered
	}
	phase := run.ClaimedPhase
	if phase != "plan" && phase != "apply" {
		return errors.New("original completion phase unavailable")
	}
	if req.Phase != "" && req.Phase != phase {
		return repository.ErrInvalidClaim
	}
	canceled := run.Status == models.RunStatusCancelled
	active := (phase == "plan" && run.Status == models.RunStatusPlanning) || (phase == "apply" && run.Status == models.RunStatusApplying)
	if run.DispatchedAt == nil || (!active && !canceled) {
		return refuseCompletedClaim(c)
	}
	effect.phase, effect.cancelMarker = phase, canceled
	var err error
	effect.organization, effect.pool, err = h.runOrgAndPool(&run)
	if err != nil {
		return err
	}
	if req.PlanJSON != "" || req.HasChanges {
		if run.PlanOutput == nil {
			run.PlanOutput = make(models.PlanOutput)
		}
		run.PlanOutput["AddCount"] = float64(req.ResourceAdditions)
		run.PlanOutput["ChangeCount"] = float64(req.ResourceChanges)
		run.PlanOutput["DestroyCount"] = float64(req.ResourceDestructions)
		run.PlanOutput["OutputChangeCount"] = float64(req.OutputChanges)
		if req.PlanJSON != "" {
			var plan map[string]any
			if json.Unmarshal([]byte(req.PlanJSON), &plan) == nil {
				for name, value := range plan {
					run.PlanOutput[name] = value
				}
			}
		}
	}
	now := time.Now()
	if !canceled {
		switch req.Status {
		case "completed":
			if err := h.completeRunPhase(&run, phase, now); err != nil {
				return err
			}
		case "failed":
			run.Status, run.CompletedAt = models.RunStatusErrored, &now
			run.ErrorMessage = req.ErrorMessage
			if run.ErrorMessage == "" {
				run.ErrorMessage = req.Output
			}
		case "canceled":
			run.Status = models.RunStatusCancelled
			if run.CompletedAt == nil {
				run.CompletedAt = &now
			}
		}
	}
	// Consume this phase, including a canceled final report. The original identity
	// remains available to classify a request authenticated before token expiry.
	run.DispatchedAt = nil
	if phase == "plan" && run.Status == models.RunStatusApplying {
		run.RunnerID = nil
	}
	if err := h.db.Model(&run).Omit(clause.Associations).
		Select("status", "completed_at", "plan_completed_at", "auto_apply_resolved", "plan_output", "error_message", "dispatched_at", "runner_id").Updates(&run).Error; err != nil {
		return err
	}
	return repository.NewRunRepository(h.db).ReleaseStateLock(run.WorkspaceID, run.ID)
}

func (h *RunnerAgentHandler) completeRunPhase(run *models.Run, phase string, now time.Time) error {
	stages := repository.NewTaskStageRepository(h.db)
	if phase == "apply" {
		hasStage, err := stages.HasStage(run.ID, models.TaskStagePostApply)
		if err != nil {
			return err
		}
		run.Status, run.CompletedAt = models.RunStatusApplied, &now
		if hasStage {
			run.Status, run.CompletedAt = models.RunStatusPostApplyRunning, nil
		}
		return nil
	}
	autoApply := false
	if (run.AutoApplyAfterPlan || run.AutoApply) && (run.Operation == models.RunOperationPlanAndApply || run.Operation == models.RunOperationDestroy) {
		autoApply = run.AutoApply
		if run.ConfigurationVersionID != nil {
			configuration, err := h.runConfigurationVersion(run)
			if err != nil {
				return err
			}
			if configuration.Source == "tfe-vcs" {
				var workspace models.Workspace
				if err := h.db.First(&workspace, "id = ?", run.WorkspaceID).Error; err != nil {
					return err
				}
				autoApply = autoApply || workspace.AutoApply
			}
		}
	}
	hasStage, err := stages.HasStage(run.ID, models.TaskStagePostPlan)
	if err != nil {
		return err
	}
	run.PlanCompletedAt = &now
	run.Status = planFinishedStatus(run.Operation, run.PlanOutput.IndicatesChanges(), hasStage, autoApply)
	if run.Status == models.RunStatusPostPlanRunning {
		run.AutoApplyResolved = autoApply
	}
	if run.Status == models.RunStatusPlannedAndFinished {
		run.CompletedAt = &now
	}
	return nil
}

func (h *RunnerAgentHandler) completeWorkItemClaim(c *gin.Context, principal apikey.JobPrincipal, req JobCompleteRequest, effect *completedClaim) error {
	var item models.WorkItem
	if err := h.db.Clauses(clause.Locking{Strength: "UPDATE"}).First(&item, "id = ?", effect.id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errCompletionMissing
		}
		return err
	}
	if !authorizeJobPrincipal(c, principal, effect.kind, effect.id, item.RunnerID, item.Attempt, false) || !h.authorizeRunnerForWorkItem(c, &item, true) {
		return errCompletionAnswered
	}
	if item.Status != models.WorkItemStatusRunning {
		return refuseCompletedClaim(c)
	}
	status := models.WorkItemStatusFailed
	switch req.Status {
	case "completed", "successful":
		status = models.WorkItemStatusCompleted
	case "canceled":
		status = models.WorkItemStatusCanceled
	}
	finished, err := ansible.NewWorkItemRuntime(h.db, nil, nil).FinishedContext(c.Request.Context(), &item, status, req.ErrorMessage, req.WorkResult)
	if err != nil {
		return err
	}
	if !finished {
		return refuseCompletedClaim(c)
	}
	return nil
}

func (h *RunnerAgentHandler) finalizeCompletedClaim(ctx context.Context, effect completedClaim) {
	if effect.kind != models.JobTypeTofuRun {
		return
	}
	if effect.cancelMarker {
		line := "\n" + cancelMarker + "\n"
		var err error
		if h.logBuffer != nil {
			_, err = h.logBuffer.AppendCapped(ctx, effect.id, effect.phase, line, h.jobLogLimits())
		} else if h.storageClient != nil {
			_, err = logbuffer.AppendStorageLogCapped(ctx, h.storageClient, effect.id, effect.phase, line, h.jobLogLimits())
		}
		if err != nil {
			logger.Warnf("appending the completed claim's cancel marker for %s/%s: %v", effect.id, effect.phase, err)
		}
	}
	if h.logBuffer != nil {
		if err := h.logBuffer.Finalize(ctx, effect.id, effect.phase); err != nil {
			logger.Warnf("finalizing the completed claim's log for %s/%s: %v", effect.id, effect.phase, err)
		}
		if h.storageClient != nil {
			if err := h.logBuffer.CopyToStorage(ctx, effect.id, effect.phase, h.storageClient); err != nil {
				logger.Warnf("persisting the completed claim's log for %s/%s: %v", effect.id, effect.phase, err)
			}
		}
		return
	}
	if h.storageClient != nil {
		if err := logbuffer.FinalizeStorageLog(ctx, h.storageClient, effect.id, effect.phase); err != nil {
			logger.Warnf("finalizing the completed claim's stored log for %s/%s: %v", effect.id, effect.phase, err)
		}
	}
}
