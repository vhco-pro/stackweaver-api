// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/settings"
	"gorm.io/gorm"
)

// JobToken mints the job token for a job the calling runner has claimed (#933, D1). The launcher
// calls it after JobStart and hands the token to the executor it places; the executor fetches the
// job's artifacts and reports the job with it, and the runner token is never in its environment.
//
// The token is valid for this job and the attempt the claim started, until the job's resolved
// timeout plus a grace, and is revoked when the job completes, turns terminal or is re-dispatched.
//
// POST /api/v2/runner/jobs/:id/token
func (h *RunnerAgentHandler) JobToken(c *gin.Context) {
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "runner identity required")
		return
	}
	if h.apiKeyService == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	jobID := c.Param("id")
	var (
		orgID   uuid.UUID
		kind    models.JobType
		attempt int
		timeout int
		pool    *uuid.UUID
		cache   func() *runnercontract.CacheDescriptor
	)
	deployment := settings.DeploymentRunTimeout(os.Getenv)
	switch {
	case isWorkItem(jobID):
		item, ok := h.workItemTokenFields(c, jobID)
		if !ok {
			return
		}
		orgID, kind, attempt, timeout, pool = item.OrganizationID, models.JobTypeWorkItem, item.Attempt, item.TimeoutSeconds, item.AgentPoolID
		if timeout <= 0 {
			timeout = settings.SyncTimeout(os.Getenv)
		}
	case strings.HasPrefix(jobID, "run-"):
		var run models.Run
		if err := h.db.Preload("Workspace.Project.Organization").First(&run, "id = ?", jobID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Run not found")
			} else {
				jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			}
			return
		}
		if !h.authorizeRunnerForRun(c, &run, true) {
			return
		}
		if runFinished(&run) {
			jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the run has finished")
			return
		}
		orgID, kind, attempt, pool = run.Workspace.Project.OrganizationID, models.JobTypeTofuRun, run.Attempt, run.AgentPoolID
		timeout = settings.EffectiveWorkspaceRunTimeout(&run.Workspace, deployment).Value
		cache = func() *runnercontract.CacheDescriptor { return h.runCacheDescriptorFor(c.Request.Context(), &run) }
	default:
		id, err := uuid.Parse(jobID)
		if err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid job ID")
			return
		}
		job, err := h.ansibleJobRepo.GetByID(id)
		if err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Job not found")
			return
		}
		if !h.authorizeRunnerForAnsibleJob(c, job, true) {
			return
		}
		if ansibleJobFinished(job) {
			jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the job has finished")
			return
		}
		orgID, kind, attempt, pool = job.Project.OrganizationID, models.JobTypeAnsibleJob, job.Attempt, job.AgentPoolID
		timeout = job.TimeoutSeconds
		cache = func() *runnercontract.CacheDescriptor {
			return h.ansibleCacheDescriptor(c.Request.Context(), job.Project.OrganizationID, job)
		}
		if timeout <= 0 {
			timeout = deployment
		}
	}
	if attempt < 1 {
		// A claim always increments the attempt; a row still at zero was claimed before the
		// counter existed and counts as its first attempt.
		attempt = 1
	}

	identity, err := h.jobIdentity(kind, jobID, pool)
	if err != nil {
		if errors.Is(err, repository.ErrBindingNotOffered) {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
			return
		}
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	image, err := h.jobImage(kind, jobID, pool)
	if err != nil {
		if errors.Is(err, errImageNotAllowed) {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
			return
		}
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	expiresAt := time.Now().Add(time.Duration(timeout)*time.Second + apikey.JobTokenGrace)
	principal := apikey.JobPrincipal{Kind: kind, JobID: jobID, RunnerID: runner.ID, Attempt: attempt}
	_, raw, err := h.apiKeyService.CreateJobToken(orgID, principal, expiresAt)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	var descriptor *runnercontract.CacheDescriptor
	if cache != nil {
		descriptor = cache()
	}
	c.JSON(http.StatusOK, runnercontract.JobToken{
		Token:           raw,
		JobID:           jobID,
		Attempt:         attempt,
		ExpiresAt:       expiresAt.UTC(),
		ContractVersion: runnercontract.Version,
		TimeoutSeconds:  timeout,
		Pool:            h.poolSettings(pool),
		Identity:        identity,
		Cache:           descriptor,
		Image:           image,
	})
}

// poolSettings reads what a job's pool says about placing it, or nil when the job names no pool.
func (h *RunnerAgentHandler) poolSettings(poolID *uuid.UUID) *runnercontract.PoolSettings {
	if poolID == nil {
		return nil
	}
	var pool models.AgentPool
	if err := h.db.Select("id", "keep_failed_jobs_for", "cpu_limit", "memory_limit", "limits_required", "local_readthrough_disabled").First(&pool, "id = ?", *poolID).Error; err != nil {
		return nil
	}
	return &runnercontract.PoolSettings{
		KeepFailedForSeconds: pool.KeepFailedJobsFor, CPULimit: pool.CPULimit, MemoryLimit: pool.MemoryLimit, LimitsRequired: pool.LimitsRequired,
		NoLocalReadthrough: pool.LocalReadthroughDisabled,
	}
}
