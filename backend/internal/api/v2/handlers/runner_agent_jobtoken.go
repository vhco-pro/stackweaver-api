// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/settings"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
		writeRunnerForbidden(c, "launcher identity required")
		return
	}
	if h.apiKeyService == nil || h.db == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	var expected runnercontract.JobTokenRequest
	if c.Request.Body != nil {
		if err := c.ShouldBindJSON(&expected); err != nil && !errors.Is(err, io.EOF) {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "invalid expected claim identity")
			return
		}
	}
	var payload *runnercontract.JobToken
	var cacheHint func(*RunnerAgentHandler) *runnercontract.CacheDescriptor
	err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		scoped := *h
		scoped.db = tx
		scoped.apiKeyService = apikey.NewService(repository.NewAPIKeyRepository(tx), nil, nil, nil)
		var accepted bool
		payload, accepted = scoped.jobTokenForClaim(c, runner.ID, expected, &cacheHint)
		if !accepted {
			return errors.New("job token request refused")
		}
		return nil
	})
	if err != nil {
		if !c.Writer.Written() {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}
	// Cache hints are optional. Resolve them after the claim lock has been released.
	if cacheHint != nil {
		scoped := *h
		scoped.db = h.db.WithContext(c.Request.Context())
		payload.Cache = cacheHint(&scoped)
	}
	c.JSON(http.StatusOK, payload)
}

func (h *RunnerAgentHandler) jobTokenForClaim(c *gin.Context, runnerID uuid.UUID, expected runnercontract.JobTokenRequest, cacheHint *func(*RunnerAgentHandler) *runnercontract.CacheDescriptor) (*runnercontract.JobToken, bool) {
	jobID := c.Param("id")
	var (
		orgID            uuid.UUID
		kind             models.JobType
		attempt, timeout int
		phase, runType   string
		recovery, active bool
		pool             *uuid.UUID
		target           any
		placement        models.JobPlacement
		authorize        func() bool
	)
	metadata := map[string]any{}
	deployment := settings.DeploymentRunTimeout(os.Getenv)
	locked := h.db.Clauses(clause.Locking{Strength: "UPDATE"})
	switch {
	case isWorkItem(jobID):
		if h.workItems == nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Work item not found")
			return nil, false
		}
		item, err := repository.NewWorkItemRepository(locked).GetByID(jobID)
		if err != nil {
			writeRunnerJobReadError(c, err)
			return nil, false
		}
		orgID, kind, attempt, timeout, pool = item.OrganizationID, models.JobTypeWorkItem, item.Attempt, item.TimeoutSeconds, item.AgentPoolID
		recovery, active = item.ClaimRecovery, item.Status == models.WorkItemStatusRunning
		target, placement = &models.WorkItem{ID: item.ID}, item.Placement
		authorize = func() bool { return h.authorizeRunnerForWorkItem(c, item, true) }
		if timeout <= 0 {
			timeout = settings.SyncTimeout(os.Getenv)
		}
	case strings.HasPrefix(jobID, "run-"):
		var run models.Run
		if err := locked.Preload("Workspace.Project.Organization").First(&run, "id = ?", jobID).Error; err != nil {
			writeRunnerJobReadError(c, err)
			return nil, false
		}
		orgID, kind, attempt, pool = run.Workspace.Project.OrganizationID, models.JobTypeTofuRun, run.Attempt, run.AgentPoolID
		if pool == nil {
			pool = run.Workspace.AgentPoolID
		}
		timeout = settings.EffectiveWorkspaceRunTimeout(&run.Workspace, deployment).Value
		phase, runType, recovery = run.ClaimedPhase, run.ClaimedRunType, run.ClaimRecovery
		active = run.Status == models.RunStatusPlanning || run.Status == models.RunStatusApplying
		if phase != "" {
			active = (phase == "plan" && run.Status == models.RunStatusPlanning) || (phase == "apply" && run.Status == models.RunStatusApplying)
			resolvedType := runnercontract.ExecutableRunType(run.Operation, phase)
			if resolvedType == "" || (runType != "" && runType != resolvedType) {
				active = false
			} else if runType == "" {
				runType = resolvedType
				metadata["claimed_run_type"] = runType
			}
		}
		if recovery && (run.DispatchedAt == nil || phase == "") {
			active = false
		}
		if run.Status == models.RunStatusApplying && run.DispatchedAt == nil {
			active = false
		}
		if run.Attempt == 0 && run.PhaseAttempt == 0 && phase != "" && active {
			metadata["phase_attempt"] = 1
		}
		target, placement = &models.Run{ID: run.ID}, run.Placement
		authorize = func() bool { return h.authorizeRunnerForRun(c, &run, true) }
		*cacheHint = func(committed *RunnerAgentHandler) *runnercontract.CacheDescriptor {
			return committed.runCacheDescriptorFor(c.Request.Context(), &run)
		}
	default:
		id, err := uuid.Parse(jobID)
		if err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid job ID")
			return nil, false
		}
		if h.ansibleJobRepo == nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return nil, false
		}
		job, err := repository.NewAnsibleJobRepository(locked).GetByID(id)
		if err != nil {
			writeRunnerJobReadError(c, err)
			return nil, false
		}
		orgID, kind, attempt, timeout, pool = job.Project.OrganizationID, models.JobTypeAnsibleJob, job.Attempt, job.TimeoutSeconds, job.AgentPoolID
		recovery, active = job.ClaimRecovery, job.Status == models.AnsibleJobStatusRunning
		target, placement = &models.AnsibleJob{ID: job.ID}, job.Placement
		authorize = func() bool { return h.authorizeRunnerForAnsibleJob(c, job, true) }
		*cacheHint = func(committed *RunnerAgentHandler) *runnercontract.CacheDescriptor {
			// Token issuance can normalize a legacy attempt from zero to one.
			claim := *job
			claim.Attempt = attempt
			return committed.ansibleCacheDescriptor(c.Request.Context(), job.Project.OrganizationID, &claim)
		}
		if timeout <= 0 {
			timeout = deployment
		}
	}
	var runner models.Runner
	if err := h.db.First(&runner, "id = ?", runnerID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeRunnerForbidden(c, "launcher identity is unavailable")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return nil, false
	}
	c.Set(middleware.CallingRunnerKey, &runner)
	if !authorize() {
		return nil, false
	}
	if !active {
		jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the job has no active claim")
		return nil, false
	}
	if attempt < 0 || (recovery && attempt == 0) {
		writeRunnerClaimError(c, repository.ErrClaimConflict)
		return nil, false
	}
	if attempt == 0 {
		attempt = 1
		metadata["attempt"] = attempt
	}
	actual := runnercontract.JobStartResponse{Attempt: attempt, Phase: phase, RunType: runType}
	if err := validateJobTokenClaim(expected, actual, kind, recovery); err != nil {
		writeRunnerClaimError(c, err)
		return nil, false
	}
	if len(metadata) > 0 {
		if err := h.db.Model(target).Updates(metadata).Error; err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return nil, false
		}
	}
	identity, err := h.attemptIdentity(&runner, kind, jobID, pool, attempt, placement, target)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrBindingNotOffered):
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
		case errors.Is(err, errIdentityNotApplicable):
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", strings.TrimPrefix(err.Error(), errIdentityNotApplicable.Error()+": "))
		default:
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return nil, false
	}
	image, err := h.jobImage(kind, jobID, pool)
	if err != nil {
		if errors.Is(err, errImageNotAllowed) {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return nil, false
	}
	placementSettings, err := h.poolSettings(pool)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	expiresAt := time.Now().Add(time.Duration(timeout)*time.Second + apikey.JobTokenGrace)
	principal := apikey.JobPrincipal{Kind: kind, JobID: jobID, RunnerID: runner.ID, Attempt: attempt}
	_, raw, err := h.apiKeyService.CreateJobToken(orgID, runner.AgentPoolID, principal, expiresAt)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return &runnercontract.JobToken{
		Token: raw, JobID: jobID, Attempt: attempt, Phase: phase, RunType: runType,
		ExpiresAt: expiresAt.UTC(), ContractVersion: runnercontract.Version,
		TimeoutSeconds: timeout, Pool: placementSettings, Identity: identity, Image: image,
	}, true
}

func validateJobTokenClaim(expected runnercontract.JobTokenRequest, actual runnercontract.JobStartResponse, kind models.JobType, recovery bool) error {
	identity := expected.Attempt != 0 || expected.Phase != "" || expected.RunType != ""
	if !identity {
		if recovery {
			return repository.ErrInvalidClaim
		}
		return nil
	}
	if expected.Attempt <= 0 {
		return repository.ErrInvalidClaim
	}
	if kind == models.JobTypeTofuRun {
		if (expected.Phase != "plan" && expected.Phase != "apply") || expected.RunType == "" {
			return repository.ErrInvalidClaim
		}
	} else if expected.Phase != "" || expected.RunType != "" {
		return repository.ErrInvalidClaim
	}
	if expected.Attempt != actual.Attempt || expected.Phase != actual.Phase || expected.RunType != actual.RunType {
		return repository.ErrClaimConflict
	}
	return nil
}

// poolSettings reads what a job's pool says about placing it, or nil when the job names no pool.
func (h *RunnerAgentHandler) poolSettings(poolID *uuid.UUID) (*runnercontract.PoolSettings, error) {
	if poolID == nil {
		return nil, nil //nolint:nilnil // a job without a pool has no placement settings
	}
	var pool models.AgentPool
	if err := h.db.Select("id", "keep_failed_jobs_for", "cpu_limit", "memory_limit", "limits_required", "local_readthrough_disabled").First(&pool, "id = ?", *poolID).Error; err != nil {
		return nil, err
	}
	return &runnercontract.PoolSettings{
		KeepFailedForSeconds: pool.KeepFailedJobsFor, CPULimit: pool.CPULimit, MemoryLimit: pool.MemoryLimit, LimitsRequired: pool.LimitsRequired,
		NoLocalReadthrough: pool.LocalReadthroughDisabled,
	}, nil
}
