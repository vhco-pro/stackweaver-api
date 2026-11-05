// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

// AUD-001 authorization helpers for the runner control plane.
//
// Every /runner/* job handler (except register) runs behind middleware.RunnerAuth,
// which authenticates the caller as exactly one runner and stores it under
// middleware.CallingRunnerKey. These helpers bind a job/run to that runner:
//   - org-equality  - the runner's org must own the job (kills cross-tenant access);
//   - pool-equality - the job's agent pool must be the runner's pool;
//   - assignment    - if the job is already claimed, only the assignee may touch it.
// The body-supplied runner_id is never trusted; the authenticated runner is.

// callingRunner returns the runner resolved by middleware.RunnerAuth.
func callingRunner(c *gin.Context) (*models.Runner, bool) {
	v, ok := c.Get(middleware.CallingRunnerKey)
	if !ok {
		return nil, false
	}
	r, ok := v.(*models.Runner)
	return r, ok && r != nil
}

// writeRunnerForbidden writes the standard 403 for a runner acting outside its
// org/pool/assignment.
func writeRunnerForbidden(c *gin.Context, detail string) {
	jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", detail)
}

// runOrgAndPool resolves a terraform run's owning organization and agent pool.
// Org path is Run → Workspace → Project → Organization (Workspace has no direct
// OrganizationID). The pool is the run's own pool, falling back to the workspace's.
func (h *RunnerAgentHandler) runOrgAndPool(run *models.Run) (orgID uuid.UUID, poolID *uuid.UUID, err error) {
	var ws models.Workspace
	if err = h.db.First(&ws, "id = ?", run.WorkspaceID).Error; err != nil {
		return uuid.Nil, nil, err
	}
	var proj models.Project
	if err = h.db.First(&proj, "id = ?", ws.ProjectID).Error; err != nil {
		return uuid.Nil, nil, err
	}
	pool := run.AgentPoolID
	if pool == nil {
		pool = ws.AgentPoolID
	}
	return proj.OrganizationID, pool, nil
}

// ansibleJobOrgAndPool resolves an ansible job's owning organization (Job →
// Project → Organization) and its agent pool.
func (h *RunnerAgentHandler) ansibleJobOrgAndPool(job *models.AnsibleJob) (orgID uuid.UUID, poolID *uuid.UUID, err error) {
	var proj models.Project
	if err = h.db.First(&proj, "id = ?", job.ProjectID).Error; err != nil {
		return uuid.Nil, nil, err
	}
	return proj.OrganizationID, job.AgentPoolID, nil
}

// authorizeRunnerForRun enforces AUD-001 for terraform-run control-plane ops.
// requireAssigned demands the run already be claimed by the calling runner (for
// post-start ops: output/complete/state). At the offer/claim boundary (artifacts,
// start) pass false - the run may still be unassigned, and org+pool equality plus
// the atomic claim carry the guarantee. Returns true iff the caller is authorized;
// otherwise it has already written the error response.
func (h *RunnerAgentHandler) authorizeRunnerForRun(c *gin.Context, run *models.Run, requireAssigned bool) bool {
	return h.authorizeRunnerForRunAs(c, run, requireAssigned, runFinished(run))
}

// authorizeRunnerForRunReport authorizes the final report of a run's job: its output, the state it
// saved and its completion. It is authorizeRunnerForRun(c, run, true), except that a canceled run
// still takes the report of the attempt that was running: cancelling interrupts OpenTofu, which
// saves the state of what it already changed, and that state must reach the workspace, as TFE keeps
// the state of an interrupted apply. The job token still has to be the run's, for its runner and
// its current attempt, and the completion revokes it, so the report is accepted once.
func (h *RunnerAgentHandler) authorizeRunnerForRunReport(c *gin.Context, run *models.Run) bool {
	return h.authorizeRunnerForRunAs(c, run, true, runFinished(run) && run.Status != models.RunStatusCancelled)
}

func (h *RunnerAgentHandler) authorizeRunnerForRunAs(c *gin.Context, run *models.Run, requireAssigned, finished bool) bool {
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "runner identity required")
		return false
	}
	orgID, poolID, err := h.runOrgAndPool(run)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to resolve run organization")
		return false
	}
	// Every run that reaches a runner carries a pool (the hosted one by default, #933 D9), so a
	// run without one is no runner's business, as a pool-less Ansible job is not.
	if !h.authorizePool(c, runner, orgID, poolID, run.RunnerID, "run") {
		return false
	}
	if run.RunnerID != nil && *run.RunnerID != runner.ID {
		writeRunnerForbidden(c, "run is assigned to a different runner")
		return false
	}
	if requireAssigned && (run.RunnerID == nil || *run.RunnerID != runner.ID) {
		writeRunnerForbidden(c, "run is not assigned to this runner")
		return false
	}
	if p, ok := callingJob(c); ok {
		return authorizeJobPrincipal(c, p, models.JobTypeTofuRun, run.ID, run.RunnerID, run.Attempt, finished)
	}
	return true
}

// authorizeRunnerForAnsibleJob is the ansible-job counterpart of
// authorizeRunnerForRun. requireAssigned checks the job's reservation
// (job.RunnerID) rather than a RunnerJobExecution row.
func (h *RunnerAgentHandler) authorizeRunnerForAnsibleJob(c *gin.Context, job *models.AnsibleJob, requireAssigned bool) bool {
	return h.authorizeRunnerForAnsibleJobAs(c, job, requireAssigned, ansibleJobFinished(job))
}

// authorizeRunnerForAnsibleJobReport is authorizeRunnerForRunReport for an Ansible job: its output,
// events and completion are still taken from the attempt that was running when it was canceled,
// so its log keeps what the interrupted playbook printed, as a run's does.
func (h *RunnerAgentHandler) authorizeRunnerForAnsibleJobReport(c *gin.Context, job *models.AnsibleJob) bool {
	return h.authorizeRunnerForAnsibleJobAs(c, job, true, ansibleJobFinished(job) && job.Status != models.AnsibleJobStatusCanceled)
}

func (h *RunnerAgentHandler) authorizeRunnerForAnsibleJobAs(c *gin.Context, job *models.AnsibleJob, requireAssigned, finished bool) bool {
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "runner identity required")
		return false
	}
	orgID, poolID, err := h.ansibleJobOrgAndPool(job)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to resolve job organization")
		return false
	}
	// A job without an agent pool is no runner's business, so the pool must be set and must be the
	// runner's own, or for a hosted runner a hosted pool the job was reserved on for it.
	if !h.authorizePool(c, runner, orgID, poolID, job.RunnerID, "job") {
		return false
	}
	if job.RunnerID != nil && *job.RunnerID != runner.ID {
		writeRunnerForbidden(c, "job is reserved by a different runner")
		return false
	}
	if requireAssigned && (job.RunnerID == nil || *job.RunnerID != runner.ID) {
		writeRunnerForbidden(c, "job is not reserved by this runner")
		return false
	}
	if p, ok := callingJob(c); ok {
		return authorizeJobPrincipal(c, p, models.JobTypeAnsibleJob, job.ID.String(), job.RunnerID, job.Attempt, finished)
	}
	return true
}

// authorizePool binds a job's organization and pool to the calling runner (#933, D9). A customer
// runner reaches its own organization's jobs on its own pool. A hosted runner reaches a job of any
// organization, but only on a hosted pool and only once the job is reserved for it, and a job token
// it presents must be bound to the job's organization; a customer runner never reaches a hosted
// pool's job, nor a hosted runner a customer pool's.
func (h *RunnerAgentHandler) authorizePool(c *gin.Context, runner *models.Runner, orgID uuid.UUID, poolID, assignee *uuid.UUID, what string) bool {
	if poolID == nil {
		writeRunnerForbidden(c, what+" is not assigned to an agent pool")
		return false
	}
	if !runner.IsHosted() {
		if orgID != runner.OrgID() {
			writeRunnerForbidden(c, what+" belongs to a different organization")
			return false
		}
		if *poolID != runner.PoolID() {
			writeRunnerForbidden(c, what+" is assigned to a different agent pool")
			return false
		}
		return true
	}
	var pool models.AgentPool
	if err := h.db.Select("id", "kind", "organization_id").First(&pool, "id = ?", *poolID).Error; err != nil || !pool.IsHosted() || pool.OrganizationID != orgID {
		writeRunnerForbidden(c, what+" is not on a hosted pool")
		return false
	}
	if assignee == nil || *assignee != runner.ID {
		writeRunnerForbidden(c, what+" is not reserved for this hosted runner")
		return false
	}
	if _, isJob := callingJob(c); isJob {
		raw, _ := c.Get("api_key")
		key, _ := raw.(*models.APIKey)
		if key == nil || key.OrganizationID == nil || *key.OrganizationID != orgID {
			writeRunnerForbidden(c, "this job token belongs to a different organization")
			return false
		}
	}
	return true
}

// callingJob returns the principal of the job token the caller presented, if it presented one
// (middleware.RunnerAuth stores it).
func callingJob(c *gin.Context) (apikey.JobPrincipal, bool) {
	v, ok := c.Get(middleware.JobPrincipalKey)
	if !ok {
		return apikey.JobPrincipal{}, false
	}
	p, ok := v.(apikey.JobPrincipal)
	return p, ok
}

// authorizeJobPrincipal binds a job token to the one job it was minted for (#933, D1, AC2): the
// job must be the token's job, still claimed by the token's runner, in the token's attempt and not
// terminal. The last two refusals carry the codes an executor stops on.
func authorizeJobPrincipal(c *gin.Context, p apikey.JobPrincipal, kind models.JobType, jobID string, assignee *uuid.UUID, attempt int, finished bool) bool {
	if p.Kind != kind || p.JobID != jobID {
		writeRunnerForbidden(c, "this job token is for a different job")
		return false
	}
	if assignee == nil || *assignee != p.RunnerID {
		jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTokenRevoked, "Forbidden", "the job is no longer assigned to this token's runner")
		return false
	}
	// A row claimed before the attempt counter existed reads 0 and counts as its first attempt.
	if max(attempt, 1) != p.Attempt {
		jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTokenRevoked, "Forbidden", "a later attempt of this job exists")
		return false
	}
	if finished {
		jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the job has finished")
		return false
	}
	return true
}

// cancelMarker ends the log of a run canceled while its job ran, after whatever the interrupted
// engine printed, so the log says how the run ended.
const cancelMarker = "Stackweaver: the run was canceled."

// jobCancelMarker is the last event of an Ansible job canceled while it ran.
const jobCancelMarker = "Stackweaver: the job was canceled."

// finishedRunStatuses are the statuses after which an OpenTofu run has no job left to execute.
var finishedRunStatuses = []models.RunStatus{
	models.RunStatusApplied,
	models.RunStatusFailed,
	models.RunStatusCancelled,
	models.RunStatusCompleted,
}

// runFinished reports whether a run has reached a terminal status.
func runFinished(run *models.Run) bool {
	return slices.Contains(finishedRunStatuses, run.Status)
}

// finishedAnsibleJobStatuses are the terminal statuses of an Ansible job.
var finishedAnsibleJobStatuses = []models.AnsibleJobStatus{
	models.AnsibleJobStatusSuccessful,
	models.AnsibleJobStatusFailed,
	models.AnsibleJobStatusCanceled,
	models.AnsibleJobStatusError,
}

// ansibleJobFinished reports whether a job has reached a terminal status.
func ansibleJobFinished(job *models.AnsibleJob) bool {
	return slices.Contains(finishedAnsibleJobStatuses, job.Status)
}

// refuseFinishedAnsibleJob guards the endpoints that hand a runner what it needs to
// prepare a job: the artifacts (decrypted credentials, minted tokens) and the playbook
// snapshot. A finished job has nothing left to prepare, so neither is served again. It
// deliberately does not guard the write endpoints: output, events and the completion
// call can legitimately arrive around the moment a job turns terminal.
func refuseFinishedAnsibleJob(c *gin.Context, job *models.AnsibleJob) bool {
	if !ansibleJobFinished(job) {
		return false
	}
	writeRunnerForbidden(c, "job has finished; its artifacts and playbook snapshot are no longer served")
	return true
}
