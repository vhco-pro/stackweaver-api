// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/core/models"
)

// AUD-001 authorization helpers for the runner control plane.
//
// Every /runner/* job handler (except register) runs behind middleware.RunnerAuth,
// which authenticates the caller as exactly one runner and stores it under
// middleware.CallingRunnerKey. These helpers bind a job/run to that runner:
//   - org-equality  — the runner's org must own the job (kills cross-tenant access);
//   - pool-equality — the job's agent pool must be the runner's pool;
//   - assignment    — if the job is already claimed, only the assignee may touch it.
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
	c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{
		"status": "403", "title": "Forbidden", "detail": detail,
	}}})
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
// start) pass false — the run may still be unassigned, and org+pool equality plus
// the atomic claim carry the guarantee. Returns true iff the caller is authorized;
// otherwise it has already written the error response.
func (h *RunnerAgentHandler) authorizeRunnerForRun(c *gin.Context, run *models.Run, requireAssigned bool) bool {
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "runner identity required")
		return false
	}
	orgID, poolID, err := h.runOrgAndPool(run)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{
			"status": "500", "title": "Internal Server Error", "detail": "failed to resolve run organization",
		}}})
		return false
	}
	if orgID != runner.OrganizationID {
		writeRunnerForbidden(c, "run belongs to a different organization")
		return false
	}
	if poolID != nil && *poolID != runner.AgentPoolID {
		writeRunnerForbidden(c, "run is assigned to a different agent pool")
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
	return true
}

// authorizeRunnerForAnsibleJob is the ansible-job counterpart of
// authorizeRunnerForRun. requireAssigned checks the job's reservation
// (job.RunnerID) rather than a RunnerJobExecution row.
func (h *RunnerAgentHandler) authorizeRunnerForAnsibleJob(c *gin.Context, job *models.AnsibleJob, requireAssigned bool) bool {
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "runner identity required")
		return false
	}
	orgID, poolID, err := h.ansibleJobOrgAndPool(job)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{
			"status": "500", "title": "Internal Server Error", "detail": "failed to resolve job organization",
		}}})
		return false
	}
	if orgID != runner.OrganizationID {
		writeRunnerForbidden(c, "job belongs to a different organization")
		return false
	}
	if poolID != nil && *poolID != runner.AgentPoolID {
		writeRunnerForbidden(c, "job is assigned to a different agent pool")
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
	return true
}
