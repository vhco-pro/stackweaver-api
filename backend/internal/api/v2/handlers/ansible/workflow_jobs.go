// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

// SetEngine wires the workflow execution engine (optional setter to avoid
// constructor churn).
func (h *WorkflowHandler) SetEngine(engine *ansible.WorkflowEngineService) {
	h.engine = engine
}

// resolveWorkflowForRun loads the workflow and checks the caller's permission.
// Writes the error response and returns nil on failure.
func (h *WorkflowHandler) resolveWorkflowForRun(c *gin.Context, permission rbac.Permission) *models.AnsibleWorkflow {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid workflow ID"}}})
		return nil
	}
	return h.resolveWorkflowByID(c, id, permission)
}

// resolveWorkflowByID is resolveWorkflowForRun for callers that already know
// the workflow ID (run/node-run endpoints whose :id is a different resource).
func (h *WorkflowHandler) resolveWorkflowByID(c *gin.Context, id uuid.UUID, permission rbac.Permission) *models.AnsibleWorkflow {
	workflow, err := h.workflowRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Workflow not found"}}})
		return nil
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return nil
	}
	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(), user.ID, rbac.ResourceTypeAnsibleJobTemplate, workflow.ID.String(), permission, &workflow.ProjectID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to check permissions"}}})
		return nil
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to run this workflow"}}})
		return nil
	}
	return workflow
}

func formatWorkflowJob(job *models.AnsibleWorkflowJob) gin.H {
	attrs := gin.H{
		"name":        job.Name,
		"status":      job.Status,
		"started-at":  job.StartedAt,
		"finished-at": job.FinishedAt,
		"created-at":  job.CreatedAt.Format(time.RFC3339),
	}
	return gin.H{
		"id":         job.ID.String(),
		"type":       "ansible-workflow-jobs",
		"attributes": attrs,
		"relationships": gin.H{
			"workflow": gin.H{"data": gin.H{"id": job.WorkflowID.String(), "type": "ansible-workflows"}},
		},
	}
}

func formatWorkflowNodeJob(nodeJob *models.AnsibleWorkflowNodeJob) gin.H {
	attrs := gin.H{
		"status":      nodeJob.Status,
		"node-type":   nodeJob.Node.NodeType,
		"identifier":  nodeJob.Node.Identifier,
		"started-at":  nodeJob.StartedAt,
		"finished-at": nodeJob.FinishedAt,
		"denied":      nodeJob.Denied,
	}
	rels := gin.H{
		"node": gin.H{"data": gin.H{"id": nodeJob.NodeID.String(), "type": "ansible-workflow-nodes"}},
	}
	if nodeJob.AnsibleJobID != nil {
		rels["job"] = gin.H{"data": gin.H{"id": nodeJob.AnsibleJobID.String(), "type": "ansible-jobs"}}
	}
	if nodeJob.Node.JobTemplateID != nil {
		rels["job-template"] = gin.H{"data": gin.H{"id": nodeJob.Node.JobTemplateID.String(), "type": "ansible-job-templates"}}
	}
	return gin.H{
		"id":            nodeJob.ID.String(),
		"type":          "ansible-workflow-node-jobs",
		"attributes":    attrs,
		"relationships": rels,
	}
}

// LaunchWorkflow starts a run of the workflow's current graph.
// POST /api/v2/ansible/workflows/:id/launch
func (h *WorkflowHandler) LaunchWorkflow(c *gin.Context) {
	workflow := h.resolveWorkflowForRun(c, rbac.PermissionAnsibleJobExecute)
	if workflow == nil {
		return
	}
	if h.engine == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Workflow engine not configured"}}})
		return
	}
	var req struct {
		ExtraVars map[string]interface{} `json:"extra_vars"`
	}
	_ = c.ShouldBindJSON(&req) // body is optional

	user, _ := h.authService.GetUserFromContext(c)
	var launchedBy *uuid.UUID
	if user != nil {
		launchedBy = &user.ID
	}

	wfJob, err := h.engine.LaunchWorkflow(c.Request.Context(), workflow.ID, launchedBy, req.ExtraVars)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"errors": []gin.H{{"status": "409", "title": "Conflict", "detail": err.Error()}}})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": formatWorkflowJob(wfJob)})
}

// ListWorkflowJobs lists a workflow's runs.
// GET /api/v2/ansible/workflows/:id/jobs
func (h *WorkflowHandler) ListWorkflowJobs(c *gin.Context) {
	workflow := h.resolveWorkflowForRun(c, rbac.PermissionAnsibleJobTemplateRead)
	if workflow == nil {
		return
	}
	jobs, total, err := h.workflowRepo.ListWorkflowJobsByWorkflow(workflow.ID, 50, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to list workflow runs"}}})
		return
	}
	data := make([]gin.H, 0, len(jobs))
	for i := range jobs {
		data = append(data, formatWorkflowJob(&jobs[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": data, "meta": gin.H{"total-count": total}})
}

// GetWorkflowJob returns one run with its node jobs.
// GET /api/v2/ansible/workflow-jobs/:id
func (h *WorkflowHandler) GetWorkflowJob(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid workflow job ID"}}})
		return
	}
	wfJob, err := h.workflowRepo.GetWorkflowJobByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Workflow run not found"}}})
		return
	}
	// Permission via the parent workflow.
	if h.resolveWorkflowByID(c, wfJob.WorkflowID, rbac.PermissionAnsibleJobTemplateRead) == nil {
		return
	}
	nodes := make([]gin.H, 0, len(wfJob.NodeJobs))
	for i := range wfJob.NodeJobs {
		nodes = append(nodes, formatWorkflowNodeJob(&wfJob.NodeJobs[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": formatWorkflowJob(wfJob), "included": nodes})
}

// ApproveWorkflowNode approves a waiting approval node.
// POST /api/v2/ansible/workflow-node-jobs/:id/approve
func (h *WorkflowHandler) ApproveWorkflowNode(c *gin.Context) {
	h.decideWorkflowNode(c, true)
}

// DenyWorkflowNode denies a waiting approval node.
// POST /api/v2/ansible/workflow-node-jobs/:id/deny
func (h *WorkflowHandler) DenyWorkflowNode(c *gin.Context) {
	h.decideWorkflowNode(c, false)
}

func (h *WorkflowHandler) decideWorkflowNode(c *gin.Context, approve bool) {
	if h.engine == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Workflow engine not configured"}}})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid node job ID"}}})
		return
	}
	nodeJob, err := h.workflowRepo.GetNodeJobByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Workflow node run not found"}}})
		return
	}
	wfJob, err := h.workflowRepo.GetWorkflowJobByID(nodeJob.WorkflowJobID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Workflow run not found"}}})
		return
	}
	// Approving runs jobs, so it requires execute permission on the workflow.
	if h.resolveWorkflowByID(c, wfJob.WorkflowID, rbac.PermissionAnsibleJobExecute) == nil {
		return
	}
	user, _ := h.authService.GetUserFromContext(c)
	var decidedBy *uuid.UUID
	if user != nil {
		decidedBy = &user.ID
	}
	if approve {
		err = h.engine.ApproveNode(c.Request.Context(), id, decidedBy)
	} else {
		err = h.engine.DenyNode(c.Request.Context(), id, decidedBy)
	}
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"errors": []gin.H{{"status": "409", "title": "Conflict", "detail": err.Error()}}})
		return
	}
	c.Status(http.StatusNoContent)
}
