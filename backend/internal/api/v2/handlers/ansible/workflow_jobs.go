// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
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
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workflow ID")
		return nil
	}
	return h.resolveWorkflowByID(c, id, permission)
}

// resolveWorkflowByID is resolveWorkflowForRun for callers that already know
// the workflow ID (run/node-run endpoints whose :id is a different resource).
func (h *WorkflowHandler) resolveWorkflowByID(c *gin.Context, id uuid.UUID, permission rbac.Permission) *models.AnsibleWorkflow {
	workflow, err := h.workflowRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workflow not found")
		return nil
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil
	}
	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(), user.ID, rbac.ResourceTypeAnsibleJobTemplate, workflow.ID.String(), permission, &workflow.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return nil
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to run this workflow")
		return nil
	}
	return workflow
}

func formatWorkflowJob(job *models.AnsibleWorkflowJob) jsonapi.Resource[WorkflowJobAttributes] {
	return jsonapi.Resource[WorkflowJobAttributes]{
		ID:   job.ID.String(),
		Type: "ansible-workflow-jobs",
		Attributes: WorkflowJobAttributes{
			Name:       job.Name,
			Status:     job.Status,
			StartedAt:  job.StartedAt,
			FinishedAt: job.FinishedAt,
			CreatedAt:  job.CreatedAt.Format(time.RFC3339),
		},
		Relationships: WorkflowJobOnlyRelationships{
			Workflow: jsonapi.ToOne(job.WorkflowID.String(), "ansible-workflows"),
		},
	}
}

func formatWorkflowNodeJob(nodeJob *models.AnsibleWorkflowNodeJob) jsonapi.Resource[WorkflowNodeJobAttributes] {
	rels := WorkflowNodeJobRelationships{
		Node: jsonapi.ToOne(nodeJob.NodeID.String(), "ansible-workflow-nodes"),
	}
	if nodeJob.AnsibleJobID != nil {
		r := jsonapi.ToOne(nodeJob.AnsibleJobID.String(), "ansible-jobs")
		rels.Job = &r
	}
	if nodeJob.Node.JobTemplateID != nil {
		r := jsonapi.ToOne(nodeJob.Node.JobTemplateID.String(), "ansible-job-templates")
		rels.JobTemplate = &r
	}
	return jsonapi.Resource[WorkflowNodeJobAttributes]{
		ID:   nodeJob.ID.String(),
		Type: "ansible-workflow-node-jobs",
		Attributes: WorkflowNodeJobAttributes{
			Status:     nodeJob.Status,
			NodeType:   nodeJob.Node.NodeType,
			Identifier: nodeJob.Node.Identifier,
			StartedAt:  nodeJob.StartedAt,
			FinishedAt: nodeJob.FinishedAt,
			Denied:     nodeJob.Denied,
		},
		Relationships: rels,
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
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Workflow engine not configured")
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
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
		return
	}
	jsonapi.WriteDocument(c, http.StatusCreated, formatWorkflowJob(wfJob))
}

// ListWorkflowJobs lists a workflow's runs.
// GET /api/v2/ansible/workflows/:id/jobs
func (h *WorkflowHandler) ListWorkflowJobs(c *gin.Context) {
	workflow := h.resolveWorkflowForRun(c, rbac.PermissionAnsibleJobTemplateRead)
	if workflow == nil {
		return
	}
	// This one caps rows, so it cannot use NewFullPageMeta. It already carried the true total,
	// just in a bespoke one-member block no client knows how to read; the six-member block says
	// the same thing in the shape go-tfe and fetchAllPages already expect. Reporting it obliges
	// the handler to honour page[number] too - see PageParams.
	page, perPage := jsonapi.PageParams(c, 50, 100)
	jobs, total, err := h.workflowRepo.ListWorkflowJobsByWorkflow(workflow.ID, perPage, jsonapi.Offset(page, perPage))
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list workflow runs")
		return
	}
	data := make([]jsonapi.Resource[WorkflowJobAttributes], 0, len(jobs))
	for i := range jobs {
		data = append(data, formatWorkflowJob(&jobs[i]))
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(page, perPage, total))
}

// GetWorkflowJob returns one run with its node jobs.
// GET /api/v2/ansible/workflow-jobs/:id
func (h *WorkflowHandler) GetWorkflowJob(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workflow job ID")
		return
	}
	wfJob, err := h.workflowRepo.GetWorkflowJobByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workflow run not found")
		return
	}
	// Permission via the parent workflow.
	if h.resolveWorkflowByID(c, wfJob.WorkflowID, rbac.PermissionAnsibleJobTemplateRead) == nil {
		return
	}
	nodes := make([]jsonapi.Resource[WorkflowNodeJobAttributes], 0, len(wfJob.NodeJobs))
	for i := range wfJob.NodeJobs {
		nodes = append(nodes, formatWorkflowNodeJob(&wfJob.NodeJobs[i]))
	}
	c.JSON(http.StatusOK, jsonapi.Document{Data: formatWorkflowJob(wfJob), Included: nodes})
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
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Workflow engine not configured")
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid node job ID")
		return
	}
	nodeJob, err := h.workflowRepo.GetNodeJobByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workflow node run not found")
		return
	}
	wfJob, err := h.workflowRepo.GetWorkflowJobByID(nodeJob.WorkflowJobID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workflow run not found")
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
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}
