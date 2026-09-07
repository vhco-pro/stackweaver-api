// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// RunnerHandlerV2 handles runner management endpoints
type RunnerHandlerV2 struct {
	runnerRepo  *repository.RunnerRepository
	jobExecRepo *repository.RunnerJobExecutionRepository
	poolRepo    *repository.AgentPoolRepository
	orgRepo     *repository.OrganizationRepository
	rbacService *rbac.Service
}

// NewRunnerHandlerV2 creates a new runner handler
func NewRunnerHandlerV2(
	runnerRepo *repository.RunnerRepository,
	jobExecRepo *repository.RunnerJobExecutionRepository,
	poolRepo *repository.AgentPoolRepository,
	orgRepo *repository.OrganizationRepository,
	rbacService *rbac.Service,
) *RunnerHandlerV2 {
	return &RunnerHandlerV2{
		runnerRepo:  runnerRepo,
		jobExecRepo: jobExecRepo,
		poolRepo:    poolRepo,
		orgRepo:     orgRepo,
		rbacService: rbacService,
	}
}

// requireManageAgentPools checks org:manage-agent-pools permission
func (h *RunnerHandlerV2) requireManageAgentPools(c *gin.Context, orgID uuid.UUID) bool {
	userID, exists := c.Get("user_id")
	if !exists {
		jsonapi.WriteErrorNoDetail(c, http.StatusUnauthorized, "Unauthorized")
		return false
	}
	uid := userID.(uuid.UUID)
	ok, err := h.rbacService.CheckOrgManageAgentPools(c.Request.Context(), uid, orgID)
	if err != nil || !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage agent pools/runners for this organization")
		return false
	}
	return true
}

// List lists runners for an organization
// GET /api/v2/organizations/:name/runners
func (h *RunnerHandlerV2) List(c *gin.Context) {
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Organization not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	if !h.requireManageAgentPools(c, org.ID) {
		return
	}

	// Parse query params
	opts := repository.ListRunnersOptions{
		Query: c.Query("q"),
		Sort:  c.Query("sort"),
	}

	if poolIDStr := c.Query("filter[agent_pool_id]"); poolIDStr != "" {
		poolID, err := uuid.Parse(poolIDStr)
		if err == nil {
			opts.AgentPoolID = &poolID
		}
	}
	if status := c.Query("filter[status]"); status != "" {
		opts.Status = status
	}
	if runnerType := c.Query("filter[runner_type]"); runnerType != "" {
		opts.RunnerType = runnerType
	}

	// Pagination
	pageSize := 20
	pageNum := 1
	if ps := c.Query("page[size]"); ps != "" {
		if n, err := strconv.Atoi(ps); err == nil && n > 0 && n <= 100 {
			pageSize = n
		}
	}
	if pn := c.Query("page[number]"); pn != "" {
		if n, err := strconv.Atoi(pn); err == nil && n > 0 {
			pageNum = n
		}
	}
	opts.Limit = pageSize
	opts.Offset = (pageNum - 1) * pageSize

	runners, total, err := h.runnerRepo.ListByOrganization(org.ID, opts)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Build response
	data := make([]jsonapi.Resource[RunnerAttributes], 0, len(runners))
	for _, r := range runners {
		data = append(data, buildRunnerResponse(&r))
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(pageNum, pageSize, total))
}

// GetByID returns a runner by ID
// GET /api/v2/runners/:id
func (h *RunnerHandlerV2) GetByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid runner ID")
		return
	}

	runner, err := h.runnerRepo.GetByID(id)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Runner not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	if !h.requireManageAgentPools(c, runner.OrganizationID) {
		return
	}

	// Get job history
	jobs, _ := h.jobExecRepo.ListByRunner(runner.ID, 10)
	currentJobs, _ := h.jobExecRepo.CountActiveByRunner(runner.ID)
	runner.CurrentJobs = int(currentJobs)

	response := buildRunnerResponse(runner)

	// Add job history to response
	jobHistory := make([]RunnerRecentJob, 0, len(jobs))
	for _, j := range jobs {
		jobHistory = append(jobHistory, RunnerRecentJob{
			ID:            j.ID.String(),
			JobType:       j.JobType,
			JobID:         j.JobID.String(),
			WorkspaceID:   j.WorkspaceID,
			WorkspaceName: j.WorkspaceName,
			Status:        j.Status,
			StartedAt:     j.StartedAt,
			FinishedAt:    j.FinishedAt,
			DurationMS:    j.Duration().Milliseconds(),
		})
	}
	response.Attributes.RecentJobs = &jobHistory

	jsonapi.WriteDocument(c, http.StatusOK, response)
}

// Update updates a runner (labels, description)
// PATCH /api/v2/runners/:id
func (h *RunnerHandlerV2) Update(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid runner ID")
		return
	}

	runner, err := h.runnerRepo.GetByID(id)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Runner not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	if !h.requireManageAgentPools(c, runner.OrganizationID) {
		return
	}

	var req struct {
		Data struct {
			Attributes struct {
				Description *string  `json:"description"`
				Labels      []string `json:"labels"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	if req.Data.Attributes.Description != nil {
		runner.Description = *req.Data.Attributes.Description
	}
	if req.Data.Attributes.Labels != nil {
		runner.Labels = models.RunnerLabels(req.Data.Attributes.Labels)
	}

	if err := h.runnerRepo.Update(runner); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, buildRunnerResponse(runner))
}

// Delete deletes a runner
// DELETE /api/v2/runners/:id
func (h *RunnerHandlerV2) Delete(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid runner ID")
		return
	}

	runner, err := h.runnerRepo.GetByID(id)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Runner not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	if !h.requireManageAgentPools(c, runner.OrganizationID) {
		return
	}

	if err := h.runnerRepo.Delete(id); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	c.Status(http.StatusNoContent)
}

// GetStats returns runner statistics for an organization
// GET /api/v2/organizations/:name/runners/stats
func (h *RunnerHandlerV2) GetStats(c *gin.Context) {
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Organization not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	if !h.requireManageAgentPools(c, org.ID) {
		return
	}

	total, online, err := h.runnerRepo.CountByOrganization(org.ID)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, RunnerStatsDocument{
		Type: "runner-stats",
		Attributes: RunnerStatsAttributes{
			Total:   total,
			Online:  online,
			Offline: total - online,
		},
	})
}

// buildRunnerResponse builds a JSON:API response for a runner
func buildRunnerResponse(r *models.Runner) jsonapi.Resource[RunnerAttributes] {
	var lastHeartbeat *string
	if r.LastHeartbeatAt != nil {
		formatted := r.LastHeartbeatAt.Format("2006-01-02T15:04:05Z")
		lastHeartbeat = &formatted
	}

	attrs := RunnerAttributes{
		Name:                 r.Name,
		Description:          r.Description,
		AgentPoolID:          r.AgentPoolID.String(),
		RunnerType:           r.RunnerType,
		Status:               r.Status,
		Hostname:             r.Hostname,
		IPAddress:            r.IPAddress,
		OSType:               r.OSType,
		OSVersion:            r.OSVersion,
		AgentVersion:         r.AgentVersion,
		Labels:               r.Labels,
		TofuVersion:          r.TofuVersion,
		AnsibleVersion:       r.AnsibleVersion,
		AvailableCollections: r.AvailableCollections,
		MaxConcurrentJobs:    r.MaxConcurrentJobs,
		CurrentJobs:          r.CurrentJobs,
		LastHeartbeatAt:      lastHeartbeat,
		RegisteredAt:         r.RegisteredAt.Format("2006-01-02T15:04:05Z"),
	}

	// Include pool name if preloaded
	if r.AgentPool.ID != uuid.Nil {
		attrs.AgentPoolName = r.AgentPool.Name
	}

	return jsonapi.Resource[RunnerAttributes]{
		ID:         r.ID.String(),
		Type:       "runners",
		Attributes: attrs,
		Relationships: OrgAndAgentPoolRelationships{
			Organization: jsonapi.ToOne(r.OrganizationID.String(), "organizations"),
			AgentPool:    jsonapi.ToOne(r.AgentPoolID.String(), "agent-pools"),
		},
	}
}
