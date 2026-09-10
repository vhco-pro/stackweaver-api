// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/response"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

// ScheduleHandler handles schedule API requests
type ScheduleHandler struct {
	schedulerService *ansible.SchedulerService
	orgRepo          *repository.OrganizationRepository
	authService      *auth.Service
	rbacService      *rbac.Service
}

// NewScheduleHandler creates a new schedule handler
func NewScheduleHandler(schedulerService *ansible.SchedulerService, orgRepo *repository.OrganizationRepository, authService *auth.Service, rbacService *rbac.Service) *ScheduleHandler {
	return &ScheduleHandler{
		schedulerService: schedulerService,
		orgRepo:          orgRepo,
		authService:      authService,
		rbacService:      rbacService,
	}
}

// CreateScheduleRequest represents the request to create a schedule (JSON:API format)
type CreateScheduleRequest struct {
	Data struct {
		Type       string `json:"type" binding:"required"` // Must be "schedules"
		Attributes struct {
			Name              string                `json:"name" binding:"required,min=1,max=255"`
			Description       string                `json:"description"`
			ScheduleType      models.ScheduleType   `json:"schedule-type" binding:"required,oneof=job_template inventory_source playbook_sync workflow"`
			JobTemplateID     string                `json:"job-template-id"`
			InventorySourceID string                `json:"inventory-source-id"`
			PlaybookID        string                `json:"playbook-id"`
			WorkflowID        string                `json:"workflow-id"`
			CronExpression    string                `json:"cron-expression" binding:"required"`
			Timezone          string                `json:"timezone" binding:"required"`
			StartDateTime     string                `json:"start-date-time"`
			EndDateTime       string                `json:"end-date-time"`
			Config            models.ScheduleConfig `json:"config"`
		} `json:"attributes" binding:"required"`
	} `json:"data" binding:"required"`
}

// UpdateScheduleRequest represents the request to update a schedule
type UpdateScheduleRequest struct {
	Name           *string                `json:"name"`
	Description    *string                `json:"description"`
	CronExpression *string                `json:"cron_expression"`
	Timezone       *string                `json:"timezone"`
	Config         *models.ScheduleConfig `json:"config"`
}

// Create creates a new schedule
func (h *ScheduleHandler) Create(c *gin.Context) {
	var req CreateScheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	// Log request for debugging (remove in production)
	// logger.Debugf("CreateSchedule: Type=%s, Name=%s, ScheduleType=%s", req.Data.Type, req.Data.Attributes.Name, req.Data.Attributes.ScheduleType)

	// Validate JSON:API type
	if req.Data.Type != "schedules" {
		response.BadRequest(c, "data.type must be 'schedules'")
		return
	}

	// Get organization by name from URL param
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		response.NotFound(c, "Organization not found")
		return
	}
	orgID := org.ID

	// RBAC: check org-level write permission
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	hasPermission, err := h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to create schedules in this organization")
		return
	}

	// Parse target IDs based on type
	var jobTemplateID, inventorySourceID, playbookID, workflowID *uuid.UUID
	attrs := req.Data.Attributes

	switch attrs.ScheduleType {
	case models.ScheduleTypeJobTemplate:
		if attrs.JobTemplateID == "" {
			response.BadRequest(c, "job-template-id is required for job_template schedules")
			return
		}
		id, err := uuid.Parse(attrs.JobTemplateID)
		if err != nil {
			response.BadRequest(c, "Invalid job-template-id")
			return
		}
		jobTemplateID = &id

	case models.ScheduleTypeInventorySource:
		if attrs.InventorySourceID == "" {
			response.BadRequest(c, "inventory-source-id is required for inventory_source schedules")
			return
		}
		id, err := uuid.Parse(attrs.InventorySourceID)
		if err != nil {
			response.BadRequest(c, "Invalid inventory-source-id")
			return
		}
		inventorySourceID = &id

	case models.ScheduleTypePlaybookSync:
		if attrs.PlaybookID == "" {
			response.BadRequest(c, "playbook-id is required for playbook_sync schedules")
			return
		}
		id, err := uuid.Parse(attrs.PlaybookID)
		if err != nil {
			response.BadRequest(c, "Invalid playbook-id")
			return
		}
		playbookID = &id

	case models.ScheduleTypeWorkflow:
		if attrs.WorkflowID == "" {
			response.BadRequest(c, "workflow-id is required for workflow schedules")
			return
		}
		id, err := uuid.Parse(attrs.WorkflowID)
		if err != nil {
			response.BadRequest(c, "Invalid workflow-id")
			return
		}
		workflowID = &id
	}

	// Parse optional date times
	var startDateTime, endDateTime *time.Time
	if attrs.StartDateTime != "" {
		startDT, err := time.Parse(time.RFC3339, attrs.StartDateTime)
		if err != nil {
			response.BadRequest(c, "Invalid start-date-time format, must be RFC3339")
			return
		}
		startDateTime = &startDT
	}
	if attrs.EndDateTime != "" {
		endDT, err := time.Parse(time.RFC3339, attrs.EndDateTime)
		if err != nil {
			response.BadRequest(c, "Invalid end-date-time format, must be RFC3339")
			return
		}
		endDateTime = &endDT
	}

	// Attribute the schedule to the authenticated user (already resolved for the
	// RBAC check above). The previous c.Get("user_id").(string) assertion
	// panicked: the auth middleware stores user_id as a uuid.UUID, not a string.
	createdBy := &user.ID

	// Ensure Config is not nil (default to empty map)
	config := attrs.Config
	if config == nil {
		config = make(models.ScheduleConfig)
	}

	schedule, err := h.schedulerService.CreateSchedule(
		orgID,
		attrs.Name,
		attrs.Description,
		attrs.ScheduleType,
		attrs.CronExpression,
		attrs.Timezone,
		jobTemplateID,
		inventorySourceID,
		playbookID,
		workflowID,
		config,
		createdBy,
		startDateTime,
		endDateTime,
	)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, formatScheduleResponse(schedule))
}

// formatScheduleResponse formats a schedule for JSON:API response
func formatScheduleResponse(schedule *models.AnsibleSchedule) jsonapi.Resource[ScheduleAttributes] {
	// Ensure config is not nil for response
	config := schedule.Config
	if config == nil {
		config = make(models.ScheduleConfig)
	}

	attributes := ScheduleAttributes{
		Name:           schedule.Name,
		Description:    schedule.Description,
		ScheduleType:   schedule.Type,
		Status:         schedule.Status,
		CronExpression: schedule.CronExpression,
		Timezone:       schedule.Timezone,
		Config:         config,
		CreatedAt:      schedule.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:      schedule.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		LastRunStatus:  schedule.LastRunStatus,
		RunCount:       schedule.RunCount,
	}

	if schedule.StartDateTime != nil {
		attributes.StartDateTime = schedule.StartDateTime.Format(time.RFC3339)
	}
	if schedule.EndDateTime != nil {
		attributes.EndDateTime = schedule.EndDateTime.Format(time.RFC3339)
	}
	if schedule.NextRunAt != nil {
		attributes.NextRunAt = schedule.NextRunAt.Format(time.RFC3339)
	}
	if schedule.LastRunAt != nil {
		attributes.LastRunAt = schedule.LastRunAt.Format(time.RFC3339)
	}

	relationships := ScheduleRelationships{
		Organization: jsonapi.ToOne(schedule.OrganizationID.String(), "organizations"),
	}
	if schedule.JobTemplateID != nil {
		r := jsonapi.ToOne(schedule.JobTemplateID.String(), "ansible-job-templates")
		relationships.JobTemplate = &r
	}
	if schedule.InventorySourceID != nil {
		r := jsonapi.ToOne(schedule.InventorySourceID.String(), "ansible-inventory-sources")
		relationships.InventorySource = &r
	}
	if schedule.PlaybookID != nil {
		r := jsonapi.ToOne(schedule.PlaybookID.String(), "ansible-playbooks")
		relationships.Playbook = &r
	}
	if schedule.LastJobID != nil {
		r := jsonapi.ToOne(schedule.LastJobID.String(), "ansible-jobs")
		relationships.LastJob = &r
	}
	if schedule.CreatedBy != nil {
		r := jsonapi.ToOne(schedule.CreatedBy.String(), "users")
		relationships.CreatedBy = &r
	}

	return jsonapi.Resource[ScheduleAttributes]{
		ID:            schedule.ID.String(),
		Type:          "schedules",
		Attributes:    attributes,
		Relationships: relationships,
	}
}

// Get retrieves a schedule by ID
func (h *ScheduleHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("schedule_id"))
	if err != nil {
		response.BadRequest(c, "Invalid schedule ID")
		return
	}

	schedule, err := h.schedulerService.GetSchedule(id)
	if err != nil {
		response.NotFound(c, "Schedule not found")
		return
	}

	// RBAC: check org-level read permission
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	hasPermission, err := h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, schedule.OrganizationID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to view this schedule")
		return
	}

	c.JSON(http.StatusOK, schedule)
}

// Update updates a schedule
func (h *ScheduleHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("schedule_id"))
	if err != nil {
		response.BadRequest(c, "Invalid schedule ID")
		return
	}

	// RBAC: fetch schedule and check org-level write permission
	existingSchedule, err := h.schedulerService.GetSchedule(id)
	if err != nil {
		response.NotFound(c, "Schedule not found")
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	hasPermission, err := h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, existingSchedule.OrganizationID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to update this schedule")
		return
	}

	var req UpdateScheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	schedule, err := h.schedulerService.UpdateSchedule(id, req.Name, req.Description, req.CronExpression, req.Timezone, req.Config)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	c.JSON(http.StatusOK, schedule)
}

// Delete deletes a schedule
func (h *ScheduleHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("schedule_id"))
	if err != nil {
		response.BadRequest(c, "Invalid schedule ID")
		return
	}

	// RBAC: fetch schedule and check org-level write permission
	schedule, err := h.schedulerService.GetSchedule(id)
	if err != nil {
		response.NotFound(c, "Schedule not found")
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	hasPermission, err := h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, schedule.OrganizationID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to delete this schedule")
		return
	}

	if err := h.schedulerService.DeleteSchedule(id); err != nil {
		response.InternalError(c, err.Error())
		return
	}

	c.Status(http.StatusNoContent)
}

// Enable enables a schedule
func (h *ScheduleHandler) Enable(c *gin.Context) {
	id, err := uuid.Parse(c.Param("schedule_id"))
	if err != nil {
		response.BadRequest(c, "Invalid schedule ID")
		return
	}

	// RBAC: fetch schedule and check org-level write permission
	schedule, err := h.schedulerService.GetSchedule(id)
	if err != nil {
		response.NotFound(c, "Schedule not found")
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	hasPermission, err := h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, schedule.OrganizationID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to enable this schedule")
		return
	}

	if err := h.schedulerService.EnableSchedule(id); err != nil {
		response.InternalError(c, err.Error())
		return
	}

	response.Message(c, http.StatusOK, "Schedule enabled")
}

// Disable disables a schedule
func (h *ScheduleHandler) Disable(c *gin.Context) {
	id, err := uuid.Parse(c.Param("schedule_id"))
	if err != nil {
		response.BadRequest(c, "Invalid schedule ID")
		return
	}

	// RBAC: fetch schedule and check org-level write permission
	schedule, err := h.schedulerService.GetSchedule(id)
	if err != nil {
		response.NotFound(c, "Schedule not found")
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	hasPermission, err := h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, schedule.OrganizationID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to disable this schedule")
		return
	}

	if err := h.schedulerService.DisableSchedule(id); err != nil {
		response.InternalError(c, err.Error())
		return
	}

	response.Message(c, http.StatusOK, "Schedule disabled")
}

// ValidateCron validates a cron expression and returns the next run time
func (h *ScheduleHandler) ValidateCron(c *gin.Context) {
	var req ValidateCronRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	if err := h.schedulerService.ValidateCronExpression(req.CronExpression); err != nil {
		response.BadRequest(c, "Invalid cron expression: "+err.Error())
		return
	}

	timezone := req.Timezone
	if timezone == "" {
		timezone = "UTC"
	}

	nextRun, err := h.schedulerService.GetNextRunTime(req.CronExpression, timezone)
	if err != nil {
		response.BadRequest(c, "Error calculating next run time: "+err.Error())
		return
	}

	c.JSON(http.StatusOK, ValidateCronResponse{
		Valid:          true,
		CronExpression: req.CronExpression,
		Timezone:       timezone,
		NextRunAt:      nextRun.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// ValidateCronRequest represents the request to validate a cron expression
type ValidateCronRequest struct {
	CronExpression string `json:"cron_expression" binding:"required"`
	Timezone       string `json:"timezone"`
}

// ValidateCronResponse represents the response for cron validation
type ValidateCronResponse struct {
	Valid          bool   `json:"valid"`
	CronExpression string `json:"cron_expression"`
	Timezone       string `json:"timezone"`
	NextRunAt      string `json:"next_run_at"`
}

// GetCronPresets returns the available cron presets
func (h *ScheduleHandler) GetCronPresets(c *gin.Context) {
	c.JSON(http.StatusOK, models.CronPresets)
}

// ListByOrganization lists schedules for an organization by name
func (h *ScheduleHandler) ListByOrganization(c *gin.Context) {
	// Get organization by name from URL param
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		response.NotFound(c, "Organization not found")
		return
	}
	orgID := org.ID

	// RBAC: check org-level read permission
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	hasPermission, err := h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to list schedules in this organization")
		return
	}

	// page[number]/page[size], not limit/offset: every client builds the former (pageQuery in
	// frontend/src/api/ansible.ts), so reading the latter silently discarded the requested size
	// and applied this handler's own default of 20 instead. Parsed inline to match the sibling
	// Ansible handlers (groups.go, jobs.go) - the shared paginate() helper is unexported and
	// lives in the terraform package, so this one cannot reach it.
	page, perPage := jsonapi.PageParams(c, 20, 100)
	offset := (page - 1) * perPage

	schedules, total, err := h.schedulerService.ListSchedules(orgID, perPage, offset)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	formatted := make([]jsonapi.Resource[ScheduleAttributes], 0, len(schedules))
	for i := range schedules {
		formatted = append(formatted, formatScheduleResponse(&schedules[i]))
	}
	// The JSON:API envelope, not response.Paginated: fetchAllPages reads
	// meta.pagination.total-pages and fell back to "one page" against the old top-level shape,
	// capping the Schedules screen at 20 rows.
	jsonapi.WriteDocumentMeta(c, http.StatusOK, formatted, jsonapi.NewPaginationMeta(page, perPage, total))
}

// RunNow triggers immediate execution of a schedule
func (h *ScheduleHandler) RunNow(c *gin.Context) {
	id, err := uuid.Parse(c.Param("schedule_id"))
	if err != nil {
		response.BadRequest(c, "Invalid schedule ID")
		return
	}

	// RBAC: fetch schedule and check org-level write permission
	schedule, err := h.schedulerService.GetSchedule(id)
	if err != nil {
		response.NotFound(c, "Schedule not found")
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	hasPermission, err := h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, schedule.OrganizationID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to run this schedule")
		return
	}

	if err := h.schedulerService.RunScheduleNow(id); err != nil {
		response.InternalError(c, err.Error())
		return
	}

	response.Message(c, http.StatusOK, "Schedule triggered")
}
