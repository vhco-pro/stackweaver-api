// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/datatypes"
)

// NotificationHandler manages org-scoped notification templates and their
// attachments to job templates / workflows.
type NotificationHandler struct {
	repo            *repository.AnsibleNotificationRepository
	templateRepo    *repository.AnsibleJobTemplateRepository
	workflowRepo    *repository.AnsibleWorkflowRepository
	orgRepo         *repository.OrganizationRepository
	authService     *auth.Service
	rbacService     *rbac.Service
	cryptoService   *crypto.CryptoService
	notificationSvc *ansible.NotificationService
}

// NewNotificationHandler creates a notification handler.
func NewNotificationHandler(
	repo *repository.AnsibleNotificationRepository,
	templateRepo *repository.AnsibleJobTemplateRepository,
	workflowRepo *repository.AnsibleWorkflowRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	cryptoService *crypto.CryptoService,
	notificationSvc *ansible.NotificationService,
) *NotificationHandler {
	return &NotificationHandler{
		repo:            repo,
		templateRepo:    templateRepo,
		workflowRepo:    workflowRepo,
		orgRepo:         orgRepo,
		authService:     authService,
		rbacService:     rbacService,
		cryptoService:   cryptoService,
		notificationSvc: notificationSvc,
	}
}

// resolveOrg checks the caller's org-level ansible permission. Writes the error
// response and returns nil on failure.
func (h *NotificationHandler) resolveOrg(c *gin.Context, write bool) *models.Organization {
	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return nil
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil
	}
	var hasPermission bool
	if write {
		hasPermission, err = h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, org.ID)
	} else {
		hasPermission, err = h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, org.ID)
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return nil
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage notifications in this organization")
		return nil
	}
	return org
}

func formatNotificationTemplate(t *models.AnsibleNotificationTemplate) jsonapi.Resource[NotificationTemplateAttributes] {
	var config map[string]interface{}
	_ = json.Unmarshal(t.Config, &config)
	return jsonapi.Resource[NotificationTemplateAttributes]{
		ID:   t.ID.String(),
		Type: "ansible-notification-templates",
		Attributes: NotificationTemplateAttributes{
			Name:             t.Name,
			Description:      t.Description,
			NotificationType: t.Type,
			Config:           config,
			HasSecret:        t.Secret != "",
			CreatedAt:        t.CreatedAt,
		},
	}
}

type notificationTemplateRequest struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Config      map[string]interface{} `json:"config"`
	// Secret is the channel's sensitive value (webhook basic-auth password /
	// SMTP password); stored encrypted, never returned.
	Secret *string `json:"secret"`
}

// List notification templates.
// GET /api/v2/organizations/:name/ansible/notification-templates
func (h *NotificationHandler) List(c *gin.Context) {
	org := h.resolveOrg(c, false)
	if org == nil {
		return
	}
	templates, err := h.repo.ListByOrganization(org.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list notification templates")
		return
	}
	data := make([]jsonapi.Resource[NotificationTemplateAttributes], 0, len(templates))
	for i := range templates {
		data = append(data, formatNotificationTemplate(&templates[i]))
	}
	jsonapi.WriteDocument(c, http.StatusOK, data)
}

// Create a notification template.
// POST /api/v2/organizations/:name/ansible/notification-templates
func (h *NotificationHandler) Create(c *gin.Context) {
	org := h.resolveOrg(c, true)
	if org == nil {
		return
	}
	var req notificationTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "name is required")
		return
	}
	nType := models.NotificationType(req.Type)
	if nType != models.NotificationTypeWebhook && nType != models.NotificationTypeEmail && nType != models.NotificationTypeTeams {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "type must be webhook, email, or teams")
		return
	}
	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		configJSON = []byte("{}")
	}
	template := &models.AnsibleNotificationTemplate{
		OrganizationID: org.ID,
		Name:           req.Name,
		Description:    req.Description,
		Type:           nType,
		Config:         datatypes.JSON(configJSON),
	}
	if req.Secret != nil && *req.Secret != "" && h.cryptoService != nil {
		encrypted, err := h.cryptoService.Encrypt(*req.Secret)
		if err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to encrypt secret")
			return
		}
		template.Secret = encrypted
	}
	if err := h.repo.Create(template); err != nil {
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", "Failed to create notification template (name may already exist)")
		return
	}
	jsonapi.WriteDocument(c, http.StatusCreated, formatNotificationTemplate(template))
}

// Update a notification template.
// PATCH /api/v2/ansible/notification-templates/:id
func (h *NotificationHandler) Update(c *gin.Context) {
	template := h.resolveTemplate(c, true)
	if template == nil {
		return
	}
	var req notificationTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if req.Name != "" {
		template.Name = req.Name
	}
	template.Description = req.Description
	if req.Config != nil {
		if configJSON, err := json.Marshal(req.Config); err == nil {
			template.Config = datatypes.JSON(configJSON)
		}
	}
	if req.Secret != nil && h.cryptoService != nil {
		if *req.Secret == "" {
			template.Secret = ""
		} else if encrypted, err := h.cryptoService.Encrypt(*req.Secret); err == nil {
			template.Secret = encrypted
		}
	}
	if err := h.repo.Update(template); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update notification template")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, formatNotificationTemplate(template))
}

// Delete a notification template (and its attachments).
// DELETE /api/v2/ansible/notification-templates/:id
func (h *NotificationHandler) Delete(c *gin.Context) {
	template := h.resolveTemplate(c, true)
	if template == nil {
		return
	}
	if err := h.repo.Delete(template.ID); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete notification template")
		return
	}
	c.Status(http.StatusNoContent)
}

// TestSend delivers a synthetic payload over the template's channel.
// POST /api/v2/ansible/notification-templates/:id/test
func (h *NotificationHandler) TestSend(c *gin.Context) {
	template := h.resolveTemplate(c, true)
	if template == nil {
		return
	}
	if h.notificationSvc == nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Notification service not configured")
		return
	}
	if err := h.notificationSvc.TestSend(c.Request.Context(), template.ID); err != nil {
		jsonapi.WriteError(c, http.StatusBadGateway, "Bad Gateway", err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

// resolveTemplate loads a template by :id and checks org permission on its org.
func (h *NotificationHandler) resolveTemplate(c *gin.Context, write bool) *models.AnsibleNotificationTemplate {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid notification template ID")
		return nil
	}
	template, err := h.repo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Notification template not found")
		return nil
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil
	}
	var hasPermission bool
	if write {
		hasPermission, err = h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, template.OrganizationID)
	} else {
		hasPermission, err = h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, template.OrganizationID)
	}
	if err != nil || !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this notification template")
		return nil
	}
	return template
}

type attachRequest struct {
	NotificationTemplateID string `json:"notification_template_id"`
	JobTemplateID          string `json:"job_template_id"`
	WorkflowID             string `json:"workflow_id"`
	OnStarted              bool   `json:"on_started"`
	OnSuccess              bool   `json:"on_success"`
	OnFailure              bool   `json:"on_failure"`
}

// Attach binds a notification template to a job template or workflow.
// POST /api/v2/organizations/:name/ansible/notification-attachments
func (h *NotificationHandler) Attach(c *gin.Context) {
	org := h.resolveOrg(c, true)
	if org == nil {
		return
	}
	var req attachRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.NotificationTemplateID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "notification_template_id is required")
		return
	}
	if (req.JobTemplateID == "") == (req.WorkflowID == "") {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "exactly one of job_template_id or workflow_id is required")
		return
	}
	ntID, err := uuid.Parse(req.NotificationTemplateID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid notification template ID")
		return
	}
	notification, err := h.repo.GetByID(ntID)
	if err != nil || notification.OrganizationID != org.ID {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Notification template not found in this organization")
		return
	}

	attachment := &models.AnsibleNotificationAttachment{
		NotificationTemplateID: ntID,
		OnStarted:              req.OnStarted,
		OnSuccess:              req.OnSuccess,
		OnFailure:              req.OnFailure,
	}
	if req.JobTemplateID != "" {
		jtID, err := uuid.Parse(req.JobTemplateID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid job template ID")
			return
		}
		jobTemplate, err := h.templateRepo.GetByID(jtID)
		if err != nil || jobTemplate.Project.OrganizationID != org.ID {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Job template not found in this organization")
			return
		}
		attachment.JobTemplateID = &jtID
	} else {
		wfID, err := uuid.Parse(req.WorkflowID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workflow ID")
			return
		}
		workflow, err := h.workflowRepo.GetByID(wfID)
		if err != nil || workflow.OrganizationID != org.ID {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workflow not found in this organization")
			return
		}
		attachment.WorkflowID = &wfID
	}

	if err := h.repo.CreateAttachment(attachment); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to attach notification")
		return
	}
	jsonapi.WriteDocument(c, http.StatusCreated, formatAttachment(attachment, &notification.Name))
}

// Detach removes a notification attachment.
// DELETE /api/v2/organizations/:name/ansible/notification-attachments/:attachment_id
func (h *NotificationHandler) Detach(c *gin.Context) {
	org := h.resolveOrg(c, true)
	if org == nil {
		return
	}
	id, err := uuid.Parse(c.Param("attachment_id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid attachment ID")
		return
	}
	// Org boundary: the attachment's channel must belong to the URL org, or a
	// caller could delete another org's attachment by ID.
	attachment, err := h.repo.GetAttachmentByID(id)
	if err != nil || attachment.NotificationTemplate.OrganizationID != org.ID {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Notification attachment not found in this organization")
		return
	}
	if err := h.repo.DeleteAttachment(id); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to detach notification")
		return
	}
	c.Status(http.StatusNoContent)
}

// ListForJobTemplate lists a job template's notification attachments.
// GET /api/v2/ansible/job-templates/:id/notifications
func (h *NotificationHandler) ListForJobTemplate(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid job template ID")
		return
	}
	// Authorize: the caller must be able to read Ansible in the template's
	// organization (attachments expose channel names + trigger config).
	template, err := h.templateRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Job template not found")
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	hasPermission, err := h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, template.Project.OrganizationID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You don't have permission to view this template's notifications")
		return
	}
	attachments, err := h.repo.ListAttachmentsByJobTemplate(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list notifications")
		return
	}
	data := make([]jsonapi.Resource[NotificationAttachmentAttributes], 0, len(attachments))
	for i := range attachments {
		data = append(data, formatAttachment(&attachments[i], &attachments[i].NotificationTemplate.Name))
	}
	jsonapi.WriteDocument(c, http.StatusOK, data)
}

func formatAttachment(a *models.AnsibleNotificationAttachment, templateName *string) jsonapi.Resource[NotificationAttachmentAttributes] {
	attrs := NotificationAttachmentAttributes{
		OnStarted: a.OnStarted,
		OnSuccess: a.OnSuccess,
		OnFailure: a.OnFailure,
	}
	if templateName != nil {
		attrs.NotificationTemplateName = *templateName
	}
	rels := NotificationAttachmentRelationships{
		NotificationTemplate: jsonapi.ToOne(a.NotificationTemplateID.String(), "ansible-notification-templates"),
	}
	if a.JobTemplateID != nil {
		r := jsonapi.ToOne(a.JobTemplateID.String(), "ansible-job-templates")
		rels.JobTemplate = &r
	}
	if a.WorkflowID != nil {
		r := jsonapi.ToOne(a.WorkflowID.String(), "ansible-workflows")
		rels.Workflow = &r
	}
	return jsonapi.Resource[NotificationAttachmentAttributes]{
		ID:            a.ID.String(),
		Type:          "ansible-notification-attachments",
		Attributes:    attrs,
		Relationships: rels,
	}
}
