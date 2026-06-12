// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Organization not found"}}})
		return nil
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return nil
	}
	var hasPermission bool
	if write {
		hasPermission, err = h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, org.ID)
	} else {
		hasPermission, err = h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, org.ID)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to check permissions"}}})
		return nil
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to manage notifications in this organization"}}})
		return nil
	}
	return org
}

func formatNotificationTemplate(t *models.AnsibleNotificationTemplate) gin.H {
	var config map[string]interface{}
	_ = json.Unmarshal(t.Config, &config)
	return gin.H{
		"id":   t.ID.String(),
		"type": "ansible-notification-templates",
		"attributes": gin.H{
			"name":              t.Name,
			"description":       t.Description,
			"notification-type": t.Type,
			"config":            config,
			"has-secret":        t.Secret != "",
			"created-at":        t.CreatedAt,
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
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to list notification templates"}}})
		return
	}
	data := make([]gin.H, 0, len(templates))
	for i := range templates {
		data = append(data, formatNotificationTemplate(&templates[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
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
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "name is required"}}})
		return
	}
	nType := models.NotificationType(req.Type)
	if nType != models.NotificationTypeWebhook && nType != models.NotificationTypeEmail && nType != models.NotificationTypeTeams {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "type must be webhook, email, or teams"}}})
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
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to encrypt secret"}}})
			return
		}
		template.Secret = encrypted
	}
	if err := h.repo.Create(template); err != nil {
		c.JSON(http.StatusConflict, gin.H{"errors": []gin.H{{"status": "409", "title": "Conflict", "detail": "Failed to create notification template (name may already exist)"}}})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": formatNotificationTemplate(template)})
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
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}}})
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
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to update notification template"}}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatNotificationTemplate(template)})
}

// Delete a notification template (and its attachments).
// DELETE /api/v2/ansible/notification-templates/:id
func (h *NotificationHandler) Delete(c *gin.Context) {
	template := h.resolveTemplate(c, true)
	if template == nil {
		return
	}
	if err := h.repo.Delete(template.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to delete notification template"}}})
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
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Notification service not configured"}}})
		return
	}
	if err := h.notificationSvc.TestSend(c.Request.Context(), template.ID); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"errors": []gin.H{{"status": "502", "title": "Bad Gateway", "detail": err.Error()}}})
		return
	}
	c.Status(http.StatusNoContent)
}

// resolveTemplate loads a template by :id and checks org permission on its org.
func (h *NotificationHandler) resolveTemplate(c *gin.Context, write bool) *models.AnsibleNotificationTemplate {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid notification template ID"}}})
		return nil
	}
	template, err := h.repo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Notification template not found"}}})
		return nil
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return nil
	}
	var hasPermission bool
	if write {
		hasPermission, err = h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, template.OrganizationID)
	} else {
		hasPermission, err = h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, template.OrganizationID)
	}
	if err != nil || !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to manage this notification template"}}})
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
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "notification_template_id is required"}}})
		return
	}
	if (req.JobTemplateID == "") == (req.WorkflowID == "") {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "exactly one of job_template_id or workflow_id is required"}}})
		return
	}
	ntID, err := uuid.Parse(req.NotificationTemplateID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid notification template ID"}}})
		return
	}
	notification, err := h.repo.GetByID(ntID)
	if err != nil || notification.OrganizationID != org.ID {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Notification template not found in this organization"}}})
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
			c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid job template ID"}}})
			return
		}
		jobTemplate, err := h.templateRepo.GetByID(jtID)
		if err != nil || jobTemplate.Project.OrganizationID != org.ID {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Job template not found in this organization"}}})
			return
		}
		attachment.JobTemplateID = &jtID
	} else {
		wfID, err := uuid.Parse(req.WorkflowID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid workflow ID"}}})
			return
		}
		workflow, err := h.workflowRepo.GetByID(wfID)
		if err != nil || workflow.OrganizationID != org.ID {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Workflow not found in this organization"}}})
			return
		}
		attachment.WorkflowID = &wfID
	}

	if err := h.repo.CreateAttachment(attachment); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to attach notification"}}})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": formatAttachment(attachment, &notification.Name)})
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
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid attachment ID"}}})
		return
	}
	// Org boundary: the attachment's channel must belong to the URL org, or a
	// caller could delete another org's attachment by ID.
	attachment, err := h.repo.GetAttachmentByID(id)
	if err != nil || attachment.NotificationTemplate.OrganizationID != org.ID {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Notification attachment not found in this organization"}}})
		return
	}
	if err := h.repo.DeleteAttachment(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to detach notification"}}})
		return
	}
	c.Status(http.StatusNoContent)
}

// ListForJobTemplate lists a job template's notification attachments.
// GET /api/v2/ansible/job-templates/:id/notifications
func (h *NotificationHandler) ListForJobTemplate(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid job template ID"}}})
		return
	}
	// Authorize: the caller must be able to read Ansible in the template's
	// organization (attachments expose channel names + trigger config).
	template, err := h.templateRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Job template not found"}}})
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return
	}
	hasPermission, err := h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, template.Project.OrganizationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to check permissions"}}})
		return
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You don't have permission to view this template's notifications"}}})
		return
	}
	attachments, err := h.repo.ListAttachmentsByJobTemplate(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to list notifications"}}})
		return
	}
	data := make([]gin.H, 0, len(attachments))
	for i := range attachments {
		data = append(data, formatAttachment(&attachments[i], &attachments[i].NotificationTemplate.Name))
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

func formatAttachment(a *models.AnsibleNotificationAttachment, templateName *string) gin.H {
	attrs := gin.H{
		"on-started": a.OnStarted,
		"on-success": a.OnSuccess,
		"on-failure": a.OnFailure,
	}
	if templateName != nil {
		attrs["notification-template-name"] = *templateName
	}
	rels := gin.H{
		"notification-template": gin.H{"data": gin.H{"id": a.NotificationTemplateID.String(), "type": "ansible-notification-templates"}},
	}
	if a.JobTemplateID != nil {
		rels["job-template"] = gin.H{"data": gin.H{"id": a.JobTemplateID.String(), "type": "ansible-job-templates"}}
	}
	if a.WorkflowID != nil {
		rels["workflow"] = gin.H{"data": gin.H{"id": a.WorkflowID.String(), "type": "ansible-workflows"}}
	}
	return gin.H{
		"id":            a.ID.String(),
		"type":          "ansible-notification-attachments",
		"attributes":    attrs,
		"relationships": rels,
	}
}
