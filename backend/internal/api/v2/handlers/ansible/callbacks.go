// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

// ProvisioningCallbackHandler serves AWX-style provisioning callbacks: a
// freshly provisioned host POSTs the template's host config key to request its
// own configuration; the launched job is limited to that host. The endpoint is
// public (key-authenticated) and must be registered outside the auth
// middleware, mirroring the VCS webhook endpoints.
type ProvisioningCallbackHandler struct {
	templateRepo  *repository.AnsibleJobTemplateRepository
	inventoryRepo *repository.AnsibleInventoryRepository
	jobService    *ansible.JobService
}

// NewProvisioningCallbackHandler creates a provisioning callback handler.
func NewProvisioningCallbackHandler(
	templateRepo *repository.AnsibleJobTemplateRepository,
	inventoryRepo *repository.AnsibleInventoryRepository,
	jobService *ansible.JobService,
) *ProvisioningCallbackHandler {
	return &ProvisioningCallbackHandler{
		templateRepo:  templateRepo,
		inventoryRepo: inventoryRepo,
		jobService:    jobService,
	}
}

// Handle processes a provisioning callback.
// POST /api/v2/ansible/job-templates/:id/callback  {"host_config_key": "..."}
func (h *ProvisioningCallbackHandler) Handle(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid job template ID"}}})
		return
	}
	var req struct {
		HostConfigKey string `json:"host_config_key"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.HostConfigKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "host_config_key is required"}}})
		return
	}
	template, err := h.templateRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Job template not found"}}})
		return
	}
	if !template.AllowCallbacks || template.HostConfigKey == "" ||
		subtle.ConstantTimeCompare([]byte(template.HostConfigKey), []byte(req.HostConfigKey)) != 1 {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "Provisioning callbacks are not enabled for this template or the key is wrong"}}})
		return
	}
	if template.Disabled {
		c.JSON(http.StatusConflict, gin.H{"errors": []gin.H{{"status": "409", "title": "Conflict", "detail": "Job template is disabled"}}})
		return
	}

	// The requesting host must exist in the template's inventory: match the
	// caller's IP against host names and connection addresses.
	clientIP := c.ClientIP()
	hostName := h.findRequestingHost(template.InventoryID, clientIP)
	if hostName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Requesting host " + clientIP + " was not found in the template's inventory"}}})
		return
	}

	input := ansible.LaunchJobInput{
		ProjectID:     template.ProjectID,
		PlaybookID:    template.PlaybookID,
		InventoryID:   template.InventoryID,
		TemplateID:    &template.ID,
		Name:          "Callback: " + template.Name + " (" + hostName + ")",
		JobType:       models.AnsibleJobTypeRun,
		ExtraVars:     models.JobExtraVars(template.ExtraVars),
		Limit:         hostName, // callbacks only configure the requesting host
		Tags:          template.Tags,
		SkipTags:      template.SkipTags,
		Verbosity:     template.Verbosity,
		Forks:         template.Forks,
		CredentialID:  template.CredentialID,
		AgentPoolID:   template.AgentPoolID,
		BecomeEnabled: template.BecomeEnabled,
		DiffMode:      template.DiffMode,
	}
	job, err := h.jobService.LaunchJob(c.Request.Context(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": err.Error()}}})
		return
	}
	logger.Infof("Provisioning callback: launched job %s for host %s (template %s)", job.ID, hostName, template.Name)
	c.JSON(http.StatusCreated, gin.H{"data": gin.H{"id": job.ID.String(), "type": "ansible-jobs", "attributes": gin.H{"status": job.Status, "limit": hostName}}})
}

// findRequestingHost matches a client IP against the inventory's hosts (name,
// connection hostname, or ansible_host variable). Returns the inventory host
// name or "".
func (h *ProvisioningCallbackHandler) findRequestingHost(inventoryID uuid.UUID, clientIP string) string {
	const pageSize = 500
	for offset := 0; ; offset += pageSize {
		hosts, _, err := h.inventoryRepo.ListHostsByInventory(inventoryID, pageSize, offset)
		if err != nil || len(hosts) == 0 {
			return ""
		}
		for i := range hosts {
			host := &hosts[i]
			if host.Name == clientIP || host.Hostname == clientIP {
				return host.Name
			}
			if ah, ok := host.Variables["ansible_host"].(string); ok && ah == clientIP {
				return host.Name
			}
		}
		if len(hosts) < pageSize {
			return ""
		}
	}
}
