// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// SetCredentialRepo wires the credential repository used by the template
// multi-credential endpoints (optional setter to avoid constructor churn).
func (h *PlaybookHandler) SetCredentialRepo(repo *repository.AnsibleCredentialRepository) {
	h.credentialRepo = repo
}

// resolveTemplateForCredentialOp loads the template and checks the caller's
// permission. Writes the error response and returns nil on failure.
func (h *PlaybookHandler) resolveTemplateForCredentialOp(c *gin.Context, permission rbac.Permission) *models.AnsibleJobTemplate {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid job template ID"}}})
		return nil
	}
	template, err := h.templateRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Job template not found"}}})
		return nil
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return nil
	}
	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(), user.ID, rbac.ResourceTypeAnsibleJobTemplate, template.ID.String(), permission, &template.ProjectID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to check permissions"}}})
		return nil
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to manage this job template"}}})
		return nil
	}
	return template
}

func formatTemplateCredential(cred *models.AnsibleCredential) gin.H {
	return gin.H{
		"id":   cred.ID.String(),
		"type": "ansible-credentials",
		"attributes": gin.H{
			"name":            cred.Name,
			"credential-type": cred.Type,
			"vault-id":        cred.VaultID,
			"username":        cred.Username,
		},
	}
}

// GetTemplateAccess returns a read-only summary of which teams can read,
// edit, and execute this job template (org + project access combined).
// GET /api/v2/ansible/job-templates/:id/access
func (h *PlaybookHandler) GetTemplateAccess(c *gin.Context) {
	template := h.resolveTemplateForCredentialOp(c, rbac.PermissionAnsibleJobTemplateRead)
	if template == nil {
		return
	}
	access, err := h.rbacService.GetTeamAccessForAnsibleTemplate(template.Project.OrganizationID, template.ProjectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to compute team access"}}})
		return
	}
	data := make([]gin.H, 0, len(access))
	for _, a := range access {
		data = append(data, gin.H{
			"id":   a.TeamID.String(),
			"type": "team-access",
			"attributes": gin.H{
				"team-name": a.TeamName,
				"read":      a.Read,
				"write":     a.Write,
				"execute":   a.Execute,
			},
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

// ListTemplateCredentials lists the template's attached credentials.
// GET /api/v2/ansible/job-templates/:id/credentials
func (h *PlaybookHandler) ListTemplateCredentials(c *gin.Context) {
	template := h.resolveTemplateForCredentialOp(c, rbac.PermissionAnsibleJobTemplateRead)
	if template == nil {
		return
	}
	creds, err := h.templateRepo.ListCredentials(template.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to list credentials"}}})
		return
	}
	data := make([]gin.H, 0, len(creds))
	for i := range creds {
		data = append(data, formatTemplateCredential(&creds[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

// AttachTemplateCredential attaches a credential to the template's set,
// enforcing the AWX multi-credential rule (one per type; multiple vaults with
// distinct vault IDs).
// POST /api/v2/ansible/job-templates/:id/credentials  {"credential_id": "..."}
func (h *PlaybookHandler) AttachTemplateCredential(c *gin.Context) {
	template := h.resolveTemplateForCredentialOp(c, rbac.PermissionAnsibleJobTemplateWrite)
	if template == nil {
		return
	}
	var req struct {
		CredentialID string `json:"credential_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.CredentialID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "credential_id is required"}}})
		return
	}
	credID, err := uuid.Parse(req.CredentialID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid credential ID"}}})
		return
	}
	if h.credentialRepo == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Credential repository not configured"}}})
		return
	}
	cred, err := h.credentialRepo.GetByID(credID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Credential not found"}}})
		return
	}
	// The org is the tenant boundary (credentials are org-scoped; the template's
	// org comes via its project).
	if template.Project.OrganizationID != cred.OrganizationID {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Credential does not belong to this template's organization"}}})
		return
	}
	if err := h.templateRepo.AttachCredential(template.ID, cred); err != nil {
		c.JSON(http.StatusConflict, gin.H{"errors": []gin.H{{"status": "409", "title": "Conflict", "detail": err.Error()}}})
		return
	}
	// Keep the legacy single credential reference in sync with the machine
	// credential so older consumers keep working.
	if cred.Type == models.CredentialTypeSSH || cred.Type == models.CredentialTypeMachineSSH {
		template.CredentialID = &cred.ID
		if err := h.templateRepo.Update(template); err != nil {
			logger.Warnf("Failed to sync legacy credential_id on template %s: %v", template.ID, err)
		}
	}
	c.JSON(http.StatusCreated, gin.H{"data": formatTemplateCredential(cred)})
}

// DetachTemplateCredential removes a credential from the template's set.
// DELETE /api/v2/ansible/job-templates/:id/credentials/:credential_id
func (h *PlaybookHandler) DetachTemplateCredential(c *gin.Context) {
	template := h.resolveTemplateForCredentialOp(c, rbac.PermissionAnsibleJobTemplateWrite)
	if template == nil {
		return
	}
	credID, err := uuid.Parse(c.Param("credential_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid credential ID"}}})
		return
	}
	if err := h.templateRepo.DetachCredential(template.ID, credID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to detach credential"}}})
		return
	}
	if template.CredentialID != nil && *template.CredentialID == credID {
		template.CredentialID = nil
		if err := h.templateRepo.Update(template); err != nil {
			logger.Warnf("Failed to clear legacy credential_id on template %s: %v", template.ID, err)
		}
	}
	c.Status(http.StatusNoContent)
}
