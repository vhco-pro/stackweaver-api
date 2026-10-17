// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/apierror"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
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
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid job template ID")
		return nil
	}
	template, err := h.templateRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Job template not found")
		return nil
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil
	}
	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(), user.ID, rbac.ResourceTypeAnsibleJobTemplate, template.ID.String(), permission, &template.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return nil
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this job template")
		return nil
	}
	return template
}

func formatTemplateCredential(cred *models.AnsibleCredential) jsonapi.Resource[TemplateCredentialAttributes] {
	return jsonapi.Resource[TemplateCredentialAttributes]{
		ID:   cred.ID.String(),
		Type: "ansible-credentials",
		Attributes: TemplateCredentialAttributes{
			Name:           cred.Name,
			CredentialType: cred.Type,
			VaultID:        cred.VaultID,
			Username:       cred.Username,
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
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to compute team access")
		return
	}
	data := make([]jsonapi.Resource[TeamAccessAttributes], 0, len(access))
	for _, a := range access {
		data = append(data, jsonapi.Resource[TeamAccessAttributes]{
			ID:   a.TeamID.String(),
			Type: "team-access",
			Attributes: TeamAccessAttributes{
				TeamName: a.TeamName,
				Read:     a.Read,
				Write:    a.Write,
				Execute:  a.Execute,
			},
		})
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewFullPageMeta(len(data)))
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
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list credentials")
		return
	}
	data := make([]jsonapi.Resource[TemplateCredentialAttributes], 0, len(creds))
	for i := range creds {
		data = append(data, formatTemplateCredential(&creds[i]))
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewFullPageMeta(len(data)))
}

// CredentialIdentifierRequest attaches an existing credential by identity alone, so its data is
// a resource identifier object: {"data": {"type": "ansible-credentials", "id": "<uuid>"}}
// (#858, D5).
type CredentialIdentifierRequest struct {
	Data *struct {
		Type string `json:"type"`
		ID   string `json:"id" binding:"required"`
	} `json:"data" binding:"required"`
}

// PrimaryType reports data.type and whether data was sent (jsonapi.TypedDocument).
func (r *CredentialIdentifierRequest) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
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
	var req CredentialIdentifierRequest
	if !jsonapi.BindIdentifier(c, &req, "ansible-credentials") {
		return
	}
	credID, err := uuid.Parse(req.Data.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid credential ID")
		return
	}
	if h.credentialRepo == nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Credential repository not configured")
		return
	}
	// The organization is the tenant boundary (credentials are org-scoped; the template's
	// organization comes via its project). The check is the one a template create and update
	// make, so a credential of another organization gets the same answer here as there, and the
	// same answer as one that does not exist: this handler used to tell the two apart with a
	// 400 and a 404.
	if !h.templateReferentsAccepted(c, template.ProjectID, nil, nil, []uuid.UUID{credID}, "Failed to attach credential") {
		return
	}
	cred, err := h.credentialRepo.GetByID(credID)
	if err != nil {
		// It was there a moment ago: deleted in between, or the database failed.
		apierror.Internal(c, "Failed to attach credential", err)
		return
	}
	if err := h.templateRepo.AttachCredential(template.ID, cred); err != nil {
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
		return
	}
	jsonapi.WriteDocument(c, http.StatusCreated, formatTemplateCredential(cred))
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
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid credential ID")
		return
	}
	if err := h.templateRepo.DetachCredential(template.ID, credID); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to detach credential")
		return
	}
	c.Status(http.StatusNoContent)
}
