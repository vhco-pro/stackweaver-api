// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

// CredentialHandler handles Ansible credential API endpoints
type CredentialHandler struct {
	credentialService *ansible.CredentialService
	orgRepo           *repository.OrganizationRepository
	projectRepo       *repository.ProjectRepository
	authService       *auth.Service
	rbacService       *rbac.Service
}

// NewCredentialHandler creates a new credential handler
func NewCredentialHandler(
	credentialService *ansible.CredentialService,
	orgRepo *repository.OrganizationRepository,
	projectRepo *repository.ProjectRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *CredentialHandler {
	return &CredentialHandler{
		credentialService: credentialService,
		orgRepo:           orgRepo,
		projectRepo:       projectRepo,
		authService:       authService,
		rbacService:       rbacService,
	}
}

// CreateCredentialRequest represents the request to create a credential
type CreateCredentialRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name               string `json:"name" binding:"required"`
			Description        string `json:"description"`
			Type               string `json:"credential-type" binding:"required"`
			Username           string `json:"username"`
			SSHPrivateKey      string `json:"ssh-private-key"` //nolint:gosec // G117: credential field
			SSHPassphrase      string `json:"ssh-passphrase"`
			Password           string `json:"password"`              //nolint:gosec // G117: credential field
			VaultPassword      string `json:"vault-password"`        //nolint:gosec // G117: credential field
			BecomePassword     string `json:"become-password"`       //nolint:gosec // G117: credential field
			AWSAccessKeyID     string `json:"aws-access-key-id"`     //nolint:gosec // G117: credential field
			AWSSecretAccessKey string `json:"aws-secret-access-key"` //nolint:gosec // G117: credential field
			AzureTenantID      string `json:"azure-tenant-id"`
			AzureClientID      string `json:"azure-client-id"`
			AzureClientSecret  string `json:"azure-client-secret"` //nolint:gosec // G117: credential field
			GCPServiceAccount  string `json:"gcp-service-account"`
			SSHPort            int    `json:"ssh-port"`
			SSHBecomeUser      string `json:"ssh-become-user"`
		} `json:"attributes"`
		Relationships struct {
			Project struct {
				Data *struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"project"`
		} `json:"relationships"`
	} `json:"data"`
}

// UpdateCredentialRequest represents the request to update a credential
type UpdateCredentialRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name               *string `json:"name"`
			Description        *string `json:"description"`
			Username           *string `json:"username"`
			SSHPrivateKey      *string `json:"ssh-private-key"` //nolint:gosec // G117: credential field
			SSHPassphrase      *string `json:"ssh-passphrase"`
			Password           *string `json:"password"`              //nolint:gosec // G117: credential field
			VaultPassword      *string `json:"vault-password"`        //nolint:gosec // G117: credential field
			BecomePassword     *string `json:"become-password"`       //nolint:gosec // G117: credential field
			AWSAccessKeyID     *string `json:"aws-access-key-id"`     //nolint:gosec // G117: credential field
			AWSSecretAccessKey *string `json:"aws-secret-access-key"` //nolint:gosec // G117: credential field
			AzureTenantID      *string `json:"azure-tenant-id"`
			AzureClientID      *string `json:"azure-client-id"`
			AzureClientSecret  *string `json:"azure-client-secret"` //nolint:gosec // G117: credential field
			GCPServiceAccount  *string `json:"gcp-service-account"`
			SSHPort            *int    `json:"ssh-port"`
			SSHBecomeUser      *string `json:"ssh-become-user"`
		} `json:"attributes"`
		Relationships struct {
			Project struct {
				Data *struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"project"`
		} `json:"relationships"`
	} `json:"data"`
}

// List lists all credentials for an organization
// GET /api/v2/organizations/:name/ansible/credentials
func (h *CredentialHandler) List(c *gin.Context) {
	orgName := c.Param("name")

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	hasPermission, err := h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to list credentials in this organization")
		return
	}

	page, perPage := jsonapi.PageParams(c, 20, 100)
	offset := (page - 1) * perPage

	// Optional type filter
	credTypeFilter := c.Query("filter[type]")

	var credentials []models.AnsibleCredential
	var total int64

	if credTypeFilter != "" {
		credType := models.CredentialType(credTypeFilter)
		credentials, total, err = h.credentialService.ListCredentialsByType(org.ID, credType, perPage, offset)
	} else {
		credentials, total, err = h.credentialService.ListCredentials(org.ID, perPage, offset)
	}

	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list credentials")
		return
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, formatCredentialsResponse(credentials), jsonapi.NewPaginationMeta(page, perPage, total))
}

// Create creates a new credential
// POST /api/v2/organizations/:name/ansible/credentials
func (h *CredentialHandler) Create(c *gin.Context) {
	orgName := c.Param("name")

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	hasPermission, err := h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to create credentials in this organization")
		return
	}

	var req CreateCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	// Validate credential type
	credType := models.CredentialType(req.Data.Attributes.Type)
	switch credType {
	case models.CredentialTypeSSH, models.CredentialTypeSCM, models.CredentialTypeVault,
		models.CredentialTypeMachineSSH, models.CredentialTypeAWSAccessKey,
		models.CredentialTypeAzure, models.CredentialTypeGCP, models.CredentialTypeVMware:
		// Valid
	default:
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid credential type")
		return
	}

	// Parse project ID if provided, otherwise use default project
	var projectID *uuid.UUID
	if req.Data.Relationships.Project.Data != nil {
		pid, err := uuid.Parse(req.Data.Relationships.Project.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid project ID")
			return
		}
		// Verify project belongs to organization
		project, err := h.projectRepo.GetByID(pid)
		if err != nil || project.OrganizationID != org.ID {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Project not found or does not belong to organization")
			return
		}
		projectID = &pid
	} else {
		// Use default project
		defaultProject, err := h.projectRepo.GetByOrganizationAndName(org.ID, "default")
		if err == nil && defaultProject != nil {
			projectID = &defaultProject.ID
		} else {
			// Create default project if it doesn't exist
			defaultProject = &models.Project{
				OrganizationID: org.ID,
				Name:           "default",
				Description:    "Default project for your organization",
			}
			if err := h.projectRepo.Create(defaultProject); err != nil {
				jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to get default project")
				return
			}
			projectID = &defaultProject.ID
		}
	}

	input := ansible.CreateCredentialInput{
		OrganizationID:     org.ID,
		ProjectID:          projectID,
		Name:               req.Data.Attributes.Name,
		Description:        req.Data.Attributes.Description,
		Type:               credType,
		Username:           req.Data.Attributes.Username,
		SSHPrivateKey:      req.Data.Attributes.SSHPrivateKey,
		SSHPassphrase:      req.Data.Attributes.SSHPassphrase,
		Password:           req.Data.Attributes.Password,
		VaultPassword:      req.Data.Attributes.VaultPassword,
		BecomePassword:     req.Data.Attributes.BecomePassword,
		AWSAccessKeyID:     req.Data.Attributes.AWSAccessKeyID,
		AWSSecretAccessKey: req.Data.Attributes.AWSSecretAccessKey,
		AzureTenantID:      req.Data.Attributes.AzureTenantID,
		AzureClientID:      req.Data.Attributes.AzureClientID,
		AzureClientSecret:  req.Data.Attributes.AzureClientSecret,
		GCPServiceAccount:  req.Data.Attributes.GCPServiceAccount,
		SSHPort:            req.Data.Attributes.SSHPort,
		SSHBecomeUser:      req.Data.Attributes.SSHBecomeUser,
	}

	credential, err := h.credentialService.CreateCredential(input)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, formatCredentialResponse(credential))
}

// Get retrieves a credential by ID
// GET /api/v2/ansible/credentials/:id
func (h *CredentialHandler) Get(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid credential ID")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	credential, err := h.credentialService.GetCredential(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Credential not found")
		return
	}

	// RBAC: if credential is project-scoped, check project-level permission; otherwise check org-level
	var hasPermission bool
	if credential.ProjectID != nil {
		hasPermission, err = h.rbacService.CheckAnsibleResourcePermission(
			c.Request.Context(),
			user.ID,
			rbac.ResourceTypeAnsibleCredential,
			credential.ID.String(),
			rbac.PermissionAnsibleCredentialRead,
			credential.ProjectID,
		)
	} else {
		hasPermission, err = h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, credential.OrganizationID)
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to view this credential")
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatCredentialResponse(credential))
}

// Update updates a credential
// PATCH /api/v2/ansible/credentials/:id
func (h *CredentialHandler) Update(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid credential ID")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	// Fetch existing credential for RBAC check and project validation
	existingCredential, err := h.credentialService.GetCredential(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Credential not found")
		return
	}

	// RBAC: if credential is project-scoped, check project-level permission; otherwise check org-level
	var hasPermission bool
	if existingCredential.ProjectID != nil {
		hasPermission, err = h.rbacService.CheckAnsibleResourcePermission(
			c.Request.Context(),
			user.ID,
			rbac.ResourceTypeAnsibleCredential,
			existingCredential.ID.String(),
			rbac.PermissionAnsibleCredentialWrite,
			existingCredential.ProjectID,
		)
	} else {
		hasPermission, err = h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, existingCredential.OrganizationID)
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to update this credential")
		return
	}

	var req UpdateCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	// Parse project ID if provided
	var projectID *uuid.UUID
	if req.Data.Relationships.Project.Data != nil {
		pid, err := uuid.Parse(req.Data.Relationships.Project.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid project ID")
			return
		}
		// Verify project belongs to same organization
		project, err := h.projectRepo.GetByID(pid)
		if err != nil || project.OrganizationID != existingCredential.OrganizationID {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Project not found or does not belong to organization")
			return
		}
		projectID = &pid
	}

	input := ansible.UpdateCredentialInput{
		ProjectID:          projectID,
		Name:               req.Data.Attributes.Name,
		Description:        req.Data.Attributes.Description,
		Username:           req.Data.Attributes.Username,
		SSHPrivateKey:      req.Data.Attributes.SSHPrivateKey,
		SSHPassphrase:      req.Data.Attributes.SSHPassphrase,
		Password:           req.Data.Attributes.Password,
		VaultPassword:      req.Data.Attributes.VaultPassword,
		BecomePassword:     req.Data.Attributes.BecomePassword,
		AWSAccessKeyID:     req.Data.Attributes.AWSAccessKeyID,
		AWSSecretAccessKey: req.Data.Attributes.AWSSecretAccessKey,
		AzureTenantID:      req.Data.Attributes.AzureTenantID,
		AzureClientID:      req.Data.Attributes.AzureClientID,
		AzureClientSecret:  req.Data.Attributes.AzureClientSecret,
		GCPServiceAccount:  req.Data.Attributes.GCPServiceAccount,
		SSHPort:            req.Data.Attributes.SSHPort,
		SSHBecomeUser:      req.Data.Attributes.SSHBecomeUser,
	}

	credential, err := h.credentialService.UpdateCredential(id, input)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatCredentialResponse(credential))
}

// Delete deletes a credential
// DELETE /api/v2/ansible/credentials/:id
func (h *CredentialHandler) Delete(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid credential ID")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	// Fetch credential for RBAC check
	credential, err := h.credentialService.GetCredential(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Credential not found")
		return
	}

	// RBAC: if credential is project-scoped, check project-level permission; otherwise check org-level
	var hasPermission bool
	if credential.ProjectID != nil {
		hasPermission, err = h.rbacService.CheckAnsibleResourcePermission(
			c.Request.Context(),
			user.ID,
			rbac.ResourceTypeAnsibleCredential,
			credential.ID.String(),
			rbac.PermissionAnsibleCredentialWrite,
			credential.ProjectID,
		)
	} else {
		hasPermission, err = h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, credential.OrganizationID)
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to delete this credential")
		return
	}

	if err := h.credentialService.DeleteCredential(id); err != nil {
		// Check for foreign key constraint violation
		errStr := err.Error()
		if strings.Contains(errStr, "violates foreign key constraint") {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", "Cannot delete credential: it is referenced by one or more job templates, jobs, or inventory sources. Remove the credential from those resources first.")
			return
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	c.Status(http.StatusNoContent)
}

// formatCredentialResponse formats a credential for JSON:API response
// Note: Sensitive fields are never included in responses
func formatCredentialResponse(cred *models.AnsibleCredential) jsonapi.Resource[CredentialAttributes] {
	return jsonapi.Resource[CredentialAttributes]{
		ID:   cred.ID.String(),
		Type: "ansible-credentials",
		Attributes: CredentialAttributes{
			Name:              cred.Name,
			Description:       cred.Description,
			CredentialType:    cred.Type,
			Username:          cred.Username,
			AzureTenantID:     cred.AzureTenantID,
			AzureClientID:     cred.AzureClientID,
			SSHPort:           cred.SSHPort,
			SSHBecomeUser:     cred.SSHBecomeUser,
			HasSSHPrivateKey:  cred.HasSSHPrivateKey,
			HasPassword:       cred.HasPassword,
			HasVaultPassword:  cred.HasVaultPassword,
			HasBecomePassword: cred.HasBecomePassword,
			CreatedAt:         cred.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:         cred.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		},
		Relationships: CredentialRelationships{
			Organization: jsonapi.ToOne(cred.OrganizationID.String(), "organizations"),
		},
	}
}

// formatCredentialsResponse formats multiple credentials for JSON:API response
func formatCredentialsResponse(credentials []models.AnsibleCredential) []jsonapi.Resource[CredentialAttributes] {
	result := make([]jsonapi.Resource[CredentialAttributes], len(credentials))
	for i, cred := range credentials {
		result[i] = formatCredentialResponse(&cred)
	}
	return result
}
