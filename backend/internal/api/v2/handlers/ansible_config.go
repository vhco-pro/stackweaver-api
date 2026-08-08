// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// AnsibleConfigHandler handles ansible config API endpoints
type AnsibleConfigHandler struct {
	configRepo  *repository.AnsibleConfigRepository
	orgRepo     *repository.OrganizationRepository
	projectRepo *repository.ProjectRepository
	rbacService *rbac.Service
	db          *gorm.DB
}

// NewAnsibleConfigHandler creates a new ansible config handler
func NewAnsibleConfigHandler(
	configRepo *repository.AnsibleConfigRepository,
	orgRepo *repository.OrganizationRepository,
	projectRepo *repository.ProjectRepository,
	rbacService *rbac.Service,
	db *gorm.DB,
) *AnsibleConfigHandler {
	return &AnsibleConfigHandler{
		configRepo:  configRepo,
		orgRepo:     orgRepo,
		projectRepo: projectRepo,
		rbacService: rbacService,
		db:          db,
	}
}

// AnsibleConfigRequest is the JSON:API request body for upserting an ansible
// config (#608): { data: { type, attributes: { "config-content": "..." } } },
// matching the envelope every other /api/v2 write endpoint accepts.
type AnsibleConfigRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			ConfigContent string `json:"config-content" binding:"required"`
		} `json:"attributes" binding:"required"`
	} `json:"data" binding:"required"`
}

// buildAnsibleConfigResponse renders the standard JSON:API resource object
// (#608): attributes nested and dasherized, scope parents expressed as
// relationships rather than flat *_id attributes.
func buildAnsibleConfigResponse(config *models.AnsibleConfig) gin.H {
	resp := gin.H{
		"type": "ansible-configs",
		"id":   config.ID.String(),
		"attributes": gin.H{
			"scope":          config.Scope(),
			"config-content": config.ConfigContent,
			"created-at":     config.CreatedAt.Format("2006-01-02T15:04:05Z"),
			"updated-at":     config.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		},
	}
	relationships := gin.H{}
	if config.OrganizationID != nil {
		relationships["organization"] = gin.H{"data": gin.H{"type": "organizations", "id": config.OrganizationID.String()}}
	}
	if config.ProjectID != nil {
		relationships["project"] = gin.H{"data": gin.H{"type": "projects", "id": config.ProjectID.String()}}
	}
	if config.WorkspaceID != nil {
		relationships["workspace"] = gin.H{"data": gin.H{"type": "workspaces", "id": *config.WorkspaceID}}
	}
	if len(relationships) > 0 {
		resp["relationships"] = relationships
	}
	return resp
}

// GetByOrganization returns the org-level ansible config
// GET /api/v2/organizations/:name/ansible-config
func (h *AnsibleConfigHandler) GetByOrganization(c *gin.Context) {
	orgName := c.Param("name")

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Organization not found"}}})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		}
		return
	}

	config, err := h.configRepo.GetByOrganization(org.ID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Ansible config not found"}}})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": buildAnsibleConfigResponse(config)})
}

// UpsertByOrganization creates or updates the org-level ansible config
// PUT /api/v2/organizations/:name/ansible-config
func (h *AnsibleConfigHandler) UpsertByOrganization(c *gin.Context) {
	orgName := c.Param("name")

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Organization not found"}}})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		}
		return
	}

	// Check permissions
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized"}}})
		return
	}
	// The auth middleware stores user_id as uuid.UUID (auth/service.go
	// c.Set("user_id", user.ID)). The pre-#608 string assertion here panicked
	// on every write - unreachable until the request binding was fixed, since
	// the old body shape 400'd first.
	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized"}}})
		return
	}

	// Require org manage-workspaces permission (ansible configs affect workspace execution)
	hasAccess, err := h.rbacService.CheckOrgManageWorkspaces(c.Request.Context(), userUUID, org.ID)
	if err != nil || !hasAccess {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "Organization manage-workspaces permission required"}}})
		return
	}

	var req AnsibleConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}}})
		return
	}

	config := &models.AnsibleConfig{
		OrganizationID: &org.ID,
		ConfigContent:  req.Data.Attributes.ConfigContent,
		CreatedByID:    userUUID,
		UpdatedByID:    userUUID,
	}

	if err := h.configRepo.Upsert(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		return
	}

	// Fetch the updated config
	config, _ = h.configRepo.GetByOrganization(org.ID)

	c.JSON(http.StatusOK, gin.H{"data": buildAnsibleConfigResponse(config)})
}

// DeleteByOrganization deletes the org-level ansible config
// DELETE /api/v2/organizations/:name/ansible-config
func (h *AnsibleConfigHandler) DeleteByOrganization(c *gin.Context) {
	orgName := c.Param("name")

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Organization not found"}}})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		}
		return
	}

	// Check permissions
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized"}}})
		return
	}
	// The auth middleware stores user_id as uuid.UUID (auth/service.go
	// c.Set("user_id", user.ID)). The pre-#608 string assertion here panicked
	// on every write - unreachable until the request binding was fixed, since
	// the old body shape 400'd first.
	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized"}}})
		return
	}

	// Require org manage-workspaces permission
	hasAccess, err := h.rbacService.CheckOrgManageWorkspaces(c.Request.Context(), userUUID, org.ID)
	if err != nil || !hasAccess {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "Organization manage-workspaces permission required"}}})
		return
	}

	config, err := h.configRepo.GetByOrganization(org.ID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Ansible config not found"}}})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		}
		return
	}

	if err := h.configRepo.Delete(config.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetByProject returns the project-level ansible config
// GET /api/v2/projects/:id/ansible-config
func (h *AnsibleConfigHandler) GetByProject(c *gin.Context) {
	projectIDStr := c.Param("id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Invalid project ID"}}})
		return
	}

	config, err := h.configRepo.GetByProject(projectID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Ansible config not found"}}})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": buildAnsibleConfigResponse(config)})
}

// UpsertByProject creates or updates the project-level ansible config
// PUT /api/v2/projects/:id/ansible-config
func (h *AnsibleConfigHandler) UpsertByProject(c *gin.Context) {
	projectIDStr := c.Param("id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Invalid project ID"}}})
		return
	}

	// Get project to verify it exists
	project, err := h.projectRepo.GetByID(projectID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Project not found"}}})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		}
		return
	}

	// Check permissions
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized"}}})
		return
	}
	// The auth middleware stores user_id as uuid.UUID (auth/service.go
	// c.Set("user_id", user.ID)). The pre-#608 string assertion here panicked
	// on every write - unreachable until the request binding was fixed, since
	// the old body shape 400'd first.
	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized"}}})
		return
	}

	// Require org manage-workspaces permission (project ansible configs affect workspace execution)
	hasAccess, err := h.rbacService.CheckOrgManageWorkspaces(c.Request.Context(), userUUID, project.OrganizationID)
	if err != nil || !hasAccess {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "Organization manage-workspaces permission required"}}})
		return
	}

	var req AnsibleConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}}})
		return
	}

	config := &models.AnsibleConfig{
		ProjectID:     &projectID,
		ConfigContent: req.Data.Attributes.ConfigContent,
		CreatedByID:   userUUID,
		UpdatedByID:   userUUID,
	}

	if err := h.configRepo.Upsert(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		return
	}

	// Fetch the updated config
	config, _ = h.configRepo.GetByProject(projectID)

	c.JSON(http.StatusOK, gin.H{"data": buildAnsibleConfigResponse(config)})
}

// DeleteByProject deletes the project-level ansible config
// DELETE /api/v2/projects/:id/ansible-config
func (h *AnsibleConfigHandler) DeleteByProject(c *gin.Context) {
	projectIDStr := c.Param("id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Invalid project ID"}}})
		return
	}

	// Get project to verify it exists
	project, err := h.projectRepo.GetByID(projectID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Project not found"}}})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		}
		return
	}

	// Check permissions
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized"}}})
		return
	}
	// The auth middleware stores user_id as uuid.UUID (auth/service.go
	// c.Set("user_id", user.ID)). The pre-#608 string assertion here panicked
	// on every write - unreachable until the request binding was fixed, since
	// the old body shape 400'd first.
	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized"}}})
		return
	}

	// Require org manage-workspaces permission
	hasAccess, err := h.rbacService.CheckOrgManageWorkspaces(c.Request.Context(), userUUID, project.OrganizationID)
	if err != nil || !hasAccess {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "Organization manage-workspaces permission required"}}})
		return
	}

	config, err := h.configRepo.GetByProject(projectID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Ansible config not found"}}})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		}
		return
	}

	if err := h.configRepo.Delete(config.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetEffective returns the effective ansible config for a given scope
// GET /api/v2/organizations/:name/ansible-config/effective?project_id=...&workspace_id=...
func (h *AnsibleConfigHandler) GetEffective(c *gin.Context) {
	orgName := c.Param("name")

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Organization not found"}}})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		}
		return
	}

	projectIDStr := c.Query("project_id")
	workspaceID := c.Query("workspace_id")

	var projectID uuid.UUID
	if projectIDStr != "" {
		projectID, _ = uuid.Parse(projectIDStr)
	}

	config, err := h.configRepo.GetForWorkspace(workspaceID, projectID, org.ID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "No ansible config found at any scope"}}})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error"}}})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": buildAnsibleConfigResponse(config)})
}
