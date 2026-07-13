// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// TagBindingHandlerV2 serves the TFE-compatible tag-binding endpoints on projects and workspaces:
//
//	GET/PATCH /projects/:id/tag-bindings          GET /projects/:id/effective-tag-bindings
//	GET/PATCH /workspaces/:id/tag-bindings        GET /workspaces/:id/effective-tag-bindings
type TagBindingHandlerV2 struct {
	tagRepo       *repository.TagBindingRepository
	projectRepo   *repository.ProjectRepository
	workspaceRepo *repository.WorkspaceRepository
	orgRepo       *repository.OrganizationRepository
	authService   *auth.Service
	rbacService   *rbac.Service
}

func NewTagBindingHandlerV2(tagRepo *repository.TagBindingRepository, projectRepo *repository.ProjectRepository, workspaceRepo *repository.WorkspaceRepository, orgRepo *repository.OrganizationRepository, authService *auth.Service, rbacService *rbac.Service) *TagBindingHandlerV2 {
	return &TagBindingHandlerV2{
		tagRepo:       tagRepo,
		projectRepo:   projectRepo,
		workspaceRepo: workspaceRepo,
		orgRepo:       orgRepo,
		authService:   authService,
		rbacService:   rbacService,
	}
}

func tagErr(c *gin.Context, status int, title, detail string) {
	c.JSON(status, gin.H{"errors": []gin.H{{"status": strconv.Itoa(status), "title": title, "detail": detail}}})
}

// formatTagBindings renders a list of tag bindings as JSON:API. resourceType is "tag-bindings" or
// "effective-tag-bindings". Effective bindings get a synthetic id (their key) since they are computed.
func formatTagBindings(bindings []models.TagBinding, resourceType string) gin.H {
	data := make([]gin.H, 0, len(bindings))
	for i := range bindings {
		b := bindings[i]
		id := b.ID
		if id == "" {
			id = b.Key // effective bindings are synthetic
		}
		data = append(data, gin.H{
			"type":       resourceType,
			"id":         id,
			"attributes": gin.H{"key": b.Key, "value": b.Value},
		})
	}
	return gin.H{"data": data}
}

// tagBindingsRequest is the PATCH body — a JSON:API list of tag-bindings (go-tfe AddTagBindings).
type tagBindingsRequest struct {
	Data []struct {
		Type       string `json:"type"`
		Attributes struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"attributes"`
	} `json:"data"`
}

func (r tagBindingsRequest) toBindings() []models.TagBinding {
	out := make([]models.TagBinding, 0, len(r.Data))
	for _, d := range r.Data {
		out = append(out, models.TagBinding{Key: d.Attributes.Key, Value: d.Attributes.Value})
	}
	return out
}

// TagBindingsRelationship renders the tag-bindings / effective-tag-bindings relationship object for a
// project/workspace response (a list of {type,id} linkages).
func TagBindingsRelationship(bindings []models.TagBinding, resourceType string) gin.H {
	data := make([]gin.H, 0, len(bindings))
	for i := range bindings {
		id := bindings[i].ID
		if id == "" {
			id = bindings[i].Key
		}
		data = append(data, gin.H{"type": resourceType, "id": id})
	}
	return gin.H{"data": data}
}

// IncludedTagBindingResources renders tag-bindings as JSON:API `included` resource objects (for
// ?include= responses).
func IncludedTagBindingResources(bindings []models.TagBinding, resourceType string) []gin.H {
	out := make([]gin.H, 0, len(bindings))
	for i := range bindings {
		b := bindings[i]
		id := b.ID
		if id == "" {
			id = b.Key
		}
		out = append(out, gin.H{"type": resourceType, "id": id, "attributes": gin.H{"key": b.Key, "value": b.Value}})
	}
	return out
}

// ---- project auth helpers ---------------------------------------------------

func (h *TagBindingHandlerV2) authProject(c *gin.Context, write bool) (*models.Project, bool) {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		tagErr(c, http.StatusBadRequest, "Bad Request", "Invalid project ID format")
		return nil, false
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		tagErr(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	project, err := h.projectRepo.GetByID(projectID)
	if err != nil {
		tagErr(c, http.StatusNotFound, "Not Found", "Project not found")
		return nil, false
	}
	if write {
		ok, err := h.rbacService.CheckOrgManageProjects(c.Request.Context(), user.ID, project.OrganizationID)
		if err != nil {
			tagErr(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
			return nil, false
		}
		if !ok {
			tagErr(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this project's tags")
			return nil, false
		}
	} else {
		inOrg, err := h.orgRepo.UserInOrg(user.ID, project.OrganizationID)
		if err != nil || !inOrg {
			tagErr(c, http.StatusForbidden, "Forbidden", "You must be a member of this organization")
			return nil, false
		}
	}
	return project, true
}

// ---- workspace auth helpers -------------------------------------------------

func (h *TagBindingHandlerV2) authWorkspace(c *gin.Context, write bool) (*models.Workspace, bool) {
	workspaceID := c.Param("id")
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		tagErr(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	ws, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		tagErr(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return nil, false
	}
	perm := rbac.PermissionWorkspaceRead
	if write {
		perm = rbac.PermissionWorkspaceWrite
	}
	ok, err := h.rbacService.CheckResourcePermission(c.Request.Context(), user.ID, rbac.ResourceTypeTerraformWorkspace, ws.ID, perm, &ws.ProjectID)
	if err != nil {
		tagErr(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return nil, false
	}
	if !ok {
		tagErr(c, http.StatusForbidden, "Forbidden", "You do not have permission to access this workspace's tags")
		return nil, false
	}
	return ws, true
}

// ---- project endpoints ------------------------------------------------------

// GetProjectTagBindings — GET /projects/:id/tag-bindings
func (h *TagBindingHandlerV2) GetProjectTagBindings(c *gin.Context) {
	project, ok := h.authProject(c, false)
	if !ok {
		return
	}
	bindings, err := h.tagRepo.ListByProject(project.ID)
	if err != nil {
		tagErr(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list tag bindings")
		return
	}
	c.JSON(http.StatusOK, formatTagBindings(bindings, "tag-bindings"))
}

// GetProjectEffectiveTagBindings — GET /projects/:id/effective-tag-bindings
// A project is top-level, so its effective bindings equal its own.
func (h *TagBindingHandlerV2) GetProjectEffectiveTagBindings(c *gin.Context) {
	project, ok := h.authProject(c, false)
	if !ok {
		return
	}
	bindings, err := h.tagRepo.ListByProject(project.ID)
	if err != nil {
		tagErr(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list effective tag bindings")
		return
	}
	c.JSON(http.StatusOK, formatTagBindings(bindings, "effective-tag-bindings"))
}

// PatchProjectTagBindings — PATCH /projects/:id/tag-bindings (replace the project's bindings)
func (h *TagBindingHandlerV2) PatchProjectTagBindings(c *gin.Context) {
	project, ok := h.authProject(c, true)
	if !ok {
		return
	}
	var req tagBindingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		tagErr(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if err := h.tagRepo.ReplaceForProject(project.ID, req.toBindings()); err != nil {
		tagErr(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update tag bindings")
		return
	}
	bindings, _ := h.tagRepo.ListByProject(project.ID)
	c.JSON(http.StatusOK, formatTagBindings(bindings, "tag-bindings"))
}

// ---- workspace endpoints ----------------------------------------------------

// GetWorkspaceTagBindings — GET /workspaces/:id/tag-bindings
func (h *TagBindingHandlerV2) GetWorkspaceTagBindings(c *gin.Context) {
	ws, ok := h.authWorkspace(c, false)
	if !ok {
		return
	}
	bindings, err := h.tagRepo.ListByWorkspace(ws.ID)
	if err != nil {
		tagErr(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list tag bindings")
		return
	}
	c.JSON(http.StatusOK, formatTagBindings(bindings, "tag-bindings"))
}

// GetWorkspaceEffectiveTagBindings — GET /workspaces/:id/effective-tag-bindings
// A workspace's effective bindings are its own merged with those inherited from its project.
func (h *TagBindingHandlerV2) GetWorkspaceEffectiveTagBindings(c *gin.Context) {
	ws, ok := h.authWorkspace(c, false)
	if !ok {
		return
	}
	bindings, err := h.tagRepo.EffectiveForWorkspace(ws.ID)
	if err != nil {
		tagErr(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list effective tag bindings")
		return
	}
	c.JSON(http.StatusOK, formatTagBindings(bindings, "effective-tag-bindings"))
}

// PatchWorkspaceTagBindings — PATCH /workspaces/:id/tag-bindings (replace the workspace's bindings)
func (h *TagBindingHandlerV2) PatchWorkspaceTagBindings(c *gin.Context) {
	ws, ok := h.authWorkspace(c, true)
	if !ok {
		return
	}
	var req tagBindingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		tagErr(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if err := h.tagRepo.ReplaceForWorkspace(ws.ID, req.toBindings()); err != nil {
		tagErr(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update tag bindings")
		return
	}
	bindings, _ := h.tagRepo.ListByWorkspace(ws.ID)
	c.JSON(http.StatusOK, formatTagBindings(bindings, "tag-bindings"))
}
