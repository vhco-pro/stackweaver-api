// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// ChangeRequestHandlerV2 serves the change-request endpoints (HCP Terraform's
// workspace_change_requests): an admin files an action item against one or more workspaces, and the
// team that owns each workspace archives it once the work is done.
//
// The paths match TFE exactly, including /workspaces/change-requests/:id, whose static segment sits
// where /workspaces/:id already binds a wildcard: gin resolves static before wildcard, so both work
// (proved by TestChangeRequestRoutesMatchTFE in the routes package).
type ChangeRequestHandlerV2 struct {
	repo          *repository.ChangeRequestRepository
	workspaceRepo *repository.WorkspaceRepository
	orgRepo       *repository.OrganizationRepository
	authService   *auth.Service
	rbacService   *rbac.Service
}

func NewChangeRequestHandlerV2(
	repo *repository.ChangeRequestRepository,
	workspaceRepo *repository.WorkspaceRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *ChangeRequestHandlerV2 {
	return &ChangeRequestHandlerV2{
		repo:          repo,
		workspaceRepo: workspaceRepo,
		orgRepo:       orgRepo,
		authService:   authService,
		rbacService:   rbacService,
	}
}

func crError(c *gin.Context, status int, title, detail string) {
	c.JSON(status, gin.H{"errors": []gin.H{{"status": strconv.Itoa(status), "title": title, "detail": detail}}})
}

// bulkActionRequest is the JSON:API body of POST /organizations/:name/explorer/bulk-actions. Note the
// attribute keys are snake_case here, not the kebab-case used elsewhere in the TFE API: this endpoint
// is documented that way, so we match it rather than our house style.
type bulkActionRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			ActionType   string `json:"action_type"`
			ActionInputs struct {
				Subject string `json:"subject"`
				Message string `json:"message"`
			} `json:"action_inputs"`
			TargetIDs []string       `json:"target_ids"`
			Query     map[string]any `json:"query"`
		} `json:"attributes"`
	} `json:"data"`
}

// formatChangeRequest renders a change request as JSON:API. archived-by/archived-at are null while the
// request is open, matching TFE. workspace-name and created-by are Stackweaver extras (TFE exposes
// neither); they let the UI render a filer and a workspace label without an extra round trip, and
// additive attributes are ignored by TFE clients.
func formatChangeRequest(cr *models.ChangeRequest) gin.H {
	attrs := gin.H{
		"subject":     cr.Subject,
		"message":     cr.Message,
		"archived-by": nil,
		"archived-at": nil,
		"created-by":  cr.CreatedBy.String(),
		"created-at":  cr.CreatedAt.Format(time.RFC3339),
		"updated-at":  cr.UpdatedAt.Format(time.RFC3339),
	}
	if cr.ArchivedBy != nil {
		attrs["archived-by"] = cr.ArchivedBy.String()
	}
	if cr.ArchivedAt != nil {
		attrs["archived-at"] = cr.ArchivedAt.Format(time.RFC3339)
	}
	if cr.Workspace != nil {
		attrs["workspace-name"] = cr.Workspace.Name
	}
	return gin.H{
		"id":         cr.ID,
		"type":       "workspace_change_requests",
		"attributes": attrs,
		"relationships": gin.H{
			"workspace": gin.H{"data": gin.H{"id": cr.WorkspaceID, "type": "workspaces"}},
		},
	}
}

// authWorkspace loads a workspace and checks the caller can read (or write) its change requests.
func (h *ChangeRequestHandlerV2) authWorkspace(c *gin.Context, workspaceID string, write bool) (*models.Workspace, bool) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		crError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	ws, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		crError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return nil, false
	}
	perm := rbac.PermissionWorkspaceRead
	if write {
		perm = rbac.PermissionWorkspaceWrite
	}
	ok, err := h.rbacService.CheckWorkspacePermission(c.Request.Context(), user.ID, ws.ID, perm, ws.ProjectID)
	if err == nil && ok {
		return ws, true
	}
	// CheckWorkspacePermission deliberately has no owners-team bypass, so an org owner with no explicit
	// grant would be locked out of their own workspace's change requests. Fall back to the org-owner
	// check, the same workaround CheckVariableSetPermission uses.
	if owner, oerr := h.rbacService.IsOrgOwner(c.Request.Context(), user.ID, ws.Project.OrganizationID); oerr == nil && owner {
		return ws, true
	}
	crError(c, http.StatusForbidden, "Forbidden", "You do not have permission to access this workspace's change requests")
	return nil, false
}

// authOrgManageWorkspaces resolves the :name organization and requires org:manage-workspaces, the
// permission that stands in for TFE's "administrator" when filing change requests. The owners-team
// bypass is honored automatically by checkOrgPermission.
func (h *ChangeRequestHandlerV2) authOrgManageWorkspaces(c *gin.Context) (*models.Organization, bool) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		crError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		crError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return nil, false
	}
	ok, err := h.rbacService.CheckOrgManageWorkspaces(c.Request.Context(), user.ID, org.ID)
	if err != nil || !ok {
		crError(c, http.StatusForbidden, "Forbidden", "You do not have permission to file change requests in this organization")
		return nil, false
	}
	return org, true
}

// paginate reads TFE-style page[number]/page[size] query params.
func paginate(c *gin.Context) (page, pageSize, offset int) {
	page, _ = strconv.Atoi(c.DefaultQuery("page[number]", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ = strconv.Atoi(c.DefaultQuery("page[size]", "20"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize, (page - 1) * pageSize
}

func paginationMeta(page, pageSize int, total int64) gin.H {
	return gin.H{"pagination": gin.H{"current-page": page, "page-size": pageSize, "total-count": total}}
}

// BulkActions handles POST /organizations/:name/explorer/bulk-actions. This is TFE's only documented
// way to create change requests: one subject/message filed against many target workspaces at once.
func (h *ChangeRequestHandlerV2) BulkActions(c *gin.Context) {
	org, ok := h.authOrgManageWorkspaces(c)
	if !ok {
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		crError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	var req bulkActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		crError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	a := req.Data.Attributes
	if a.ActionType != "change_requests" {
		crError(c, http.StatusUnprocessableEntity, "Invalid Attribute",
			"action_type must be \"change_requests\"; no other bulk action is supported")
		return
	}
	// The query variant selects targets by an Explorer query. Stackweaver has no Explorer, so we accept
	// only explicit target_ids and say so rather than silently filing against nothing.
	if len(a.Query) > 0 {
		crError(c, http.StatusUnprocessableEntity, "Unsupported Attribute",
			"query-based targeting requires the Explorer, which Stackweaver does not implement; pass target_ids instead")
		return
	}
	if a.ActionInputs.Subject == "" {
		crError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "action_inputs.subject is required")
		return
	}
	if len(a.TargetIDs) == 0 {
		crError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "target_ids must contain at least one workspace")
		return
	}

	// Every target must live in this organization. Checked before creating anything so a bad id fails
	// the whole batch rather than filing a partial set the caller cannot reason about.
	crs := make([]*models.ChangeRequest, 0, len(a.TargetIDs))
	for _, wsID := range a.TargetIDs {
		ws, err := h.workspaceRepo.GetByID(wsID)
		if err != nil {
			crError(c, http.StatusNotFound, "Not Found", "Workspace "+wsID+" not found")
			return
		}
		if ws.Project.OrganizationID != org.ID {
			crError(c, http.StatusForbidden, "Forbidden", "Workspace "+wsID+" is not in organization "+org.Name)
			return
		}
		crs = append(crs, &models.ChangeRequest{
			WorkspaceID: ws.ID,
			Subject:     a.ActionInputs.Subject,
			Message:     a.ActionInputs.Message,
			CreatedBy:   user.ID,
		})
	}

	if err := h.repo.CreateBatch(crs); err != nil {
		crError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create change requests")
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": gin.H{
		"type": "bulk_actions",
		"attributes": gin.H{
			"organization_id": org.ID.String(),
			"action_type":     a.ActionType,
			"action_inputs":   gin.H{"subject": a.ActionInputs.Subject, "message": a.ActionInputs.Message},
			"created_by":      gin.H{"id": user.ID.String(), "type": "users"},
		},
	}})
}

// ListByWorkspace handles GET /workspaces/:id/change-requests. Archived requests are excluded unless
// filter[archived]=true, matching TFE's separate sorting of archived requests.
func (h *ChangeRequestHandlerV2) ListByWorkspace(c *gin.Context) {
	ws, ok := h.authWorkspace(c, c.Param("id"), false)
	if !ok {
		return
	}
	page, pageSize, offset := paginate(c)
	includeArchived := c.Query("filter[archived]") == "true"

	crs, total, err := h.repo.ListByWorkspace(ws.ID, includeArchived, pageSize, offset)
	if err != nil {
		crError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list change requests")
		return
	}
	data := make([]gin.H, 0, len(crs))
	for i := range crs {
		data = append(data, formatChangeRequest(&crs[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": data, "meta": paginationMeta(page, pageSize, total)})
}

// ListByOrganization handles GET /organizations/:name/change-requests, the org-wide triage view. Not a
// TFE endpoint: TFE surfaces this through the Explorer, which we do not implement.
func (h *ChangeRequestHandlerV2) ListByOrganization(c *gin.Context) {
	org, ok := h.authOrgManageWorkspaces(c)
	if !ok {
		return
	}
	page, pageSize, offset := paginate(c)

	crs, total, err := h.repo.ListOpenByOrg(org.ID, pageSize, offset)
	if err != nil {
		crError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list change requests")
		return
	}
	data := make([]gin.H, 0, len(crs))
	for i := range crs {
		data = append(data, formatChangeRequest(&crs[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": data, "meta": paginationMeta(page, pageSize, total)})
}

// loadForCaller loads a change request by id and authorizes the caller against its workspace.
func (h *ChangeRequestHandlerV2) loadForCaller(c *gin.Context, write bool) (*models.ChangeRequest, bool) {
	cr, err := h.repo.GetByID(c.Param("id"))
	if err != nil {
		crError(c, http.StatusNotFound, "Not Found", "Change request not found")
		return nil, false
	}
	if _, ok := h.authWorkspace(c, cr.WorkspaceID, write); !ok {
		return nil, false
	}
	return cr, true
}

// Read handles GET /workspaces/change-requests/:id.
func (h *ChangeRequestHandlerV2) Read(c *gin.Context) {
	cr, ok := h.loadForCaller(c, false)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatChangeRequest(cr)})
}

// Archive handles PATCH (and POST, which TFE's docs also describe) /workspaces/change-requests/:id.
// Requires workspace:write, not org:manage-workspaces: the team that does the work closes the request
// out, which is TFE's model ("team members can archive a change request once they've completed that
// request's task").
func (h *ChangeRequestHandlerV2) Archive(c *gin.Context) {
	cr, ok := h.loadForCaller(c, true)
	if !ok {
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		crError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	if cr.Archived() {
		// Already archived: return it as-is rather than overwriting the original archiver.
		c.JSON(http.StatusOK, gin.H{"data": formatChangeRequest(cr)})
		return
	}
	if err := h.repo.Archive(cr.ID, user.ID); err != nil {
		crError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to archive change request")
		return
	}
	updated, err := h.repo.GetByID(cr.ID)
	if err != nil {
		crError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to reload change request")
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatChangeRequest(updated)})
}

// Delete handles DELETE /workspaces/change-requests/:id. Not a TFE endpoint (TFE only archives).
// Requires org:manage-workspaces: deleting destroys the record, so it is an admin action, not a team one.
func (h *ChangeRequestHandlerV2) Delete(c *gin.Context) {
	cr, err := h.repo.GetByID(c.Param("id"))
	if err != nil {
		crError(c, http.StatusNotFound, "Not Found", "Change request not found")
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		crError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	ws, err := h.workspaceRepo.GetByID(cr.WorkspaceID)
	if err != nil {
		crError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}
	ok, err := h.rbacService.CheckOrgManageWorkspaces(c.Request.Context(), user.ID, ws.Project.OrganizationID)
	if err != nil || !ok {
		crError(c, http.StatusForbidden, "Forbidden", "You do not have permission to delete change requests")
		return
	}
	if err := h.repo.Delete(cr.ID); err != nil {
		crError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete change request")
		return
	}
	c.Status(http.StatusNoContent)
}
