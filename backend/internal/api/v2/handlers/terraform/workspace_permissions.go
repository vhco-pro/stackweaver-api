// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
)

// workspacePermissionResolver answers the caller-dependent flags of a workspace response's
// permissions block from the checks the matching actions make:
//
//   - can-queue-run: run create, the runs permission and write access;
//   - can-queue-destroy: the same, and the workspace allows destroy plans (run create refuses a
//     destroy otherwise);
//   - can-update-variable: variable writes, the variables permission and write access;
//   - can-read-settings: workspace read, membership of the organization;
//   - can-update and can-destroy: workspace update and delete, "Manage workspaces" in the
//     organization or write access to the workspace;
//   - can-lock and can-unlock: the lock permission Lock and Unlock check;
//   - can-force-unlock: ForceUnlock's admin check.
//
// The caller's grants are loaded once per organization per request (rbac.WorkspaceGrants), and
// every workspace is answered in memory, so a list costs the same queries as one workspace. A
// caller the request does not identify, or grants that fail to load, get false.
type workspacePermissionResolver struct {
	h          *WorkspaceHandlerV2
	c          *gin.Context
	userID     uuid.UUID
	known      bool
	grants     map[uuid.UUID]*rbac.WorkspaceGrants // organization -> the caller's grants
	projectOrg map[uuid.UUID]uuid.UUID             // project -> organization
}

// workspaceResponse is formatWorkspaceResponse with the permissions block answered for the caller.
func (h *WorkspaceHandlerV2) workspaceResponse(c *gin.Context, ws *models.Workspace) *WorkspaceResource {
	res := formatWorkspaceResponse(ws, h.vcsConnectionRepo)
	h.permissionResolver(c).apply(res, ws)
	return res
}

func (h *WorkspaceHandlerV2) permissionResolver(c *gin.Context) *workspacePermissionResolver {
	r := &workspacePermissionResolver{
		h: h, c: c,
		grants: map[uuid.UUID]*rbac.WorkspaceGrants{}, projectOrg: map[uuid.UUID]uuid.UUID{},
	}
	if h.authService == nil || h.rbacService == nil {
		return r
	}
	if user, err := h.authService.GetUserFromContext(c); err == nil && user != nil {
		r.userID, r.known = user.ID, true
	}
	return r
}

// withOrganization records that the workspaces about to be answered belong to orgID, which
// saves looking their projects up.
func (r *workspacePermissionResolver) withOrganization(orgID uuid.UUID, workspaces []models.Workspace) *workspacePermissionResolver {
	for i := range workspaces {
		r.projectOrg[workspaces[i].ProjectID] = orgID
	}
	return r
}

// apply sets the caller-dependent flags of a workspace response.
func (r *workspacePermissionResolver) apply(res *WorkspaceResource, ws *models.Workspace) {
	p := &res.Attributes.Permissions
	p.CanQueueRun, p.CanQueueDestroy, p.CanUpdateVariable, p.CanReadSettings = false, false, false, false
	p.CanUpdate, p.CanDestroy, p.CanLock, p.CanUnlock, p.CanForceUnlock = false, false, false, false, false
	g := r.grantsFor(ws.ProjectID)
	if g == nil {
		return
	}
	has := func(perm rbac.Permission) bool { return g.Has(ws.ProjectID, ws.ID, perm) }

	write := has(rbac.PermissionWorkspaceWrite)
	p.CanQueueRun = has(rbac.PermissionRuns) && write
	p.CanQueueDestroy = p.CanQueueRun && ws.AllowDestroyPlan
	p.CanUpdateVariable = has(rbac.PermissionVariables) && write
	p.CanReadSettings = g.InOrganization()
	p.CanUpdate = g.ManagesWorkspaces() || write
	p.CanDestroy = p.CanUpdate
	p.CanLock = has(rbac.PermissionWorkspaceLocking)
	p.CanUnlock = p.CanLock
	p.CanForceUnlock = g.IsWorkspaceAdmin(ws.ProjectID, ws.ID)
}

// grantsFor returns the caller's grants in the organization that owns the project, loading them
// on first use.
func (r *workspacePermissionResolver) grantsFor(projectID uuid.UUID) *rbac.WorkspaceGrants {
	if !r.known {
		return nil
	}
	orgID, ok := r.projectOrg[projectID]
	if !ok {
		if r.h.projectRepo == nil {
			return nil
		}
		project, err := r.h.projectRepo.GetByID(projectID)
		if err != nil {
			return nil
		}
		orgID = project.OrganizationID
		r.projectOrg[projectID] = orgID
	}
	if g, ok := r.grants[orgID]; ok {
		return g
	}
	g, err := r.h.rbacService.LoadWorkspaceGrants(r.c.Request.Context(), r.userID, orgID)
	if err != nil {
		logger.Warnf("Workspace permissions: loading the grants of %s in %s: %v", r.userID, orgID, err)
		g = nil
	}
	r.grants[orgID] = g
	return g
}
