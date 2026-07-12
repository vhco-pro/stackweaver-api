// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/activity"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/repository"
)

type ActivityHandlerV2 struct {
	activityService *activity.Service
	authService     *auth.Service
	orgRepo         *repository.OrganizationRepository
	workspaceRepo   *repository.WorkspaceRepository
	projectRepo     *repository.ProjectRepository
}

func NewActivityHandlerV2(
	activityService *activity.Service,
	authService *auth.Service,
	orgRepo *repository.OrganizationRepository,
	workspaceRepo *repository.WorkspaceRepository,
	projectRepo *repository.ProjectRepository,
) *ActivityHandlerV2 {
	return &ActivityHandlerV2{
		activityService: activityService,
		authService:     authService,
		orgRepo:         orgRepo,
		workspaceRepo:   workspaceRepo,
		projectRepo:     projectRepo,
	}
}

// requireOrgMembership writes a 403 and returns false when userID is not a member
// of orgID. JWT/browser identities bypass the org-resolution wall, so this
// per-handler check is the only defense for them (AUD-139).
func (h *ActivityHandlerV2) requireOrgMembership(c *gin.Context, userID, orgID uuid.UUID) bool {
	inOrg, err := h.orgRepo.UserInOrg(userID, orgID)
	if err != nil || !inOrg {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You must be a member of this organization"}}})
		return false
	}
	return true
}

// ListActivities handles GET /api/v2/activities
func (h *ActivityHandlerV2) ListActivities(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return
	}

	// Parse query parameters
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")
	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	if limit > 100 {
		limit = 100
	}
	if limit < 1 {
		limit = 50
	}

	// Parse optional filters
	var userID *uuid.UUID
	if c.Query("user_id") != "" {
		if id, err := uuid.Parse(c.Query("user_id")); err == nil {
			userID = &id
		}
	}

	var orgID *uuid.UUID
	if c.Query("organization_id") != "" {
		if id, err := uuid.Parse(c.Query("organization_id")); err == nil {
			orgID = &id
		}
	}

	var workspaceID *string
	if c.Query("workspace_id") != "" {
		workspaceIDStr := c.Query("workspace_id")
		workspaceID = &workspaceIDStr
	}

	// AUD-139: authorize the requested scope. Attacker-supplied
	// organization_id/workspace_id/user_id filters previously widened the query
	// past the caller's own rows with no membership check, exposing another
	// tenant's audit trail. A caller may only read activity they are authorized
	// for: an org/workspace they belong to, or (absent any org/workspace scope)
	// their own rows.
	if workspaceID != nil {
		workspace, err := h.workspaceRepo.GetByID(*workspaceID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Workspace not found"}}})
			return
		}
		project, err := h.projectRepo.GetByID(workspace.ProjectID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to resolve workspace organization"}}})
			return
		}
		if !h.requireOrgMembership(c, user.ID, project.OrganizationID) {
			return
		}
	}
	if orgID != nil {
		if !h.requireOrgMembership(c, user.ID, *orgID) {
			return
		}
	}
	// With no authorized org/workspace scope, a caller may only see their own
	// rows — this both preserves the "my activities" default and prevents a bare
	// user_id filter from reading another user's activity.
	if orgID == nil && workspaceID == nil {
		userID = &user.ID
	}

	filters := repository.AuditLogFilters{
		UserID:         userID,
		OrganizationID: orgID,
		WorkspaceID:    workspaceID,
		Action:         c.Query("action"),
		ResourceType:   c.Query("resource_type"),
	}

	activities, total, err := h.activityService.GetActivities(filters, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": err.Error()}}})
		return
	}

	// Format response
	activitiesData := make([]gin.H, len(activities))
	for i, act := range activities {
		attrs := gin.H{
			"action":        act.Action,
			"resource_type": act.ResourceType,
			"details":       act.Details,
			"created_at":    act.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}

		// Convert UUID pointers to strings (or omit if nil)
		if act.ResourceID != nil {
			attrs["resource_id"] = act.ResourceID.String()
		}
		if act.UserID != nil {
			attrs["user_id"] = act.UserID.String()
		}
		if act.OrganizationID != nil {
			attrs["organization_id"] = act.OrganizationID.String()
		}
		if act.ProjectID != nil {
			attrs["project_id"] = act.ProjectID.String()
		}
		if act.WorkspaceID != nil {
			attrs["workspace_id"] = act.WorkspaceID.String()
		}

		activitiesData[i] = gin.H{
			"id":         act.ID.String(),
			"type":       "activity",
			"attributes": attrs,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"data": activitiesData,
		"meta": gin.H{
			"pagination": gin.H{
				"total":  total,
				"limit":  limit,
				"offset": offset,
			},
		},
	})
}

// GetRecentActivities handles GET /api/v2/activities/recent
func (h *ActivityHandlerV2) GetRecentActivities(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return
	}

	limitStr := c.DefaultQuery("limit", "10")
	limit, _ := strconv.Atoi(limitStr)
	if limit > 50 {
		limit = 50
	}
	if limit < 1 {
		limit = 10
	}

	var orgID *uuid.UUID
	if c.Query("organization_id") != "" {
		if id, err := uuid.Parse(c.Query("organization_id")); err == nil {
			orgID = &id
		}
	}

	activities, err := h.activityService.GetRecentActivities(&user.ID, orgID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": err.Error()}}})
		return
	}

	activitiesData := make([]gin.H, len(activities))
	for i, act := range activities {
		attrs := gin.H{
			"action":        act.Action,
			"resource_type": act.ResourceType,
			"details":       act.Details,
			"created_at":    act.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}

		// Convert UUID pointers to strings (or omit if nil)
		if act.ResourceID != nil {
			attrs["resource_id"] = act.ResourceID.String()
		}
		if act.UserID != nil {
			attrs["user_id"] = act.UserID.String()
		}
		if act.OrganizationID != nil {
			attrs["organization_id"] = act.OrganizationID.String()
		}
		if act.ProjectID != nil {
			attrs["project_id"] = act.ProjectID.String()
		}
		if act.WorkspaceID != nil {
			attrs["workspace_id"] = act.WorkspaceID.String()
		}

		activitiesData[i] = gin.H{
			"id":         act.ID.String(),
			"type":       "activity",
			"attributes": attrs,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"data": activitiesData,
	})
}
