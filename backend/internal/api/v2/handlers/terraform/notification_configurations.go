// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/notification"
)

// NotificationConfigurationHandlerV2 serves the TFE-compatible workspace notification-configuration
// endpoints (tfe_notification_configuration). Delivery is handled by the orchestrator poll; this handler
// owns CRUD + the verify action.
type NotificationConfigurationHandlerV2 struct {
	repo          *repository.NotificationConfigurationRepository
	workspaceRepo *repository.WorkspaceRepository
	projectRepo   *repository.ProjectRepository
	orgRepo       *repository.OrganizationRepository
	teamRepo      *repository.TeamRepository
	authService   *auth.Service
	rbacService   *rbac.Service
	cryptoService *crypto.CryptoService
	notifier      *notification.Service
}

func NewNotificationConfigurationHandlerV2(
	repo *repository.NotificationConfigurationRepository,
	workspaceRepo *repository.WorkspaceRepository,
	projectRepo *repository.ProjectRepository,
	orgRepo *repository.OrganizationRepository,
	teamRepo *repository.TeamRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	cryptoService *crypto.CryptoService,
	notifier *notification.Service,
) *NotificationConfigurationHandlerV2 {
	return &NotificationConfigurationHandlerV2{
		repo:          repo,
		workspaceRepo: workspaceRepo,
		projectRepo:   projectRepo,
		orgRepo:       orgRepo,
		teamRepo:      teamRepo,
		authService:   authService,
		rbacService:   rbacService,
		cryptoService: cryptoService,
		notifier:      notifier,
	}
}

func ncError(c *gin.Context, status int, title, detail string) {
	c.JSON(status, gin.H{"errors": []gin.H{{"status": strconv.Itoa(status), "title": title, "detail": detail}}})
}

// ncRequest is the JSON:API create/update body (type: notification-configurations).
type ncRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name            *string  `json:"name"`
			DestinationType *string  `json:"destination-type"`
			URL             *string  `json:"url"`
			Token           *string  `json:"token"`
			Enabled         *bool    `json:"enabled"`
			Triggers        []string `json:"triggers"`
			EmailAddresses  []string `json:"email-addresses"`
		} `json:"attributes"`
	} `json:"data"`
}

// formatNotificationConfig renders a config as JSON:API (never includes the token).
func formatNotificationConfig(nc *models.NotificationConfiguration) gin.H {
	triggers := []string(nc.Triggers)
	if triggers == nil {
		triggers = []string{}
	}
	emails := []string(nc.EmailAddresses)
	if emails == nil {
		emails = []string{}
	}
	// subscribable is polymorphic: the workspace, project or team the config is bound to. Every scope
	// MUST have a branch here: an unhandled one emits "subscribable": null, a valid-looking 200 that
	// silently breaks the provider round-trip rather than failing loudly.
	var subscribable gin.H
	switch {
	case nc.WorkspaceID != nil:
		subscribable = gin.H{"data": gin.H{"id": *nc.WorkspaceID, "type": "workspaces"}}
	case nc.ProjectID != nil:
		subscribable = gin.H{"data": gin.H{"id": nc.ProjectID.String(), "type": "projects"}}
	case nc.TeamID != nil:
		subscribable = gin.H{"data": gin.H{"id": nc.TeamID.String(), "type": "teams"}}
	}
	return gin.H{
		"id":   nc.ID,
		"type": "notification-configurations",
		"attributes": gin.H{
			"name":             nc.Name,
			"destination-type": string(nc.Destination),
			"url":              nc.URL,
			"enabled":          nc.Enabled,
			"triggers":         triggers,
			"email-addresses":  emails,
			"created-at":       nc.CreatedAt.Format(time.RFC3339),
			"updated-at":       nc.UpdatedAt.Format(time.RFC3339),
		},
		"relationships": gin.H{"subscribable": subscribable},
	}
}

// authWorkspace loads a workspace and checks the caller's permission (read or write).
func (h *NotificationConfigurationHandlerV2) authWorkspace(c *gin.Context, workspaceID string, write bool) (*models.Workspace, bool) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		ncError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	ws, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		ncError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return nil, false
	}
	perm := rbac.PermissionWorkspaceRead
	if write {
		perm = rbac.PermissionWorkspaceWrite
	}
	ok, err := h.rbacService.CheckWorkspacePermission(c.Request.Context(), user.ID, ws.ID, perm, ws.ProjectID)
	if err != nil || !ok {
		ncError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this workspace's notifications")
		return nil, false
	}
	return ws, true
}

// applyAttributes copies request attributes onto a config, encrypting the token. isCreate seeds defaults.
func (h *NotificationConfigurationHandlerV2) applyAttributes(nc *models.NotificationConfiguration, req *ncRequest, isCreate bool) error {
	a := req.Data.Attributes
	if a.Name != nil {
		nc.Name = *a.Name
	}
	if a.DestinationType != nil {
		nc.Destination = models.NotificationDestinationType(*a.DestinationType)
	}
	if a.URL != nil {
		nc.URL = *a.URL
	}
	if a.Triggers != nil {
		nc.Triggers = models.StringArray(a.Triggers)
	}
	if a.EmailAddresses != nil {
		nc.EmailAddresses = models.StringArray(a.EmailAddresses)
	}
	if a.Enabled != nil {
		nc.Enabled = *a.Enabled
	} else if isCreate {
		nc.Enabled = true
	}
	// Token is write-only: encrypt when provided; leave untouched on update when omitted.
	if a.Token != nil && *a.Token != "" {
		if h.cryptoService == nil {
			return errors.New("token encryption unavailable")
		}
		enc, err := h.cryptoService.Encrypt(*a.Token)
		if err != nil {
			return err
		}
		nc.Token = enc
	}
	return nil
}

// Create handles POST /workspaces/:id/notification-configurations
func (h *NotificationConfigurationHandlerV2) Create(c *gin.Context) {
	ws, ok := h.authWorkspace(c, c.Param("id"), true)
	if !ok {
		return
	}
	nc, ok := h.buildFromRequest(c)
	if !ok {
		return
	}
	nc.WorkspaceID = &ws.ID
	h.createAndRespond(c, nc)
}

// CreateForProject handles POST /projects/:id/notification-configurations
func (h *NotificationConfigurationHandlerV2) CreateForProject(c *gin.Context) {
	project, ok := h.authProject(c, true)
	if !ok {
		return
	}
	nc, ok := h.buildFromRequest(c)
	if !ok {
		return
	}
	nc.ProjectID = &project.ID
	h.createAndRespond(c, nc)
}

// CreateForTeam handles POST /teams/:id/notification-configurations
// (tfe_team_notification_configuration). Its only meaningful trigger is change_request:created.
func (h *NotificationConfigurationHandlerV2) CreateForTeam(c *gin.Context) {
	team, ok := h.authTeam(c, true)
	if !ok {
		return
	}
	nc, ok := h.buildFromRequest(c)
	if !ok {
		return
	}
	nc.TeamID = &team.ID
	h.createAndRespond(c, nc)
}

// buildFromRequest parses + validates the create body into a new (scope-less) config.
func (h *NotificationConfigurationHandlerV2) buildFromRequest(c *gin.Context) (*models.NotificationConfiguration, bool) {
	var req ncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ncError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return nil, false
	}
	if req.Data.Attributes.Name == nil || *req.Data.Attributes.Name == "" {
		ncError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "name is required")
		return nil, false
	}
	if req.Data.Attributes.DestinationType == nil {
		ncError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "destination-type is required")
		return nil, false
	}
	nc := &models.NotificationConfiguration{}
	if err := h.applyAttributes(nc, &req, true); err != nil {
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to prepare notification configuration")
		return nil, false
	}
	return nc, true
}

func (h *NotificationConfigurationHandlerV2) createAndRespond(c *gin.Context, nc *models.NotificationConfiguration) {
	if err := h.repo.Create(nc); err != nil {
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create notification configuration")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": formatNotificationConfig(nc)})
}

// List handles GET /workspaces/:id/notification-configurations
func (h *NotificationConfigurationHandlerV2) List(c *gin.Context) {
	ws, ok := h.authWorkspace(c, c.Param("id"), false)
	if !ok {
		return
	}
	configs, err := h.repo.ListByWorkspace(ws.ID)
	h.respondList(c, configs, err)
}

// ListForProject handles GET /projects/:id/notification-configurations
func (h *NotificationConfigurationHandlerV2) ListForProject(c *gin.Context) {
	project, ok := h.authProject(c, false)
	if !ok {
		return
	}
	configs, err := h.repo.ListByProject(project.ID)
	h.respondList(c, configs, err)
}

// ListForTeam handles GET /teams/:id/notification-configurations
func (h *NotificationConfigurationHandlerV2) ListForTeam(c *gin.Context) {
	team, ok := h.authTeam(c, false)
	if !ok {
		return
	}
	configs, err := h.repo.ListByTeam(team.ID)
	h.respondList(c, configs, err)
}

func (h *NotificationConfigurationHandlerV2) respondList(c *gin.Context, configs []models.NotificationConfiguration, err error) {
	if err != nil {
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list notification configurations")
		return
	}
	data := make([]gin.H, 0, len(configs))
	for i := range configs {
		data = append(data, formatNotificationConfig(&configs[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

// authProject loads the project named by :id and checks the caller's permission (org-manage-projects for
// write, org membership for read), mirroring the project tag-bindings handler.
func (h *NotificationConfigurationHandlerV2) authProject(c *gin.Context, write bool) (*models.Project, bool) {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		ncError(c, http.StatusBadRequest, "Bad Request", "Invalid project ID")
		return nil, false
	}
	return h.authProjectByID(c, projectID, write)
}

func (h *NotificationConfigurationHandlerV2) authProjectByID(c *gin.Context, projectID uuid.UUID, write bool) (*models.Project, bool) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		ncError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	project, err := h.projectRepo.GetByID(projectID)
	if err != nil {
		ncError(c, http.StatusNotFound, "Not Found", "Project not found")
		return nil, false
	}
	if write {
		ok, err := h.rbacService.CheckOrgManageProjects(c.Request.Context(), user.ID, project.OrganizationID)
		if err != nil || !ok {
			ncError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this project's notifications")
			return nil, false
		}
	} else {
		inOrg, err := h.orgRepo.UserInOrg(user.ID, project.OrganizationID)
		if err != nil || !inOrg {
			ncError(c, http.StatusForbidden, "Forbidden", "You must be a member of this organization")
			return nil, false
		}
	}
	return project, true
}

// authTeam loads the team named by :id and checks the caller's permission.
func (h *NotificationConfigurationHandlerV2) authTeam(c *gin.Context, write bool) (*models.Team, bool) {
	teamID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		ncError(c, http.StatusBadRequest, "Bad Request", "Invalid team ID")
		return nil, false
	}
	return h.authTeamByID(c, teamID, write)
}

// authTeamByID mirrors authProjectByID's asymmetry: managing a team's notifications is an org-admin
// action (org:manage-teams), while reading them only requires membership of the organization.
func (h *NotificationConfigurationHandlerV2) authTeamByID(c *gin.Context, teamID uuid.UUID, write bool) (*models.Team, bool) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		ncError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	team, err := h.teamRepo.GetByID(teamID)
	if err != nil {
		ncError(c, http.StatusNotFound, "Not Found", "Team not found")
		return nil, false
	}
	if write {
		ok, err := h.rbacService.CheckOrgManageTeams(c.Request.Context(), user.ID, team.OrganizationID)
		if err != nil || !ok {
			ncError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this team's notifications")
			return nil, false
		}
	} else {
		inOrg, err := h.orgRepo.UserInOrg(user.ID, team.OrganizationID)
		if err != nil || !inOrg {
			ncError(c, http.StatusForbidden, "Forbidden", "You must be a member of this organization")
			return nil, false
		}
	}
	return team, true
}

// loadForCaller loads a config by id and authorizes the caller against its scope (workspace, project or
// team).
func (h *NotificationConfigurationHandlerV2) loadForCaller(c *gin.Context, write bool) (*models.NotificationConfiguration, bool) {
	nc, err := h.repo.GetByID(c.Param("id"))
	if err != nil {
		ncError(c, http.StatusNotFound, "Not Found", "Notification configuration not found")
		return nil, false
	}
	switch {
	case nc.WorkspaceID != nil:
		if _, ok := h.authWorkspace(c, *nc.WorkspaceID, write); !ok {
			return nil, false
		}
	case nc.ProjectID != nil:
		if _, ok := h.authProjectByID(c, *nc.ProjectID, write); !ok {
			return nil, false
		}
	case nc.TeamID != nil:
		if _, ok := h.authTeamByID(c, *nc.TeamID, write); !ok {
			return nil, false
		}
	default:
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Notification configuration has no scope")
		return nil, false
	}
	return nc, true
}

// Read handles GET /notification-configurations/:id
func (h *NotificationConfigurationHandlerV2) Read(c *gin.Context) {
	nc, ok := h.loadForCaller(c, false)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatNotificationConfig(nc)})
}

// Update handles PATCH /notification-configurations/:id
func (h *NotificationConfigurationHandlerV2) Update(c *gin.Context) {
	nc, ok := h.loadForCaller(c, true)
	if !ok {
		return
	}
	var req ncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ncError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if err := h.applyAttributes(nc, &req, false); err != nil {
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to prepare notification configuration")
		return
	}
	if err := h.repo.Update(nc); err != nil {
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update notification configuration")
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatNotificationConfig(nc)})
}

// Delete handles DELETE /notification-configurations/:id
func (h *NotificationConfigurationHandlerV2) Delete(c *gin.Context) {
	nc, ok := h.loadForCaller(c, true)
	if !ok {
		return
	}
	if err := h.repo.Delete(nc.ID); err != nil {
		ncError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete notification configuration")
		return
	}
	c.Status(http.StatusNoContent)
}

// Verify handles POST /notification-configurations/:id/actions/verify (sends a test delivery).
func (h *NotificationConfigurationHandlerV2) Verify(c *gin.Context) {
	nc, ok := h.loadForCaller(c, true)
	if !ok {
		return
	}
	rc := notification.RunContext{
		RunID:         "run-verify",
		WorkspaceName: "verify",
		Status:        models.RunStatusPending,
		Operation:     models.RunOperationPlanAndApply,
		Message:       "Verification notification from Stackweaver",
		UpdatedAt:     time.Now(),
	}
	// Fill scope/org names best-effort for the payload.
	switch {
	case nc.WorkspaceID != nil:
		if ws, err := h.workspaceRepo.GetByID(*nc.WorkspaceID); err == nil {
			rc.WorkspaceID = ws.ID
			rc.WorkspaceName = ws.Name
			rc.Organization = ws.Project.Organization.Name
		}
	case nc.ProjectID != nil:
		if p, err := h.projectRepo.GetByID(*nc.ProjectID); err == nil {
			rc.ProjectID = p.ID
			rc.WorkspaceName = p.Name
			rc.Organization = p.Organization.Name // "" if not preloaded
		}
	case nc.TeamID != nil:
		// A team config has no workspace of its own; the notifier turns this into a synthetic
		// change-request event, so only the org name is meaningful here.
		if team, err := h.teamRepo.GetByID(*nc.TeamID); err == nil {
			rc.WorkspaceName = team.Name
			if org, oerr := h.orgRepo.GetByID(team.OrganizationID); oerr == nil {
				rc.Organization = org.Name
			}
		}
	}
	if err := h.notifier.Verify(c.Request.Context(), nc, rc); err != nil {
		ncError(c, http.StatusBadGateway, "Delivery Failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": formatNotificationConfig(nc)})
}
