// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/helpers"
	"github.com/michielvha/stackweaver/backend/internal/api/pagination"
	"github.com/michielvha/stackweaver/backend/internal/services/activity"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

type ProjectHandlerV2 struct {
	projectRepo     *repository.ProjectRepository
	orgRepo         *repository.OrganizationRepository
	teamRepo        *repository.TeamRepository
	agentPoolRepo   *repository.AgentPoolRepository
	tagRepo         *repository.TagBindingRepository
	authService     *auth.Service
	activityService *activity.Service
	rbacService     *rbac.Service
}

func NewProjectHandlerV2(projectRepo *repository.ProjectRepository, orgRepo *repository.OrganizationRepository, teamRepo *repository.TeamRepository, agentPoolRepo *repository.AgentPoolRepository, tagRepo *repository.TagBindingRepository, authService *auth.Service, activityService *activity.Service, rbacService *rbac.Service) *ProjectHandlerV2 {
	return &ProjectHandlerV2{
		projectRepo:     projectRepo,
		orgRepo:         orgRepo,
		teamRepo:        teamRepo,
		agentPoolRepo:   agentPoolRepo,
		tagRepo:         tagRepo,
		authService:     authService,
		activityService: activityService,
		rbacService:     rbacService,
	}
}

// applyProjectSettings applies tfe_project_settings attributes (default execution mode + default agent
// pool + setting-overwrites) onto a project. Returns a user-facing error message + false if invalid.
// A workspace that does not overwrite its own execution mode inherits these at run time.
func (h *ProjectHandlerV2) applyProjectSettings(project *models.Project, attrs projectSettingsAttrs) (string, bool) {
	// setting-overwrites: a `false` flag clears the project's own value (reverts to the remote default).
	if attrs.SettingOverwrites != nil {
		if attrs.SettingOverwrites.DefaultExecutionMode != nil && !*attrs.SettingOverwrites.DefaultExecutionMode {
			project.DefaultExecutionMode = "remote"
			project.DefaultAgentPoolID = nil
			project.SettingsOverwritten = false
		}
		if attrs.SettingOverwrites.DefaultAgentPool != nil && !*attrs.SettingOverwrites.DefaultAgentPool {
			project.DefaultAgentPoolID = nil
		}
	}

	if attrs.DefaultExecutionMode != nil {
		mode := *attrs.DefaultExecutionMode
		switch mode {
		case "remote", "agent", "local":
		default:
			return "default-execution-mode must be one of: remote, agent, local", false
		}
		project.DefaultExecutionMode = mode
		// Explicitly setting the execution mode marks the project as overwriting (both flags, as TFE does).
		project.SettingsOverwritten = true
		// Leaving agent mode clears any stale default pool.
		if mode != "agent" {
			project.DefaultAgentPoolID = nil
		}
	}

	if attrs.DefaultAgentPoolID != nil {
		if *attrs.DefaultAgentPoolID == "" {
			project.DefaultAgentPoolID = nil
		} else {
			poolID, err := uuid.Parse(*attrs.DefaultAgentPoolID)
			if err != nil {
				return "default-agent-pool-id is not a valid ID", false
			}
			// The pool must exist and belong to the project's organization (tenant safety).
			pool, err := h.agentPoolRepo.GetByID(poolID, false)
			if err != nil || pool == nil || pool.OrganizationID != project.OrganizationID {
				return "default agent pool not found in this organization", false
			}
			project.DefaultAgentPoolID = &poolID
		}
	}

	// TFE requires an agent pool when the default execution mode is agent.
	if project.DefaultExecutionMode == "agent" && project.DefaultAgentPoolID == nil {
		return "default-agent-pool-id is required when default-execution-mode is agent", false
	}
	return "", true
}

// projectSettingsAttrs is the subset of UpdateProjectRequestV2 attributes carrying project settings.
type projectSettingsAttrs struct {
	DefaultExecutionMode *string
	DefaultAgentPoolID   *string
	SettingOverwrites    *projectSettingOverwritesReq
}

// projectSettingOverwritesReq is TFE's setting-overwrites object on a project update.
type projectSettingOverwritesReq struct {
	DefaultExecutionMode *bool `json:"default-execution-mode,omitempty"`
	DefaultAgentPool     *bool `json:"default-agent-pool,omitempty"`
}

// tagBindingsRel captures the `tag-bindings` relationship in a project/workspace request. The tfe
// provider serialises the `tags` map here with the key/value INLINE in each relationship-data member's
// attributes (a non-standard JSON:API shape — the attributes are not sideloaded into top-level
// `included`).
type tagBindingsRel struct {
	TagBindings *struct {
		Data []struct {
			Attributes struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"attributes"`
		} `json:"data"`
	} `json:"tag-bindings,omitempty"`
}

// bindings extracts the tag bindings from the relationship (nil-safe).
func (t *tagBindingsRel) bindings() []models.TagBinding {
	if t == nil || t.TagBindings == nil {
		return nil
	}
	out := make([]models.TagBinding, 0, len(t.TagBindings.Data))
	for _, d := range t.TagBindings.Data {
		if d.Attributes.Key != "" {
			out = append(out, models.TagBinding{Key: d.Attributes.Key, Value: d.Attributes.Value})
		}
	}
	return out
}

// CreateProjectRequestV2 uses JSON:API format (TFE-compatible)
type CreateProjectRequestV2 struct {
	Data struct {
		Type       string `json:"type" binding:"required"` // Must be "projects"
		Attributes struct {
			Name        string `json:"name" binding:"required"`
			Description string `json:"description"`
		} `json:"attributes" binding:"required"`
		Relationships *tagBindingsRel `json:"relationships,omitempty"`
	} `json:"data" binding:"required"`
}

// UpdateProjectRequestV2 uses JSON:API format (TFE-compatible)
type UpdateProjectRequestV2 struct {
	Data struct {
		Type       string `json:"type" binding:"required"` // Must be "projects"
		Attributes struct {
			Name        *string `json:"name,omitempty"`
			Description *string `json:"description,omitempty"`
			// TFE tfe_project_settings: default workspace execution settings.
			DefaultExecutionMode *string `json:"default-execution-mode,omitempty"`
			DefaultAgentPoolID   *string `json:"default-agent-pool-id,omitempty"`
			// SettingOverwrites is computed by TFE; clearing a flag reverts to org defaults. Stackweaver
			// has no org-default-settings yet, so `false` clears the project's own value (back to remote).
			SettingOverwrites *projectSettingOverwritesReq `json:"setting-overwrites,omitempty"`
		} `json:"attributes"`
		Relationships *tagBindingsRel `json:"relationships,omitempty"`
	} `json:"data" binding:"required"`
}

// tagsPresent reports whether the request is managing tag bindings (the tag-bindings relationship is
// present, or included tag-bindings were sent).
func (r *CreateProjectRequestV2) tagsPresent() bool {
	return r.Data.Relationships != nil && r.Data.Relationships.TagBindings != nil
}

func (r *UpdateProjectRequestV2) tagsPresent() bool {
	return r.Data.Relationships != nil && r.Data.Relationships.TagBindings != nil
}

// formatProjectResponse formats a project in TFE-compatible JSON:API format
// orgName is the organization name (not UUID) as TFE uses organization name as the primary identifier
func formatProjectResponse(project *models.Project, orgName string) gin.H {
	// TFE tfe_project_settings: default workspace execution settings on the project. setting-overwrites
	// tells the provider which values the project specifies itself (vs. deferring to org defaults) —
	// mirrors the per-workspace overwrite logic (a non-remote mode / a set pool is an explicit overwrite).
	execMode := project.DefaultExecutionMode
	if execMode == "" {
		execMode = "remote"
	}
	relationships := gin.H{
		"organization": gin.H{
			"data": gin.H{
				"id":   orgName, // TFE uses organization name as primary identifier
				"type": "organizations",
			},
		},
	}
	if project.DefaultAgentPoolID != nil {
		relationships["default-agent-pool"] = gin.H{
			"data": gin.H{
				"id":   project.DefaultAgentPoolID.String(),
				"type": "agent-pools",
			},
		}
	} else {
		relationships["default-agent-pool"] = gin.H{"data": nil}
	}
	return gin.H{
		"id":   project.ID.String(),
		"type": "projects",
		"attributes": gin.H{
			"name":                   project.Name,
			"description":            project.Description,
			"is-unified":             false, // StackWeaver projects are not unified
			"default-execution-mode": execMode,
			"setting-overwrites": gin.H{
				// The provider sets both overwrite flags together, so they mirror one stored flag.
				"default-execution-mode": project.SettingsOverwritten,
				"default-agent-pool":     project.SettingsOverwritten,
			},
			"created-at": project.CreatedAt.Format(time.RFC3339),
			"updated-at": project.UpdatedAt.Format(time.RFC3339),
		},
		"relationships": relationships,
		"links": gin.H{
			"self": "/api/v2/projects/" + project.ID.String(),
		},
	}
}

// formatProjectResponseWithCounts formats a project with resource counts
func formatProjectResponseWithCounts(project *models.Project, orgName string) gin.H {
	response := formatProjectResponse(project, orgName)

	// Add resource counts to attributes
	attributes := response["attributes"].(gin.H)
	attributes["workspaces-count"] = len(project.Workspaces)
	attributes["inventories-count"] = len(project.Inventories)
	attributes["playbooks-count"] = len(project.Playbooks)
	attributes["job-templates-count"] = len(project.JobTemplates)
	attributes["workflows-count"] = len(project.Workflows)
	attributes["credentials-count"] = len(project.Credentials)

	return response
}

// List returns all projects for an organization
// GET /api/v2/organizations/:name/projects
func (h *ProjectHandlerV2) List(c *gin.Context) {
	orgName := c.Param("name")

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Organization not found",
				},
			},
		})
		return
	}

	// Get user for permission checking
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}

	// Check if user has organization-level read-projects permission
	hasOrgReadProjects, err := h.rbacService.CheckOrgReadProjects(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to check permissions",
				},
			},
		})
		return
	}

	page, perPage := pagination.Parse(c, 20)
	if perPage > 100 {
		perPage = 100
	}
	offset := (page - 1) * perPage

	var projects []models.Project
	var total int64

	if hasOrgReadProjects {
		// User has organization-level read-projects permission - show all projects
		projects, total, err = h.projectRepo.WithContext(c.Request.Context()).ListByOrganization(org.ID, perPage, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"errors": []gin.H{
					{
						"status": "500",
						"title":  "Internal Server Error",
						"detail": "Failed to list projects",
					},
				},
			})
			return
		}
	} else {
		// User does NOT have organization-level read-projects permission
		// Filter projects to only those the user has team project access to
		// Get all teams user is member of
		teams, err := h.teamRepo.GetTeamsByUserID(user.ID, org.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"errors": []gin.H{
					{
						"status": "500",
						"title":  "Internal Server Error",
						"detail": "Failed to get user teams",
					},
				},
			})
			return
		}

		// Collect all project IDs the user's teams have access to
		accessibleProjectIDs := make(map[uuid.UUID]bool)
		for _, team := range teams {
			// Get team with project access preloaded
			teamWithAccess, err := h.teamRepo.GetByID(team.ID)
			if err != nil {
				// Log error but continue with other teams
				continue
			}
			// Collect project IDs from team's project access
			for _, access := range teamWithAccess.ProjectAccess {
				accessibleProjectIDs[access.ProjectID] = true
			}
		}

		// If user has no team project access, return empty list
		if len(accessibleProjectIDs) == 0 {
			projects = []models.Project{}
			total = 0
		} else {
			// Get all projects first to count total
			allProjects, _, err := h.projectRepo.WithContext(c.Request.Context()).ListByOrganization(org.ID, 10000, 0)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"errors": []gin.H{
						{
							"status": "500",
							"title":  "Internal Server Error",
							"detail": "Failed to list projects",
						},
					},
				})
				return
			}

			// Filter to only accessible projects
			filteredProjects := make([]models.Project, 0)
			for _, project := range allProjects {
				if accessibleProjectIDs[project.ID] {
					filteredProjects = append(filteredProjects, project)
				}
			}
			total = int64(len(filteredProjects))

			// Apply pagination
			start := offset
			if start > len(filteredProjects) {
				start = len(filteredProjects)
			}
			end := start + perPage
			if end > len(filteredProjects) {
				end = len(filteredProjects)
			}
			if start < len(filteredProjects) {
				projects = filteredProjects[start:end]
			} else {
				projects = []models.Project{}
			}
		}
	}

	// Format projects in JSON:API format
	formattedProjects := make([]gin.H, len(projects))
	for i := range projects {
		formattedProjects[i] = formatProjectResponse(&projects[i], org.Name)
	}

	c.JSON(http.StatusOK, gin.H{
		"data": formattedProjects,
		"meta": gin.H{
			"pagination": gin.H{
				"page":     page,
				"per_page": perPage,
				"total":    total,
			},
		},
	})
}

// Get returns a single project by organization name and project name
// GET /api/v2/organizations/:name/projects/:name
func (h *ProjectHandlerV2) Get(c *gin.Context) {
	orgName := c.Param("name")
	projectName := c.Param("project_name")

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Organization not found",
				},
			},
		})
		return
	}

	project, err := h.projectRepo.GetByOrganizationAndName(org.ID, projectName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Project not found",
				},
			},
		})
		return
	}

	// AUD-046: gate the read on org membership, mirroring GetByID. Without this the
	// by-name read leaked project configuration cross-tenant to any authenticated user.
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}},
		})
		return
	}
	inOrg, err := h.orgRepo.UserInOrg(user.ID, org.ID)
	if err != nil || !inOrg {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You must be a member of this organization (via team membership)"}},
		})
		return
	}

	// Get project with all resources for counts
	projectWithResources, err := h.projectRepo.GetByIDWithResources(project.ID)
	if err != nil {
		// Fallback to project without resources if preload fails
		projectWithResources = project
	}

	c.JSON(http.StatusOK, gin.H{
		"data": formatProjectResponseWithCounts(projectWithResources, org.Name),
	})
}

// GetByID returns a single project by ID (TFE-compatible)
// GET /api/v2/projects/:id
func (h *ProjectHandlerV2) GetByID(c *gin.Context) {
	projectIDStr := c.Param("id")

	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Invalid project ID format",
				},
			},
		})
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}

	project, err := h.projectRepo.GetByIDWithResources(projectID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Project not found",
				},
			},
		})
		return
	}

	// Verify user has access to the organization
	org, err := h.orgRepo.GetByID(project.OrganizationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to retrieve organization",
				},
			},
		})
		return
	}

	inOrg, err := h.orgRepo.UserInOrg(user.ID, org.ID)
	if err != nil || !inOrg {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "You must be a member of this organization (via team membership)",
				},
			},
		})
		return
	}

	data := formatProjectResponseWithCounts(project, org.Name)
	resp := gin.H{"data": data}
	// TFE ?include=effective-tag-bindings — the provider's tfe_project resource + data.tfe_project read
	// the project's tags this way. A project's effective tags equal its own bindings.
	if includeHasEffectiveTagBindings(c) {
		bindings, _ := h.tagRepo.ListByProject(project.ID)
		if rels, ok := data["relationships"].(gin.H); ok {
			rels["effective-tag-bindings"] = TagBindingsRelationship(bindings, "effective-tag-bindings")
			rels["tag-bindings"] = TagBindingsRelationship(bindings, "tag-bindings")
		}
		resp["included"] = IncludedTagBindingResources(bindings, "effective-tag-bindings")
	}
	c.JSON(http.StatusOK, resp)
}

// includeHasEffectiveTagBindings reports whether the request asked to include effective tag bindings.
// go-tfe sends the include value with underscores (`effective_tag_bindings`); accept the hyphenated
// form too for robustness.
func includeHasEffectiveTagBindings(c *gin.Context) bool {
	inc := c.Query("include")
	return strings.Contains(inc, "effective_tag_bindings") || strings.Contains(inc, "effective-tag-bindings")
}

// Create creates a new project in an organization
// POST /api/v2/organizations/:name/projects
func (h *ProjectHandlerV2) Create(c *gin.Context) {
	orgName := c.Param("name")

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Organization not found",
				},
			},
		})
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}

	// Check if user has permission to create projects (team-based)
	// Project creation requires org-level manage-projects permission via team membership
	hasManageProjects, err := h.rbacService.CheckOrgManageProjects(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to check permissions",
				},
			},
		})
		return
	}

	if !hasManageProjects {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "You do not have permission to create projects. Project creation requires organization-level manage-projects permission via team membership.",
				},
			},
		})
		return
	}

	var req CreateProjectRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": err.Error(),
				},
			},
		})
		return
	}

	// Validate JSON:API format
	if req.Data.Type != "projects" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "data.type must be 'projects'",
				},
			},
		})
		return
	}

	attrs := req.Data.Attributes

	// Validate name length
	if len(attrs.Name) == 0 || len(attrs.Name) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Validation Error",
					"detail": "Name must be between 1 and 200 characters",
				},
			},
		})
		return
	}

	// Check for duplicate name in organization (race condition protection)
	existing, _ := h.projectRepo.GetByOrganizationAndName(org.ID, attrs.Name)
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{
			"errors": []gin.H{
				{
					"status": "409",
					"title":  "Conflict",
					"detail": "Project with this name already exists in this organization",
				},
			},
		})
		return
	}

	project := &models.Project{
		OrganizationID: org.ID,
		Name:           attrs.Name,
		Description:    attrs.Description,
	}

	if err := h.projectRepo.Create(project); err != nil {
		// Handle duplicate key constraint violation (race condition)
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "23505") {
			c.JSON(http.StatusConflict, gin.H{
				"errors": []gin.H{
					{
						"status": "409",
						"title":  "Conflict",
						"detail": "Project with this name already exists in this organization",
					},
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to create project",
				},
			},
		})
		return
	}

	// Automatically grant "owners" team admin access to the new project
	// This ensures owners have full access to all projects for granular permissions (runs, state, variables)
	ownersTeam, err := h.teamRepo.GetByName(org.ID, "owners")
	if err == nil && ownersTeam != nil {
		// Check if project access already exists (idempotent)
		existingAccess, err := h.teamRepo.GetProjectAccessByTeamAndProject(ownersTeam.ID, project.ID)
		if err == gorm.ErrRecordNotFound || existingAccess == nil {
			// Project access doesn't exist, create it with "admin" level
			adminAccess := "admin"
			projectAccess := &models.TeamProjectAccess{
				TeamID:    ownersTeam.ID,
				ProjectID: project.ID,
				Access:    &adminAccess,
			}
			if err := h.teamRepo.CreateProjectAccess(projectAccess); err != nil {
				// Log error but don't fail project creation - access can be granted later
				// This is a best-effort operation to ensure owners have access
				_ = err // Explicitly ignore error - project creation should not fail if access grant fails
			}
		}
	}

	// TFE tag bindings: the provider sends the project's `tags` as a tag-bindings relation (key/value
	// inline in the relationship data). Apply them if present.
	if req.tagsPresent() {
		if err := h.tagRepo.ReplaceForProject(project.ID, req.Data.Relationships.bindings()); err != nil {
			_ = err // best-effort: don't fail project creation on a tag write
		}
	}

	// Log activity (non-blocking)
	if h.activityService != nil {
		activityCtx := helpers.GetActivityContext(c)
		activityCtx.OrganizationID = &org.ID
		activityCtx.ProjectID = &project.ID
		_ = h.activityService.LogCreate(c.Request.Context(), "project", project.ID.String(), project.Name, activityCtx)
	}

	c.JSON(http.StatusCreated, gin.H{
		"data": formatProjectResponse(project, org.Name),
	})
}

// Update updates a project by organization name and project name
// PATCH /api/v2/organizations/:name/projects/:name
func (h *ProjectHandlerV2) Update(c *gin.Context) {
	orgName := c.Param("name")
	projectName := c.Param("project_name")

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Organization not found",
				},
			},
		})
		return
	}

	project, err := h.projectRepo.GetByOrganizationAndName(org.ID, projectName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Project not found",
				},
			},
		})
		return
	}

	// Check if user has permission to update project
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}

	// Check org-level permission (team-based) - project management is org-level
	hasOrgManage, err := h.rbacService.CheckOrgManageProjects(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to check permissions",
				},
			},
		})
		return
	}

	if !hasOrgManage {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "You do not have permission to update projects. Project management requires organization-level manage-projects permission via team membership.",
				},
			},
		})
		return
	}

	var req UpdateProjectRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": err.Error(),
				},
			},
		})
		return
	}

	// Validate JSON:API format
	if req.Data.Type != "projects" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "data.type must be 'projects'",
				},
			},
		})
		return
	}

	attrs := req.Data.Attributes

	if attrs.Name != nil && *attrs.Name != "" {
		// Check if new name conflicts with existing project in organization
		if *attrs.Name != project.Name {
			existing, _ := h.projectRepo.GetByOrganizationAndName(org.ID, *attrs.Name)
			if existing != nil {
				c.JSON(http.StatusConflict, gin.H{
					"errors": []gin.H{
						{
							"status": "409",
							"title":  "Conflict",
							"detail": "Project with this name already exists in this organization",
						},
					},
				})
				return
			}
		}
		project.Name = *attrs.Name
	}
	if attrs.Description != nil {
		project.Description = *attrs.Description
	}
	if msg, ok := h.applyProjectSettings(project, projectSettingsAttrs{
		DefaultExecutionMode: attrs.DefaultExecutionMode,
		DefaultAgentPoolID:   attrs.DefaultAgentPoolID,
		SettingOverwrites:    attrs.SettingOverwrites,
	}); !ok {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"errors": []gin.H{{"status": "422", "title": "Invalid Project Settings", "detail": msg}},
		})
		return
	}

	if err := h.projectRepo.Update(project); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to update project",
				},
			},
		})
		return
	}

	// Log activity (non-blocking)
	if h.activityService != nil {
		activityCtx := helpers.GetActivityContext(c)
		activityCtx.OrganizationID = &org.ID
		activityCtx.ProjectID = &project.ID
		changes := map[string]interface{}{}
		if attrs.Name != nil && *attrs.Name != "" {
			changes["name"] = *attrs.Name
		}
		if attrs.Description != nil {
			changes["description"] = *attrs.Description
		}
		_ = h.activityService.LogUpdate(c.Request.Context(), "project", project.ID.String(), project.Name, changes, activityCtx)
	}

	c.JSON(http.StatusOK, gin.H{
		"data": formatProjectResponse(project, org.Name),
	})
}

// Delete deletes a project by organization name and project name
// DELETE /api/v2/organizations/:name/projects/:name
func (h *ProjectHandlerV2) Delete(c *gin.Context) {
	orgName := c.Param("name")
	projectName := c.Param("project_name")

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Organization not found",
				},
			},
		})
		return
	}

	project, err := h.projectRepo.GetByOrganizationAndName(org.ID, projectName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Project not found",
				},
			},
		})
		return
	}

	// Check if user has permission to delete project
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}

	// Check org-level permission (team-based: CheckOrgManageProjects checks for "owners" team and manage-projects permission)
	hasOrgManage, err := h.rbacService.CheckOrgManageProjects(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to check permissions",
				},
			},
		})
		return
	}

	if !hasOrgManage {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "You do not have permission to delete projects. Project deletion requires organization-level manage-projects permission via team membership (e.g., being in the 'owners' team).",
				},
			},
		})
		return
	}

	// Log activity before deletion (non-blocking)
	if h.activityService != nil {
		activityCtx := helpers.GetActivityContext(c)
		activityCtx.OrganizationID = &org.ID
		activityCtx.ProjectID = &project.ID
		_ = h.activityService.LogDelete(c.Request.Context(), "project", project.ID.String(), project.Name, activityCtx)
	}

	if err := h.projectRepo.Delete(project.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to delete project",
				},
			},
		})
		return
	}

	c.Status(http.StatusNoContent)
}

// UpdateByID updates a project by ID (TFE-compatible: go-tfe Projects.Update → PATCH /projects/:id).
// Serves both tfe_project (name/description) and tfe_project_settings (default-execution-mode,
// default-agent-pool-id, setting-overwrites).
// PATCH /api/v2/projects/:id
func (h *ProjectHandlerV2) UpdateByID(c *gin.Context) {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid project ID format"}},
		})
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}},
		})
		return
	}

	project, err := h.projectRepo.GetByID(projectID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Project not found"}},
		})
		return
	}

	org, err := h.orgRepo.GetByID(project.OrganizationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to retrieve organization"}},
		})
		return
	}

	// Project management is an org-level permission (team-based), same as the by-name Update.
	hasOrgManage, err := h.rbacService.CheckOrgManageProjects(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to check permissions"}},
		})
		return
	}
	if !hasOrgManage {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to update projects in this organization"}},
		})
		return
	}

	var req UpdateProjectRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}},
		})
		return
	}
	if req.Data.Type != "projects" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "data.type must be 'projects'"}},
		})
		return
	}

	attrs := req.Data.Attributes
	if attrs.Name != nil && *attrs.Name != "" && *attrs.Name != project.Name {
		if existing, _ := h.projectRepo.GetByOrganizationAndName(org.ID, *attrs.Name); existing != nil {
			c.JSON(http.StatusConflict, gin.H{
				"errors": []gin.H{{"status": "409", "title": "Conflict", "detail": "Project with this name already exists in this organization"}},
			})
			return
		}
		project.Name = *attrs.Name
	}
	if attrs.Description != nil {
		project.Description = *attrs.Description
	}
	if msg, ok := h.applyProjectSettings(project, projectSettingsAttrs{
		DefaultExecutionMode: attrs.DefaultExecutionMode,
		DefaultAgentPoolID:   attrs.DefaultAgentPoolID,
		SettingOverwrites:    attrs.SettingOverwrites,
	}); !ok {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"errors": []gin.H{{"status": "422", "title": "Invalid Project Settings", "detail": msg}},
		})
		return
	}

	if err := h.projectRepo.Update(project); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to update project"}},
		})
		return
	}

	// TFE tag bindings: replace the project's tags when the request manages them.
	if req.tagsPresent() {
		if err := h.tagRepo.ReplaceForProject(project.ID, req.Data.Relationships.bindings()); err != nil {
			_ = err
		}
	}

	if h.activityService != nil {
		activityCtx := helpers.GetActivityContext(c)
		activityCtx.OrganizationID = &org.ID
		activityCtx.ProjectID = &project.ID
		_ = h.activityService.LogUpdate(c.Request.Context(), "project", project.ID.String(), project.Name, map[string]interface{}{}, activityCtx)
	}

	c.JSON(http.StatusOK, gin.H{"data": formatProjectResponse(project, org.Name)})
}

// DeleteByID deletes a project by ID (TFE-compatible)
// DELETE /api/v2/projects/:id
func (h *ProjectHandlerV2) DeleteByID(c *gin.Context) {
	projectIDStr := c.Param("id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Invalid project ID format",
				},
			},
		})
		return
	}

	project, err := h.projectRepo.GetByID(projectID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Project not found",
				},
			},
		})
		return
	}

	// Get organization for validation and activity logging
	org, err := h.orgRepo.GetByID(project.OrganizationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to retrieve organization",
				},
			},
		})
		return
	}

	// Check if user has permission to delete project
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}

	// Check org-level permission (team-based: CheckOrgManageProjects checks for "owners" team and manage-projects permission)
	hasOrgManage, err := h.rbacService.CheckOrgManageProjects(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to check permissions",
				},
			},
		})
		return
	}

	if !hasOrgManage {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "You do not have permission to delete projects. Project deletion requires organization-level manage-projects permission via team membership (e.g., being in the 'owners' team).",
				},
			},
		})
		return
	}

	// Log activity before deletion (non-blocking)
	if h.activityService != nil && org != nil {
		activityCtx := helpers.GetActivityContext(c)
		activityCtx.OrganizationID = &org.ID
		activityCtx.ProjectID = &project.ID
		_ = h.activityService.LogDelete(c.Request.Context(), "project", project.ID.String(), project.Name, activityCtx)
	}

	if err := h.projectRepo.Delete(project.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to delete project",
				},
			},
		})
		return
	}

	c.Status(http.StatusNoContent)
}
