// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/helpers"
	"github.com/michielvha/stackweaver/backend/internal/api/pagination"
	"github.com/michielvha/stackweaver/backend/internal/services/activity"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/tofu"
	"gorm.io/gorm"
)

type OrganizationHandlerV2 struct {
	orgRepo         *repository.OrganizationRepository
	teamRepo        *repository.TeamRepository
	projectRepo     *repository.ProjectRepository
	agentPoolRepo   *repository.AgentPoolRepository
	authService     *auth.Service
	activityService *activity.Service
	rbacService     *rbac.Service
	db              *gorm.DB
}

func NewOrganizationHandlerV2(orgRepo *repository.OrganizationRepository, teamRepo *repository.TeamRepository, projectRepo *repository.ProjectRepository, agentPoolRepo *repository.AgentPoolRepository, authService *auth.Service, activityService *activity.Service, rbacService *rbac.Service, db *gorm.DB) *OrganizationHandlerV2 {
	return &OrganizationHandlerV2{
		orgRepo:         orgRepo,
		teamRepo:        teamRepo,
		projectRepo:     projectRepo,
		agentPoolRepo:   agentPoolRepo,
		authService:     authService,
		activityService: activityService,
		rbacService:     rbacService,
		db:              db,
	}
}

// OrganizationAttributes contains TFE-compatible organization attributes
type OrganizationAttributes struct {
	Name                    string  `json:"name"`
	Email                   string  `json:"email"`
	Description             string  `json:"description"`
	CollaboratorAuthPolicy  string  `json:"collaborator-auth-policy"`  // password or two_factor_mandatory
	CostEstimationEnabled   *bool   `json:"cost-estimation-enabled"`   // pointer to distinguish unset from false
	DefaultTerraformVersion *string `json:"default-terraform-version"` // org-wide default terraform version
	// Org-wide retention for finished Ansible jobs (0 = keep forever).
	AnsibleJobRetentionDays *int    `json:"ansible-job-retention-days"`
	AnsibleAdHocModules     *string `json:"ansible-adhoc-modules"`
	// DefaultExecutionMode is the org-wide default workspace execution mode
	// (tfe_organization_default_settings): remote|agent|local.
	DefaultExecutionMode *string `json:"default-execution-mode"`

	// tfe_organization policy flags (all optional pointers so PATCH can distinguish unset from
	// false). See the tfe_organization spec doc for the runtime each one drives.
	UserTokensEnabled                                 *bool `json:"user-tokens-enabled"`
	AllowForceDeleteWorkspaces                        *bool `json:"allow-force-delete-workspaces"`
	AssessmentsEnforced                               *bool `json:"assessments-enforced"`
	SpeculativePlanManagementEnabled                  *bool `json:"speculative-plan-management-enabled"`
	AggregatedCommitStatusEnabled                     *bool `json:"aggregated-commit-status-enabled"`
	SendPassingStatusesForUntriggeredSpeculativePlans *bool `json:"send-passing-statuses-for-untriggered-speculative-plans"`
}

// applyOrgPolicyAttributes copies the tfe_organization policy flags from a request onto the org
// (nil = leave unchanged) and enforces the TFE invariant that aggregated commit statuses and
// passing-statuses-for-untriggered-plans are mutually exclusive. Returns an error detail and false
// when the resulting state is invalid.
func applyOrgPolicyAttributes(org *models.Organization, attrs *OrganizationAttributes) (string, bool) {
	if attrs.UserTokensEnabled != nil {
		org.UserTokensEnabled = attrs.UserTokensEnabled
	}
	if attrs.AllowForceDeleteWorkspaces != nil {
		org.AllowForceDeleteWorkspaces = *attrs.AllowForceDeleteWorkspaces
	}
	if attrs.AssessmentsEnforced != nil {
		org.AssessmentsEnforced = *attrs.AssessmentsEnforced
	}
	if attrs.SpeculativePlanManagementEnabled != nil {
		org.SpeculativePlanManagementEnabled = attrs.SpeculativePlanManagementEnabled
	}
	if attrs.AggregatedCommitStatusEnabled != nil {
		org.AggregatedCommitStatusEnabled = *attrs.AggregatedCommitStatusEnabled
	}
	if attrs.SendPassingStatusesForUntriggeredSpeculativePlans != nil {
		org.SendPassingStatusesForUntriggeredSpeculativePlans = *attrs.SendPassingStatusesForUntriggeredSpeculativePlans
	}
	// TFE rule (go-tfe): aggregated commit statuses require send-passing-statuses to be false.
	if org.AggregatedCommitStatusEnabled && org.SendPassingStatusesForUntriggeredSpeculativePlans {
		return "aggregated-commit-status-enabled requires send-passing-statuses-for-untriggered-speculative-plans to be false", false
	}
	return "", true
}

// CreateOrganizationRequestV2 supports both simple JSON and JSON:API format
// Simple: { "name": "...", "description": "..." }
// JSON:API: { "data": { "type": "organizations", "attributes": { "name": "...", "email": "..." } } }
type CreateOrganizationRequestV2 struct {
	// Simple format fields
	Name        string `json:"name"`
	Description string `json:"description"`

	// JSON:API format
	Data *struct {
		Type       string                 `json:"type"`
		Attributes OrganizationAttributes `json:"attributes"`
	} `json:"data"`
}

// orgRelationships captures the relationships an organization update may carry.
//
// default-agent-pool is a RELATIONSHIP here, not an attribute: go-tfe declares it
// `jsonapi:"relation,default-agent-pool"` on OrganizationUpdateOptions. Note this differs from the
// project resource, which carries `default-agent-pool-id` as a plain attribute. The two are not
// symmetric on the wire, so do not "tidy" this into an attribute.
type orgRelationships struct {
	DefaultAgentPool *struct {
		Data *struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"data"`
	} `json:"default-agent-pool,omitempty"`
}

// UpdateOrganizationRequestV2 supports both simple JSON and JSON:API format
type UpdateOrganizationRequestV2 struct {
	// Simple format fields
	Name        string `json:"name"`
	Description string `json:"description"`

	// JSON:API format
	Data *struct {
		Type          string                 `json:"type"`
		Attributes    OrganizationAttributes `json:"attributes"`
		Relationships *orgRelationships      `json:"relationships,omitempty"`
	} `json:"data"`
}

// buildTFEOrganizationResponse creates a TFE-compatible JSON:API response for an organization.
// defaultProjectID, when non-nil, is emitted as the default-project relationship (the provider's
// computed default_project_id).
func buildTFEOrganizationResponse(org *models.Organization, defaultProjectID *uuid.UUID) gin.H {
	// Use defaults if values are empty
	collaboratorAuthPolicy := org.CollaboratorAuthPolicy
	if collaboratorAuthPolicy == "" {
		collaboratorAuthPolicy = "password"
	}

	// tfe_organization_default_settings reads this back after every write, so an unset mode must still
	// report the effective default rather than "" or the provider sees drift on the next plan.
	defaultExecutionMode := org.DefaultExecutionMode
	if defaultExecutionMode == "" {
		defaultExecutionMode = "remote"
	}

	return gin.H{
		"id":   org.Name, // TFE uses name as ID for organizations
		"type": "organizations",
		"attributes": gin.H{
			"name":                                org.Name,
			"external-id":                         org.ID.String(),
			"created-at":                          org.CreatedAt.Format("2006-01-02T15:04:05Z"),
			"updated-at":                          org.UpdatedAt.Format("2006-01-02T15:04:05Z"),
			"email":                               org.Email,
			"session-timeout":                     nil,
			"session-remember":                    nil,
			"collaborator-auth-policy":            collaboratorAuthPolicy,
			"cost-estimation-enabled":             org.CostEstimationEnabled,
			"default-terraform-version":           org.DefaultTofuVersion,
			"default-execution-mode":              defaultExecutionMode,
			"ansible-job-retention-days":          org.AnsibleJobRetentionDays,
			"ansible-adhoc-modules":               org.AnsibleAdHocModules,
			"speculative-plan-management-enabled": org.SpeculativePlanManagement(),
			"aggregated-commit-status-enabled":    org.AggregatedCommitStatusEnabled,
			"assessments-enforced":                org.AssessmentsEnforced,
			"allow-force-delete-workspaces":       org.AllowForceDeleteWorkspaces,
			"user-tokens-enabled":                 org.UserTokensAllowed(),
			"send-passing-statuses-for-untriggered-speculative-plans": org.SendPassingStatusesForUntriggeredSpeculativePlans,
			// Declined surface (see the tfe_organization spec): echoed as drift-free constants.
			// Sessions are Zitadel's; SAML/HYOK/Stacks/max-TTL have no subsystem.
			"owners-team-saml-role-id": "",
			"enforce-hyok":             false,
			"stacks-enabled":           false,
			"max-ttl-enabled":          false,
			"two-factor-conformant":    false,
			"permissions": gin.H{
				"can-update":                  true,
				"can-destroy":                 true,
				"can-access-via-teams":        true,
				"can-create-module":           true,
				"can-create-team":             true,
				"can-create-workspace":        true,
				"can-manage-users":            true,
				"can-manage-subscription":     false,
				"can-manage-sso":              false,
				"can-update-oauth":            true,
				"can-update-sentinel":         false,
				"can-update-ssh-keys":         true,
				"can-update-api-token":        true,
				"can-traverse":                true,
				"can-start-trial":             false,
				"can-update-agent-pools":      true,
				"can-manage-tags":             true,
				"can-manage-varsets":          true,
				"can-read-varsets":            true,
				"can-manage-public-modules":   true,
				"can-create-provider":         true,
				"can-manage-public-providers": false,
				"can-create-project":          true,
				"can-manage-assessments":      true,
				"can-read-assessments":        true,
				"can-view-explorer":           true,
				"can-deploy-no-code-modules":  false,
				"can-manage-policies":         true,
				"can-manage-policy-overrides": true,
				"can-manage-run-tasks":        true,
				"can-read-run-tasks":          true,
				"can-manage-projects":         true,
			},
		},
		"relationships": orgRelationshipsResponse(org, defaultProjectID),
		"links": gin.H{
			"self": "/api/v2/organizations/" + org.Name,
		},
	}
}

// applyOrgDefaultSettings validates and applies tfe_organization_default_settings onto an org,
// returning an error detail and false when the request is invalid.
//
// The rules mirror the project-level equivalent in projects.go, deliberately: these are the same two
// settings one level up the chain, and TFE enforces the same constraints at both levels.
func (h *OrganizationHandlerV2) applyOrgDefaultSettings(org *models.Organization, mode *string, rels *orgRelationships) (string, bool) {
	if mode != nil {
		switch *mode {
		case "remote", "agent", "local":
		default:
			return "default-execution-mode must be one of: remote, agent, local", false
		}
		org.DefaultExecutionMode = *mode
		// Leaving agent mode clears any stale default pool, so the org cannot report agent execution
		// against a pool it no longer uses.
		if *mode != "agent" {
			org.DefaultAgentPoolID = nil
		}
	}

	if rels != nil && rels.DefaultAgentPool != nil {
		// An explicit {"data": null} clears the default; a data object sets it.
		if rels.DefaultAgentPool.Data == nil || rels.DefaultAgentPool.Data.ID == "" {
			org.DefaultAgentPoolID = nil
		} else {
			poolID, err := uuid.Parse(rels.DefaultAgentPool.Data.ID)
			if err != nil {
				return "default-agent-pool id is not a valid ID", false
			}
			// Tenant safety: the pool must exist and belong to THIS organization, or an org could
			// point its default at another tenant's pool.
			pool, err := h.agentPoolRepo.GetByID(poolID, false)
			if err != nil || pool == nil || pool.OrganizationID != org.ID {
				return "default agent pool not found in this organization", false
			}
			org.DefaultAgentPoolID = &poolID
		}
	}

	// TFE requires an agent pool when the default execution mode is agent (the provider raises
	// "Default execution mode must be set to 'agent' when default_agent_pool_id is set" for the
	// inverse); reject the incoherent state rather than store a default that cannot dispatch.
	if org.DefaultExecutionMode == "agent" && org.DefaultAgentPoolID == nil {
		return "default-agent-pool is required when default-execution-mode is agent", false
	}

	return "", true
}

// orgRelationshipsResponse renders the organization's relationships. default-agent-pool is omitted
// entirely when unset: the provider maps a missing relation to a null default_agent_pool_id, whereas an
// explicit {"data": null} is equally valid JSON:API but noisier to no benefit. default-project is
// likewise omitted when the org has no "default" project (pre-bootstrap edge) - the provider
// nil-guards its read.
func orgRelationshipsResponse(org *models.Organization, defaultProjectID *uuid.UUID) gin.H {
	rels := gin.H{}
	if org.DefaultAgentPoolID != nil {
		rels["default-agent-pool"] = gin.H{
			"data": gin.H{"id": org.DefaultAgentPoolID.String(), "type": "agent-pools"},
		}
	}
	if defaultProjectID != nil {
		rels["default-project"] = gin.H{
			"data": gin.H{"id": defaultProjectID.String(), "type": "projects"},
		}
	}
	return rels
}

// defaultProjectID resolves the org's "default" project for the default-project relationship
// (created by the org bootstrap; nil when absent).
func (h *OrganizationHandlerV2) defaultProjectID(org *models.Organization) *uuid.UUID {
	if h.projectRepo == nil {
		return nil
	}
	p, err := h.projectRepo.GetByOrganizationAndName(org.ID, "default")
	if err != nil || p == nil {
		return nil
	}
	return &p.ID
}

// List returns all organizations that the user is a member of
// GET /api/v2/organizations
func (h *OrganizationHandlerV2) List(c *gin.Context) {
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

	// List organizations where the user has at least one team (team-based access; tenant
	// isolation). An ORG-BOUND api-key is narrower still: it sees only its bound org - resolving
	// via the owning user would let an automation token scoped to one org enumerate every org its
	// owner belongs to.
	var orgs []models.Organization
	if kindVal, isToken := c.Get("token_kind"); isToken {
		if kind, _ := kindVal.(string); kind == models.APIKeyKindOrg {
			boundVal, _ := c.Get("token_org_id")
			boundOrg, ok := boundVal.(uuid.UUID)
			if !ok {
				c.JSON(http.StatusForbidden, gin.H{
					"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "token is not bound to an organization"}},
				})
				return
			}
			org, err := h.orgRepo.GetByID(boundOrg)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to list organizations"}},
				})
				return
			}
			orgs = []models.Organization{*org}
		}
	}
	if orgs == nil {
		var err error
		orgs, err = h.orgRepo.WithContext(c.Request.Context()).ListByUser(user.ID)
		if err != nil {
			logger.Errorf("Failed to list organizations for user %s: %v", user.ID, err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"errors": []gin.H{
					{
						"status": "500",
						"title":  "Internal Server Error",
						"detail": "Failed to list organizations",
					},
				},
			})
			return
		}
	}

	total := int64(len(orgs))

	// Apply pagination
	page, perPage := pagination.Parse(c, 20)
	if perPage > 100 {
		perPage = 100
	}
	offset := (page - 1) * perPage

	start := offset
	if start > len(orgs) {
		start = len(orgs)
	}
	end := start + perPage
	if end > len(orgs) {
		end = len(orgs)
	}

	var paginatedOrgs []models.Organization
	if start < len(orgs) {
		paginatedOrgs = orgs[start:end]
	}

	// TFE-compatible JSON:API list (go-tfe Organizations.List decodes JSON:API resource objects,
	// not raw model structs). The default-project relationship is omitted here (nil): the provider's
	// list path reads only names + external-ids, and resolving it per row would be an N+1 across the
	// page. The single-org GET still emits it.
	data := make([]gin.H, 0, len(paginatedOrgs))
	for i := range paginatedOrgs {
		data = append(data, buildTFEOrganizationResponse(&paginatedOrgs[i], nil))
	}

	// Full TFE pagination meta: go-tfe's multi-page loops advance via next-page, so it must be
	// present (a missing key decodes to 0 and would wedge a >1-page listing on page[number]=0).
	totalPages := int((total + int64(perPage) - 1) / int64(perPage))
	var prevPage, nextPage any
	if page > 1 {
		prevPage = page - 1
	}
	if page < totalPages {
		nextPage = page + 1
	}
	c.JSON(http.StatusOK, gin.H{
		"data": data,
		"meta": gin.H{
			"pagination": gin.H{
				"current-page": page,
				"prev-page":    prevPage,
				"next-page":    nextPage,
				"page-size":    perPage,
				"total-pages":  totalPages,
				"total-count":  total,
			},
		},
	})
}

// Get returns a single organization by name
// GET /api/v2/organizations/:name
// TFE-compatible JSON:API format
func (h *OrganizationHandlerV2) Get(c *gin.Context) {
	name := c.Param("name")

	org, err := h.orgRepo.GetByName(name)
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

	// TFE-compatible JSON:API response
	c.JSON(http.StatusOK, gin.H{
		"data": buildTFEOrganizationResponse(org, h.defaultProjectID(org)),
	})
}

// Create creates a new organization
// POST /api/v2/organizations
func (h *OrganizationHandlerV2) Create(c *gin.Context) {
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

	var req CreateOrganizationRequestV2
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

	// Extract fields from either format (JSON:API or simple)
	name := req.Name
	description := req.Description
	email := ""
	collaboratorAuthPolicy := "password" // Default per TFE spec
	costEstimationEnabled := true        // Default per TFE spec

	if req.Data != nil {
		if req.Data.Attributes.Name != "" {
			name = req.Data.Attributes.Name
		}
		if req.Data.Attributes.Description != "" {
			description = req.Data.Attributes.Description
		}
		if req.Data.Attributes.Email != "" {
			email = req.Data.Attributes.Email
		}
		if req.Data.Attributes.CollaboratorAuthPolicy != "" {
			collaboratorAuthPolicy = req.Data.Attributes.CollaboratorAuthPolicy
		}
		if req.Data.Attributes.CostEstimationEnabled != nil {
			costEstimationEnabled = *req.Data.Attributes.CostEstimationEnabled
		}
	}

	// Validate collaborator auth policy
	if collaboratorAuthPolicy != "password" && collaboratorAuthPolicy != "two_factor_mandatory" {
		collaboratorAuthPolicy = "password"
	}

	// Validate name length
	if len(name) == 0 || len(name) > 200 {
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

	// Check for duplicate name
	existing, _ := h.orgRepo.GetByName(name)
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{
			"errors": []gin.H{
				{
					"status": "409",
					"title":  "Conflict",
					"detail": "Organization with this name already exists",
				},
			},
		})
		return
	}

	org := &models.Organization{
		Name:                   name,
		Description:            description,
		Email:                  email,
		CollaboratorAuthPolicy: collaboratorAuthPolicy,
		CostEstimationEnabled:  costEstimationEnabled,
	}

	// tfe_organization policy flags (the stock provider creates with name+email only and PATCHes
	// the rest, but the wire contract accepts them on create too).
	if req.Data != nil {
		if detail, ok := applyOrgPolicyAttributes(org, &req.Data.Attributes); !ok {
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"errors": []gin.H{{"status": "422", "title": "Invalid Attribute", "detail": detail}},
			})
			return
		}
	}

	if err := h.orgRepo.Create(org); err != nil {
		// AUD-109: a permanently-reserved name (previously used, now deleted) is a client error,
		// not a server error - surface it as 422 so the caller knows to pick a different name.
		if errors.Is(err, repository.ErrOrganizationNameReserved) {
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"errors": []gin.H{
					{
						"status": "422",
						"title":  "Unprocessable Entity",
						"detail": "Organization name is reserved and cannot be reused",
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
					"detail": "Failed to create organization",
				},
			},
		})
		return
	}

	// Create default teams: "owners" and "viewers"
	if err := h.createDefaultTeams(org.ID); err != nil {
		logger.Errorf("Failed to create default teams for org %s: %v", org.ID, err)
		h.cleanupFailedOrgBootstrap(org.ID, org.Name) // AUD-023: don't leave a half-built org
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": fmt.Sprintf("Failed to create default teams: %v", err),
				},
			},
		})
		return
	}

	// Add creator to organization (no role - roles are deprecated)
	if err := h.orgRepo.AddMember(org.ID, user.ID); err != nil {
		errStr := strings.ToLower(err.Error())
		// AUD-023: a benign "already a member" duplicate must CONTINUE the bootstrap (add to the
		// owners team, create the default project), not `return` out of the handler. The old code
		// returned here, which both skipped the rest of the bootstrap (half-built org) and sent no
		// HTTP response at all (an empty 200). Only a genuine failure aborts with a 500.
		isDuplicate := err == gorm.ErrDuplicatedKey ||
			strings.Contains(errStr, "duplicate key") ||
			strings.Contains(errStr, "unique constraint") ||
			strings.Contains(errStr, "idx_org_user")
		switch {
		case isDuplicate:
			logger.Warnf("User %s is already a member of org %s; continuing bootstrap", user.ID, org.ID)
		case strings.Contains(errStr, "foreign key") || strings.Contains(errStr, "violates foreign key constraint"):
			logger.Errorf("Failed to add member %s to org %s: %v", user.ID, org.ID, err)
			h.cleanupFailedOrgBootstrap(org.ID, org.Name) // AUD-023
			c.JSON(http.StatusInternalServerError, gin.H{
				"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to add user to organization: user record not found. Please contact support."}},
			})
			return
		default:
			logger.Errorf("Failed to add member %s to org %s: %v", user.ID, org.ID, err)
			h.cleanupFailedOrgBootstrap(org.ID, org.Name) // AUD-023
			c.JSON(http.StatusInternalServerError, gin.H{
				"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": fmt.Sprintf("Failed to add member: %v", err)}},
			})
			return
		}
	}

	// Add creator to "owners" team (replaces old admin role)
	ownersTeam, err := h.teamRepo.GetByName(org.ID, "owners")
	if err != nil {
		logger.Errorf("Failed to find owners team for org %s: %v", org.ID, err)
		h.cleanupFailedOrgBootstrap(org.ID, org.Name) // AUD-023
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": fmt.Sprintf("Failed to find owners team: %v", err),
				},
			},
		})
		return
	}
	if err := h.teamRepo.AddMember(ownersTeam.ID, user.ID); err != nil {
		logger.Errorf("Failed to add member %s to owners team %s: %v", user.ID, ownersTeam.ID, err)
		h.cleanupFailedOrgBootstrap(org.ID, org.Name) // AUD-023
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": fmt.Sprintf("Failed to add creator to owners team: %v", err),
				},
			},
		})
		return
	}

	// Create default project and grant owners team access
	// This ensures the creator has access to the default project via team project access
	if err := h.createDefaultProject(org.ID, ownersTeam.ID); err != nil {
		logger.Errorf("Failed to create default project for org %s: %v", org.ID, err)
		h.cleanupFailedOrgBootstrap(org.ID, org.Name) // AUD-023
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": fmt.Sprintf("Failed to create default project: %v", err),
				},
			},
		})
		return
	}

	// Set the latest stable Terraform version as org default
	if org.DefaultTofuVersion == "" && h.db != nil {
		var versions []models.TofuVersion
		if err := h.db.Where("enabled = ? AND beta = ? AND deprecated = ?", true, false, false).
			Find(&versions).Error; err == nil && len(versions) > 0 {
			// Sort by semver descending to find the latest
			sort.Slice(versions, func(i, j int) bool {
				return tofu.CompareVersions(versions[i].Version, versions[j].Version) > 0
			})
			org.DefaultTofuVersion = versions[0].Version
			if err := h.orgRepo.Update(org); err != nil {
				logger.Warnf("Failed to set default opentofu version for org %s: %v", org.Name, err)
			} else {
				logger.Infof("Set default opentofu version for org %s to %s", org.Name, versions[0].Version)
			}
		}
	}

	// Log activity
	if h.activityService != nil {
		activityCtx := helpers.GetActivityContext(c)
		activityCtx.UserID = &user.ID
		activityCtx.OrganizationID = &org.ID
		_ = h.activityService.LogCreate(c.Request.Context(), "organization", org.ID.String(), org.Name, activityCtx)
	}

	// Return TFE-compatible JSON:API response
	c.JSON(http.StatusCreated, gin.H{
		"data": buildTFEOrganizationResponse(org, h.defaultProjectID(org)),
	})
}

// Update updates an organization by name
// PATCH /api/v2/organizations/:name
func (h *OrganizationHandlerV2) Update(c *gin.Context) {
	name := c.Param("name")

	org, err := h.orgRepo.GetByName(name)
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

	// AUD-151: gate org-settings mutation on manage-membership (owner-tier), mirroring
	// Delete. JWT/browser identities bypass the org-resolution wall, so without this
	// per-handler check any authenticated user could rewrite any org by name - rename,
	// downgrade collaborator_auth_policy, or change the org run-execution defaults.
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}},
		})
		return
	}
	canManage, err := h.rbacService.CheckOrgManageMembership(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to check permissions"}},
		})
		return
	}
	if !canManage {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to update this organization"}},
		})
		return
	}

	var req UpdateOrganizationRequestV2
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

	// Extract fields from either format (JSON:API or simple)
	newName := req.Name
	newDescription := req.Description
	newEmail := ""
	newCollaboratorAuthPolicy := ""
	var newCostEstimationEnabled *bool
	var newDefaultTerraformVersion *string
	var newAnsibleJobRetentionDays *int
	var newAnsibleAdHocModules *string

	if req.Data != nil {
		if req.Data.Attributes.Name != "" {
			newName = req.Data.Attributes.Name
		}
		if req.Data.Attributes.Description != "" {
			newDescription = req.Data.Attributes.Description
		}
		if req.Data.Attributes.Email != "" {
			newEmail = req.Data.Attributes.Email
		}
		if req.Data.Attributes.CollaboratorAuthPolicy != "" {
			newCollaboratorAuthPolicy = req.Data.Attributes.CollaboratorAuthPolicy
		}
		newCostEstimationEnabled = req.Data.Attributes.CostEstimationEnabled
		newDefaultTerraformVersion = req.Data.Attributes.DefaultTerraformVersion
		newAnsibleJobRetentionDays = req.Data.Attributes.AnsibleJobRetentionDays
		newAnsibleAdHocModules = req.Data.Attributes.AnsibleAdHocModules
	}

	if newName != "" {
		// Check if new name conflicts with existing organization
		if newName != org.Name {
			existing, _ := h.orgRepo.GetByName(newName)
			if existing != nil {
				c.JSON(http.StatusConflict, gin.H{
					"errors": []gin.H{
						{
							"status": "409",
							"title":  "Conflict",
							"detail": "Organization with this name already exists",
						},
					},
				})
				return
			}
		}
		org.Name = newName
	}
	if newDescription != "" {
		org.Description = newDescription
	}
	if newEmail != "" {
		org.Email = newEmail
	}
	if newCollaboratorAuthPolicy != "" {
		// Validate collaborator auth policy
		if newCollaboratorAuthPolicy == "password" || newCollaboratorAuthPolicy == "two_factor_mandatory" {
			org.CollaboratorAuthPolicy = newCollaboratorAuthPolicy
		}
	}
	if newCostEstimationEnabled != nil {
		org.CostEstimationEnabled = *newCostEstimationEnabled
	}
	if newDefaultTerraformVersion != nil {
		org.DefaultTofuVersion = *newDefaultTerraformVersion
	}
	if newAnsibleJobRetentionDays != nil && *newAnsibleJobRetentionDays >= 0 {
		org.AnsibleJobRetentionDays = *newAnsibleJobRetentionDays
	}
	if newAnsibleAdHocModules != nil {
		org.AnsibleAdHocModules = *newAnsibleAdHocModules
	}

	// tfe_organization_default_settings: the org-wide execution defaults.
	if req.Data != nil {
		if detail, ok := h.applyOrgDefaultSettings(org, req.Data.Attributes.DefaultExecutionMode, req.Data.Relationships); !ok {
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"errors": []gin.H{{"status": "422", "title": "Invalid Attribute", "detail": detail}},
			})
			return
		}
		// tfe_organization policy flags (pointer semantics: only supplied attributes change).
		if detail, ok := applyOrgPolicyAttributes(org, &req.Data.Attributes); !ok {
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"errors": []gin.H{{"status": "422", "title": "Invalid Attribute", "detail": detail}},
			})
			return
		}
	}

	if err := h.orgRepo.Update(org); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to update organization",
				},
			},
		})
		return
	}

	// Log activity
	if h.activityService != nil {
		activityCtx := helpers.GetActivityContext(c)
		if user != nil {
			activityCtx.UserID = &user.ID
		}
		activityCtx.OrganizationID = &org.ID
		changes := map[string]interface{}{}
		if newName != "" && newName != org.Name {
			changes["name"] = newName
		}
		if newDescription != "" {
			changes["description"] = newDescription
		}
		_ = h.activityService.LogUpdate(c.Request.Context(), "organization", org.ID.String(), org.Name, changes, activityCtx)
	}

	// Return TFE-compatible JSON:API response
	c.JSON(http.StatusOK, gin.H{
		"data": buildTFEOrganizationResponse(org, h.defaultProjectID(org)),
	})
}

// Delete deletes an organization by name
// DELETE /api/v2/organizations/:name
func (h *OrganizationHandlerV2) Delete(c *gin.Context) {
	name := c.Param("name")

	org, err := h.orgRepo.GetByName(name)
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

	// Check if user has permission to delete organization
	// Organization deletion requires user to be in "owners" team
	hasManageMembership, err := h.rbacService.CheckOrgManageMembership(c.Request.Context(), user.ID, org.ID)
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

	if !hasManageMembership {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "You do not have permission to delete this organization. Organization deletion requires membership in the 'owners' team.",
				},
			},
		})
		return
	}

	// Log activity before deletion
	if h.activityService != nil {
		activityCtx := helpers.GetActivityContext(c)
		activityCtx.UserID = &user.ID
		activityCtx.OrganizationID = &org.ID
		_ = h.activityService.LogDelete(c.Request.Context(), "organization", org.ID.String(), org.Name, activityCtx)
	}

	if err := h.orgRepo.Delete(org.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to delete organization",
				},
			},
		})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetEntitlementSet returns the entitlement set for an organization
// GET /api/v2/organizations/:name/entitlement-set
// TFE-compatible endpoint - returns organization entitlements/features
func (h *OrganizationHandlerV2) GetEntitlementSet(c *gin.Context) {
	name := c.Param("name")

	// Verify organization exists
	org, err := h.orgRepo.GetByName(name)
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

	// TFE-compatible entitlement set response
	// This endpoint returns what features/entitlements the organization has access to
	// JSON:API format: id and type at top level, attributes contain the actual data
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"id":   org.ID.String(),
			"type": "entitlement-sets",
			"attributes": gin.H{
				"cost-estimation":         true,
				"configuration-design":    true,
				"operations":              true,
				"private-module-registry": true,
				"state-storage":           true,
				"teams":                   true,
				"vcs-integrations":        true,
				"usage-reporting":         true,
				"user-limit":              0, // 0 means unlimited
				"self-serve-billing":      false,
				"audit-logging":           true,
				"sso":                     false,
				"sentinel":                false,
				"agents":                  false,
				"policy-enforcement":      false,
			},
		},
	})
}

// createDefaultProject creates the default project and grants the owners team full access
func (h *OrganizationHandlerV2) createDefaultProject(orgID, ownersTeamID uuid.UUID) error {
	// Check if default project already exists
	existing, err := h.projectRepo.GetByOrganizationAndName(orgID, "default")
	if err == nil && existing != nil {
		// Project exists - ensure owners team has access
		_, err := h.teamRepo.GetProjectAccessByTeamAndProject(ownersTeamID, existing.ID)
		if err != nil {
			access := "admin"
			accessEntry := &models.TeamProjectAccess{
				TeamID:    ownersTeamID,
				ProjectID: existing.ID,
				Access:    &access,
			}
			if err := h.teamRepo.CreateProjectAccess(accessEntry); err != nil {
				return fmt.Errorf("failed to grant owners team access to default project: %w", err)
			}
		}
		return nil
	}

	// Create default project
	project := &models.Project{
		OrganizationID: orgID,
		Name:           "default",
		Description:    "Default project for your organization",
	}
	if err := h.projectRepo.Create(project); err != nil {
		return fmt.Errorf("failed to create default project: %w", err)
	}

	// Grant owners team full access to the default project
	access := "admin"
	accessEntry := &models.TeamProjectAccess{
		TeamID:    ownersTeamID,
		ProjectID: project.ID,
		Access:    &access,
	}
	if err := h.teamRepo.CreateProjectAccess(accessEntry); err != nil {
		return fmt.Errorf("failed to grant owners team access to default project: %w", err)
	}

	return nil
}

// cleanupFailedOrgBootstrap removes a partially-bootstrapped organization when a step after the org
// row was created fails (AUD-023). Without this the org create left a half-built organization behind
// (org row + maybe teams/membership, no default project) and returned a 500 - the operation was not
// atomic. It also frees the reserved name (AUD-109) so the caller can retry with the same name.
// Best-effort: it runs in its own transaction and only logs on failure, since the caller is already
// returning an error to the client.
func (h *OrganizationHandlerV2) cleanupFailedOrgBootstrap(orgID uuid.UUID, name string) {
	if h.db == nil {
		return
	}
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		// Remove bootstrap children first, then the org row, then release the name reservation.
		var teamIDs []uuid.UUID
		if err := tx.Model(&models.Team{}).Where("organization_id = ?", orgID).Pluck("id", &teamIDs).Error; err != nil {
			return err
		}
		if len(teamIDs) > 0 {
			if err := tx.Where("team_id IN ?", teamIDs).Delete(&models.TeamMember{}).Error; err != nil {
				return err
			}
			if err := tx.Where("team_id IN ?", teamIDs).Delete(&models.TeamOrganizationAccess{}).Error; err != nil {
				return err
			}
			if err := tx.Where("team_id IN ?", teamIDs).Delete(&models.TeamProjectAccess{}).Error; err != nil {
				return err
			}
		}
		if err := tx.Where("organization_id = ?", orgID).Delete(&models.Team{}).Error; err != nil {
			return err
		}
		if err := tx.Where("organization_id = ?", orgID).Delete(&models.OrganizationMember{}).Error; err != nil {
			return err
		}
		if err := tx.Where("organization_id = ?", orgID).Delete(&models.Project{}).Error; err != nil {
			return err
		}
		if err := tx.Where("name = ?", name).Delete(&models.ReservedOrganizationName{}).Error; err != nil {
			return err
		}
		return tx.Delete(&models.Organization{}, "id = ?", orgID).Error
	}); err != nil {
		logger.Errorf("Failed to clean up partially-created organization %s after a bootstrap error: %v", orgID, err)
	}
}

// createDefaultTeams creates the default "owners" and "viewers" teams for a new organization
// This function is idempotent - it will skip creating teams that already exist
func (h *OrganizationHandlerV2) createDefaultTeams(orgID uuid.UUID) error {
	// Check if "owners" team already exists
	ownersTeam, err := h.teamRepo.GetByName(orgID, "owners")
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return fmt.Errorf("failed to check for existing owners team: %w", err)
		}
		// Team doesn't exist, create it
		ownersTeam = &models.Team{
			OrganizationID:             orgID,
			Name:                       "owners",
			Description:                "Organization owners with full control",
			Visibility:                 "secret", // Only visible to owners and org creator
			AllowMemberTokenManagement: true,     // Explicitly set (has default but being explicit)
		}

		if err := h.teamRepo.Create(ownersTeam); err != nil {
			return fmt.Errorf("failed to create owners team: %w", err)
		}
	}

	// Check if organization access exists for owners team, create if not
	ownersOrgAccess, err := h.teamRepo.GetOrganizationAccess(ownersTeam.ID)
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return fmt.Errorf("failed to check for existing owners team organization access: %w", err)
		}
		// Organization access doesn't exist, create it
		ownersOrgAccess = &models.TeamOrganizationAccess{
			TeamID:                   ownersTeam.ID,
			ManagePolicies:           true,
			ManagePolicyOverrides:    true,
			ManageWorkspaces:         true,
			ManageVCSSettings:        true,
			ManageProviders:          true,
			ManageModules:            true,
			ManageRunTasks:           true,
			ManageProjects:           true,
			ReadWorkspaces:           true,
			ReadProjects:             true,
			ManageMembership:         true,
			ManageTeams:              true,
			ManageOrganizationAccess: true,
			AccessSecretTeams:        true,
			ManageAgentPools:         true,
		}
		if err := h.teamRepo.CreateOrganizationAccess(ownersOrgAccess); err != nil {
			return fmt.Errorf("failed to create owners team organization access: %w", err)
		}
	} else {
		// Update existing access to ensure all permissions are enabled (in case it was created with defaults)
		ownersOrgAccess.ManagePolicies = true
		ownersOrgAccess.ManagePolicyOverrides = true
		ownersOrgAccess.ManageWorkspaces = true
		ownersOrgAccess.ManageVCSSettings = true
		ownersOrgAccess.ManageProviders = true
		ownersOrgAccess.ManageModules = true
		ownersOrgAccess.ManageRunTasks = true
		ownersOrgAccess.ManageProjects = true
		ownersOrgAccess.ReadWorkspaces = true
		ownersOrgAccess.ReadProjects = true
		ownersOrgAccess.ManageMembership = true
		ownersOrgAccess.ManageTeams = true
		ownersOrgAccess.ManageOrganizationAccess = true
		ownersOrgAccess.AccessSecretTeams = true
		ownersOrgAccess.ManageAgentPools = true
		if err := h.teamRepo.UpdateOrganizationAccess(ownersOrgAccess); err != nil {
			return fmt.Errorf("failed to update owners team organization access: %w", err)
		}
	}

	// Check if "viewers" team already exists
	viewersTeam, err := h.teamRepo.GetByName(orgID, "viewers")
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return fmt.Errorf("failed to check for existing viewers team: %w", err)
		}
		// Team doesn't exist, create it
		viewersTeam = &models.Team{
			OrganizationID:             orgID,
			Name:                       "viewers",
			Description:                "Organization viewers with read-only access",
			Visibility:                 "organization", // Visible to everyone
			AllowMemberTokenManagement: false,          // Viewers don't need token management
		}

		if err := h.teamRepo.Create(viewersTeam); err != nil {
			return fmt.Errorf("failed to create viewers team: %w", err)
		}
	}

	// Check if organization access exists for viewers team, create if not
	viewersOrgAccess, err := h.teamRepo.GetOrganizationAccess(viewersTeam.ID)
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return fmt.Errorf("failed to check for existing viewers team organization access: %w", err)
		}
		// Organization access doesn't exist, create it
		viewersOrgAccess = &models.TeamOrganizationAccess{
			TeamID:                   viewersTeam.ID,
			ManagePolicies:           false,
			ManagePolicyOverrides:    false,
			ManageWorkspaces:         false,
			ManageVCSSettings:        false,
			ManageProviders:          false,
			ManageModules:            false,
			ManageRunTasks:           false,
			ManageProjects:           false,
			ReadWorkspaces:           true, // Can view workspaces
			ReadProjects:             true, // Can view projects
			ManageMembership:         false,
			ManageTeams:              false,
			ManageOrganizationAccess: false,
			AccessSecretTeams:        false,
			ManageAgentPools:         false,
		}
		if err := h.teamRepo.CreateOrganizationAccess(viewersOrgAccess); err != nil {
			return fmt.Errorf("failed to create viewers team organization access: %w", err)
		}
	} else {
		// Update existing access to ensure correct read-only permissions
		viewersOrgAccess.ManagePolicies = false
		viewersOrgAccess.ManagePolicyOverrides = false
		viewersOrgAccess.ManageWorkspaces = false
		viewersOrgAccess.ManageVCSSettings = false
		viewersOrgAccess.ManageProviders = false
		viewersOrgAccess.ManageModules = false
		viewersOrgAccess.ManageRunTasks = false
		viewersOrgAccess.ManageProjects = false
		viewersOrgAccess.ReadWorkspaces = true
		viewersOrgAccess.ReadProjects = true
		viewersOrgAccess.ManageMembership = false
		viewersOrgAccess.ManageTeams = false
		viewersOrgAccess.ManageOrganizationAccess = false
		viewersOrgAccess.AccessSecretTeams = false
		viewersOrgAccess.ManageAgentPools = false
		if err := h.teamRepo.UpdateOrganizationAccess(viewersOrgAccess); err != nil {
			return fmt.Errorf("failed to update viewers team organization access: %w", err)
		}
	}

	return nil
}

// GetEffectivePermissions returns the authenticated user's effective permissions for an organization.
// This is the union of all permissions from all teams the user is a member of.
// Used by the frontend to conditionally show/hide UI elements based on permissions.
func (h *OrganizationHandlerV2) GetEffectivePermissions(c *gin.Context) {
	orgName := c.Param("name")
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized"}}})
		return
	}

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Organization not found"}}})
		return
	}

	perms, err := h.rbacService.GetEffectivePermissions(c.Request.Context(), userID.(uuid.UUID), org.ID)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Access denied"}}})
		return
	}

	// Convert Permission keys to strings for JSON
	result := make(map[string]bool)
	for perm, granted := range perms {
		result[string(perm)] = granted
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"type":       "effective-permissions",
			"id":         org.ID.String(),
			"attributes": result,
		},
	})
}
