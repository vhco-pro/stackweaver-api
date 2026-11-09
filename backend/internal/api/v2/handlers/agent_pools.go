// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// AgentPoolHandlerV2 handles TFE-compatible agent pool API.
type AgentPoolHandlerV2 struct {
	// platformAdmin is the verdict that gates a hosted pool's cap and group (SetPlatformAdmin).
	platformAdmin *platformadmin.Service
	poolRepo      *repository.AgentPoolRepository
	apiKeyService *apikey.Service
	runnerRepo    *repository.RunnerRepository
	orgRepo       *repository.OrganizationRepository
	authService   *auth.Service
	rbacService   *rbac.Service
}

// SetPlatformAdmin wires the platform administrator verdict the hosted pool's cap and group are
// written under (#933, D9). Without it nobody writes them.
func (h *AgentPoolHandlerV2) SetPlatformAdmin(s *platformadmin.Service) { h.platformAdmin = s }

// NewAgentPoolHandlerV2 creates an AgentPoolHandlerV2.
func NewAgentPoolHandlerV2(
	poolRepo *repository.AgentPoolRepository,
	runnerRepo *repository.RunnerRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *AgentPoolHandlerV2 {
	return &AgentPoolHandlerV2{
		poolRepo:    poolRepo,
		runnerRepo:  runnerRepo,
		orgRepo:     orgRepo,
		authService: authService,
		rbacService: rbacService,
	}
}

// CreateAgentPoolRequestV2 uses JSON:API format (TFE-compatible).
type CreateAgentPoolRequestV2 struct {
	Data struct {
		Type       string `json:"type" binding:"required"`
		Attributes struct {
			Name               string `json:"name" binding:"required"`
			OrganizationScoped *bool  `json:"organization-scoped,omitempty"`
		} `json:"attributes" binding:"required"`
		Relationships *struct {
			AllowedWorkspaces  *jsonAPIRelationship `json:"allowed-workspaces,omitempty"`
			AllowedProjects    *jsonAPIRelationship `json:"allowed-projects,omitempty"`
			ExcludedWorkspaces *jsonAPIRelationship `json:"excluded-workspaces,omitempty"`
		} `json:"relationships,omitempty"`
	} `json:"data" binding:"required"`
}

// UpdateAgentPoolRequestV2 uses JSON:API format (TFE-compatible).
type UpdateAgentPoolRequestV2 struct {
	Data struct {
		Type       string `json:"type" binding:"required"`
		Attributes *struct {
			Name               *string `json:"name,omitempty"`
			OrganizationScoped *bool   `json:"organization-scoped,omitempty"`
			// Native pool settings (#933, D15).
			KeepFailedJobsFor *int    `json:"keep-failed-jobs-for,omitempty"`
			CPULimit          *string `json:"cpu-limit,omitempty"`
			MemoryLimit       *string `json:"memory-limit,omitempty"`
			LimitsRequired    *bool   `json:"limits-required,omitempty"`
			LocalReadthrough  *bool   `json:"local-readthrough,omitempty"`
			// A hosted pool's cap and group, for a platform administrator only (D9).
			MaxConcurrentJobs *int    `json:"max-concurrent-jobs,omitempty"`
			PlacementGroup    *string `json:"placement-group,omitempty"`
		} `json:"attributes,omitempty"`
		Relationships *struct {
			AllowedWorkspaces  *jsonAPIRelationship `json:"allowed-workspaces,omitempty"`
			AllowedProjects    *jsonAPIRelationship `json:"allowed-projects,omitempty"`
			ExcludedWorkspaces *jsonAPIRelationship `json:"excluded-workspaces,omitempty"`
		} `json:"relationships,omitempty"`
	} `json:"data" binding:"required"`
}

// jsonAPIRelationship wraps relationship data in JSON:API format.
type jsonAPIRelationship struct {
	Data []jsonAPIRef `json:"data"`
}

type jsonAPIRef struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

func formatAgentPoolResponse(p *models.AgentPool, orgName string, agentCount int) jsonapi.Resource[AgentPoolAttributes] {
	rel := AgentPoolRelationships{
		Organization: jsonapi.ToOne(orgName, "organizations"),
	}
	if len(p.AllowedWorkspaces) > 0 {
		refs := make([]jsonapi.ResourceID, 0, len(p.AllowedWorkspaces))
		for _, w := range p.AllowedWorkspaces {
			refs = append(refs, jsonapi.ResourceID{ID: w.ID, Type: "workspaces"})
		}
		rel.AllowedWorkspaces = &jsonapi.ManyRelationship{Data: refs}
	}
	if len(p.AllowedProjects) > 0 {
		refs := make([]jsonapi.ResourceID, 0, len(p.AllowedProjects))
		for _, pr := range p.AllowedProjects {
			refs = append(refs, jsonapi.ResourceID{ID: pr.ID.String(), Type: "projects"})
		}
		rel.AllowedProjects = &jsonapi.ManyRelationship{Data: refs}
	}
	if len(p.ExcludedWorkspaces) > 0 {
		refs := make([]jsonapi.ResourceID, 0, len(p.ExcludedWorkspaces))
		for _, w := range p.ExcludedWorkspaces {
			refs = append(refs, jsonapi.ResourceID{ID: w.ID, Type: "workspaces"})
		}
		rel.ExcludedWorkspaces = &jsonapi.ManyRelationship{Data: refs}
	}
	return jsonapi.Resource[AgentPoolAttributes]{
		ID:            p.ID.String(),
		Type:          "agent-pools",
		Attributes:    agentPoolAttributes(p, agentCount),
		Relationships: rel,
		Links:         jsonapi.SelfLink{Self: "/api/v2/agent-pools/" + p.ID.String()},
	}
}

// agentPoolAttributes renders a pool's attributes, with the cap and group on a hosted pool only.
func agentPoolAttributes(p *models.AgentPool, agentCount int) AgentPoolAttributes {
	a := AgentPoolAttributes{
		Name: p.Name, AgentCount: agentCount, OrganizationScoped: p.OrganizationScoped, CreatedAt: jsonapi.FormatTime(p.CreatedAt),
		Kind: p.Kind, KeepFailedJobsFor: p.KeepFailedJobsFor, CPULimit: p.CPULimit, MemoryLimit: p.MemoryLimit,
		LimitsRequired: p.LimitsRequired, LocalReadthrough: !p.LocalReadthroughDisabled,
	}
	if a.Kind == "" {
		a.Kind = models.AgentPoolKindCustomer
	}
	if p.IsHosted() {
		cap := 0
		if p.MaxConcurrentJobs != nil {
			cap = *p.MaxConcurrentJobs
		}
		group := p.PlacementGroup
		a.MaxConcurrentJobs, a.PlacementGroup = &cap, &group
	}
	return a
}

func (h *AgentPoolHandlerV2) requireManageAgentPools(c *gin.Context, orgID uuid.UUID) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return false
	}
	ok, err := h.rbacService.CheckOrgManageAgentPools(c.Request.Context(), user.ID, orgID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return false
	}
	if !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage agent pools")
		return false
	}
	return true
}

// List returns agent pools for an organization.
// GET /api/v2/organizations/:name/agent-pools
func (h *AgentPoolHandlerV2) List(c *gin.Context) {
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}
	if !h.requireManageAgentPools(c, org.ID) {
		return
	}

	page, pageSize := jsonapi.PageParams(c, 20, 100)
	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}
	opts := repository.ListAgentPoolsOptions{
		Query:  c.Query("q"),
		Sort:   c.DefaultQuery("sort", "created-at"),
		Limit:  pageSize,
		Offset: offset,
	}

	pools, total, err := h.poolRepo.ListByOrganization(org.ID, opts)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list agent pools")
		return
	}

	data := make([]jsonapi.Resource[AgentPoolAttributes], 0, len(pools))
	for i := range pools {
		agentCount := 0
		if h.runnerRepo != nil {
			if n, err := h.runnerRepo.CountByAgentPool(pools[i].ID); err == nil {
				agentCount = int(n)
			}
		}
		data = append(data, formatAgentPoolResponse(&pools[i], org.Name, agentCount))
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(page, pageSize, total))
}

// Create creates an agent pool.
// POST /api/v2/organizations/:name/agent-pools
func (h *AgentPoolHandlerV2) Create(c *gin.Context) {
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}
	if !h.requireManageAgentPools(c, org.ID) {
		return
	}

	var req CreateAgentPoolRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if req.Data.Type != "agent-pools" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "data.type must be 'agent-pools'")
		return
	}

	name := req.Data.Attributes.Name
	if name == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "name is required")
		return
	}
	orgScoped := true
	if req.Data.Attributes.OrganizationScoped != nil {
		orgScoped = *req.Data.Attributes.OrganizationScoped
	}

	existing, _ := h.poolRepo.GetByOrganizationAndName(org.ID, name)
	if existing != nil {
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", "Agent pool with this name already exists")
		return
	}

	pool := &models.AgentPool{
		OrganizationID:     org.ID,
		Name:               name,
		OrganizationScoped: orgScoped,
	}
	if err := h.poolRepo.Create(pool); err != nil {
		// The name lookup above skips the organization's hidden hosted pool, whose name the unique
		// index still holds.
		if repository.IsUniqueViolation(err) {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", "Agent pool with this name already exists")
			return
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create agent pool")
		return
	}

	// Apply relations if provided
	if req.Data.Relationships != nil {
		if req.Data.Relationships.AllowedWorkspaces != nil {
			ids := extractWorkspaceIDs(req.Data.Relationships.AllowedWorkspaces.Data)
			_ = h.poolRepo.ReplaceAllowedWorkspaces(pool.ID, ids)
		}
		if req.Data.Relationships.AllowedProjects != nil {
			ids := extractProjectIDs(req.Data.Relationships.AllowedProjects.Data)
			_ = h.poolRepo.ReplaceAllowedProjects(pool.ID, ids)
		}
		if req.Data.Relationships.ExcludedWorkspaces != nil {
			ids := extractWorkspaceIDs(req.Data.Relationships.ExcludedWorkspaces.Data)
			_ = h.poolRepo.ReplaceExcludedWorkspaces(pool.ID, ids)
		}
	}

	// Reload with relations
	updated, _ := h.poolRepo.GetCustomerByID(pool.ID, true)
	if updated != nil {
		pool = updated
	}
	agentCount := 0
	if h.runnerRepo != nil {
		if n, err := h.runnerRepo.CountByAgentPool(pool.ID); err == nil {
			agentCount = int(n)
		}
	}
	jsonapi.WriteDocument(c, http.StatusCreated, formatAgentPoolResponse(pool, org.Name, agentCount))
}

// GetByID returns a single agent pool by ID.
// GET /api/v2/agent-pools/:id
func (h *AgentPoolHandlerV2) GetByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "invalid agent pool id")
		return
	}

	pool, err := h.poolRepo.GetCustomerByID(id, true)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
			return
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to get agent pool")
		return
	}

	org, _ := h.orgRepo.GetByID(pool.OrganizationID)
	orgName := ""
	if org != nil {
		orgName = org.Name
	}
	if !h.requireManageAgentPools(c, pool.OrganizationID) {
		return
	}

	agentCount := 0
	if h.runnerRepo != nil {
		if n, err := h.runnerRepo.CountByAgentPool(pool.ID); err == nil {
			agentCount = int(n)
		}
	}
	jsonapi.WriteDocument(c, http.StatusOK, formatAgentPoolResponse(pool, orgName, agentCount))
}

// Update updates an agent pool (name, organization-scoped) or relation-only updates (allowed/excluded).
// PATCH /api/v2/agent-pools/:id
func (h *AgentPoolHandlerV2) Update(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "invalid agent pool id")
		return
	}

	var req UpdateAgentPoolRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if req.Data.Type != "agent-pools" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "data.type must be 'agent-pools'")
		return
	}

	pool, err := h.poolRepo.GetByID(id, true)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
			return
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to get agent pool")
		return
	}
	if pool.IsHosted() {
		h.updateHosted(c, pool, &req)
		return
	}
	org, _ := h.orgRepo.GetByID(pool.OrganizationID)
	orgName := ""
	if org != nil {
		orgName = org.Name
	}
	if !h.requireManageAgentPools(c, pool.OrganizationID) {
		return
	}
	if a := req.Data.Attributes; a != nil && (a.MaxConcurrentJobs != nil || a.PlacementGroup != nil) {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "max-concurrent-jobs and placement-group exist on hosted capacity only")
		return
	}

	// Relation-only updates (TFE UpdateAllowedWorkspaces / UpdateAllowedProjects / UpdateExcludedWorkspaces)
	if req.Data.Relationships != nil {
		if req.Data.Relationships.AllowedWorkspaces != nil {
			ids := extractWorkspaceIDs(req.Data.Relationships.AllowedWorkspaces.Data)
			if err := h.poolRepo.ReplaceAllowedWorkspaces(id, ids); err != nil {
				jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update allowed workspaces")
				return
			}
		}
		if req.Data.Relationships.AllowedProjects != nil {
			ids := extractProjectIDs(req.Data.Relationships.AllowedProjects.Data)
			if err := h.poolRepo.ReplaceAllowedProjects(id, ids); err != nil {
				jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update allowed projects")
				return
			}
		}
		if req.Data.Relationships.ExcludedWorkspaces != nil {
			ids := extractWorkspaceIDs(req.Data.Relationships.ExcludedWorkspaces.Data)
			if err := h.poolRepo.ReplaceExcludedWorkspaces(id, ids); err != nil {
				jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update excluded workspaces")
				return
			}
		}
	}

	// Attribute updates
	if req.Data.Attributes != nil {
		if req.Data.Attributes.Name != nil && *req.Data.Attributes.Name != "" {
			pool.Name = *req.Data.Attributes.Name
		}
		if req.Data.Attributes.OrganizationScoped != nil {
			pool.OrganizationScoped = *req.Data.Attributes.OrganizationScoped
		}
		if detail := applyPoolSettings(pool, req.Data.Attributes.KeepFailedJobsFor, req.Data.Attributes.CPULimit, req.Data.Attributes.MemoryLimit,
			req.Data.Attributes.LimitsRequired, req.Data.Attributes.LocalReadthrough); detail != "" {
			jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", detail)
			return
		}
		if err := h.poolRepo.Update(pool); err != nil {
			if repository.IsUniqueViolation(err) {
				jsonapi.WriteError(c, http.StatusConflict, "Conflict", "Agent pool with this name already exists")
				return
			}
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update agent pool")
			return
		}
	}

	updated, _ := h.poolRepo.GetCustomerByID(id, true)
	if updated != nil {
		pool = updated
	}
	agentCount := 0
	if h.runnerRepo != nil {
		if n, err := h.runnerRepo.CountByAgentPool(pool.ID); err == nil {
			agentCount = int(n)
		}
	}
	jsonapi.WriteDocument(c, http.StatusOK, formatAgentPoolResponse(pool, orgName, agentCount))
}

// Delete deletes an agent pool.
// DELETE /api/v2/agent-pools/:id
func (h *AgentPoolHandlerV2) Delete(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "invalid agent pool id")
		return
	}

	pool, err := h.poolRepo.GetCustomerByID(id, false)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
			return
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to get agent pool")
		return
	}
	if !h.requireManageAgentPools(c, pool.OrganizationID) {
		return
	}

	if err := h.poolRepo.Delete(id); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete agent pool")
		return
	}
	c.Status(http.StatusNoContent)
}

// ListAgents returns agents (runners) in a pool. TFE-compatible agent shape.
// GET /api/v2/agent-pools/:id/agents
func (h *AgentPoolHandlerV2) ListAgents(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "invalid agent pool id")
		return
	}

	pool, err := h.poolRepo.GetCustomerByID(id, false)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
			return
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to get agent pool")
		return
	}
	if !h.requireManageAgentPools(c, pool.OrganizationID) {
		return
	}

	runners, err := h.runnerRepo.ListByAgentPool(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list agents")
		return
	}

	// Format as TFE Agent shape: id, name, ip-address, status, last-ping-at
	data := make([]jsonapi.Resource[AgentAttributes], 0, len(runners))
	for _, r := range runners {
		data = append(data, jsonapi.Resource[AgentAttributes]{
			ID:   r.ID.String(),
			Type: "agents",
			Attributes: AgentAttributes{
				Name:                       r.Name,
				IPAddress:                  r.IPAddress,
				Status:                     string(r.Status),
				LastPingAt:                 jsonapi.FormatTimePtr(r.LastHeartbeatAt),
				Driver:                     r.Driver,
				NetworkMode:                r.NetworkMode,
				LauncherSettingsAttributes: launcherSettings(&r),
			},
		})
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(1, 20, int64(len(data))))
}

func extractWorkspaceIDs(refs []jsonAPIRef) []string {
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.ID != "" {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

func extractProjectIDs(refs []jsonAPIRef) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(refs))
	for _, r := range refs {
		if r.ID != "" {
			if u, err := uuid.Parse(r.ID); err == nil {
				ids = append(ids, u)
			}
		}
	}
	return ids
}

// SetAPIKeyService wires the API key service used by QueueDepth to enforce agent-token
// pool binding. Set after construction because the service is built later in route
// registration; QueueDepth resolves it per request and degrades safely if unset.
func (h *AgentPoolHandlerV2) SetAPIKeyService(s *apikey.Service) {
	h.apiKeyService = s
}

// QueueDepth returns how much work an agent pool has waiting and how many runners it
// has to execute it.
// GET /api/v2/agent-pools/:id/queue-depth
//
// This exists for the Kubernetes runner operator: its KEDA external scaler polls this
// every 10-15s and scales runner pods on the result, so the response is deliberately
// small and cheap (six COUNTs, no row materialisation) and safe to call frequently.
// See docs/internal/plans/infrastructure/runners/kubernetes-runner-operator-plan.md.
//
// Auth accepts two identities, because two very different callers need it:
//
//   - An **org-scoped `runner:register` API key** - what the operator holds, via the
//     Secret named by `RunnerPool.spec.tokenSecretRef`. Note this cannot use the
//     RunnerAuth middleware: that requires a token bound to exactly one *runner* and
//     explicitly rejects registration keys, but the operator has no runner identity of
//     its own. The scope check mirrors runner registration instead. Agent tokens bound
//     to a single pool may only read that pool.
//   - A **JWT/session user with manage-agent-pools**, so the same data is reachable from
//     the UI or by an operator debugging a pool by hand.
//
// An api-key caller is authorized *only* by the scope check - there is deliberately no
// fallback to the key owner's RBAC, because that would let a narrowly-scoped token act
// with its owner's full permissions across organizations.
func (h *AgentPoolHandlerV2) QueueDepth(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "invalid agent pool id")
		return
	}

	pool, err := h.poolRepo.GetCustomerByID(id, false)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
			return
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to get agent pool")
		return
	}

	if !h.authorizeQueueDepth(c, pool, id) {
		return
	}

	depth, err := h.poolRepo.QueueDepth(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to compute queue depth")
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, jsonapi.Resource[QueueDepthAttributes]{
		ID:   id.String(),
		Type: "queue-depths",
		Attributes: QueueDepthAttributes{
			PendingTerraformJobs: depth.PendingTerraformJobs,
			PendingAnsibleJobs:   depth.PendingAnsibleJobs,
			PendingWorkItems:     depth.PendingWorkItems,
			TotalPending:         depth.TotalPending,
			BusyRunners:          depth.BusyRunners,
			TotalRunners:         depth.TotalRunners,
			IdleRunners:          depth.IdleRunners,
			PendingByEngine:      QueueDepthEngines{Tofu: depth.PendingByEngine.Tofu, Ansible: depth.PendingByEngine.Ansible, Any: depth.PendingByEngine.Any},
			Capacity:             depth.Capacity,
			InFlight:             depth.InFlight,
			Headroom:             depth.Headroom,
		},
	})
}

// authorizeQueueDepth allows either an org-scoped runner:register API key (the operator)
// or a user holding manage-agent-pools. It writes the error response and returns false
// when the caller is allowed neither.
func (h *AgentPoolHandlerV2) authorizeQueueDepth(c *gin.Context, pool *models.AgentPool, poolID uuid.UUID) bool {
	if method, _ := c.Get("auth_method"); method == "api_key" {
		scopes, _ := c.Get("api_key_scopes")
		scopeStrs, ok := scopes.([]string)
		if !ok {
			jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "invalid API key scopes")
			return false
		}
		checker, cerr := apikey.NewScopeChecker(scopeStrs)
		if cerr != nil {
			jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "invalid API key scopes")
			return false
		}
		if checker.IsUnrestricted() {
			// An unrestricted key is its owner's general-purpose token, not a runner
			// credential, so it is judged as its owner, the way the org wall treats it.
			return h.requireManageAgentPools(c, pool.OrganizationID)
		}
		if !grantsRunnerRegister(checker, pool.OrganizationID) {
			// Deny outright - do NOT fall back to the key owner's RBAC. This route is
			// org-wall-agnostic (the wall's scope-vs-method check would reject a
			// runner:register key on a GET), so this check IS the tenant boundary for
			// api-key callers. An earlier revision fell through to
			// requireManageAgentPools here, which let a key scoped to
			// org:A:runner:register read org B's queue depth whenever its human owner
			// happened to hold manage-agent-pools on B - a token-scope escalation.
			// Confirmed live before the fix: a main-scoped key returned 200 for an
			// acme-corp pool.
			jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "API key does not have the launcher registration scope (runner:register) for this organization")
			return false
		}
		// Pool-binding enforcement, matching runner registration: an agent token
		// (tfe_agent_token) is bound to one pool and must not read another's depth.
		// An ordinary org-level runner:register key has no binding and may read any
		// pool in its organization.
		if h.apiKeyService != nil {
			if raw, exists := c.Get("api_key_id"); exists {
				if keyID, perr := uuid.Parse(fmt.Sprintf("%v", raw)); perr == nil {
					bound, berr := h.apiKeyService.AgentPoolBindingForKey(keyID)
					if status, detail := poolBindingVerdict(bound, berr, poolID); status != 0 {
						jsonapi.WriteError(c, status, http.StatusText(status), detail)
						return false
					}
				}
			}
		}
		return true
	}

	return h.requireManageAgentPools(c, pool.OrganizationID)
}

// JITTokenRequest is the optional body of POST /agent-pools/:id/jit-token.
type JITTokenRequest struct {
	Data *struct {
		Type       string `json:"type"`
		Attributes *struct {
			// ExpiresIn is the token's lifetime in seconds: ten minutes by default, an hour at most.
			ExpiresIn *int `json:"expires-in,omitempty"`
		} `json:"attributes,omitempty"`
	} `json:"data,omitempty"`
}

// JITTokenAttributes is a just-in-time registration token, its plaintext shown once.
type JITTokenAttributes struct {
	Token     string `json:"token"` //nolint:gosec // G117: the token is the response, shown once
	ExpiresAt string `json:"expires-at"`
}

// JITToken mints a just-in-time registration token for the pool (#933, D11): a one-time,
// short-lived agent token that registers one launcher (the --single launcher an operator starts
// per job) and is used up by that registration. The caller is the pool's own operator credential,
// as for the queue depth: an agent token of the pool, an organization key carrying runner:register
// on its organization, or a user who manages agent pools; never a fallback to a key owner's RBAC.
//
// POST /api/v2/agent-pools/:id/jit-token
func (h *AgentPoolHandlerV2) JITToken(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "invalid agent pool id")
		return
	}
	pool, err := h.poolRepo.GetCustomerByID(id, false)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
			return
		}
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !h.authorizeQueueDepth(c, pool, id) {
		return
	}
	var req JITTokenRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
			return
		}
	}
	ttl := apikey.DefaultJITTokenTTL
	if req.Data != nil && req.Data.Attributes != nil && req.Data.Attributes.ExpiresIn != nil {
		secs := *req.Data.Attributes.ExpiresIn
		if secs <= 0 || time.Duration(secs)*time.Second > apikey.MaxJITTokenTTL {
			jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "expires-in is a number of seconds up to an hour")
			return
		}
		ttl = time.Duration(secs) * time.Second
	}
	owner, ok := h.jitOwner(c)
	if !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "a just-in-time token is minted with a user's credential")
		return
	}
	key, token, err := h.apiKeyService.CreateJITToken(owner, pool.ID, pool.OrganizationID, ttl)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	jsonapi.WriteDocument(c, http.StatusCreated, jsonapi.Resource[JITTokenAttributes]{
		ID: key.ID.String(), Type: "agent-jit-tokens",
		Attributes: JITTokenAttributes{Token: token, ExpiresAt: jsonapi.FormatTime(*key.ExpiresAt)},
	})
}

// jitOwner is the user a JIT token belongs to: the calling key's owner, or the signed-in user.
func (h *AgentPoolHandlerV2) jitOwner(c *gin.Context) (uuid.UUID, bool) {
	if v, ok := c.Get("user_id"); ok {
		if id, ok := v.(uuid.UUID); ok && id != uuid.Nil {
			return id, true
		}
	}
	if h.authService != nil {
		if user, err := h.authService.GetUserFromContext(c); err == nil && user != nil {
			return user.ID, true
		}
	}
	return uuid.Nil, false
}

// A pool's limits are written in the forms both drivers read (#933, D4, AC24): the container
// driver's parser in backend/internal/launcher/driver/container.go and a Kubernetes quantity.
// CPU is cores (0.5, 2) or whole millicores (500m); memory is whole bytes or a number with a
// binary or decimal suffix up to T.
var (
	cpuLimitPattern    = regexp.MustCompile(`^(?:[0-9]+m|[0-9]+(?:\.[0-9]+)?)$`)
	memoryLimitPattern = regexp.MustCompile(`^(?:[0-9]+|[0-9]+(?:\.[0-9]+)?(?:Ki|Mi|Gi|Ti|K|M|G|T))$`)
)

// minNanoCPUs and minMemoryBytes are the smallest limits Docker accepts (0.01 CPU, 6 MiB); a
// smaller one would fail every job at launch.
const (
	minNanoCPUs    = 10_000_000
	minMemoryBytes = 6 << 20
)

// checkCPULimit names what is wrong with a cpu-limit, or returns "" for a valid one or empty.
func checkCPULimit(v string) string {
	if v == "" {
		return ""
	}
	const detail = "cpu-limit must be a number of cores (0.5, 2) or millicores (500m), at least 0.01 (10m)"
	if !cpuLimitPattern.MatchString(v) {
		return detail
	}
	n, err := strconv.ParseFloat(strings.TrimSuffix(v, "m"), 64)
	if err != nil {
		return detail
	}
	if strings.HasSuffix(v, "m") {
		n /= 1000
	}
	if n*1e9 < minNanoCPUs {
		return detail
	}
	return ""
}

// checkMemoryLimit names what is wrong with a memory-limit, or returns "" for a valid one or empty.
func checkMemoryLimit(v string) string {
	if v == "" {
		return ""
	}
	const detail = "memory-limit must be bytes or a number with Ki, Mi, Gi, Ti, K, M, G or T (512Mi, 2Gi), at least 6Mi"
	if !memoryLimitPattern.MatchString(v) {
		return detail
	}
	mult := 1.0
	num := v
	for _, u := range []struct {
		suffix string
		mult   float64
	}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40}, {"K", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12}} {
		if n, ok := strings.CutSuffix(v, u.suffix); ok {
			num, mult = n, u.mult
			break
		}
	}
	n, err := strconv.ParseFloat(num, 64)
	if err != nil || n*mult < minMemoryBytes {
		return detail
	}
	return ""
}

// applyPoolSettings applies the native pool settings of a request, or names the one it refuses.
func applyPoolSettings(pool *models.AgentPool, keep *int, cpu, mem *string, required, readthrough *bool) string {
	if keep != nil {
		if *keep < 0 {
			return "keep-failed-jobs-for must be zero or a number of seconds"
		}
		pool.KeepFailedJobsFor = *keep
	}
	if cpu != nil {
		v := strings.TrimSpace(*cpu)
		if detail := checkCPULimit(v); detail != "" {
			return detail
		}
		pool.CPULimit = v
	}
	if mem != nil {
		v := strings.TrimSpace(*mem)
		if detail := checkMemoryLimit(v); detail != "" {
			return detail
		}
		pool.MemoryLimit = v
	}
	if required != nil {
		pool.LimitsRequired = *required
	}
	if readthrough != nil {
		pool.LocalReadthroughDisabled = !*readthrough
	}
	if pool.LimitsRequired && pool.CPULimit == "" && pool.MemoryLimit == "" {
		return "limits-required needs a cpu-limit or a memory-limit"
	}
	return ""
}

// updateHosted writes a hosted pool's cap and placement group, the only settings of a hosted pool
// anyone writes, and only a platform administrator (#933, D9, AC55, AC79). Anyone else asking for
// those fields gets 403 naming them; any other change of a hosted pool answers as for a missing
// pool, because the pool is not the organization's to configure, rename or delete (AC49, AC50).
func (h *AgentPoolHandlerV2) updateHosted(c *gin.Context, pool *models.AgentPool, req *UpdateAgentPoolRequestV2) {
	a := req.Data.Attributes
	asksCap := a != nil && (a.MaxConcurrentJobs != nil || a.PlacementGroup != nil)
	other := req.Data.Relationships != nil || (a != nil && (a.Name != nil || a.OrganizationScoped != nil || a.KeepFailedJobsFor != nil ||
		a.CPULimit != nil || a.MemoryLimit != nil || a.LimitsRequired != nil || a.LocalReadthrough != nil))
	if !asksCap {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
		return
	}
	var admin *models.User
	reason := "no platform administrator verdict is configured"
	if h.platformAdmin != nil {
		admin, reason = h.platformAdmin.Check(c)
	}
	if admin == nil {
		logger.Warnf("hosted capacity %s: refused a cap or group write: %s", pool.ID, reason)
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "max-concurrent-jobs and placement-group of hosted capacity are set by a platform administrator only")
		return
	}
	if other {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "the only writable settings of hosted capacity are max-concurrent-jobs and placement-group")
		return
	}
	if a.MaxConcurrentJobs != nil {
		if *a.MaxConcurrentJobs < 0 {
			jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "max-concurrent-jobs must be zero (unlimited) or more")
			return
		}
		pool.MaxConcurrentJobs = a.MaxConcurrentJobs
	}
	if a.PlacementGroup != nil {
		g := strings.TrimSpace(*a.PlacementGroup)
		if g == "" || len(g) > 100 {
			jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "placement-group must be a name of 1 to 100 characters")
			return
		}
		pool.PlacementGroup = g
	}
	if err := h.poolRepo.Update(pool); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update agent pool")
		return
	}
	logger.Infof("Platform administrator %s set hosted capacity %s to cap %v, group %s", admin.ID, pool.ID, pool.MaxConcurrentJobs, pool.PlacementGroup)
	orgName := ""
	if org, _ := h.orgRepo.GetByID(pool.OrganizationID); org != nil {
		orgName = org.Name
	}
	jsonapi.WriteDocument(c, http.StatusOK, formatAgentPoolResponse(pool, orgName, 0))
}
