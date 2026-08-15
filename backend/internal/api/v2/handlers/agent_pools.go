// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// AgentPoolHandlerV2 handles TFE-compatible agent pool API.
type AgentPoolHandlerV2 struct {
	poolRepo      *repository.AgentPoolRepository
	apiKeyService *apikey.Service
	runnerRepo    *repository.RunnerRepository
	orgRepo       *repository.OrganizationRepository
	authService   *auth.Service
	rbacService   *rbac.Service
}

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

func formatAgentPoolResponse(p *models.AgentPool, orgName string, agentCount int) gin.H {
	attrs := gin.H{
		"name":                p.Name,
		"agent-count":         agentCount,
		"organization-scoped": p.OrganizationScoped,
		"created-at":          p.CreatedAt.Format(time.RFC3339),
	}
	rel := gin.H{
		"organization": gin.H{
			"data": gin.H{"id": orgName, "type": "organizations"},
		},
	}
	if len(p.AllowedWorkspaces) > 0 {
		var refs []gin.H
		for _, w := range p.AllowedWorkspaces {
			refs = append(refs, gin.H{"id": w.ID, "type": "workspaces"})
		}
		rel["allowed-workspaces"] = gin.H{"data": refs}
	}
	if len(p.AllowedProjects) > 0 {
		var refs []gin.H
		for _, pr := range p.AllowedProjects {
			refs = append(refs, gin.H{"id": pr.ID.String(), "type": "projects"})
		}
		rel["allowed-projects"] = gin.H{"data": refs}
	}
	if len(p.ExcludedWorkspaces) > 0 {
		var refs []gin.H
		for _, w := range p.ExcludedWorkspaces {
			refs = append(refs, gin.H{"id": w.ID, "type": "workspaces"})
		}
		rel["excluded-workspaces"] = gin.H{"data": refs}
	}
	return gin.H{
		"id":            p.ID.String(),
		"type":          "agent-pools",
		"attributes":    attrs,
		"relationships": rel,
		"links":         gin.H{"self": "/api/v2/agent-pools/" + p.ID.String()},
	}
}

func (h *AgentPoolHandlerV2) requireManageAgentPools(c *gin.Context, orgID uuid.UUID) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return false
	}
	ok, err := h.rbacService.CheckOrgManageAgentPools(c.Request.Context(), user.ID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to check permissions"}}})
		return false
	}
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to manage agent pools"}}})
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
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Organization not found"}}})
		return
	}
	if !h.requireManageAgentPools(c, org.ID) {
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page[number]", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page[size]", "20"))
	if pageSize > 100 {
		pageSize = 100
	}
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
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to list agent pools"}}})
		return
	}

	data := make([]gin.H, 0, len(pools))
	for i := range pools {
		agentCount := 0
		if h.runnerRepo != nil {
			if n, err := h.runnerRepo.CountByAgentPool(pools[i].ID); err == nil {
				agentCount = int(n)
			}
		}
		data = append(data, formatAgentPoolResponse(&pools[i], org.Name, agentCount))
	}

	c.JSON(http.StatusOK, gin.H{
		"data": data,
		"meta": gin.H{
			"pagination": gin.H{
				"current-page": page,
				"page-size":    pageSize,
				"total-count":  total,
			},
		},
	})
}

// Create creates an agent pool.
// POST /api/v2/organizations/:name/agent-pools
func (h *AgentPoolHandlerV2) Create(c *gin.Context) {
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Organization not found"}}})
		return
	}
	if !h.requireManageAgentPools(c, org.ID) {
		return
	}

	var req CreateAgentPoolRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}}})
		return
	}
	if req.Data.Type != "agent-pools" {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "data.type must be 'agent-pools'"}}})
		return
	}

	name := req.Data.Attributes.Name
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "name is required"}}})
		return
	}
	orgScoped := true
	if req.Data.Attributes.OrganizationScoped != nil {
		orgScoped = *req.Data.Attributes.OrganizationScoped
	}

	existing, _ := h.poolRepo.GetByOrganizationAndName(org.ID, name)
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"errors": []gin.H{{"status": "409", "title": "Conflict", "detail": "Agent pool with this name already exists"}}})
		return
	}

	pool := &models.AgentPool{
		OrganizationID:     org.ID,
		Name:               name,
		OrganizationScoped: orgScoped,
	}
	if err := h.poolRepo.Create(pool); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to create agent pool"}}})
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
	updated, _ := h.poolRepo.GetByID(pool.ID, true)
	if updated != nil {
		pool = updated
	}
	agentCount := 0
	if h.runnerRepo != nil {
		if n, err := h.runnerRepo.CountByAgentPool(pool.ID); err == nil {
			agentCount = int(n)
		}
	}
	c.JSON(http.StatusCreated, gin.H{"data": formatAgentPoolResponse(pool, org.Name, agentCount)})
}

// GetByID returns a single agent pool by ID.
// GET /api/v2/agent-pools/:id
func (h *AgentPoolHandlerV2) GetByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "invalid agent pool id"}}})
		return
	}

	pool, err := h.poolRepo.GetByID(id, true)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Agent pool not found"}}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to get agent pool"}}})
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
	c.JSON(http.StatusOK, gin.H{"data": formatAgentPoolResponse(pool, orgName, agentCount)})
}

// Update updates an agent pool (name, organization-scoped) or relation-only updates (allowed/excluded).
// PATCH /api/v2/agent-pools/:id
func (h *AgentPoolHandlerV2) Update(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "invalid agent pool id"}}})
		return
	}

	pool, err := h.poolRepo.GetByID(id, true)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Agent pool not found"}}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to get agent pool"}}})
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

	var req UpdateAgentPoolRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}}})
		return
	}
	if req.Data.Type != "agent-pools" {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "data.type must be 'agent-pools'"}}})
		return
	}

	// Relation-only updates (TFE UpdateAllowedWorkspaces / UpdateAllowedProjects / UpdateExcludedWorkspaces)
	if req.Data.Relationships != nil {
		if req.Data.Relationships.AllowedWorkspaces != nil {
			ids := extractWorkspaceIDs(req.Data.Relationships.AllowedWorkspaces.Data)
			if err := h.poolRepo.ReplaceAllowedWorkspaces(id, ids); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to update allowed workspaces"}}})
				return
			}
		}
		if req.Data.Relationships.AllowedProjects != nil {
			ids := extractProjectIDs(req.Data.Relationships.AllowedProjects.Data)
			if err := h.poolRepo.ReplaceAllowedProjects(id, ids); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to update allowed projects"}}})
				return
			}
		}
		if req.Data.Relationships.ExcludedWorkspaces != nil {
			ids := extractWorkspaceIDs(req.Data.Relationships.ExcludedWorkspaces.Data)
			if err := h.poolRepo.ReplaceExcludedWorkspaces(id, ids); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to update excluded workspaces"}}})
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
		if err := h.poolRepo.Update(pool); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to update agent pool"}}})
			return
		}
	}

	updated, _ := h.poolRepo.GetByID(id, true)
	if updated != nil {
		pool = updated
	}
	agentCount := 0
	if h.runnerRepo != nil {
		if n, err := h.runnerRepo.CountByAgentPool(pool.ID); err == nil {
			agentCount = int(n)
		}
	}
	c.JSON(http.StatusOK, gin.H{"data": formatAgentPoolResponse(pool, orgName, agentCount)})
}

// Delete deletes an agent pool.
// DELETE /api/v2/agent-pools/:id
func (h *AgentPoolHandlerV2) Delete(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "invalid agent pool id"}}})
		return
	}

	pool, err := h.poolRepo.GetByID(id, false)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Agent pool not found"}}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to get agent pool"}}})
		return
	}
	if !h.requireManageAgentPools(c, pool.OrganizationID) {
		return
	}

	if err := h.poolRepo.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to delete agent pool"}}})
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
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "invalid agent pool id"}}})
		return
	}

	pool, err := h.poolRepo.GetByID(id, false)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Agent pool not found"}}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to get agent pool"}}})
		return
	}
	if !h.requireManageAgentPools(c, pool.OrganizationID) {
		return
	}

	runners, err := h.runnerRepo.ListByAgentPool(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to list agents"}}})
		return
	}

	// Format as TFE Agent shape: id, name, ip-address, status, last-ping-at
	data := make([]gin.H, 0, len(runners))
	for _, r := range runners {
		agent := gin.H{
			"id":   r.ID.String(),
			"type": "agents",
			"attributes": gin.H{
				"name":         r.Name,
				"ip-address":   r.IPAddress,
				"status":       string(r.Status),
				"last-ping-at": r.LastHeartbeatAt,
			},
		}
		data = append(data, agent)
	}
	c.JSON(http.StatusOK, gin.H{
		"data": data,
		"meta": gin.H{"pagination": gin.H{"current-page": 1, "page-size": 20, "total-count": len(data)}},
	})
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
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "invalid agent pool id"}}})
		return
	}

	pool, err := h.poolRepo.GetByID(id, false)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Agent pool not found"}}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to get agent pool"}}})
		return
	}

	if !h.authorizeQueueDepth(c, pool, id) {
		return
	}

	depth, err := h.poolRepo.QueueDepth(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to compute queue depth"}}})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"type": "queue-depths",
			"id":   id.String(),
			"attributes": gin.H{
				"pending-terraform-jobs": depth.PendingTerraformJobs,
				"pending-ansible-jobs":   depth.PendingAnsibleJobs,
				"total-pending":          depth.TotalPending,
				"busy-runners":           depth.BusyRunners,
				"total-runners":          depth.TotalRunners,
				"idle-runners":           depth.IdleRunners,
			},
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
			c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "invalid API key scopes"}}})
			return false
		}
		checker, cerr := apikey.NewScopeChecker(scopeStrs)
		if cerr != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "invalid API key scopes"}}})
			return false
		}
		if !checker.HasOrgPermission(pool.OrganizationID, "runner:register") && !checker.IsUnrestricted() {
			// Deny outright - do NOT fall back to the key owner's RBAC. This route is
			// org-wall-agnostic (the wall's scope-vs-method check would reject a
			// runner:register key on a GET), so this check IS the tenant boundary for
			// api-key callers. An earlier revision fell through to
			// requireManageAgentPools here, which let a key scoped to
			// org:A:runner:register read org B's queue depth whenever its human owner
			// happened to hold manage-agent-pools on B - a token-scope escalation.
			// Confirmed live before the fix: a main-scoped key returned 200 for an
			// acme-corp pool.
			c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{
				"status": "403", "title": "Forbidden",
				"detail": "API key does not have runner:register scope for this organization",
			}}})
			return false
		}
		// Pool-binding enforcement, matching runner registration: an agent token
		// (tfe_agent_token) is bound to one pool and must not read another's depth.
		// An ordinary org-level runner:register key has no binding and may read any
		// pool in its organization.
		if h.apiKeyService != nil {
			if raw, exists := c.Get("api_key_id"); exists {
				if keyID, perr := uuid.Parse(fmt.Sprintf("%v", raw)); perr == nil {
					if bound, berr := h.apiKeyService.AgentPoolBindingForKey(keyID); berr == nil && bound != nil && *bound != poolID {
						c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "this agent token is bound to a different agent pool"}}})
						return false
					}
				}
			}
		}
		return true
	}

	return h.requireManageAgentPools(c, pool.OrganizationID)
}
