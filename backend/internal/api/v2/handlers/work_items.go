// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/placement"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// WorkItemAttributes is a work item on the wire (#933, D2, D15): a sync of the platform's control
// plane, its target named by its relationships, with the placement record every run and job
// carries (D4, AC77).
type WorkItemAttributes struct {
	Kind           string               `json:"kind"`
	Status         string               `json:"status"`
	TriggeredBy    string               `json:"triggered-by"`
	Image          string               `json:"image"`
	ImageLevel     string               `json:"image-level"`
	TimeoutSeconds int                  `json:"timeout-seconds"`
	Commit         string               `json:"commit"`
	ErrorMessage   string               `json:"error-message"`
	Output         string               `json:"output,omitempty"`
	QueuedAt       *time.Time           `json:"queued-at"`
	StartedAt      *time.Time           `json:"started-at"`
	FinishedAt     *time.Time           `json:"finished-at"`
	CreatedAt      time.Time            `json:"created-at"`
	Placement      placement.Attributes `json:"placement"`
}

// WorkItemRelationships names what a work item syncs and where it runs.
type WorkItemRelationships struct {
	Organization    jsonapi.Relationship  `json:"organization"`
	AgentPool       *jsonapi.Relationship `json:"agent-pool,omitempty"`
	Playbook        *jsonapi.Relationship `json:"playbook,omitempty"`
	Inventory       *jsonapi.Relationship `json:"inventory,omitempty"`
	InventorySource *jsonapi.Relationship `json:"inventory-source,omitempty"`
	Run             *jsonapi.Relationship `json:"run,omitempty"`
}

// WorkItemHandler serves the work item reads.
type WorkItemHandler struct {
	orgRepo     *repository.OrganizationRepository
	items       *repository.WorkItemRepository
	authService *auth.Service
	rbacService *rbac.Service
}

// NewWorkItemHandler builds the handler.
func NewWorkItemHandler(orgRepo *repository.OrganizationRepository, items *repository.WorkItemRepository, authService *auth.Service, rbacService *rbac.Service) *WorkItemHandler {
	return &WorkItemHandler{orgRepo: orgRepo, items: items, authService: authService, rbacService: rbacService}
}

// member reports whether the caller is a member of orgID, answering the request when it cannot
// tell or the caller is not.
func (h *WorkItemHandler) member(c *gin.Context, orgID uuid.UUID, notMember func()) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return false
	}
	inOrg, err := h.rbacService.UserInOrg(c.Request.Context(), user.ID, orgID)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	if !inOrg {
		notMember()
		return false
	}
	return true
}

// List returns an organization's work items, newest first.
//
// GET /api/v2/organizations/:name/work-items
func (h *WorkItemHandler) List(c *gin.Context) {
	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}
	if !h.member(c, org.ID, func() {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You are not a member of this organization")
	}) {
		return
	}
	page, pageSize := jsonapi.PageParams(c, 20, 100)
	items, total, err := h.items.ListByOrganization(org.ID, pageSize, (page-1)*pageSize)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	data := make([]jsonapi.Resource[WorkItemAttributes], 0, len(items))
	for i := range items {
		data = append(data, workItemResource(&items[i], false))
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(page, pageSize, total))
}

// Get returns one work item with its output. A work item of an organization the caller is not a
// member of is not found, as one that does not exist.
//
// GET /api/v2/work-items/:id
func (h *WorkItemHandler) Get(c *gin.Context) {
	item, err := h.items.GetByID(c.Param("id"))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Work item not found")
		return
	}
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !h.member(c, item.OrganizationID, func() {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Work item not found")
	}) {
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, workItemResource(item, true))
}

// workItemResource renders a work item; withOutput adds its stored output.
func workItemResource(item *models.WorkItem, withOutput bool) jsonapi.Resource[WorkItemAttributes] {
	attrs := WorkItemAttributes{
		Kind: item.Kind, Status: item.Status, TriggeredBy: item.TriggeredBy, Image: item.Image, ImageLevel: item.ImageLevel,
		TimeoutSeconds: item.TimeoutSeconds, Commit: item.Commit, ErrorMessage: item.ErrorMessage,
		QueuedAt: item.QueuedAt, StartedAt: item.StartedAt, FinishedAt: item.FinishedAt, CreatedAt: item.CreatedAt,
		Placement: placement.FromModel(item.Attempt, item.Placement),
	}
	if withOutput {
		attrs.Output = item.Output
	}
	rel := WorkItemRelationships{Organization: jsonapi.ToOne(item.OrganizationID.String(), "organizations")}
	toOne := func(id fmt.Stringer, typ string) *jsonapi.Relationship {
		r := jsonapi.ToOne(id.String(), typ)
		return &r
	}
	if item.AgentPoolID != nil {
		rel.AgentPool = toOne(*item.AgentPoolID, "agent-pools")
	}
	if item.PlaybookID != nil {
		rel.Playbook = toOne(*item.PlaybookID, "ansible-playbooks")
	}
	if item.InventoryID != nil {
		rel.Inventory = toOne(*item.InventoryID, "ansible-inventories")
	}
	if item.InventorySourceID != nil {
		rel.InventorySource = toOne(*item.InventorySourceID, "inventory-sources")
	}
	if item.RunID != nil {
		r := jsonapi.ToOne(*item.RunID, "runs")
		rel.Run = &r
	}
	return jsonapi.Resource[WorkItemAttributes]{ID: item.ID, Type: "work-items", Attributes: attrs, Relationships: rel}
}
