// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// AdminOrganizationsHandlerV2 serves the read half of TFE's admin organizations API to the
// platform administrator (#132, D4): every organization on the installation, whether or not the
// administrator belongs to it. It is read-only and shows no settings, policies, tokens or
// members: reaching inside an organization takes membership, as for everyone else.
// TFE API docs: https://developer.hashicorp.com/terraform/enterprise/api-docs/admin/organizations
type AdminOrganizationsHandlerV2 struct {
	orgs   *repository.OrganizationRepository
	admins *platformadmin.Service
}

// NewAdminOrganizationsHandlerV2 creates the handler.
func NewAdminOrganizationsHandlerV2(orgs *repository.OrganizationRepository, admins *platformadmin.Service) *AdminOrganizationsHandlerV2 {
	return &AdminOrganizationsHandlerV2{orgs: orgs, admins: admins}
}

// AdminOrganizationAttributes is TFE's admin organization resource as far as Stackweaver has it,
// with member-count and workspace-count as Stackweaver extensions.
type AdminOrganizationAttributes struct {
	Name              string    `json:"name"`
	ExternalID        string    `json:"external-id"`
	NotificationEmail string    `json:"notification-email"`
	IsDisabled        bool      `json:"is-disabled"`
	CreatedAt         time.Time `json:"created-at"`
	MemberCount       int64     `json:"member-count"`
	WorkspaceCount    int64     `json:"workspace-count"`
}

const adminOrgNotFound = "Organization not found, or client is not an administrator."

func (h *AdminOrganizationsHandlerV2) resources(c *gin.Context, orgs []models.Organization) ([]jsonapi.Resource[AdminOrganizationAttributes], bool) {
	ids := make([]uuid.UUID, 0, len(orgs))
	for _, o := range orgs {
		ids = append(ids, o.ID)
	}
	members, workspaces, err := h.orgs.MemberAndWorkspaceCounts(ids)
	if err != nil {
		logger.Errorf("admin organizations: %v", err)
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to list organizations")
		return nil, false
	}
	out := make([]jsonapi.Resource[AdminOrganizationAttributes], 0, len(orgs))
	for _, o := range orgs {
		out = append(out, jsonapi.Resource[AdminOrganizationAttributes]{
			ID:   o.Name,
			Type: "organizations",
			Attributes: AdminOrganizationAttributes{
				Name:              o.Name,
				ExternalID:        o.ID.String(),
				NotificationEmail: o.Email,
				CreatedAt:         o.CreatedAt,
				MemberCount:       members[o.ID],
				WorkspaceCount:    workspaces[o.ID],
			},
		})
	}
	return out, true
}

// List returns every organization on the installation.
// GET /api/v2/admin/organizations?q=&q[name]=&q[email]=
func (h *AdminOrganizationsHandlerV2) List(c *gin.Context) {
	if _, ok := h.admins.Require(c); !ok {
		return
	}
	page, pageSize := jsonapi.PageParams(c, 20, 100)
	orgs, total, err := h.orgs.ListMatching(repository.OrganizationSearch{
		Query: c.Query("q"),
		Name:  c.Query("q[name]"),
		Email: c.Query("q[email]"),
	}, pageSize, jsonapi.Offset(page, pageSize))
	if err != nil {
		logger.Errorf("admin organizations: %v", err)
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to list organizations")
		return
	}
	data, ok := h.resources(c, orgs)
	if !ok {
		return
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(page, pageSize, total))
}

// Show returns one organization.
// GET /api/v2/admin/organizations/:name
func (h *AdminOrganizationsHandlerV2) Show(c *gin.Context) {
	if _, ok := h.admins.Require(c); !ok {
		return
	}
	org, err := h.orgs.GetByName(c.Param("name"))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", adminOrgNotFound)
		return
	}
	if err != nil {
		logger.Errorf("admin organizations: reading %q: %v", c.Param("name"), err)
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to read the organization")
		return
	}
	data, ok := h.resources(c, []models.Organization{*org})
	if !ok {
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, data[0])
}
