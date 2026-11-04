// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/settings"
	"gorm.io/gorm"
)

// HostedCapacityAttributes is an organization's view of its hosted pool (#933, D9, D15, AC51): the
// cap and placement group a platform administrator set, what is in flight and queued, and how many
// hosted launchers of the group are online, as counts, since the launchers are not the
// organization's. It is read-only to every organization member.
type HostedCapacityAttributes struct {
	PoolID            string `json:"pool-id"`
	MaxConcurrentJobs int    `json:"max-concurrent-jobs"`
	PlacementGroup    string `json:"placement-group"`
	InFlight          int    `json:"in-flight"`
	Queued            int    `json:"queued"`
	LaunchersOnline   int    `json:"launchers-online"`
	QueueReason       string `json:"queue-reason"`
}

// HostedCapacityHandler serves GET /organizations/:name/hosted-capacity.
type HostedCapacityHandler struct {
	orgRepo     *repository.OrganizationRepository
	poolRepo    *repository.AgentPoolRepository
	runRepo     *repository.RunRepository
	authService *auth.Service
	rbacService *rbac.Service
}

// NewHostedCapacityHandler builds the handler.
func NewHostedCapacityHandler(orgRepo *repository.OrganizationRepository, poolRepo *repository.AgentPoolRepository, runRepo *repository.RunRepository, authService *auth.Service, rbacService *rbac.Service) *HostedCapacityHandler {
	return &HostedCapacityHandler{orgRepo: orgRepo, poolRepo: poolRepo, runRepo: runRepo, authService: authService, rbacService: rbacService}
}

// Get returns the organization's hosted capacity.
//
// GET /api/v2/organizations/:name/hosted-capacity
func (h *HostedCapacityHandler) Get(c *gin.Context) {
	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	if inOrg, err := h.rbacService.UserInOrg(c.Request.Context(), user.ID, org.ID); err != nil || !inOrg {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You are not a member of this organization")
		return
	}
	pool, err := h.poolRepo.GetHosted(org.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "the organization has no hosted pool")
			return
		}
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	st, err := h.runRepo.HostedQueue(pool.ID, settings.HostedDefaultMaxConcurrentJobs(os.Getenv))
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, jsonapi.Resource[HostedCapacityAttributes]{
		ID:   org.Name,
		Type: "hosted-capacities",
		Attributes: HostedCapacityAttributes{
			PoolID: pool.ID.String(), MaxConcurrentJobs: st.Cap, PlacementGroup: st.Group, InFlight: st.InFlight,
			Queued: st.Queued, LaunchersOnline: st.LaunchersOnline, QueueReason: st.Reason,
		},
	})
}
