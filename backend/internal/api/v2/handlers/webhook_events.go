// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/repository"
)

// WebhookEventHandlerV2 handles webhook event listing for debugging.
type WebhookEventHandlerV2 struct {
	eventRepo *repository.WebhookEventRepository
	orgRepo   *repository.OrganizationRepository
}

func NewWebhookEventHandlerV2(eventRepo *repository.WebhookEventRepository, orgRepo *repository.OrganizationRepository) *WebhookEventHandlerV2 {
	return &WebhookEventHandlerV2{
		eventRepo: eventRepo,
		orgRepo:   orgRepo,
	}
}

// List lists recent webhook events for an organization.
// GET /api/v2/organizations/:name/webhook-events
func (h *WebhookEventHandlerV2) List(c *gin.Context) {
	orgName := c.Param("name")

	// Get organization
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	// Parse pagination
	limit := 50
	offset := 0
	if l, err := strconv.Atoi(c.DefaultQuery("page[size]", "50")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	if p, err := strconv.Atoi(c.DefaultQuery("page[number]", "1")); err == nil && p > 0 {
		offset = (p - 1) * limit
	}

	events, total, err := h.eventRepo.ListByOrganization(org.ID, limit, offset)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list webhook events")
		return
	}

	// Check format parameter
	format := c.DefaultQuery("format", "")

	if format == "simple" {
		// Simple JSON format for frontend
		data := make([]WebhookEventSimple, len(events))
		for i, event := range events {
			data[i] = WebhookEventSimple{
				ID:           event.ID.String(),
				EventType:    event.EventType,
				Provider:     event.Provider,
				Repository:   event.Repository,
				Branch:       event.Branch,
				Commit:       event.Commit,
				Status:       event.Status,
				ResponseCode: event.ResponseCode,
				Message:      event.Message,
				DeliveredAt:  event.DeliveredAt,
				ProcessedAt:  event.ProcessedAt,
			}
		}
		jsonapi.WriteDocumentMeta(c, http.StatusOK, data, WebhookEventSimpleMeta{
			Total:      total,
			PageSize:   limit,
			PageNumber: (offset / limit) + 1,
		})
		return
	}

	// JSON:API format
	data := make([]jsonapi.Resource[WebhookEventAttributes], len(events))
	for i, event := range events {
		data[i] = jsonapi.Resource[WebhookEventAttributes]{
			ID:   event.ID.String(),
			Type: "webhook-events",
			Attributes: WebhookEventAttributes{
				EventType:    event.EventType,
				Provider:     event.Provider,
				Repository:   event.Repository,
				Branch:       event.Branch,
				Commit:       event.Commit,
				Status:       event.Status,
				ResponseCode: event.ResponseCode,
				Message:      event.Message,
				DeliveredAt:  event.DeliveredAt,
				ProcessedAt:  event.ProcessedAt,
			},
		}
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta((offset/limit)+1, limit, total))
}
