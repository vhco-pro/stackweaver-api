// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/placement"
	"github.com/michielvha/stackweaver/core/models"
)

// placementsType is the JSON:API type of a run's placement record.
const placementsType = "placements"

// formatRunPlacement renders a run's placement record. It is its own resource, beside the run,
// because the run resource is the TFE wire contract and does not change shape (#933, D13).
func formatRunPlacement(run *models.Run) jsonapi.Resource[placement.Attributes] {
	return jsonapi.Resource[placement.Attributes]{
		ID:         run.ID,
		Type:       placementsType,
		Attributes: placement.FromModel(run.VisibleAttempt(), run.Placement),
	}
}

// GetPlacement returns where a run's latest attempt ran: the driver, the container id or pod name,
// the image and digest and the level it came from, the identity binding and the node (#933, D4,
// AC77). Anyone who may read the run may read it.
//
// GET /api/v2/runs/:id/placement
func (h *RunHandlerV2) GetPlacement(c *gin.Context) {
	run, ok := h.authorizeRun(c, c.Param("id"), "read")
	if !ok {
		return
	}
	doc := formatRunPlacement(run)
	waiting := run.RunnerID == nil && (run.Status == models.RunStatusPending || run.Status == models.RunStatusPrePlanCompleted || run.Status == models.RunStatusApplying)
	doc.Attributes = placement.WithQueue(h.runRepo.HostedQueueAt, doc.Attributes, run.AgentPoolID, run.CreatedAt, waiting)
	jsonapi.WriteDocument(c, http.StatusOK, doc)
}
