// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/response"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
)

// MaxPlanFileBytes bounds one uploaded saved plan.
const MaxPlanFileBytes = 256 << 20

// planFileKey is where a run's saved plan waits between its plan phase and its apply phase. The
// queue runner writes the same key, so a run started on either path is applied from one place.
func planFileKey(runID string) string {
	return models.RunPlanFileKey(runID)
}

// planFilePath is the route an apply job fetches its saved plan from.
func planFilePath(runID string) string {
	return "/api/v2/runner/jobs/" + runID + "/plan"
}

// atRest returns the service every object the API writes on a job's behalf is sealed with: the
// platform key state is sealed with, or the credentials key where no state service is wired.
func (h *RunnerAgentHandler) atRest() *crypto.CryptoService {
	if h.stateService != nil && h.stateService.Crypto() != nil {
		return h.stateService.Crypto()
	}
	return h.cryptoService
}

// isUnsealedPlan reports whether data was stored as it is rather than sealed: sealed payloads are
// base64 text, and a plan file is not.
func isUnsealedPlan(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err != nil
}

// loadRunForJob loads a run and authorizes the caller as its assigned runner or its job token.
func (h *RunnerAgentHandler) loadRunForJob(c *gin.Context) (*models.Run, bool) {
	var run models.Run
	if err := h.db.First(&run, "id = ?", c.Param("id")).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Run not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return nil, false
	}
	if !h.authorizeRunnerForRun(c, &run, true) {
		return nil, false
	}
	return &run, true
}

// UploadPlan stores the saved plan a run's plan phase produced (#933, D2, AC6). The body is the
// plan file itself, streamed; it is sealed with the at-rest helper before it reaches object storage
// (AC73), because a saved plan may carry sensitive values in cleartext.
//
// POST /api/v2/runner/jobs/:id/plan
func (h *RunnerAgentHandler) UploadPlan(c *gin.Context) {
	run, ok := h.loadRunForJob(c)
	if !ok {
		return
	}
	if run.Status != models.RunStatusPlanning {
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", "a saved plan is uploaded by the plan phase only")
		return
	}
	if h.storageClient == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	plan, err := io.ReadAll(io.LimitReader(c.Request.Body, MaxPlanFileBytes+1))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "reading the plan file")
		return
	}
	if len(plan) > MaxPlanFileBytes {
		jsonapi.WriteError(c, http.StatusRequestEntityTooLarge, "Request Entity Too Large", "the plan file exceeds the size limit")
		return
	}
	if len(plan) == 0 {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "the plan file is empty")
		return
	}
	sealed, err := h.atRest().EncryptAtRest(plan)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.storageClient.Put(c.Request.Context(), planFileKey(run.ID), sealed); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	response.Status(c, http.StatusOK, "stored")
}

// DownloadPlan returns a run's saved plan to its apply job.
//
// GET /api/v2/runner/jobs/:id/plan
func (h *RunnerAgentHandler) DownloadPlan(c *gin.Context) {
	run, ok := h.loadRunForJob(c)
	if !ok {
		return
	}
	if h.storageClient == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	data, err := h.storageClient.Get(c.Request.Context(), planFileKey(run.ID))
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "No saved plan for this run")
		return
	}
	plan, err := h.atRest().DecryptAtRest(data, isUnsealedPlan)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", plan)
}

// planDescriptor returns the saved plan an apply phase applies, or nil when the run is not applying
// or its plan phase stored none.
func (h *RunnerAgentHandler) planDescriptor(ctx context.Context, run *models.Run) *runnercontract.PlanDescriptor {
	if run.Status != models.RunStatusApplying || h.storageClient == nil {
		return nil
	}
	objects, err := h.storageClient.List(ctx, planFileKey(run.ID))
	if err != nil {
		return nil
	}
	for _, o := range objects {
		if o.Key == planFileKey(run.ID) {
			return &runnercontract.PlanDescriptor{Path: planFilePath(run.ID), SizeBytes: o.Size}
		}
	}
	return nil
}
