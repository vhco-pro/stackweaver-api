// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm/clause"
)

// DefaultInlineArtifactLimit is the largest configuration tarball or state the artifacts document
// inlines as base64 for a runner that can fetch blobs; anything larger travels through the blob
// route (#933, D2, AC13).
const DefaultInlineArtifactLimit = 1 << 20

// Blob names of an OpenTofu run.
const (
	blobConfigTarball = "config.tar.gz"
	blobState         = "state"
)

// inlineLimit is the inline threshold this handler applies.
func (h *RunnerAgentHandler) inlineLimit() int {
	if h.inlineArtifactLimit > 0 {
		return h.inlineArtifactLimit
	}
	return DefaultInlineArtifactLimit
}

// runnerCan reports whether the calling runner can do capability: announced on this request, or
// declared at registration.
func runnerCan(c *gin.Context, capability string) bool {
	if runnerCapabilities(c)[capability] {
		return true
	}
	if runner, ok := callingRunner(c); ok {
		return runner.HasCapability(capability)
	}
	return false
}

// blobRef describes one blob of a run.
func blobRef(runID, name string, data []byte) *runnercontract.BlobRef {
	sum := sha256.Sum256(data)
	return &runnercontract.BlobRef{
		Path:      "/api/v2/runner/jobs/" + runID + "/blob/" + name,
		SizeBytes: int64(len(data)),
		SHA256:    hex.EncodeToString(sum[:]),
	}
}

// configTarball reads a run's configuration tarball.
func (h *RunnerAgentHandler) configTarball(ctx context.Context, run *models.Run) ([]byte, error) {
	if run.ConfigurationVersionID == nil || h.storageClient == nil {
		return nil, fmt.Errorf("run %s has no configuration version", run.ID)
	}
	cv, err := h.runConfigurationVersion(run)
	if err != nil {
		return nil, fmt.Errorf("looking up the configuration version of run %s: %w", run.ID, err)
	}
	return h.storageClient.Get(ctx, models.ConfigurationTarballKey(cv.ID))
}

// latestState reads the latest state of a run's workspace, decrypted.
func (h *RunnerAgentHandler) latestState(ctx context.Context, workspaceID string) ([]byte, error) {
	if h.stateService == nil {
		return nil, fmt.Errorf("no state service")
	}
	var latest models.StateVersion
	if err := h.db.Where("workspace_id = ?", workspaceID).Order("version DESC").First(&latest).Error; err != nil {
		return nil, err
	}
	return h.stateService.GetStateObject(ctx, workspaceID, latest.Version)
}

// GetJobBlob streams one blob of a run to its job: the configuration tarball or the latest state,
// when they are too large to inline, or an entry of the job's organization's cache. Each blob is served once per attempt; a second fetch answers
// 410. The body comes from the API, so no storage endpoint is reachable from a job's network.
//
// GET /api/v2/runner/jobs/:id/blob/*name
func (h *RunnerAgentHandler) GetJobBlob(c *gin.Context) {
	// An entry of the organization's cache, for any kind of job (#933, D7).
	if rest, ok := strings.CutPrefix(strings.TrimPrefix(c.Param("name"), "/"), "cache/"); ok {
		h.getJobCacheBlob(c, rest)
		return
	}
	run, ok := h.loadRunForJob(c)
	if !ok {
		return
	}
	if runFinished(run) {
		jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the run has finished")
		return
	}
	name := strings.TrimPrefix(c.Param("name"), "/")
	var (
		data []byte
		err  error
	)
	switch name {
	case blobConfigTarball:
		data, err = h.configTarball(c.Request.Context(), run)
	case blobState:
		data, err = h.latestState(c.Request.Context(), run.WorkspaceID)
	default:
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "No such blob")
		return
	}
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Blob not found")
		return
	}

	fetch := &models.RunnerBlobFetch{JobID: run.ID, Attempt: max(run.Attempt, 1), Name: name}
	res := h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(fetch)
	if res.Error != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if res.RowsAffected == 0 {
		jsonapi.WriteError(c, http.StatusGone, "Gone", "this attempt has already fetched the blob")
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}
