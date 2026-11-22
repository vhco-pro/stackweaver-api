// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// DefaultInlineArtifactLimit is the largest configuration tarball or state inlined as base64
// for a runner that can fetch blobs. Larger artifacts travel through the API's blob route.
const DefaultInlineArtifactLimit = 1 << 20

const (
	blobConfigTarball = "config.tar.gz"
	blobState         = "state"
)

func (h *RunnerAgentHandler) inlineLimit() int {
	if h.inlineArtifactLimit > 0 {
		return h.inlineArtifactLimit
	}
	return DefaultInlineArtifactLimit
}

// runnerCan reports a capability announced on this request or at registration.
func runnerCan(c *gin.Context, capability string) bool {
	if runnerCapabilities(c)[capability] {
		return true
	}
	if runner, ok := callingRunner(c); ok {
		return runner.HasCapability(capability)
	}
	return false
}

func blobRef(runID, name string, data []byte) *runnercontract.BlobRef {
	sum := sha256.Sum256(data)
	return &runnercontract.BlobRef{Path: "/api/v2/runner/jobs/" + runID + "/blob/" + name, SizeBytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
}

func (h *RunnerAgentHandler) configTarball(ctx context.Context, run *models.Run) ([]byte, error) {
	if run.ConfigurationVersionID == nil {
		return nil, fmt.Errorf("looking up configuration of run %s: %w", run.ID, gorm.ErrRecordNotFound)
	}
	if h.storageClient == nil {
		return nil, errors.New("object storage is not configured")
	}
	cv, err := h.runConfigurationVersion(run)
	if err != nil {
		return nil, fmt.Errorf("looking up the configuration version of run %s: %w", run.ID, err)
	}
	return h.storageClient.Get(ctx, cv.TarballKey())
}

func (h *RunnerAgentHandler) latestState(ctx context.Context, workspaceID string) ([]byte, error) {
	if h.stateService == nil {
		return nil, errors.New("state service is not configured")
	}
	var latest models.StateVersion
	if err := h.db.WithContext(ctx).Where("workspace_id = ?", workspaceID).Order("version DESC").First(&latest).Error; err != nil {
		return nil, err
	}
	return h.stateService.GetStateObject(ctx, workspaceID, latest.Version)
}

// GetJobBlob serves required configuration or state through the API. Persisted recovery claims
// permit repeated authorized reads with a strong content validator while the original claim is
// active. Legacy claims consume each blob once per attempt and answer 410 on a second read.
// GET /api/v2/runner/jobs/:id/blob/*name
func (h *RunnerAgentHandler) GetJobBlob(c *gin.Context) {
	scoped := *h
	scoped.db = h.db.WithContext(c.Request.Context())
	h = &scoped
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
	var expected string
	if run.ClaimRecovery {
		if _, ok := callingJob(c); !ok {
			writeRunnerForbidden(c, "a recovery blob requires its job token")
			return
		}
		values := c.Request.Header.Values("If-Match")
		if len(values) != 1 || len(values[0]) != 66 || values[0][0] != '"' || values[0][65] != '"' || !cacheSHA256.MatchString(values[0][1:65]) {
			jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "A single strong SHA-256 If-Match validator is required")
			return
		}
		expected = values[0][1:65]
	}
	name := strings.TrimPrefix(c.Param("name"), "/")
	var data []byte
	var err error
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
		if errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Blob not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}
	if run.ClaimRecovery {
		sum := sha256.Sum256(data)
		if !h.revalidateBlobClaim(c, run) {
			return
		}
		if hex.EncodeToString(sum[:]) != expected {
			jsonapi.WriteErrorNoDetail(c, http.StatusPreconditionFailed, "Blob content changed")
			return
		}
	} else {
		fetch := &models.RunnerBlobFetch{JobID: run.ID, Attempt: max(run.Attempt, 1), Name: name}
		result := h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(fetch)
		if result.Error != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if result.RowsAffected == 0 {
			jsonapi.WriteError(c, http.StatusGone, "Gone", "this attempt has already fetched the blob")
			return
		}
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}

// revalidateBlobClaim linearizes a required-content read after storage I/O. The run lock fences
// completion and later claims. Its token and assignment must still authorize the original read.
// The transaction holds no lock while storage is read or the response body is transferred.
func (h *RunnerAgentHandler) revalidateBlobClaim(c *gin.Context, original *models.Run) bool {
	principal, ok := callingJob(c)
	if !ok {
		writeRunnerForbidden(c, "a recovery blob requires its job token")
		return false
	}
	raw, _ := c.Get("api_key")
	authenticated, _ := raw.(*models.APIKey)
	if authenticated == nil {
		writeRunnerForbidden(c, "job token is unavailable")
		return false
	}
	err := h.db.Transaction(func(tx *gorm.DB) error {
		var current models.Run
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&current, "id = ?", original.ID).Error; err != nil {
			writeRunnerJobReadError(c, err)
			return err
		}
		active := current.DispatchedAt != nil && ((current.ClaimedPhase == "plan" && current.Status == models.RunStatusPlanning) || (current.ClaimedPhase == "apply" && current.Status == models.RunStatusApplying))
		if !current.ClaimRecovery || !active || current.Attempt != original.Attempt || current.ClaimedPhase != original.ClaimedPhase || current.ClaimedRunType != original.ClaimedRunType || original.DispatchedAt == nil || !current.DispatchedAt.Equal(*original.DispatchedAt) {
			jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the original blob claim is no longer active")
			return errors.New("original blob claim is no longer active")
		}
		var key models.APIKey
		if err := tx.Clauses(clause.Locking{Strength: "SHARE"}).First(&key, "id = ?", authenticated.ID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTokenRevoked, "Forbidden", "the job token was revoked")
			}
			return err
		}
		actual, valid := apikey.ParseJobPrincipal(key.Scopes)
		if key.Kind != models.APIKeyKindJob || !valid || actual != principal || key.ExpiresAt != nil && !key.ExpiresAt.After(time.Now()) || key.OrganizationID == nil || authenticated.OrganizationID == nil || *key.OrganizationID != *authenticated.OrganizationID {
			jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTokenRevoked, "Forbidden", "the job token no longer authorizes this claim")
			return errors.New("job token no longer authorizes blob read")
		}
		runner, err := repository.NewRunnerRepository(tx).GetByID(principal.RunnerID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				writeRunnerForbidden(c, "the launcher is no longer registered")
			}
			return err
		}
		c.Set(middleware.CallingRunnerKey, runner)
		c.Set("api_key", &key)
		scoped := *h
		scoped.db = tx
		if !scoped.authorizeRunnerForRun(c, &current, true) {
			return errors.New("blob claim authorization refused")
		}
		return nil
	})
	if err != nil {
		if !c.Writer.Written() {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return false
	}
	return true
}
