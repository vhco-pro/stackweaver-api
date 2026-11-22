// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/storage"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	errAssignedSnapshotUnavailable = errors.New("assigned playbook snapshot unavailable")
	errSnapshotClaimChanged        = errors.New("the job claim changed while reading the playbook snapshot")
)

func (h *RunnerAgentHandler) assignedPlaybookSnapshot(ctx context.Context, job *models.AnsibleJob, playbook *models.AnsiblePlaybook) (*models.PlaybookSnapshotUpload, error) {
	if job.PlaybookSnapshotUploadID == nil || playbook.PublishedSnapshotID == nil ||
		*job.PlaybookSnapshotUploadID != *playbook.PublishedSnapshotID {
		return nil, errAssignedSnapshotUnavailable
	}
	var upload models.PlaybookSnapshotUpload
	if err := h.db.WithContext(ctx).First(&upload, "id = ? AND playbook_id = ? AND sequence = ? AND stored_at IS NOT NULL",
		*job.PlaybookSnapshotUploadID, playbook.ID, playbook.PublishedSnapshotSequence).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errAssignedSnapshotUnavailable
		}
		return nil, err
	}
	return &upload, nil
}

func assignedSnapshotValidator(id uuid.UUID) string { return "\"" + id.String() + "\"" }

func (h *RunnerAgentHandler) readAssignedPlaybookSnapshot(ctx context.Context, job *models.AnsibleJob, upload *models.PlaybookSnapshotUpload) ([]byte, error) {
	data, readErr := storage.GetBounded(ctx, h.storageClient, ansible.PlaybookCaptureKey(upload.PlaybookID, upload.ID), maxPlaybookSnapshotBytes)
	if readErr == nil {
		sum := sha256.Sum256(data)
		if int64(len(data)) != upload.SizeBytes || hex.EncodeToString(sum[:]) != upload.SHA256 {
			readErr = errors.New("the stored archive differs from its accepted upload")
		}
	}
	// Admission is the last database step. A reader admitted before publication can finish
	// serving its materialized bytes. A late reader never sends a body from a superseded capture.
	if err := h.admitPlaybookSnapshotRead(ctx, job, upload); err != nil {
		return nil, err
	}
	return data, readErr
}

func (h *RunnerAgentHandler) admitPlaybookSnapshotRead(ctx context.Context, job *models.AnsibleJob, upload *models.PlaybookSnapshotUpload) error {
	return h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Lock the job before the playbook, as the held-job release does.
		var current models.AnsibleJob
		err := tx.Clauses(clause.Locking{Strength: "SHARE"}).
			Where("id = ? AND project_id = ? AND runner_id IS NOT DISTINCT FROM ? AND agent_pool_id IS NOT DISTINCT FROM ? AND attempt = ?",
				job.ID, job.ProjectID, job.RunnerID, job.AgentPoolID, job.Attempt).First(&current).Error
		if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && ansibleJobFinished(&current)) {
			return errSnapshotClaimChanged
		}
		if err != nil {
			return err
		}
		if current.PlaybookID == nil || *current.PlaybookID != upload.PlaybookID ||
			current.PlaybookSnapshotUploadID == nil || *current.PlaybookSnapshotUploadID != upload.ID {
			return errAssignedSnapshotUnavailable
		}
		var playbook models.AnsiblePlaybook
		err = tx.Clauses(clause.Locking{Strength: "SHARE"}).Select("id", "published_snapshot_id").
			First(&playbook, "id = ? AND published_snapshot_id = ?", upload.PlaybookID, upload.ID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errAssignedSnapshotUnavailable
		}
		return err
	})
}

func writeAssignedSnapshotError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errAssignedSnapshotUnavailable):
		jsonapi.WriteError(c, http.StatusPreconditionFailed, "Precondition Failed", runnercontract.PlaybookSnapshotRerun)
	case errors.Is(err, errSnapshotClaimChanged):
		writeRunnerForbidden(c, err.Error())
	case errors.Is(err, storage.ErrObjectTooLarge):
		jsonapi.WriteError(c, http.StatusRequestEntityTooLarge, "Request Entity Too Large", oversizedPlaybookSnapshot)
	default:
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
	}
}
