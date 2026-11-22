// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type snapshotUploadRefusal struct {
	status int
	detail string
}

func (e *snapshotUploadRefusal) Error() string { return e.detail }

// storePlaybookSnapshot stages an archive under a unique key. Only completion publishes it.
func (h *RunnerAgentHandler) storePlaybookSnapshot(ctx context.Context, item *models.WorkItem, commit string, data []byte) error {
	if commit == "" || len(commit) > 100 {
		return &snapshotUploadRefusal{http.StatusBadRequest, "the snapshot must name its committed revision"}
	}
	sum := sha256.Sum256(data)
	upload := models.PlaybookSnapshotUpload{
		ID: uuid.New(), PlaybookID: *item.PlaybookID, WorkItemID: item.ID,
		RunnerID: item.RunnerID, Attempt: max(item.Attempt, 1), Sequence: item.PlaybookSnapshotSequence,
		Commit: commit, SizeBytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:]),
	}
	db := h.db.WithContext(ctx)
	selected := false
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := checkPlaybookUploadClaim(tx, item, &upload, &selected); err != nil || selected {
			return err
		}
		return tx.Create(&upload).Error
	})
	if err != nil || selected {
		return err
	}

	key := ansible.PlaybookCaptureKey(upload.PlaybookID, upload.ID)
	if err := h.storageClient.Put(ctx, key, data); err != nil {
		return err
	}
	// Preserve the successful storage result even if a parent or the original claim was lost.
	if err := db.Model(&upload).UpdateColumn("stored_at", time.Now().UTC()).Error; err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := checkPlaybookUploadClaim(tx, item, &upload, &selected); err != nil || selected {
			return err
		}
		return tx.Model(&models.WorkItem{}).Where("id = ?", item.ID).
			Updates(map[string]any{"playbook_snapshot_upload_id": upload.ID, "commit": commit}).Error
	})
}

// checkPlaybookUploadClaim takes a lock that ends before any storage I/O. Each transaction
// also resolves whether a matching delivery already won selection for this attempt.
func checkPlaybookUploadClaim(tx *gorm.DB, item *models.WorkItem, upload *models.PlaybookSnapshotUpload, selected *bool) error {
	var current models.WorkItem
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&current, "id = ?", item.ID).Error; err != nil {
		return err
	}
	if conflict := heldConflict(&current, item); conflict != "" {
		return &snapshotUploadRefusal{http.StatusConflict, conflict}
	}
	if !upload.MatchesClaim(&current) || upload.Sequence == 0 {
		return &snapshotUploadRefusal{http.StatusConflict, "the capture has no current snapshot allocation"}
	}
	var playbook models.AnsiblePlaybook
	if err := tx.Select("id").First(&playbook, "id = ?", upload.PlaybookID).Error; err != nil {
		return err
	}
	if current.PlaybookSnapshotUploadID == nil {
		return nil
	}
	var prior models.PlaybookSnapshotUpload
	if err := tx.First(&prior, "id = ?", *current.PlaybookSnapshotUploadID).Error; err != nil {
		return err
	}
	if !prior.MatchesClaim(&current) {
		return nil
	}
	if prior.Commit != upload.Commit || prior.SizeBytes != upload.SizeBytes || prior.SHA256 != upload.SHA256 {
		return &snapshotUploadRefusal{http.StatusBadRequest, "the capture already accepted a different snapshot"}
	}
	if prior.StoredAt == nil {
		return errors.New("the selected playbook snapshot has no storage receipt")
	}
	*selected = true
	return nil
}

func writePlaybookUploadError(c *gin.Context, id string, err error) {
	var refusal *snapshotUploadRefusal
	switch {
	case errors.As(err, &refusal):
		jsonapi.WriteError(c, refusal.status, http.StatusText(refusal.status), refusal.detail)
	case errors.Is(err, gorm.ErrRecordNotFound):
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Playbook or capture not found")
	default:
		logger.Errorf("storing the snapshot of work item %s: %v", id, err)
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
	}
}
