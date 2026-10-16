// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The ansible-jobs resource says when a job ran on inventory its update-on-launch syncs did not
// refresh (#908): one inventory-sync-warnings entry per source, in the resource's own kebab-case
// member naming, and an empty list for a job whose inventory was refreshed or never needed to be.

package ansible

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func encodeJobAttributes(t *testing.T, job *models.AnsibleJob) map[string]any {
	t.Helper()
	raw, err := json.Marshal(formatJobResponse(job))
	if err != nil {
		t.Fatalf("encoding job: %v", err)
	}
	var doc struct {
		Attributes map[string]any `json:"attributes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decoding job: %v", err)
	}
	return doc.Attributes
}

func TestJobResponseInventorySyncWarnings(t *testing.T) {
	sourceID := uuid.New()
	failedAt := time.Date(2026, 10, 16, 10, 4, 5, 0, time.UTC)
	lastGood := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	job := &models.AnsibleJob{
		ID:          uuid.New(),
		ProjectID:   uuid.New(),
		InventoryID: uuid.New(),
		Status:      models.AnsibleJobStatusSuccessful,
		InventorySyncWarnings: models.InventorySyncWarnings{
			{SourceID: sourceID, SourceName: "aws-prod", FailedAt: failedAt, Error: "credentials expired", LastSuccessfulSyncAt: &lastGood},
			{SourceID: uuid.New(), SourceName: "azure-dev", FailedAt: failedAt, Error: "plugin not found"},
		},
	}

	attrs := encodeJobAttributes(t, job)
	list, ok := attrs["inventory-sync-warnings"].([]any)
	if !ok || len(list) != 2 {
		t.Fatalf("inventory-sync-warnings: got %#v, want two entries", attrs["inventory-sync-warnings"])
	}
	first, _ := list[0].(map[string]any)
	want := map[string]any{
		"source-id":               sourceID.String(),
		"source-name":             "aws-prod",
		"failed-at":               "2026-10-16T10:04:05Z",
		"error":                   "credentials expired",
		"last-successful-sync-at": "2026-10-15T08:00:00Z",
	}
	for k, v := range want {
		if first[k] != v {
			t.Errorf("%s: got %#v, want %#v", k, first[k], v)
		}
	}
	second, _ := list[1].(map[string]any)
	if v, present := second["last-successful-sync-at"]; !present || v != nil {
		t.Errorf("a source that never synced successfully: last-successful-sync-at is %#v (present %v), want null", v, present)
	}

	job.InventorySyncWarnings = nil
	attrs = encodeJobAttributes(t, job)
	empty, ok := attrs["inventory-sync-warnings"].([]any)
	if !ok || len(empty) != 0 {
		t.Errorf("a job without warnings: inventory-sync-warnings is %#v, want []", attrs["inventory-sync-warnings"])
	}
}
