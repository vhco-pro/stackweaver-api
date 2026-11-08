// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for
// details.

// Run now on an inventory source schedule (#885, AC1, AC2): the handler answers at once with the
// schedule resource, carrying the run it requested as pending and the work item behind it as the
// last-work-item relationship. The sync is a work item that a launcher runs; nothing in the API
// process runs ansible-inventory, which a stand-in on PATH would notice.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. It reuses the error envelope
// fixture, whose cleanup is row-scoped. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestScheduleRunNow_

//go:build integration

package ansible

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/security/runenv"
)

func TestScheduleRunNow_InventorySourceAnswersWithTheRequestedWorkItem(t *testing.T) {
	f := setupErrorEnvelope(t)

	// A stand-in for ansible-inventory that leaves a mark if anything in this process runs it.
	bin, record := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ansible-inventory"), []byte("#!/bin/sh\ntouch \"$SYNC_TEST_RECORD/ran\"\nprintf '{}'\n"), 0o700); err != nil { //nolint:gosec // an executable is the point
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SYNC_TEST_RECORD", record)
	t.Setenv(runenv.PassthroughVar, "SYNC_TEST_RECORD")

	req := httptest.NewRequest(http.MethodPost, "/ansible/schedules/"+f.enabledSourceSchedule+"/actions/run-now", nil)
	req.Header.Set("X-Test-User", f.owner.ID.String())
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("run-now = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	var doc struct {
		Data struct {
			Type          string         `json:"type"`
			ID            string         `json:"id"`
			Attributes    map[string]any `json:"attributes"`
			Relationships map[string]struct {
				Data *struct {
					Type string `json:"type"`
					ID   string `json:"id"`
				} `json:"data"`
			} `json:"relationships"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decoding the answer: %v; body: %s", err, rec.Body.String())
	}
	if doc.Data.Type != "schedules" || doc.Data.ID != f.enabledSourceSchedule {
		t.Errorf("answer is %s %s, want the schedule resource", doc.Data.Type, doc.Data.ID)
	}
	if got := doc.Data.Attributes["last-run-status"]; got != "pending" {
		t.Errorf("last-run-status = %v, want pending: the sync has only been requested", got)
	}

	var items []models.WorkItem
	if err := f.db.Where("inventory_source_id = ?", f.sourceID).Find(&items).Error; err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].TriggeredBy != "schedule" || items[0].Kind != models.WorkItemDynamicSourceSync {
		t.Fatalf("work items for the source: %+v, want one dynamic_source_sync triggered by schedule", items)
	}
	rel, ok := doc.Data.Relationships["last-work-item"]
	if !ok || rel.Data == nil || rel.Data.Type != "work-items" || rel.Data.ID != items[0].ID {
		t.Errorf("last-work-item = %+v, want work-items %s", rel.Data, items[0].ID)
	}

	if _, err := os.Stat(filepath.Join(record, "ran")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ansible-inventory ran in the API process (stat error: %v)", err)
	}
}
