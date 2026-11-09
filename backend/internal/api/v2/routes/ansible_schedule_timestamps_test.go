// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Creating an Ansible schedule and reading it back return the same timestamp strings in a
// process outside UTC (utc-timestamps spec, AC3). The create response formats the values the
// handler holds in memory, in the process zone or the schedule's own zone; the read formats the
// values loaded from the database. The provider's stackweaver_ansible_schedule showed the
// difference as a next_run_at diff on every plan after apply.
//
// It runs against the golden harness's throwaway database, which is dropped afterwards.
//
//	go test -tags integration ./internal/api/v2/routes/ -run TestAnsibleScheduleTimestamps

//go:build integration

package routes_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAnsibleScheduleTimestamps_CreateAndReadAgree(t *testing.T) {
	requireTestDatabase(t)
	if !inProcessZone(t, brusselsZone) {
		return
	}
	h := setupGoldenHarness(t)

	var playbookID string
	if err := h.db.Raw(`SELECT p.id::text FROM ansible_playbooks p
		JOIN projects pr ON pr.id = p.project_id JOIN organizations o ON o.id = pr.organization_id
		WHERE o.name = 'demo' ORDER BY p.id LIMIT 1`).Scan(&playbookID).Error; err != nil || playbookID == "" {
		t.Fatalf("no seeded playbook in the demo organization: %v", err)
	}

	do := func(t *testing.T, method, path string, body []byte, want int) map[string]any {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+h.token)
		req.Header.Set("Content-Type", "application/vnd.api+json")
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		var doc struct {
			Data struct {
				ID         string         `json:"id"`
				Attributes map[string]any `json:"attributes"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s %s returned non-JSON: %v", method, path, err)
		}
		doc.Data.Attributes["id"] = doc.Data.ID
		return doc.Data.Attributes
	}

	// The schedule's own zone differs from the process zone, so a next-run-at computed in it
	// carries a third offset unless it is written in UTC.
	create, err := json.Marshal(map[string]any{"data": map[string]any{
		"type": "schedules",
		"attributes": map[string]any{
			"name":            "utc-timestamps-schedule",
			"schedule-type":   "playbook_sync",
			"playbook-id":     playbookID,
			"cron-expression": "0 3 * * *",
			"timezone":        "America/New_York",
		},
	}})
	if err != nil {
		t.Fatalf("encoding the request: %v", err)
	}
	created := do(t, http.MethodPost, "/api/v2/organizations/demo/ansible/schedules", create, http.StatusCreated)
	read := do(t, http.MethodGet, fmt.Sprintf("/api/v2/ansible/schedules/%s", created["id"]), nil, http.StatusOK)

	for _, attr := range []string{"created-at", "updated-at", "next-run-at", "last-run-at"} {
		if fmt.Sprint(created[attr]) != fmt.Sprint(read[attr]) {
			t.Errorf("%s: create wrote %v, read wrote %v", attr, created[attr], read[attr])
		}
	}
	if s, _ := created["next-run-at"].(string); s == "" {
		t.Errorf("next-run-at is empty on a cron schedule: %v", created["next-run-at"])
	}
}
