// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// TestFormatChangeRequestOpen pins the JSON:API shape of an open request. The type string and the
// null archived-by/archived-at are the TFE contract: a client reads null as "still open".
func TestFormatChangeRequestOpen(t *testing.T) {
	created := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	filer := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	cr := &models.ChangeRequest{
		ID:          "cr-abc",
		WorkspaceID: "ws-123",
		Subject:     "Bump the deprecated module",
		Message:     "`foo/bar` v1 is EOL.",
		CreatedBy:   filer,
		CreatedAt:   created,
		UpdatedAt:   created,
	}

	out := formatChangeRequest(cr)

	if out["type"] != "workspace_change_requests" {
		t.Errorf("type = %v, want workspace_change_requests", out["type"])
	}
	if out["id"] != "cr-abc" {
		t.Errorf("id = %v, want cr-abc", out["id"])
	}

	attrs, ok := out["attributes"].(gin.H)
	if !ok {
		t.Fatalf("attributes is %T, want gin.H", out["attributes"])
	}
	if attrs["subject"] != "Bump the deprecated module" {
		t.Errorf("subject = %v", attrs["subject"])
	}
	// An open request must report null, not a zero value: a client distinguishes open from archived
	// purely by these being null.
	if attrs["archived-by"] != nil {
		t.Errorf("archived-by = %v, want nil for an open request", attrs["archived-by"])
	}
	if attrs["archived-at"] != nil {
		t.Errorf("archived-at = %v, want nil for an open request", attrs["archived-at"])
	}
	if attrs["created-by"] != filer.String() {
		t.Errorf("created-by = %v, want %v", attrs["created-by"], filer)
	}
	if attrs["created-at"] != "2026-07-15T10:00:00Z" {
		t.Errorf("created-at = %v, want RFC3339", attrs["created-at"])
	}
	// workspace-name is only emitted when the relation was preloaded.
	if _, present := attrs["workspace-name"]; present {
		t.Errorf("workspace-name should be absent when Workspace is not preloaded")
	}

	rels, ok := out["relationships"].(gin.H)
	if !ok {
		t.Fatalf("relationships is %T, want gin.H", out["relationships"])
	}
	ws, ok := rels["workspace"].(gin.H)
	if !ok {
		t.Fatalf("relationships.workspace is %T, want gin.H", rels["workspace"])
	}
	data, ok := ws["data"].(gin.H)
	if !ok {
		t.Fatalf("relationships.workspace.data is %T, want gin.H", ws["data"])
	}
	if data["id"] != "ws-123" || data["type"] != "workspaces" {
		t.Errorf("workspace linkage = %v, want ws-123/workspaces", data)
	}
}

// TestFormatChangeRequestArchived pins that archiving surfaces both archived fields.
func TestFormatChangeRequestArchived(t *testing.T) {
	archivedAt := time.Date(2026, 7, 16, 9, 30, 0, 0, time.UTC)
	archiver := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	cr := &models.ChangeRequest{
		ID:          "cr-abc",
		WorkspaceID: "ws-123",
		Subject:     "Done",
		ArchivedBy:  &archiver,
		ArchivedAt:  &archivedAt,
		Workspace:   &models.Workspace{Name: "prod-network"},
	}

	attrs := formatChangeRequest(cr)["attributes"].(gin.H)

	if attrs["archived-by"] != archiver.String() {
		t.Errorf("archived-by = %v, want %v", attrs["archived-by"], archiver)
	}
	if attrs["archived-at"] != "2026-07-16T09:30:00Z" {
		t.Errorf("archived-at = %v, want RFC3339", attrs["archived-at"])
	}
	// Preloaded workspace surfaces the name so the org triage view needs no extra round trip.
	if attrs["workspace-name"] != "prod-network" {
		t.Errorf("workspace-name = %v, want prod-network", attrs["workspace-name"])
	}
}

// TestFormatChangeRequestNeverLeaksNotifiedAt guards the delivery marker: it is internal bookkeeping
// and must not appear on the wire, where a client could mistake it for a change-request timestamp.
func TestFormatChangeRequestNeverLeaksNotifiedAt(t *testing.T) {
	now := time.Now()
	cr := &models.ChangeRequest{ID: "cr-x", WorkspaceID: "ws-1", NotifiedAt: &now}

	body, err := json.Marshal(formatChangeRequest(cr))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leak := range []string{"notified", "NotifiedAt"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("serialized change request leaks %q: %s", leak, body)
		}
	}
}

// TestBulkActionRequestBindsTFEBody parses the body exactly as HashiCorp documents it. These
// attributes are snake_case, unlike the kebab-case used everywhere else in the TFE API, so this test
// exists to catch a well-meaning "fix" to house style that would silently break real clients.
func TestBulkActionRequestBindsTFEBody(t *testing.T) {
	const tfeDocumentedBody = `{
	  "data": {
	    "type": "bulk_actions",
	    "attributes": {
	      "action_type": "change_requests",
	      "action_inputs": {
	        "subject": "Upgrade the module",
	        "message": "Please move off v1."
	      },
	      "target_ids": ["ws-1", "ws-2", "ws-3"]
	    }
	  }
	}`

	var req bulkActionRequest
	if err := json.Unmarshal([]byte(tfeDocumentedBody), &req); err != nil {
		t.Fatalf("failed to parse TFE's documented bulk-action body: %v", err)
	}
	a := req.Data.Attributes
	if req.Data.Type != "bulk_actions" {
		t.Errorf("type = %q, want bulk_actions", req.Data.Type)
	}
	if a.ActionType != "change_requests" {
		t.Errorf("action_type = %q, want change_requests", a.ActionType)
	}
	if a.ActionInputs.Subject != "Upgrade the module" {
		t.Errorf("action_inputs.subject = %q", a.ActionInputs.Subject)
	}
	if a.ActionInputs.Message != "Please move off v1." {
		t.Errorf("action_inputs.message = %q", a.ActionInputs.Message)
	}
	if len(a.TargetIDs) != 3 || a.TargetIDs[0] != "ws-1" || a.TargetIDs[2] != "ws-3" {
		t.Errorf("target_ids = %v, want 3 workspace ids", a.TargetIDs)
	}
	// The query variant must be distinguishable from its absence, since we reject it explicitly.
	if len(a.Query) != 0 {
		t.Errorf("query = %v, want empty when omitted", a.Query)
	}
}

// TestBulkActionRequestDetectsQueryVariant proves the Explorer-query form is recognisable, which is
// what lets the handler reject it with a clear error instead of filing against nothing.
func TestBulkActionRequestDetectsQueryVariant(t *testing.T) {
	const body = `{"data":{"type":"bulk_actions","attributes":{
		"action_type":"change_requests",
		"action_inputs":{"subject":"s","message":"m"},
		"query":{"filters":[{"name":"terraform_version"}]}}}}`

	var req bulkActionRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(req.Data.Attributes.Query) == 0 {
		t.Fatal("query variant not detected; the handler would silently file zero change requests")
	}
}

// TestPaginate covers the TFE page[number]/page[size] params, including the clamps.
func TestPaginate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name                           string
		query                          string
		wantPage, wantSize, wantOffset int
	}{
		{"defaults", "", 1, 20, 0},
		{"explicit page and size", "?page[number]=3&page[size]=10", 3, 10, 20},
		{"size clamped to 100", "?page[size]=5000", 1, 100, 0},
		{"zero page falls back to 1", "?page[number]=0", 1, 20, 0},
		{"negative page falls back to 1", "?page[number]=-4", 1, 20, 0},
		{"zero size falls back to default", "?page[size]=0", 1, 20, 0},
		{"garbage values fall back to defaults", "?page[number]=abc&page[size]=xyz", 1, 20, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/"+tt.query, nil)

			page, size, offset := paginate(c)
			if page != tt.wantPage || size != tt.wantSize || offset != tt.wantOffset {
				t.Errorf("paginate() = (page %d, size %d, offset %d), want (%d, %d, %d)",
					page, size, offset, tt.wantPage, tt.wantSize, tt.wantOffset)
			}
		})
	}
}
