// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Tests for the run-create request boundary (#844, AC3 and AC4): what POST /api/v2/runs accepts
// before it looks anything up.
//
// The endpoint used to accept four top-level keys beside `data` (workspace_id,
// configuration_version_id, operation, auto_apply_after_plan). They are rejected rather than
// ignored, which is the one place the endpoint is stricter than Terraform Enterprise. The reason
// is the hybrid body: a caller that still sends `operation: plan-and-apply` beside a valid
// document relied on that key to make the run applyable or speculative, and silently dropping it
// would change what the run does. A 400 that names the keys is the better failure.

package terraform

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// validRunData is the `data` member go-tfe v1.112.0 marshals for RunCreateOptions{Workspace}: no
// intent attribute, and a nil configuration version as an explicit null relationship.
const validRunData = `"data":{"type":"runs","attributes":{},"relationships":{` +
	`"workspace":{"data":{"type":"workspaces","id":"ws-abc"}},` +
	`"configuration-version":{"data":null}}}`

// The expected details are spelled out here rather than taken from the handler's constants, so a
// reworded message fails this test instead of following the change silently: old clients read
// these sentences.
const (
	wantRetiredRunKeysDetail = "top-level fields are not accepted: workspace_id, configuration_version_id, " +
		"operation, auto_apply_after_plan; use data.attributes and data.relationships"
	wantRunDocumentDetail = `request body must be a JSON:API document: {"data": {"type": "runs", "attributes": {...}}}`
)

// decodeRun drives decodeCreateRunRequest with a body and returns what it answered.
func decodeRun(t *testing.T, body string) (req *CreateRunRequestV2, ok bool, code int, detail string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runs", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/vnd.api+json")

	req, ok = decodeCreateRunRequest(c)
	if ok {
		return req, true, rec.Code, ""
	}

	var doc struct {
		Errors []struct {
			Status string `json:"status"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("rejection is not a JSON:API error document: %v (%s)", err, rec.Body.String())
	}
	if len(doc.Errors) != 1 {
		t.Fatalf("errors has %d entries, want 1 (%s)", len(doc.Errors), rec.Body.String())
	}
	if doc.Errors[0].Status != "400" || doc.Errors[0].Title != "Bad Request" {
		t.Errorf("error = %+v, want status 400 and title Bad Request", doc.Errors[0])
	}
	return nil, false, rec.Code, doc.Errors[0].Detail
}

func TestDecodeCreateRunRequest_RetiredTopLevelKeys(t *testing.T) {
	retired := []struct {
		key   string
		value string
	}{
		{"workspace_id", `"ws-abc"`},
		{"configuration_version_id", `"cv-abc"`},
		{"operation", `"plan-and-apply"`},
		{"auto_apply_after_plan", `true`},
		// Present is present: a null or empty value still means the caller is on the old shape.
		{"operation", `null`},
		{"workspace_id", `""`},
	}
	for _, k := range retired {
		member := `"` + k.key + `":` + k.value
		t.Run(k.key+"="+k.value+" alone", func(t *testing.T) {
			_, ok, code, detail := decodeRun(t, `{`+member+`}`)
			if ok || code != http.StatusBadRequest {
				t.Fatalf("accepted = %v, status = %d; want a 400", ok, code)
			}
			if detail != wantRetiredRunKeysDetail {
				t.Errorf("detail = %q, want %q", detail, wantRetiredRunKeysDetail)
			}
			if !strings.Contains(detail, k.key) {
				t.Errorf("detail %q does not name %s", detail, k.key)
			}
		})
		t.Run(k.key+"="+k.value+" beside a valid data", func(t *testing.T) {
			_, ok, code, detail := decodeRun(t, `{`+validRunData+`,`+member+`}`)
			if ok || code != http.StatusBadRequest {
				t.Fatalf("accepted = %v, status = %d; want a 400 even though data is valid", ok, code)
			}
			if detail != wantRetiredRunKeysDetail {
				t.Errorf("detail = %q, want %q", detail, wantRetiredRunKeysDetail)
			}
		})
	}

	t.Run("the hybrid body the frontend used to send", func(t *testing.T) {
		body := `{` + validRunData + `,"workspace_id":"ws-abc","configuration_version_id":null,` +
			`"operation":"plan-and-apply","auto_apply_after_plan":false}`
		_, ok, code, detail := decodeRun(t, body)
		if ok || code != http.StatusBadRequest || detail != wantRetiredRunKeysDetail {
			t.Errorf("accepted = %v, status = %d, detail = %q; want a 400 naming the retired keys", ok, code, detail)
		}
	})
}

func TestDecodeCreateRunRequest_Document(t *testing.T) {
	rejected := []struct {
		name       string
		body       string
		wantDetail string
	}{
		{"empty object", `{}`, wantRunDocumentDetail},
		{"null data", `{"data":null}`, wantRunDocumentDetail},
		{"empty body", ``, wantRunDocumentDetail},
		{"not an object", `[]`, wantRunDocumentDetail},
		{
			"wrong data.type",
			`{"data":{"type":"workspaces","relationships":{"workspace":{"data":{"type":"workspaces","id":"ws-abc"}}}}}`,
			`data.type must be "runs" (got "workspaces")`,
		},
		{
			"missing data.type",
			`{"data":{"relationships":{"workspace":{"data":{"type":"workspaces","id":"ws-abc"}}}}}`,
			`data.type must be "runs" (got "")`,
		},
		{"no relationships", `{"data":{"type":"runs","attributes":{"message":"x"}}}`, "a workspace relationship is required"},
		{
			"null workspace relationship",
			`{"data":{"type":"runs","relationships":{"workspace":{"data":null}}}}`,
			"a workspace relationship is required",
		},
		{
			"workspace relationship without an id",
			`{"data":{"type":"runs","relationships":{"workspace":{"data":{"type":"workspaces"}}}}}`,
			"a workspace relationship is required",
		},
	}
	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			_, ok, code, detail := decodeRun(t, tt.body)
			if ok || code != http.StatusBadRequest {
				t.Fatalf("accepted = %v, status = %d; want a 400", ok, code)
			}
			if detail != tt.wantDetail {
				t.Errorf("detail = %q, want %q", detail, tt.wantDetail)
			}
		})
	}

	t.Run("the go-tfe body with a null configuration version is accepted", func(t *testing.T) {
		req, ok, _, detail := decodeRun(t, `{`+validRunData+`}`)
		if !ok {
			t.Fatalf("go-tfe's own body was rejected: %s", detail)
		}
		if got := req.Data.Relationships.Workspace.Data.ID; got != "ws-abc" {
			t.Errorf("workspace id = %q, want ws-abc", got)
		}
		if got := req.Data.Relationships.ConfigurationVersion.Data.ID; got != "" {
			t.Errorf("configuration version id = %q, want none for a null relationship", got)
		}
	})

	t.Run("a configuration version relationship is read", func(t *testing.T) {
		body := `{"data":{"type":"runs","attributes":{"auto-apply":false},"relationships":{` +
			`"workspace":{"data":{"type":"workspaces","id":"ws-abc"}},` +
			`"configuration-version":{"data":{"type":"configuration-versions","id":"cv-abc"}}}}}`
		req, ok, _, detail := decodeRun(t, body)
		if !ok {
			t.Fatalf("valid document rejected: %s", detail)
		}
		if got := req.Data.Relationships.ConfigurationVersion.Data.ID; got != "cv-abc" {
			t.Errorf("configuration version id = %q, want cv-abc", got)
		}
	})

	t.Run("an unknown top-level member is ignored, as on Terraform Enterprise", func(t *testing.T) {
		if _, ok, _, detail := decodeRun(t, `{`+validRunData+`,"meta":{"client":"x"}}`); !ok {
			t.Fatalf("a document with an unrelated top-level member was rejected: %s", detail)
		}
	})
}
