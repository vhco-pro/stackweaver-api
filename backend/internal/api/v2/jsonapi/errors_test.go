// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Tests for the shared JSON:API error type (#755, AC2).
//
// These pin the serialised shape against what the handlers emitted before the migration, taken
// verbatim from the golden fixtures in internal/api/v2/routes/testdata/golden/. If the type ever
// stops reproducing that shape, 1641 call sites change their output at once.

package jsonapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
)

func recorded(t *testing.T, fn func(c *gin.Context)) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	fn(c)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, body
}

func TestWriteErrorMatchesTheShapeHandlersAlreadyEmit(t *testing.T) {
	// Verbatim from testdata/golden/errors/patch_api_v2_ansible_schedules_schedule_id.json.
	const want = `{"errors":[{"status":"404","title":"Not Found","detail":"resource not found"}]}`

	code, got := recorded(t, func(c *gin.Context) {
		WriteError(c, http.StatusNotFound, TitleNotFound, "resource not found")
	})
	if code != http.StatusNotFound {
		t.Errorf("status code: got %d, want 404", code)
	}

	var expected map[string]any
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	wantJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("serialised shape changed\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
}

// The `status` member is derived from the HTTP code rather than passed in, which is only safe
// because every call site already agreed. This pins that derivation.
func TestWriteErrorDerivesStatusFromTheHTTPCode(t *testing.T) {
	for code, title := range map[int]string{
		http.StatusBadRequest:          TitleBadRequest,
		http.StatusUnauthorized:        TitleUnauthorized,
		http.StatusForbidden:           TitleForbidden,
		http.StatusNotFound:            TitleNotFound,
		http.StatusConflict:            TitleConflict,
		http.StatusInternalServerError: TitleInternal,
	} {
		_, body := recorded(t, func(c *gin.Context) { WriteError(c, code, title, "d") })
		errs, ok := body["errors"].([]any)
		if !ok || len(errs) != 1 {
			t.Fatalf("expected exactly one error object, got %v", body)
		}
		obj := errs[0].(map[string]any)
		if obj["status"] != strconv.Itoa(code) {
			t.Errorf("status member for %d: got %v, want %q", code, obj["status"], strconv.Itoa(code))
		}
	}
}

// A title-only error must not grow an empty detail, and a three-field error must keep a
// deliberately empty one. This is the whole reason Detail is a pointer.
func TestDetailPresenceIsPreservedExactly(t *testing.T) {
	_, withEmpty := recorded(t, func(c *gin.Context) {
		WriteError(c, http.StatusBadRequest, TitleBadRequest, "")
	})
	obj := withEmpty["errors"].([]any)[0].(map[string]any)
	if _, present := obj["detail"]; !present {
		t.Error("an explicitly empty detail was dropped; clients reading errors[0].detail would see undefined")
	}

	_, without := recorded(t, func(c *gin.Context) {
		WriteErrorNoDetail(c, http.StatusBadRequest, TitleBadRequest)
	})
	obj2 := without["errors"].([]any)[0].(map[string]any)
	if _, present := obj2["detail"]; present {
		t.Error("a title-only error invented a detail member")
	}
}

func TestAbortErrorStopsTheChain(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)

	AbortError(c, http.StatusUnauthorized, TitleUnauthorized, "missing authorization header")
	if !c.IsAborted() {
		t.Error("AbortError did not abort the handler chain; middleware would fall through to the handler")
	}
}
