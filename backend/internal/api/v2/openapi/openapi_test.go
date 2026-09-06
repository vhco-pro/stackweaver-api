// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Tests for serving the OpenAPI document (#755, AC4/AC5/AC7).

package openapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func router() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterRoutes(r)
	return r
}

func get(t *testing.T, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/openapi/stable.json", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	router().ServeHTTP(rec, req)
	return rec
}

// AC4: the document is served over the wire, and without authentication. The request carries no
// Authorization header at all, which is the point - a client generating against Stackweaver has
// no token yet.
func TestServesTheDocumentUnauthenticated(t *testing.T) {
	rec := get(t, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("served body is not JSON: %v", err)
	}
	if v, _ := doc["openapi"].(string); v == "" {
		t.Error("served document has no openapi version member")
	}
	if len(doc["paths"].(map[string]any)) == 0 {
		t.Error("served document has no paths")
	}
}

// AC5b: identity is Stackweaver's own. Advertising TFE's title would invite clients to assume
// endpoints that are not implemented, so every gap would read as a bug.
func TestDocumentIdentifiesAsStackweaver(t *testing.T) {
	var doc struct {
		Info struct {
			Title   string `json:"title"`
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.Unmarshal(Spec, &doc); err != nil {
		t.Fatalf("embedded spec is not JSON: %v", err)
	}
	if doc.Info.Title != specTitleWant {
		t.Errorf("info.title: got %q, want %q", doc.Info.Title, specTitleWant)
	}
	for _, banned := range []string{"HCP Terraform", "Terraform Enterprise", "TFE API"} {
		if doc.Info.Title == banned {
			t.Errorf("info.title claims TFE identity: %q", doc.Info.Title)
		}
	}
	if doc.Info.Version == "" {
		t.Error("info.version is empty; clients pin against it")
	}
}

const specTitleWant = "Stackweaver API"

// AC5: every response object references a schema, rather than being an untyped object. A path
// list without schemas generates untyped client stubs, which is most of the value lost.
func TestEveryResponseReferencesASchema(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content map[string]struct {
					Schema map[string]any `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(Spec, &doc); err != nil {
		t.Fatalf("embedded spec is not JSON: %v", err)
	}

	var untyped []string
	ops := 0
	for path, methods := range doc.Paths {
		for method, op := range methods {
			ops++
			for code, resp := range op.Responses {
				// 204 and 304 carry no body by definition (RFC 9110), so demanding a schema
				// for them would be demanding a contradiction.
				if code == "204" || code == "304" {
					continue
				}
				if len(resp.Content) == 0 {
					untyped = append(untyped, method+" "+path+" -> "+code+" (no content)")
					continue
				}
				for ct, body := range resp.Content {
					if len(body.Schema) == 0 {
						untyped = append(untyped, method+" "+path+" -> "+code+" "+ct+" (no schema)")
					}
				}
			}
		}
	}
	if ops == 0 {
		t.Fatal("no operations in the document")
	}
	if len(untyped) > 0 {
		t.Errorf("%d response(s) carry no schema, so a generated client would be untyped there:\n  %v",
			len(untyped), untyped[:min(len(untyped), 10)])
	}
	if len(doc.Components.Schemas) == 0 {
		t.Error("components.schemas is empty")
	}
}

// AC7: conditional requests. go-tfe sends If-Modified-Since and expects 304; without it a client
// re-downloads half a megabyte on every construction.
func TestConditionalRequests(t *testing.T) {
	fresh := get(t, nil)
	lm := fresh.Header().Get("Last-Modified")
	if lm == "" {
		t.Fatal("no Last-Modified header; go-tfe's conditional fetch cannot work")
	}

	notModified := get(t, map[string]string{"If-Modified-Since": lm})
	if notModified.Code != http.StatusNotModified {
		t.Errorf("echoing Last-Modified back: got %d, want 304", notModified.Code)
	}
	if notModified.Body.Len() != 0 {
		t.Errorf("304 carried a body of %d bytes", notModified.Body.Len())
	}

	older := lastModified().Add(-48 * time.Hour).Format(http.TimeFormat)
	modified := get(t, map[string]string{"If-Modified-Since": older})
	if modified.Code != http.StatusOK {
		t.Errorf("older If-Modified-Since: got %d, want 200", modified.Code)
	}
	if modified.Body.Len() == 0 {
		t.Error("200 response carried no body")
	}
}

// A malformed If-Modified-Since must not be treated as "not modified" - that would serve a 304
// to a client that has nothing cached, leaving it with no document at all.
func TestMalformedIfModifiedSinceStillServesTheDocument(t *testing.T) {
	rec := get(t, map[string]string{"If-Modified-Since": "not-a-date"})
	if rec.Code != http.StatusOK {
		t.Errorf("malformed If-Modified-Since: got %d, want 200", rec.Code)
	}
}
