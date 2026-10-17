// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package jsonapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type widgetRequest struct {
	Data *struct {
		Type       string `json:"type"`
		Attributes struct {
			Name string `json:"name" binding:"required"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

func (r *widgetRequest) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
}

type widgetIdentifier struct {
	Data *struct {
		Type string `json:"type"`
		ID   string `json:"id" binding:"required"`
	} `json:"data" binding:"required"`
}

func (r *widgetIdentifier) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
}

func bindWith(t *testing.T, body string, fn func(c *gin.Context)) (int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	fn(c)
	return rec.Code, rec.Body.String()
}

// The three binders answer every request-shape failure with the one sentence for it (#858, D2).
func TestBindDocument(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		ok     bool
		detail string
	}{
		{"a flat body", `{"name":"w"}`, false, `request body must be a JSON:API document: {\"data\": {\"type\": \"widgets\", \"attributes\": {...}}}`},
		{"an empty object", `{}`, false, `request body must be a JSON:API document`},
		{"null", `null`, false, `request body must be a JSON:API document`},
		{"no body", ``, false, `request body must be a JSON:API document`},
		{"a wrong type", `{"data":{"type":"gadgets","attributes":{"name":"w"}}}`, false, `data.type must be \"widgets\" (got \"gadgets\")`},
		{"a missing type", `{"data":{"attributes":{"name":"w"}}}`, false, `data.type must be \"widgets\" (got \"\")`},
		{"a missing required attribute keeps gin's text", `{"data":{"type":"widgets","attributes":{}}}`, false, `Field validation for 'Name' failed on the 'required' tag`},
		{"a document", `{"data":{"type":"widgets","attributes":{"name":"w"}}}`, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req widgetRequest
			var ok bool
			code, body := bindWith(t, tt.body, func(c *gin.Context) { ok = BindDocument(c, &req, "widgets") })
			if ok != tt.ok {
				t.Fatalf("ok = %t, want %t (%d %s)", ok, tt.ok, code, body)
			}
			if !tt.ok && (code != http.StatusBadRequest || !strings.Contains(body, tt.detail)) {
				t.Errorf("got %d %s, want 400 containing %s", code, body, tt.detail)
			}
		})
	}
}

func TestBindOptionalDocument(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		present, ok bool
		detail      string
	}{
		{"no body", ``, false, true, ""},
		{"whitespace", " \n", false, true, ""},
		{"an empty object", `{}`, false, false, `request body must be a JSON:API document`},
		{"a flat body", `{"name":"w"}`, false, false, `request body must be a JSON:API document`},
		{"malformed", `{"data":`, false, false, `unexpected EOF`},
		{"a wrong type", `{"data":{"type":"gadgets","attributes":{"name":"w"}}}`, false, false, `data.type must be \"widgets\"`},
		{"a document", `{"data":{"type":"widgets","attributes":{"name":"w"}}}`, true, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req widgetRequest
			var present, ok bool
			code, body := bindWith(t, tt.body, func(c *gin.Context) { present, ok = BindOptionalDocument(c, &req, "widgets") })
			if present != tt.present || ok != tt.ok {
				t.Fatalf("present, ok = %t, %t, want %t, %t (%d %s)", present, ok, tt.present, tt.ok, code, body)
			}
			if !tt.ok && (code != http.StatusBadRequest || !strings.Contains(body, tt.detail)) {
				t.Errorf("got %d %s, want 400 containing %s", code, body, tt.detail)
			}
		})
	}
}

func TestBindIdentifier(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		ok     bool
		detail string
	}{
		{"a flat body", `{"widget_id":"1"}`, false, `request body must be a JSON:API resource identifier: {\"data\": {\"type\": \"widgets\", \"id\": \"...\"}}`},
		{"a wrong type", `{"data":{"type":"gadgets","id":"1"}}`, false, `data.type must be \"widgets\" (got \"gadgets\")`},
		{"an identifier", `{"data":{"type":"widgets","id":"1"}}`, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req widgetIdentifier
			var ok bool
			code, body := bindWith(t, tt.body, func(c *gin.Context) { ok = BindIdentifier(c, &req, "widgets") })
			if ok != tt.ok {
				t.Fatalf("ok = %t, want %t (%d %s)", ok, tt.ok, code, body)
			}
			if !tt.ok && (code != http.StatusBadRequest || !strings.Contains(body, tt.detail)) {
				t.Errorf("got %d %s, want 400 containing %s", code, body, tt.detail)
			}
		})
	}
}

// A relationship in a request is type-checked the way data is, and the answer names the member.
func TestRelationshipID(t *testing.T) {
	tests := []struct {
		name   string
		rel    *Relationship
		id     string
		ok     bool
		detail string
	}{
		{"absent", nil, "", true, ""},
		{"null", &Relationship{}, "", true, ""},
		{"the right type", &Relationship{Data: &ResourceID{ID: "1", Type: "widgets"}}, "1", true, ""},
		{"a wrong type", &Relationship{Data: &ResourceID{ID: "1", Type: "gadgets"}}, "", false, `data.relationships.widget.data.type must be \"widgets\" (got \"gadgets\")`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var id string
			var ok bool
			code, body := bindWith(t, "", func(c *gin.Context) { id, ok = RelationshipID(c, tt.rel, "widget", "widgets") })
			if id != tt.id || ok != tt.ok {
				t.Fatalf("got %q, %t, want %q, %t (%d %s)", id, ok, tt.id, tt.ok, code, body)
			}
			if !tt.ok && !strings.Contains(body, tt.detail) {
				t.Errorf("body %s, want %s", body, tt.detail)
			}
		})
	}
}
