// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Tests for the two request-shape errors every JSON:API-only endpoint answers with (#844, AC1).
//
// The bodies are pinned byte for byte because three handlers share them: a client that sent a
// flat body to organizations must read the same sentence it would read from runs, with only the
// resource type differing.

package jsonapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func recordedBody(t *testing.T, fn func(c *gin.Context)) (int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil)
	fn(c)
	return rec.Code, rec.Body.String()
}

func TestWriteDocumentRequired(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		want         string
	}{
		{
			name:         "organizations",
			resourceType: "organizations",
			want:         `{"errors":[{"status":"400","title":"Bad Request","detail":"request body must be a JSON:API document: {\"data\": {\"type\": \"organizations\", \"attributes\": {...}}}"}]}`,
		},
		{
			name:         "runs",
			resourceType: "runs",
			want:         `{"errors":[{"status":"400","title":"Bad Request","detail":"request body must be a JSON:API document: {\"data\": {\"type\": \"runs\", \"attributes\": {...}}}"}]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body := recordedBody(t, func(c *gin.Context) {
				WriteDocumentRequired(c, tt.resourceType)
			})
			if code != http.StatusBadRequest {
				t.Errorf("status code: got %d, want 400", code)
			}
			if body != tt.want {
				t.Errorf("body:\n got  %s\n want %s", body, tt.want)
			}
		})
	}
}

func TestWriteWrongType(t *testing.T) {
	tests := []struct {
		name string
		want string
		got  string
		body string
	}{
		{
			name: "a different resource type",
			want: "runs",
			got:  "workspaces",
			body: `{"errors":[{"status":"400","title":"Bad Request","detail":"data.type must be \"runs\" (got \"workspaces\")"}]}`,
		},
		{
			name: "a missing type",
			want: "organizations",
			got:  "",
			body: `{"errors":[{"status":"400","title":"Bad Request","detail":"data.type must be \"organizations\" (got \"\")"}]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body := recordedBody(t, func(c *gin.Context) {
				WriteWrongType(c, tt.want, tt.got)
			})
			if code != http.StatusBadRequest {
				t.Errorf("status code: got %d, want 400", code)
			}
			if body != tt.body {
				t.Errorf("body:\n got  %s\n want %s", body, tt.body)
			}
		})
	}
}

// WriteWrongTypeAt names the member whose type is wrong, so a client that sent the right
// document with a wrong relationship identifier is told which identifier (#858, D2).
func TestWriteWrongTypeAt(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
		got  string
		body string
	}{
		{
			name: "a relationship identifier",
			path: "data.relationships.credential.data",
			want: "ansible-credentials",
			got:  "ansible-inventories",
			body: `{"errors":[{"status":"400","title":"Bad Request","detail":"data.relationships.credential.data.type must be \"ansible-credentials\" (got \"ansible-inventories\")"}]}`,
		},
		{
			name: "the primary data, as WriteWrongType writes it",
			path: "data",
			want: "runs",
			got:  "workspaces",
			body: `{"errors":[{"status":"400","title":"Bad Request","detail":"data.type must be \"runs\" (got \"workspaces\")"}]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body := recordedBody(t, func(c *gin.Context) {
				WriteWrongTypeAt(c, tt.path, tt.want, tt.got)
			})
			if code != http.StatusBadRequest {
				t.Errorf("status code: got %d, want 400", code)
			}
			if body != tt.body {
				t.Errorf("body:\n got  %s\n want %s", body, tt.body)
			}
		})
	}
}

// WriteIdentifierRequired answers a request that attaches an existing resource by identity and
// sent no resource identifier object: the example it shows carries an id, not attributes.
func TestWriteIdentifierRequired(t *testing.T) {
	code, body := recordedBody(t, func(c *gin.Context) {
		WriteIdentifierRequired(c, "ansible-credentials")
	})
	if code != http.StatusBadRequest {
		t.Errorf("status code: got %d, want 400", code)
	}
	want := `{"errors":[{"status":"400","title":"Bad Request","detail":"request body must be a JSON:API resource identifier: {\"data\": {\"type\": \"ansible-credentials\", \"id\": \"...\"}}"}]}`
	if body != want {
		t.Errorf("body:\n got  %s\n want %s", body, want)
	}
}
