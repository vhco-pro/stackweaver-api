// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Bind-boundary tests for the organization request bodies (#844, AC1 and AC2).
//
// Both structs used to carry top-level `name` and `description` beside `data`, so a flat body
// bound without error and the handler read it. Nothing in the tree rejects unknown JSON members,
// which means that once the flat fields are gone a flat body would bind silently to zero values
// unless `data` is required. These tests pin that it is.

package handlers

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestOrganizationRequests_Binding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	bind := func(t *testing.T, method, body string, req any) error {
		t.Helper()
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequestWithContext(t.Context(), method, "/", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/vnd.api+json")
		return c.ShouldBindJSON(req)
	}

	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			// The body go-tfe marshals for OrganizationCreateOptions{Name, Email}.
			name: "JSON:API document binds",
			body: `{"data":{"type":"organizations","attributes":{"name":"acme","email":"ops@acme.test"}}}`,
		},
		{
			name: "document with the description extension binds",
			body: `{"data":{"type":"organizations","attributes":{"name":"acme","description":"Platform team"}}}`,
		},
		{name: "flat body is rejected", body: `{"name":"acme"}`, wantErr: true},
		{name: "flat body with description is rejected", body: `{"name":"acme","description":"x"}`, wantErr: true},
		{name: "empty object is rejected", body: `{}`, wantErr: true},
		{name: "null data is rejected", body: `{"data":null}`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run("create/"+tt.name, func(t *testing.T) {
			var req CreateOrganizationRequestV2
			err := bind(t, http.MethodPost, tt.body, &req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("bind error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && req.Data != nil {
				t.Error("a rejected body must leave Data nil, so the handler can name the expected document")
			}
		})
		t.Run("update/"+tt.name, func(t *testing.T) {
			var req UpdateOrganizationRequestV2
			err := bind(t, http.MethodPatch, tt.body, &req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("bind error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && req.Data != nil {
				t.Error("a rejected body must leave Data nil, so the handler can name the expected document")
			}
		})
	}

	t.Run("update keeps the default-agent-pool relationship", func(t *testing.T) {
		var req UpdateOrganizationRequestV2
		body := `{"data":{"type":"organizations","attributes":{"default-execution-mode":"agent"},` +
			`"relationships":{"default-agent-pool":{"data":{"type":"agent-pools","id":"apool-1"}}}}}`
		if err := bind(t, http.MethodPatch, body, &req); err != nil {
			t.Fatalf("valid document rejected: %v", err)
		}
		rels := req.Data.Relationships
		if rels == nil || rels.DefaultAgentPool == nil || rels.DefaultAgentPool.Data == nil {
			t.Fatal("default-agent-pool relationship was not bound")
		}
		if got := rels.DefaultAgentPool.Data.ID; got != "apool-1" {
			t.Errorf("default-agent-pool id = %q, want apool-1", got)
		}
	})
}

// TestOrganizationRequests_OnlyData pins the struct shape itself: the only top-level JSON member
// either request declares is `data`. A flat field added back beside it would make the endpoint
// dual-format again without failing any wire test, because the JSON:API half would keep working.
func TestOrganizationRequests_OnlyData(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeFor[CreateOrganizationRequestV2](),
		reflect.TypeFor[UpdateOrganizationRequestV2](),
	} {
		t.Run(typ.Name(), func(t *testing.T) {
			if typ.NumField() != 1 {
				t.Fatalf("%s declares %d top-level fields, want exactly one (data)", typ.Name(), typ.NumField())
			}
			if tag := typ.Field(0).Tag.Get("json"); tag != "data" {
				t.Errorf("%s top-level member is %q, want data", typ.Name(), tag)
			}
		})
	}
}
