// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package jsonapi_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/openapi"
)

// nullableRequest is a request document with one attribute bound through jsonapi.Nullable.
type nullableRequest struct {
	Data *struct {
		Type       string `json:"type"`
		Attributes struct {
			Version jsonapi.Nullable[string] `json:"terraform-version"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

func (r *nullableRequest) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
}

// A Nullable attribute inside a bound document tells an absent key, a JSON null, an empty string
// and a value apart, which a *string cannot: encoding/json reads an absent key and a null alike
// (#1069, D2, AC22).
func TestNullable_TellsAbsentNullEmptyAndValueApart(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name          string
		attributes    string
		present, null bool
		value         string
	}{
		{name: "absent", attributes: `{}`},
		{name: "null", attributes: `{"terraform-version": null}`, present: true, null: true},
		{name: "empty", attributes: `{"terraform-version": ""}`, present: true},
		{name: "a value", attributes: `{"terraform-version": "1.12.0"}`, present: true, value: "1.12.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			body := `{"data": {"type": "workspaces", "attributes": ` + tc.attributes + `}}`
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/", strings.NewReader(body))
			c.Request.Header.Set("Content-Type", "application/vnd.api+json")
			var req nullableRequest
			if !jsonapi.BindDocument(c, &req, "workspaces") {
				t.Fatalf("bind refused: %d %s", rec.Code, rec.Body.String())
			}
			got := req.Data.Attributes.Version
			if got.Present != tc.present || got.Null != tc.null || got.Value != tc.value {
				t.Errorf("decoded %+v, want present=%t null=%t value=%q", got, tc.present, tc.null, tc.value)
			}
		})
	}

	t.Run("a value of the wrong type is refused", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/", strings.NewReader(`{"data": {"type": "workspaces", "attributes": {"terraform-version": 12}}}`))
		c.Request.Header.Set("Content-Type", "application/vnd.api+json")
		var req nullableRequest
		if jsonapi.BindDocument(c, &req, "workspaces") {
			t.Fatal("a number bound into a Nullable[string]")
		}
	})
}

// The OpenAPI document describes a Nullable[T] member as T, nullable, rather than as an opaque
// value with no type.
func TestNullable_RendersInTheOpenAPIDocument(t *testing.T) {
	s := openapi.SchemaForType(reflect.TypeFor[nullableRequest]())
	attrs := s.Properties["data"].Properties["attributes"]
	member := attrs.Properties["terraform-version"]
	if member == nil || member.Type != "string" || !member.Nullable || member.Opaque {
		t.Fatalf("terraform-version schema = %+v, want a nullable string", member)
	}
}
