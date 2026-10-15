// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package openapi

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The request types below are shaped like the ones the handlers bind: a JSON:API envelope of
// inline structs, kebab-case members, `binding:"required"` on the ones a request cannot omit.

type embeddedPaging struct {
	Page int `json:"page"`
	Size int `json:"size,omitempty"`
}

// ownDecoding has a wire form reflection cannot see: it decodes from either a string or a list.
type ownDecoding struct{ values []string }

func (o *ownDecoding) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		o.values = []string{one}
		return nil
	}
	return json.Unmarshal(b, &o.values)
}

type createThingRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name        string            `json:"name" binding:"required"`
			Description string            `json:"description"`
			Kind        string            `json:"inventory-type,omitempty"`
			Retries     int               `json:"retries"`
			Ratio       float64           `json:"ratio"`
			Enabled     *bool             `json:"enabled"`
			Tags        []string          `json:"tags"`
			Labels      map[string]string `json:"labels"`
			Extra       any               `json:"extra-vars"`
			Raw         json.RawMessage   `json:"raw"`
			Limit       ownDecoding       `json:"limit"`
			StartsAt    time.Time         `json:"starts-at"`
			Count       int64             `json:"count,string"`
			Internal    string            `json:"-"`
			unexported  string
			Untagged    string
			embeddedPaging
		} `json:"attributes" binding:"required"`
		Relationships *struct {
			Workspace struct {
				Data struct {
					ID   string `json:"id" binding:"required"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"workspace"`
		} `json:"relationships,omitempty"`
	} `json:"data" binding:"required"`
}

type selfReferential struct {
	Name     string            `json:"name"`
	Children []selfReferential `json:"children"`
}

func TestSchemaForType(t *testing.T) {
	root := SchemaForType(reflect.TypeOf(createThingRequest{}))

	if root.Type != "object" {
		t.Fatalf("a struct is an object, got %q", root.Type)
	}
	if !reflect.DeepEqual(root.Required, []string{"data"}) {
		t.Fatalf("required at the root = %v, want [data]", root.Required)
	}
	data := root.Properties["data"]
	if data == nil || data.Type != "object" {
		t.Fatalf("an inline struct member is an object, got %+v", data)
	}
	if !reflect.DeepEqual(data.Required, []string{"attributes"}) {
		t.Fatalf("required under data = %v, want [attributes]", data.Required)
	}

	attrs := data.Properties["attributes"]
	if attrs == nil {
		t.Fatal("attributes is missing")
	}
	if !reflect.DeepEqual(attrs.Required, []string{"name"}) {
		t.Fatalf("required attributes = %v, want [name]: only binding:\"required\" marks a member required", attrs.Required)
	}

	// Every JSON member of the type, by its JSON name, and nothing the decoder ignores.
	wantMembers := []string{
		"name", "description", "inventory-type", "retries", "ratio", "enabled", "tags", "labels",
		"extra-vars", "raw", "limit", "starts-at", "count", "Untagged", "page", "size",
	}
	for _, m := range wantMembers {
		if attrs.Properties[m] == nil {
			t.Errorf("member %q is missing from the schema", m)
		}
	}
	for _, m := range []string{"Internal", "-", "unexported", "embeddedPaging"} {
		if attrs.Properties[m] != nil {
			t.Errorf("%q is not a JSON member of the type and must not be in the schema", m)
		}
	}
	if got := len(attrs.Properties); got != len(wantMembers) {
		t.Errorf("attributes has %d members, want %d: %v", got, len(wantMembers), memberNames(attrs))
	}

	checks := []struct {
		member string
		want   Schema
	}{
		{"name", Schema{Type: "string"}},
		{"inventory-type", Schema{Type: "string"}},
		{"retries", Schema{Type: "integer"}},
		{"ratio", Schema{Type: "number"}},
		{"enabled", Schema{Type: "boolean", Nullable: true}},
		{"tags", Schema{Type: "array", Items: &Schema{Type: "string"}}},
		{"starts-at", Schema{Type: "string", Format: "date-time"}},
		{"count", Schema{Type: "string"}},
		{"page", Schema{Type: "integer"}},
	}
	for _, c := range checks {
		got := attrs.Properties[c.member]
		if got == nil || !reflect.DeepEqual(*got, c.want) {
			t.Errorf("%s = %+v, want %+v", c.member, got, c.want)
		}
	}

	labels := attrs.Properties["labels"]
	if labels == nil || labels.Type != "object" || labels.AdditionalProperties == nil || !*labels.AdditionalProperties {
		t.Errorf("a map is an object with additional properties, got %+v", labels)
	}

	// Members whose shape the type does not state are listed without one, and say so, so the
	// recorder knows to describe them from the example it recorded instead.
	for _, m := range []string{"extra-vars", "raw", "limit"} {
		got := attrs.Properties[m]
		if got == nil {
			continue // reported above
		}
		if got.Type != "" || got.Properties != nil || got.Items != nil {
			t.Errorf("%s has a shape (%+v); a member typed any, json.RawMessage or with its own JSON decoding has none the type can state", m, got)
		}
		if !got.Opaque {
			t.Errorf("%s is not marked opaque", m)
		}
	}

	rel := data.Properties["relationships"]
	if rel == nil || !rel.Nullable || rel.Type != "object" {
		t.Fatalf("a pointer to a struct is a nullable object, got %+v", rel)
	}
	id := rel.Properties["workspace"].Properties["data"]
	if !reflect.DeepEqual(id.Required, []string{"id"}) {
		t.Errorf("required three levels down = %v, want [id]", id.Required)
	}
}

func TestSchemaForType_PointerRoot(t *testing.T) {
	// A handler passes a pointer to ShouldBindJSON, so the observed value is a pointer.
	got := SchemaForType(reflect.TypeOf(&createThingRequest{}))
	if got.Type != "object" || got.Properties["data"] == nil {
		t.Fatalf("a pointer to a request type describes the request type, got %+v", got)
	}
	if got.Nullable {
		t.Fatal("the root of a request body is not nullable just because the handler bound a pointer")
	}
}

func TestSchemaForType_Recursive(t *testing.T) {
	// A type that contains itself must terminate, and the inner occurrence stays an object.
	got := SchemaForType(reflect.TypeOf(selfReferential{}))
	children := got.Properties["children"]
	if children == nil || children.Type != "array" || children.Items == nil || children.Items.Type != "object" {
		t.Fatalf("children = %+v, want an array of objects", children)
	}
}

func TestSchemaForType_UntypedMap(t *testing.T) {
	// A handler that binds a map has no members to list.
	got := SchemaForType(reflect.TypeOf(map[string]any{}))
	if got.Type != "object" || got.Properties != nil || !got.Opaque {
		t.Fatalf("an untyped map is an opaque object, got %+v", got)
	}
}

func TestSchemaJSON_OmitsTheOpaqueMarker(t *testing.T) {
	// Opaque is the recorder's signal, not part of the published document.
	raw, err := json.Marshal(SchemaForType(reflect.TypeOf(createThingRequest{})))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "opaque") {
		t.Fatalf("the opaque marker leaked into the JSON: %s", raw)
	}
}

func TestSchemaForValue(t *testing.T) {
	var v any
	raw := `{"name":"x","count":3,"ratio":1.5,"on":true,"none":null,"id":"<uuid>","at":"<timestamp>",
		"list":[{"a":1},{"b":"two"}],"empty":[],"nested":{"k":"v"}}`
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	got := SchemaForValue(v)
	want := map[string]Schema{
		"name":  {Type: "string"},
		"count": {Type: "integer"},
		"ratio": {Type: "number"},
		"on":    {Type: "boolean"},
		"none":  {Nullable: true},
		"id":    {Type: "string", Format: "uuid"},
		"at":    {Type: "string", Format: "date-time"},
	}
	for name, w := range want {
		g := got.Properties[name]
		if g == nil || !reflect.DeepEqual(*g, w) {
			t.Errorf("%s = %+v, want %+v", name, g, w)
		}
	}
	// An array's item schema is the union of its elements, so an optional member of one
	// element does not vanish because the first element lacked it.
	items := got.Properties["list"].Items
	if items == nil || items.Properties["a"] == nil || items.Properties["b"] == nil {
		t.Errorf("list items = %+v, want the union of both elements' members", items)
	}
	if e := got.Properties["empty"]; e == nil || e.Type != "array" || e.Items != nil {
		t.Errorf("an empty array says nothing about its items, got %+v", e)
	}
	if n := got.Properties["nested"]; n == nil || n.Type != "object" || n.Properties["k"] == nil {
		t.Errorf("nested = %+v", n)
	}
}

func TestFillOpaque(t *testing.T) {
	// The type lists the members; the example describes only the ones the type could not.
	s := SchemaForType(reflect.TypeOf(createThingRequest{}))
	var example any
	raw := `{"data":{"type":"things","attributes":{"name":"n","labels":{"team":"core"},"extra-vars":{"region":"eu","replicas":2},"limit":["a","b"]}}}`
	if err := json.Unmarshal([]byte(raw), &example); err != nil {
		t.Fatal(err)
	}
	FillOpaque(s, example)

	attrs := s.Properties["data"].Properties["attributes"]
	extra := attrs.Properties["extra-vars"]
	if extra.Type != "object" || extra.Properties["region"] == nil || extra.Properties["replicas"].Type != "integer" {
		t.Errorf("extra-vars was not described from the example: %+v", extra)
	}
	limit := attrs.Properties["limit"]
	if limit.Type != "array" || limit.Items == nil || limit.Items.Type != "string" {
		t.Errorf("limit was not described from the example: %+v", limit)
	}
	// A member the type states is left exactly as the type states it, whatever the example sent.
	if name := attrs.Properties["name"]; !reflect.DeepEqual(*name, Schema{Type: "string"}) {
		t.Errorf("name changed: %+v", name)
	}
	// An opaque member the example did not send stays listed, without a shape.
	if rawMember := attrs.Properties["raw"]; rawMember == nil || rawMember.Type != "" {
		t.Errorf("raw = %+v, want it listed with no shape", rawMember)
	}
	// A map keeps what its type says, an object with any members: the keys one example carried
	// are not its members.
	if labels := attrs.Properties["labels"]; labels.Properties != nil || labels.AdditionalProperties == nil {
		t.Errorf("labels took the example's keys as its members: %+v", labels)
	}
	untyped := SchemaForType(reflect.TypeOf(map[string]any{}))
	FillOpaque(untyped, map[string]any{"release": "1.4.2"})
	if untyped.Properties != nil || untyped.AdditionalProperties == nil {
		t.Errorf("an untyped map took the example's keys as its members: %+v", untyped)
	}
	// And every member the type declares is still there.
	if attrs.Properties["description"] == nil || attrs.Properties["tags"] == nil {
		t.Error("FillOpaque dropped members the example did not send")
	}
}

func memberNames(s *Schema) []string {
	out := make([]string, 0, len(s.Properties))
	for k := range s.Properties {
		out = append(out, k)
	}
	return out
}
