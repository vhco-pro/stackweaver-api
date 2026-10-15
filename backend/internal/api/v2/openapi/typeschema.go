// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package openapi

import (
	"encoding"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"time"
)

// Schema is an OpenAPI 3.0 schema object: as much of one as the request side of the document
// needs.
type Schema struct {
	Type                 string             `json:"type,omitempty"`
	Format               string             `json:"format,omitempty"`
	Nullable             bool               `json:"nullable,omitempty"`
	Items                *Schema            `json:"items,omitempty"`
	Properties           map[string]*Schema `json:"properties,omitempty"`
	Required             []string           `json:"required,omitempty"`
	AdditionalProperties *bool              `json:"additionalProperties,omitempty"`

	// Opaque marks a value whose shape its Go type does not state: `any`, json.RawMessage, an
	// untyped map, or a type that decodes its own JSON. The golden write recorder (#869) reads it
	// to know where the recorded example is the only description there is. It is the recorder's
	// signal and not part of the published document, so it is never serialised.
	Opaque bool `json:"-"`
}

var (
	jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()
	timeType            = reflect.TypeFor[time.Time]()
	rawMessageType      = reflect.TypeFor[json.RawMessage]()
)

// SchemaForType describes the JSON a value of type t is decoded from.
//
// It exists so the document can list every member a handler accepts and not only the ones a
// recorded example happened to send. The golden write recorder observes the value a handler
// binds, hands its type here, and commits the result with the fixture; the generator copies it.
//
// It reads what encoding/json reads: exported fields under their `json` name, embedded structs
// flattened, `json:"-"` skipped. A member is required only when its field carries
// `binding:"required"`, which is the one requirement the type states; a rule the handler
// enforces in code is not visible here.
//
// Where the type does not state a shape, the schema does not invent one: such a member is
// returned with no type and Opaque set.
func SchemaForType(t reflect.Type) *Schema {
	// A handler binds through a pointer. The request body it describes is not nullable for that.
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return schemaFor(t, map[reflect.Type]bool{})
}

func schemaFor(t reflect.Type, inProgress map[reflect.Type]bool) *Schema {
	if t.Kind() == reflect.Pointer {
		s := schemaFor(t.Elem(), inProgress)
		s.Nullable = true
		return s
	}

	switch {
	case t == timeType:
		return &Schema{Type: "string", Format: "date-time"}
	case t == rawMessageType:
		return &Schema{Opaque: true}
	case decodesItself(t):
		// The wire form is whatever its UnmarshalJSON or UnmarshalText accepts, which the
		// type's fields say nothing about.
		return &Schema{Opaque: true}
	}

	switch t.Kind() {
	case reflect.String:
		return &Schema{Type: "string"}
	case reflect.Bool:
		return &Schema{Type: "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return &Schema{Type: "integer"}
	case reflect.Float32, reflect.Float64:
		return &Schema{Type: "number"}
	case reflect.Interface:
		return &Schema{Opaque: true}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			// encoding/json decodes []byte from a base64 string.
			return &Schema{Type: "string", Format: "byte"}
		}
		return &Schema{Type: "array", Items: schemaFor(t.Elem(), inProgress)}
	case reflect.Map:
		yes := true
		s := &Schema{Type: "object", AdditionalProperties: &yes}
		if t.Elem().Kind() == reflect.Interface {
			// map[string]any: an object, with members the type does not name.
			s.Opaque = true
		}
		return s
	case reflect.Struct:
		return structSchema(t, inProgress)
	case reflect.Invalid, reflect.Uintptr, reflect.Complex64, reflect.Complex128, reflect.Chan,
		reflect.Func, reflect.Pointer, reflect.UnsafePointer:
		// Nothing encoding/json decodes into (a pointer is unwrapped above). Listed so that a
		// kind added to the language is a compile-time question here, not a silent default.
		return &Schema{Opaque: true}
	default:
		return &Schema{Opaque: true}
	}
}

// decodesItself reports whether values of t are decoded by a method of their own.
func decodesItself(t reflect.Type) bool {
	p := reflect.PointerTo(t)
	return t.Implements(jsonUnmarshalerType) || p.Implements(jsonUnmarshalerType) ||
		t.Implements(textUnmarshalerType) || p.Implements(textUnmarshalerType)
}

func structSchema(t reflect.Type, inProgress map[reflect.Type]bool) *Schema {
	s := &Schema{Type: "object"}
	if inProgress[t] {
		// A type that contains itself: the inner occurrence is an object, and stops there.
		return s
	}
	inProgress[t] = true
	defer delete(inProgress, t)

	s.Properties = map[string]*Schema{}
	collectFields(t, s, inProgress)
	sort.Strings(s.Required)
	if len(s.Properties) == 0 {
		s.Properties = nil
	}
	return s
}

// collectFields adds t's JSON members to s, flattening embedded structs the way encoding/json does.
func collectFields(t reflect.Type, s *Schema, inProgress map[reflect.Type]bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}

		if f.Anonymous && name == "" {
			et := f.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct && !decodesItself(et) {
				collectFields(et, s, inProgress)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}

		member := schemaFor(f.Type, inProgress)
		if hasOption(opts, "string") && (member.Type == "integer" || member.Type == "number" || member.Type == "boolean") {
			// `json:",string"`: the value travels as a JSON string.
			member = &Schema{Type: "string", Nullable: member.Nullable}
		}
		s.Properties[name] = member

		if hasOption(f.Tag.Get("binding"), "required") {
			s.Required = append(s.Required, name)
		}
	}
}

// SchemaForValue describes a decoded JSON value by its shape.
//
// It is the fallback for what a type cannot say: a body a handler decodes by hand or binds into
// a map, and the members FillOpaque completes. The result describes one example, so a member the
// example did not send is absent; callers say so in the document.
//
// The golden harness replaces volatile values with placeholders before a value gets here, and
// those are carried through as formats, so the schema says "a UUID" and not "the string <uuid>".
func SchemaForValue(v any) *Schema {
	switch t := v.(type) {
	case map[string]any:
		s := &Schema{Type: "object"}
		if len(t) == 0 {
			yes := true
			s.AdditionalProperties = &yes
			return s
		}
		s.Properties = make(map[string]*Schema, len(t))
		for k, val := range t {
			s.Properties[k] = SchemaForValue(val)
		}
		return s
	case []any:
		s := &Schema{Type: "array"}
		for _, el := range t {
			s.Items = mergeValueSchemas(s.Items, SchemaForValue(el))
		}
		return s
	case string:
		switch t {
		case "<timestamp>":
			return &Schema{Type: "string", Format: "date-time"}
		case "<uuid>":
			return &Schema{Type: "string", Format: "uuid"}
		}
		return &Schema{Type: "string"}
	case bool:
		return &Schema{Type: "boolean"}
	case float64:
		if t == float64(int64(t)) {
			return &Schema{Type: "integer"}
		}
		return &Schema{Type: "number"}
	case nil:
		return &Schema{Nullable: true}
	default:
		return &Schema{}
	}
}

// mergeValueSchemas is the union of two element schemas of one array.
func mergeValueSchemas(a, b *Schema) *Schema {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case a.Type == "" && a.Nullable:
		b.Nullable = true
		return b
	case b.Type == "" && b.Nullable:
		a.Nullable = true
		return a
	case a.Type != b.Type:
		return &Schema{} // elements of different kinds: say nothing rather than something false
	case a.Type == "object":
		if a.Properties == nil {
			a.Properties = map[string]*Schema{}
		}
		for k, v := range b.Properties {
			a.Properties[k] = mergeValueSchemas(a.Properties[k], v)
		}
		if len(a.Properties) > 0 {
			a.AdditionalProperties = nil
		}
		return a
	case a.Type == "array":
		a.Items = mergeValueSchemas(a.Items, b.Items)
		return a
	default:
		return a
	}
}

// FillOpaque completes a schema built from a type with what a recorded example shows, at the
// places the type left without a shape and nowhere else.
//
// A member the type states stays exactly as the type states it, and a member the example did
// not send stays listed. Only an Opaque node with no type and a value in the example changes: it
// takes the shape of that value.
//
// An untyped map is Opaque too and is left alone. Its type already says everything there is to
// say, an object with members of the caller's choosing, and replacing that with the keys one
// example happened to carry would publish them as if they were the members.
func FillOpaque(s *Schema, example any) {
	if s == nil || example == nil {
		return
	}
	if s.Opaque && s.Type == "" {
		filled := SchemaForValue(example)
		filled.Nullable = filled.Nullable || s.Nullable
		*s = *filled
		return
	}
	switch ex := example.(type) {
	case map[string]any:
		for name, member := range s.Properties {
			if val, ok := ex[name]; ok {
				FillOpaque(member, val)
			}
		}
	case []any:
		for _, el := range ex {
			FillOpaque(s.Items, el)
		}
	}
}

// hasOption reports whether a comma-separated tag value carries opt.
func hasOption(tagValue, opt string) bool {
	for _, o := range strings.Split(tagValue, ",") {
		if strings.TrimSpace(o) == opt {
			return true
		}
	}
	return false
}
