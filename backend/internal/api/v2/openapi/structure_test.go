// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package openapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// TestDocumentIsWellFormed checks the committed document the way a client generator meets it
// (#869, AC7): every reference leads somewhere, and nothing that claims to carry a body leaves
// the reader without either a schema or a sentence saying why there is none.
//
// The explorer and a generated client both fail quietly on a dangling `$ref`: the one renders
// an empty box, the other an untyped value. Neither reports it, so this does.
func TestDocumentIsWellFormed(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]struct {
			Description string `json:"description"`
			RequestBody *struct {
				Description string                    `json:"description"`
				Content     map[string]map[string]any `json:"content"`
			} `json:"requestBody"`
			Responses map[string]struct {
				Description string                    `json:"description"`
				Content     map[string]map[string]any `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(Spec, &doc); err != nil {
		t.Fatalf("embedded spec is not JSON: %v", err)
	}

	var problems []string
	say := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	// Every $ref anywhere in the document, the ones inside components included.
	var generic any
	if err := json.Unmarshal(Spec, &generic); err != nil {
		t.Fatal(err)
	}
	refs := map[string]bool{}
	collectRefs(generic, refs)
	if len(refs) == 0 {
		t.Fatal("the document has no $ref at all; the walk is broken")
	}
	const prefix = "#/components/schemas/"
	for ref := range refs {
		name, ok := strings.CutPrefix(ref, prefix)
		if !ok {
			say("$ref %s does not point into components.schemas", ref)
			continue
		}
		if _, defined := doc.Components.Schemas[name]; !defined {
			say("$ref %s points at a schema that is not defined", ref)
		}
	}

	bodies, responses := 0, 0
	for path, methods := range doc.Paths {
		for method, op := range methods {
			where := strings.ToUpper(method) + " " + path
			if rb := op.RequestBody; rb != nil {
				bodies++
				if len(rb.Content) == 0 {
					say("%s: requestBody has no media type", where)
				}
				for mediaType, media := range rb.Content {
					if len(asMap(media["schema"])) == 0 && strings.TrimSpace(rb.Description) == "" {
						say("%s: requestBody %s has no schema and no description saying why", where, mediaType)
					}
				}
			}
			if len(op.Responses) == 0 {
				say("%s: no responses", where)
			}
			for code, resp := range op.Responses {
				responses++
				if len(resp.Content) == 0 {
					// A response with no body, or one that was not recorded: the description
					// is all there is, so it has to be there.
					if strings.TrimSpace(resp.Description) == "" {
						say("%s -> %s: no content and no description saying why", where, code)
					}
					continue
				}
				for mediaType, media := range resp.Content {
					if len(asMap(media["schema"])) == 0 {
						say("%s -> %s %s: no schema", where, code, mediaType)
					}
				}
			}
		}
	}
	if bodies == 0 {
		say("no operation in the document has a requestBody; the write side is missing")
	}
	if responses == 0 {
		t.Fatal("no responses in the document")
	}

	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("%d problem(s) in the committed document:\n  %s", len(problems), strings.Join(problems[:min(len(problems), 25)], "\n  "))
	}
}

func collectRefs(v any, into map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if ref, ok := val.(string); ok && k == "$ref" {
				into[ref] = true
				continue
			}
			collectRefs(val, into)
		}
	case []any:
		for _, val := range t {
			collectRefs(val, into)
		}
	}
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// TestEveryJSONBodyIsADocumentRefusesFlatShapes drives the guard over synthetic documents, so
// that the rule is proven to fail where it must and not only to pass on today's tree (#858,
// D12 Guard 1). Every failure names the guideline, because that page is where an agent who
// trips the guard learns the rule.
func TestEveryJSONBodyIsADocumentRefusesFlatShapes(t *testing.T) {
	const guideline = "docs/internal/guidelines/api/json-api-everywhere.md"
	op := func(path, method, opJSON string) []byte {
		return []byte(`{"paths": {"` + path + `": {"` + method + `": ` + opJSON + `}}, "components": {"schemas": {
			"flat-request": {"type": "object", "properties": {"description": {"type": "string"}}},
			"doc-request": {"type": "object", "required": ["data"], "properties": {"data": {"type": "object", "properties": {"type": {"type": "string"}, "attributes": {"type": "object"}}}}},
			"message": {"type": "object", "properties": {"message": {"type": "string"}}},
			"strings": {"type": "object", "properties": {"data": {"type": "array", "items": {"type": "string"}}, "meta": {"type": "object"}}},
			"resource": {"type": "object", "properties": {"data": {"type": "object", "properties": {"type": {"type": "string"}, "id": {"type": "string"}}}}},
			"meta-only": {"type": "object", "properties": {"meta": {"type": "object"}}}
		}}}`)
	}
	ok := `{"description": "Success", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/resource"}}}}`
	tests := []struct {
		name    string
		spec    []byte
		wantErr string // empty: the operation passes
	}{
		{
			name:    "a flat request schema",
			spec:    op("/api/v2/tokens", "post", `{"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/flat-request"}}}}, "responses": {"201": `+ok+`}}`),
			wantErr: "POST /api/v2/tokens: the request body is not a JSON:API document",
		},
		{
			name:    "a message success body",
			spec:    op("/api/v2/widgets/{id}/actions/enable", "post", `{"description": "Takes no request body.", "responses": {"200": {"description": "Success", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/message"}}}}}}`),
			wantErr: "POST /api/v2/widgets/{id}/actions/enable -> 200: the success body is not a JSON:API document",
		},
		{
			name:    "strings under data",
			spec:    op("/api/v2/widgets", "get", `{"responses": {"200": {"description": "Success", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/strings"}}}}}}`),
			wantErr: "GET /api/v2/widgets -> 200: the success body is not a JSON:API document",
		},
		{
			name:    "a mutating operation that is neither a document nor the generator's sentence",
			spec:    op("/api/v2/widgets", "post", `{"description": "Creates a widget.", "responses": {"201": `+ok+`}}`),
			wantErr: "POST /api/v2/widgets: no request body is described and the description is not the generator's",
		},
		{
			name: "a document request and a resource response",
			spec: op("/api/v2/widgets", "post", `{"requestBody": {"content": {"application/vnd.api+json": {"schema": {"$ref": "#/components/schemas/doc-request"}}}}, "responses": {"201": `+ok+`}}`),
		},
		{
			name: "a meta-only response",
			spec: op("/api/v2/widgets/{id}/install", "get", `{"responses": {"200": {"description": "Success", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/meta-only"}}}}}}`),
		},
		{
			name: "a 204 and the generator's no-body sentence",
			spec: op("/api/v2/widgets/{id}", "delete", `{"description": "Takes no request body.", "responses": {"204": {"description": "Success. No content."}}}`),
		},
		{
			name: "an operation outside /api/v2 is not judged",
			spec: op("/v1/modules", "get", `{"responses": {"200": {"description": "Success", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/message"}}}}}}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems, err := jsonBodyProblems(tt.spec, map[string]string{})
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantErr == "" {
				if len(problems) != 0 {
					t.Errorf("want no problem, got %q", problems)
				}
				return
			}
			if len(problems) != 1 || !strings.Contains(problems[0], tt.wantErr) {
				t.Fatalf("want one problem containing %q, got %q", tt.wantErr, problems)
			}
			if !strings.Contains(problems[0], guideline) {
				t.Errorf("the problem does not name the guideline %s: %q", guideline, problems[0])
			}
		})
	}

	// The list is exact: an entry that matches no operation fails.
	flat := op("/api/v2/tokens", "post", `{"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/flat-request"}}}}, "responses": {"201": `+ok+`}}`)
	problems, err := jsonBodyProblems(flat, map[string]string{"GET /api/v2/nothing": "stale", "POST /api/v2/tokens": "a protocol"})
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "byDesign entry GET /api/v2/nothing matches no operation") {
		t.Errorf("a stale byDesign entry: got %q", problems)
	}
}

// TestEveryJSONBodyIsADocument holds the request-and-response rule against the committed
// document (#858, D12 Guard 1): under /api/v2, a JSON request body is a JSON:API document, a
// 2xx JSON body holds resources under data or only meta, and a mutating operation with no
// described body says why in the generator's own words. The only operations it skips are the
// protocol surfaces in byDesign. The rule: docs/internal/guidelines/api/json-api-everywhere.md
func TestEveryJSONBodyIsADocument(t *testing.T) {
	problems, err := jsonBodyProblems(Spec, byDesign)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Errorf("%d operation(s) break the JSON:API rule:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
}

const jsonAPIGuideline = "docs/internal/guidelines/api/json-api-everywhere.md"

// The two sentences the generator writes for a mutating operation that has no requestBody
// (cmd/openapi-gen/writes.go, noBodyStatement and notRecordedStatement). Anything else in that
// place is a hand edit that silences the rule.
var generatorNoBodyPrefixes = []string{"Takes no request body.", "Not recorded:"}

// jsonBodyProblems judges every /api/v2 operation of an OpenAPI document. byDesign skips an
// operation, and an entry that matches none fails, so the list stays exact. Every problem names
// the guideline.
//
// What it checks is the D1 form, document against flat: a request has a data member that is an
// object or an array; a 2xx body has data holding resource objects (an object with type, or an
// array of them, or an array whose element was never recorded) or holds meta and no data. It
// does not check that data is marked required or that every resource carries an id: the
// existing documents that miss those are the near-misses #894 owns.
func jsonBodyProblems(spec []byte, byDesign map[string]string) ([]string, error) {
	var doc struct {
		Paths map[string]map[string]struct {
			Description string `json:"description"`
			RequestBody *struct {
				Content map[string]struct {
					Schema map[string]any `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
			Responses map[string]struct {
				Content map[string]struct {
					Schema map[string]any `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(spec, &doc); err != nil {
		return nil, fmt.Errorf("decoding the document: %w", err)
	}
	resolve := func(s map[string]any) map[string]any {
		if ref, ok := s["$ref"].(string); ok {
			return doc.Components.Schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
		}
		return s
	}
	props := func(s map[string]any) map[string]any { return asMap(s["properties"]) }
	isResource := func(s map[string]any) bool {
		if s["type"] != "object" {
			return false
		}
		p := props(s)
		// An element never recorded (an empty collection) has no properties to judge.
		if len(p) == 0 {
			return true
		}
		_, hasType := p["type"]
		return hasType
	}

	var problems []string
	seen := map[string]bool{}
	for path, methods := range doc.Paths {
		if !strings.HasPrefix(path, "/api/v2/") {
			continue
		}
		for method, op := range methods {
			key := strings.ToUpper(method) + " " + path
			seen[key] = true
			if _, skip := byDesign[key]; skip {
				continue
			}
			var found []string
			if rb := op.RequestBody; rb != nil {
				for mediaType, media := range rb.Content {
					if !strings.Contains(mediaType, "json") {
						continue
					}
					data := asMap(props(resolve(media.Schema))["data"])
					if data["type"] != "object" && data["type"] != "array" {
						found = append(found, fmt.Sprintf("%s: the request body is not a JSON:API document (no data member)", key))
					}
				}
			} else if method == "post" || method == "put" || method == "patch" || method == "delete" {
				said := false
				for _, prefix := range generatorNoBodyPrefixes {
					said = said || strings.HasPrefix(op.Description, prefix)
				}
				if !said {
					found = append(found, fmt.Sprintf("%s: no request body is described and the description is not the generator's (%q or %q)", key, generatorNoBodyPrefixes[0], generatorNoBodyPrefixes[1]))
				}
			}
			for code, resp := range op.Responses {
				if !strings.HasPrefix(code, "2") {
					continue
				}
				for mediaType, media := range resp.Content {
					if !strings.Contains(mediaType, "json") {
						continue
					}
					p := props(resolve(media.Schema))
					good := false
					if data, ok := p["data"]; ok {
						d := asMap(data)
						if d["type"] == "array" {
							good = isResource(asMap(d["items"]))
						} else {
							good = isResource(d)
						}
					} else {
						_, good = p["meta"]
					}
					if !good {
						found = append(found, fmt.Sprintf("%s -> %s: the success body is not a JSON:API document (resources under data, or meta alone)", key, code))
					}
				}
			}
			for _, f := range found {
				problems = append(problems, f+"; see "+jsonAPIGuideline)
			}
		}
	}
	for key := range byDesign {
		if !seen[key] {
			problems = append(problems, fmt.Sprintf("byDesign entry %s matches no operation; delete it (%s)", key, jsonAPIGuideline))
		}
	}
	sort.Strings(problems)
	return problems, nil
}
