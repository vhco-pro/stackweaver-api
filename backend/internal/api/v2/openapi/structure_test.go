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
