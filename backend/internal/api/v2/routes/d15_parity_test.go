// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The D15 parity table of the runner architecture spec (#933, AC66), held against the real route
// table, the org wall registry, the OpenAPI document and the golden fixtures. Every capability
// the table lists exists in /api/v2 first: the route is registered, classified in the org wall as
// the table says, answers JSON:API (its recorded golden response is a JSON:API document) and
// carries the attributes the table names. A row removed from the router, reclassified or turned
// into a non-JSON:API answer fails here, not in a customer's automation.

//go:build integration
// +build integration

package routes_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	v2routes "github.com/michielvha/stackweaver/backend/internal/api/v2/routes"
	"github.com/michielvha/stackweaver/core/dbtest"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// d15Route is one route of the D15 table. class is the org wall classification the table
// names; flatJSON marks the runner control plane, which exchanges flat JSON by design and
// reports errors in the JSON:API error document.
type d15Route struct {
	method, path, class string
	flatJSON            bool
}

var d15Routes = []d15Route{
	// Run images per organization (D6).
	{"GET", "/api/v2/organizations/:name/run-images", "org-by-name", false},
	{"POST", "/api/v2/organizations/:name/run-images", "org-by-name", false},
	{"GET", "/api/v2/run-images/:id", "resource:id", false},
	{"PATCH", "/api/v2/run-images/:id", "resource:id", false},
	{"DELETE", "/api/v2/run-images/:id", "resource:id", false},
	// The registry credential is a type on the existing Ansible credentials routes (D6).
	{"POST", "/api/v2/organizations/:name/ansible/credentials", "org-by-name", false},
	{"PATCH", "/api/v2/ansible/credentials/:id", "resource:id", false},
	// Effective settings with the level each came from (D0).
	{"GET", "/api/v2/workspaces/:id/effective-settings", "resource:id", false},
	{"GET", "/api/v2/ansible/job-templates/:id/effective-settings", "resource:id", false},
	{"GET", "/api/v2/ansible/inventory-sources/:source_id/effective-settings", "resource:source_id", false},
	// Identity bindings per pool (D8).
	{"GET", "/api/v2/agent-pools/:id/identity-bindings", "resource:id", false},
	{"POST", "/api/v2/agent-pools/:id/identity-bindings", "resource:id", false},
	{"GET", "/api/v2/identity-bindings/:id", "resource:id", false},
	{"PATCH", "/api/v2/identity-bindings/:id", "resource:id", false},
	{"DELETE", "/api/v2/identity-bindings/:id", "resource:id", false},
	// Registry pull Secrets per pool (D8).
	{"GET", "/api/v2/agent-pools/:id/pull-secrets", "resource:id", false},
	{"POST", "/api/v2/agent-pools/:id/pull-secrets", "resource:id", false},
	{"GET", "/api/v2/pull-secrets/:id", "resource:id", false},
	{"PATCH", "/api/v2/pull-secrets/:id", "resource:id", false},
	{"DELETE", "/api/v2/pull-secrets/:id", "resource:id", false},
	// Pool settings, the hosted cap and placement group (D7, D9).
	{"PATCH", "/api/v2/agent-pools/:id", "resource:id", false},
	// Hosted capacity per organization (D9).
	{"GET", "/api/v2/organizations/:name/hosted-capacity", "org-by-name", false},
	// Deployment-level settings, read-only on the platform administrator spec's resource (D0).
	{"GET", "/api/v2/platform/settings", "agnostic", false},
	// Queue depth, JIT registration token and drain (D11).
	{"GET", "/api/v2/agent-pools/:id/queue-depth", "agnostic", false},
	{"POST", "/api/v2/agent-pools/:id/jit-token", "agnostic", false},
	{"POST", "/api/v2/runner/drain", "agnostic", true},
	{"POST", "/api/v2/runners/:id/actions/drain", "resource:id", false},
	// Work items (D2).
	{"GET", "/api/v2/organizations/:name/work-items", "org-by-name", false},
	{"GET", "/api/v2/work-items/:id", "resource:id", false},
	// The placement record beside the run, which keeps the TFE run resource unchanged (D4, D13).
	{"GET", "/api/v2/runs/:id/placement", "resource:id", false},
}

// d15Attributes are the attributes the table puts on existing routes, by OpenAPI operation.
var d15Attributes = map[string][]string{
	"patch /api/v2/workspaces/{id}":                             {"run-image-id", "identity-binding-id", "run-timeout"},
	"patch /api/v2/ansible/job-templates/{id}":                  {"run-image-id", "identity-binding-id", "timeout-seconds"},
	"patch /api/v2/ansible/inventory-sources/{source_id}":       {"run-image-id", "identity-binding-id", "sync-timeout"},
	"patch /api/v2/projects/{id}":                               {"tofu-run-image-id", "ansible-run-image-id", "identity-binding-id", "run-timeout"},
	"patch /api/v2/organizations/{name}":                        {"tofu-run-image-id", "ansible-run-image-id", "identity-binding-id", "run-timeout", "cache-size-limit"},
	"patch /api/v2/agent-pools/{id}":                            {"keep-failed-jobs-for", "cpu-limit", "memory-limit", "limits-required", "local-readthrough", "max-concurrent-jobs", "placement-group"},
	"get /api/v2/agent-pools/{id}/queue-depth":                  {"pending-by-engine", "capacity", "in-flight", "headroom"},
	"get /api/v2/platform/settings":                             {"deployment"},
	"get /api/v2/ansible/jobs/{id}":                             {"queue-reason", "placement"},
	"get /api/v2/work-items/{id}":                               {"queue-reason", "placement", "kind"},
	"get /api/v2/organizations/{name}/hosted-capacity":          {"queue-reason", "placement-group"},
	"get /api/v2/workspaces/{id}/effective-settings":            {"level"},
	"get /api/v2/ansible/job-templates/{id}/effective-settings": {"level"},
}

func TestD15Parity_EveryRowIsRoutedClassifiedAndJSONAPI(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	t.Setenv("DEV_INSECURE_KEY", "1")
	db, err := dbtest.Open(t, dbURL, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2routes.SetupV2Routes(r, db, nil, nil)

	registered := map[string]bool{}
	for _, rt := range r.Routes() {
		registered[rt.Method+" "+rt.Path] = true
	}

	for _, row := range d15Routes {
		key := row.method + " " + row.path
		if !registered[key] {
			t.Errorf("%s: the D15 route is not registered", key)
			continue
		}
		if got := middleware.WallClass(row.path); got != row.class {
			t.Errorf("%s: org wall class %q, the D15 table says %q", key, got, row.class)
		}
		body, status, found := goldenBody(t, goldenDir, row.method, row.path)
		if !found {
			t.Errorf("%s: no golden fixture records its response", key)
			continue
		}
		if row.flatJSON || status == 202 && body == nil || status == 204 {
			continue
		}
		if status >= 300 {
			t.Errorf("%s: the golden fixture records a %d, not the route's success answer", key, status)
			continue
		}
		if !isJSONAPIDocument(body) {
			t.Errorf("%s: the recorded %d response is not a JSON:API document", key, status)
		}
	}
}

func TestD15Parity_TheTablesAttributesAreInTheAPI(t *testing.T) {
	var doc struct {
		Paths      map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	readJSON(t, filepath.Join(repoRootDir(t), "backend/internal/api/v2/openapi/spec.json"), &doc)

	for op, attrs := range d15Attributes {
		method, path, _ := strings.Cut(op, " ")
		operation, ok := doc.Paths[path][method]
		if !ok {
			t.Errorf("%s: no such operation in the OpenAPI document", op)
			continue
		}
		names := map[string]bool{}
		collectProperties(operation, doc.Components.Schemas, map[string]bool{}, names)
		for _, a := range attrs {
			if !names[a] {
				t.Errorf("%s: the D15 attribute %q is not in its request or response schema", op, a)
			}
		}
	}
}

// collectProperties gathers every property name under v, following component references once.
func collectProperties(v any, schemas map[string]any, seen, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok {
			name := ref[strings.LastIndex(ref, "/")+1:]
			if !seen[name] {
				seen[name] = true
				collectProperties(schemas[name], schemas, seen, out)
			}
		}
		if props, ok := x["properties"].(map[string]any); ok {
			for name := range props {
				out[name] = true
			}
		}
		for _, child := range x {
			collectProperties(child, schemas, seen, out)
		}
	case []any:
		for _, child := range x {
			collectProperties(child, schemas, seen, out)
		}
	}
}

// repoRootDir is the repository root, five levels above this package.
func repoRootDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../../../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	return root
}

// goldenBody returns the recorded body and status of a route: the read fixture for a GET, the
// write fixture otherwise.
func goldenBody(t *testing.T, dir, method, path string) (body any, status int, found bool) {
	t.Helper()
	name := strings.ToLower(method) + "_" + strings.ReplaceAll(strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "_"), ":", "") + ".json"
	file := filepath.Join(dir, name)
	if method != "GET" {
		file = filepath.Join(dir, "writes", name)
	}
	raw, err := os.ReadFile(file) //nolint:gosec // a fixture path built from the table above
	if err != nil {
		return nil, 0, false
	}
	// A read fixture records the body under "body", a write fixture under "response".
	var fixture struct {
		Status   int `json:"status"`
		Body     any `json:"body"`
		Response any `json:"response"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	if fixture.Body == nil {
		fixture.Body = fixture.Response
	}
	return fixture.Body, fixture.Status, true
}

// isJSONAPIDocument reports whether body is a JSON:API document whose primary data is one
// resource object or a list of them, each with a type and an id.
func isJSONAPIDocument(body any) bool {
	m, ok := body.(map[string]any)
	if !ok {
		return false
	}
	resource := func(v any) bool {
		r, ok := v.(map[string]any)
		if !ok {
			return false
		}
		_, hasType := r["type"].(string)
		_, hasID := r["id"].(string)
		return hasType && hasID
	}
	switch data := m["data"].(type) {
	case map[string]any:
		return resource(data)
	case []any:
		for _, item := range data {
			if !resource(item) {
				return false
			}
		}
		return true
	}
	return false
}
