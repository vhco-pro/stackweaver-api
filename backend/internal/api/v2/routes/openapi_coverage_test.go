// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The OpenAPI document must describe the API the router actually serves (#755, AC6/AC9).
//
// The document is generated from a committed route manifest and committed fixtures, which is
// fast and reproducible but is one step removed from the running server. These tests close that
// gap by building the real router and comparing: an operation the router does not serve is a
// lie, and a route with no operation is a hole a client generator will never fill.
//
//	go test -tags integration ./internal/api/v2/routes/ -run TestOpenAPI

//go:build integration
// +build integration

package routes_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type openAPIDoc struct {
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

// ginToOpenAPI mirrors the generator: gin writes :name and *name, OpenAPI writes {name}.
func ginToOpenAPI(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") || strings.HasPrefix(s, "*") {
			segs[i] = "{" + strings.TrimLeft(s, ":*") + "}"
		}
	}
	return strings.Join(segs, "/")
}

func loadSpec(t *testing.T, repoRoot string) openAPIDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "backend/internal/api/v2/openapi/spec.json"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var doc openAPIDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	return doc
}

func buildRealRouter(t *testing.T) *gin.Engine {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	if os.Getenv("DEV_INSECURE_KEY") == "" {
		t.Setenv("DEV_INSECURE_KEY", "1")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	gin.SetMode(gin.TestMode)
	// The full router, not just its v2 half - the same one the golden harness records and the
	// server serves. Building only SetupV2Routes here made these tests agree with a document
	// that was itself missing 59 routes, so neither the "covers everything" nor the "invents
	// nothing" direction could see the gap (#790).
	return buildHarnessRouter(t, db, nil)
}

// TestOpenAPICoversEveryRegisteredRoute is AC6.
func TestOpenAPICoversEveryRegisteredRoute(t *testing.T) {
	repoRoot, err := filepath.Abs("../../../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	doc := loadSpec(t, repoRoot)
	r := buildRealRouter(t)

	documented := map[string]bool{}
	for path, methods := range doc.Paths {
		for method := range methods {
			documented[strings.ToUpper(method)+" "+path] = true
		}
	}

	var missing []string
	registered := 0
	for _, rt := range r.Routes() {
		registered++
		if !documented[rt.Method+" "+ginToOpenAPI(rt.Path)] {
			missing = append(missing, rt.Method+" "+rt.Path)
		}
	}
	sort.Strings(missing)

	if registered == 0 {
		t.Fatal("router registered no routes")
	}
	if len(missing) > 0 {
		t.Errorf("%d registered route(s) have no operation in the OpenAPI document - a client "+
			"generated from it would not know they exist:\n  %s\n\nRegenerate with: go run ./cmd/openapi-gen",
			len(missing), strings.Join(missing, "\n  "))
	}
	t.Logf("%d registered routes, all documented", registered)
}

// TestOpenAPIInventsNoRoutes is the other direction: an operation for an endpoint nobody serves
// sends a client generator off to build calls that 404.
func TestOpenAPIInventsNoRoutes(t *testing.T) {
	repoRoot, err := filepath.Abs("../../../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	doc := loadSpec(t, repoRoot)
	r := buildRealRouter(t)

	real := map[string]bool{}
	for _, rt := range r.Routes() {
		real[rt.Method+" "+ginToOpenAPI(rt.Path)] = true
	}

	var invented []string
	for path, methods := range doc.Paths {
		for method := range methods {
			if !real[strings.ToUpper(method)+" "+path] {
				invented = append(invented, strings.ToUpper(method)+" "+path)
			}
		}
	}
	sort.Strings(invented)
	if len(invented) > 0 {
		t.Errorf("the OpenAPI document describes %d operation(s) the router does not serve:\n  %s",
			len(invented), strings.Join(invented, "\n  "))
	}
}

// TestOpenAPIDocumentIsCurrent is AC9: the committed artifact must equal what the generator
// produces, and the two committed copies must be byte-identical to each other.
func TestOpenAPIDocumentIsCurrent(t *testing.T) {
	repoRoot, err := filepath.Abs("../../../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	cmd := exec.Command("go", "run", "./cmd/openapi-gen", "-check")
	cmd.Dir = filepath.Join(repoRoot, "backend")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("the committed OpenAPI document is out of date:\n%s", out)
	}

	embedded, err := os.ReadFile(filepath.Join(repoRoot, "backend/internal/api/v2/openapi/spec.json"))
	if err != nil {
		t.Fatalf("read embedded spec: %v", err)
	}
	published, err := os.ReadFile(filepath.Join(repoRoot, "docs/api-reference/openapi.json"))
	if err != nil {
		t.Fatalf("read published spec: %v", err)
	}
	if string(embedded) != string(published) {
		t.Error("the embedded spec and the published docs copy differ; a reader of the docs site " +
			"would be looking at a different API than the server serves")
	}
}
