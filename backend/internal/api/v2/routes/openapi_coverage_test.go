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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/dbtest"
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
	db, err := dbtest.Open(t, dbURL, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	gin.SetMode(gin.TestMode)
	// The full router, not just its v2 half - the same one the golden harness records and the
	// server serves. Building only SetupV2Routes here made these tests agree with a document
	// that was itself missing 59 routes, so neither the "covers everything" nor the "invents
	// nothing" direction could see the gap (#790).
	return buildHarnessRouter(t, db, nil, identityFromEnv())
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

// What the published document says about a write. The generator has the same sentences; they
// are repeated here as text on purpose, so that rewording one is a decision made twice.
const (
	docNoBody      = "Takes no request body."
	docFromType    = "Described from the type the server decodes this body into"
	docFromExample = "Described from one accepted request rather than from a type"
	docBinary      = "A binary body."
	docNotRecorded = "Not recorded: a successful call "
)

// TestOpenAPIRequestBodies holds the published document to what was recorded about every write
// (#869, AC1, AC2, AC3, AC5).
//
// The generator copies write fixtures into the document, so this compares the two artifacts it
// does not own the relationship between: for each mutating route the server registers, the
// operation must describe its request and its success, or say in one of two fixed sentences why
// it does not. An operation that says nothing is the failure this exists for, because a reader
// cannot tell "takes no body" from "nobody wrote it down".
//
// It reads committed files and needs no service. It still runs only under the local switch, by
// the owner's decision that nothing about writes runs on GitHub.
func TestOpenAPIRequestBodies(t *testing.T) {
	if os.Getenv(envWritePhase) == "" {
		t.Skip(writePhaseSkipHelp)
	}
	repoRoot, err := filepath.Abs("../../../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	var doc struct {
		Paths      map[string]map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	readJSON(t, filepath.Join(repoRoot, "backend/internal/api/v2/openapi/spec.json"), &doc)
	var man routeManifest
	readJSON(t, filepath.Join(goldenDir, "routes.json"), &man)

	// resolve follows a {"$ref": ...} to the schema it names.
	resolve := func(v any) any {
		m, _ := v.(map[string]any)
		ref, _ := m["$ref"].(string)
		if ref == "" {
			return v
		}
		return doc.Components.Schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
	}
	reasons := []namedReason{needsOutsideSystem, needsAuthenticator, needsRunnerArtefact, needsInstanceSetting}

	var problems []string
	say := func(route, format string, args ...any) {
		problems = append(problems, route+": "+fmt.Sprintf(format, args...))
	}

	mutating := 0
	for _, rt := range man.Routes {
		route := rt.Method + " " + rt.Path
		op := doc.Paths[ginToOpenAPI(rt.Path)][strings.ToLower(rt.Method)]
		if op == nil {
			say(route, "has no operation in the document")
			continue
		}

		// AC5, for reads as much as writes: the Ansible API is found under ansible/ groups.
		if strings.Contains(rt.Path, "/ansible/") {
			tags, _ := op["tags"].([]any)
			if len(tags) != 1 || !strings.HasPrefix(fmt.Sprint(tags[0]), "ansible/") {
				say(route, "is grouped as %v, not under an ansible/ group", tags)
			}
		}
		if !rt.Mutating {
			continue
		}
		mutating++

		var fx map[string]any
		raw, err := os.ReadFile(writeFixturePath(route))
		if err != nil {
			say(route, "has no write fixture, so the document cannot describe it")
			continue
		}
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("parse %s: %v", writeFixturePath(route), err)
		}
		description, _ := op["description"].(string)
		body, _ := op["requestBody"].(map[string]any)

		if named, _ := fx["named"].(map[string]any); named != nil {
			matched := false
			for _, r := range reasons {
				matched = matched || strings.HasPrefix(description, docNotRecorded+string(r)+".")
			}
			if !matched {
				say(route, "is named instead of recorded, and its description does not say so with one of the four reasons: %q", description)
			}
			if body != nil {
				say(route, "is named instead of recorded and documents a request body that was never sent")
			}
			continue
		}

		// The request.
		req, _ := fx["request"].(map[string]any)
		contentType, _ := req["content_type"].(string)
		media, _ := asObject(body["content"])[contentType].(map[string]any)
		bodyDescription, _ := body["description"].(string)
		switch {
		case req["takes_none"] == true:
			if body != nil {
				say(route, "was recorded taking no body and documents one")
			}
			if !strings.Contains(description, docNoBody) {
				say(route, "takes no body and does not say so: %q", description)
			}
		case body == nil:
			say(route, "was recorded with a %s body and documents no requestBody", contentType)
		case media == nil:
			say(route, "was recorded with a %s body and its requestBody has no such media type", contentType)
		case req["body"] != nil:
			if !reflect.DeepEqual(media["example"], req["body"]) {
				say(route, "the published example is not the request that was recorded")
			}
			if !reflect.DeepEqual(resolve(media["schema"]), req["schema"]) {
				say(route, "the published request schema is not the one recorded for the type the handler binds")
			}
			want := docFromExample
			if req["schema_source"] == schemaFromType {
				want = docFromType
			}
			if !strings.HasPrefix(bodyDescription, want) {
				say(route, "the request body's description does not say where its schema comes from (%s): %q", req["schema_source"], bodyDescription)
			}
		case req["form"] != nil:
			if !reflect.DeepEqual(media["example"], req["form"]) {
				say(route, "the published form example is not the form that was recorded")
			}
			fields := asObject(asObject(resolve(media["schema"]))["properties"])
			for field := range asObject(req["form"]) {
				if fields[field] == nil {
					say(route, "the form field %q was sent and is not in the published schema", field)
				}
			}
			if !strings.HasPrefix(bodyDescription, docFromExample) {
				say(route, "the form body does not say its schema comes from an example: %q", bodyDescription)
			}
		case req["binary"] == true:
			if asObject(media["schema"])["format"] != "binary" || !strings.HasPrefix(bodyDescription, docBinary) {
				say(route, "the binary body is not described as one")
			}
		default:
			say(route, "the write fixture records neither a body nor that the write takes none")
		}
		if req["takes_none"] != true && strings.Contains(description, docNoBody) {
			say(route, "says it takes no body and was recorded sending one")
		}

		// The success response.
		status := fmt.Sprint(fx["status"])
		resp, _ := asObject(op["responses"])[status].(map[string]any)
		switch {
		case resp == nil:
			say(route, "was recorded answering %s and documents no such response", status)
		case fx["response"] == nil:
			if resp["content"] != nil {
				say(route, "answered %s with no body and documents one", status)
			}
		default:
			schemas := 0
			for _, m := range asObject(resp["content"]) {
				if len(asObject(resolve(asObject(m)["schema"]))) > 0 {
					schemas++
				}
			}
			if schemas == 0 {
				say(route, "answered %s with a body and documents no schema for it", status)
			}
		}
	}

	if mutating == 0 {
		t.Fatal("the manifest lists no mutating route")
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("%d problem(s) across %d mutating routes:\n  %s\n\nRecord with `make record-golden-writes`, then regenerate with `go run ./cmd/openapi-gen`.",
			len(problems), mutating, strings.Join(problems, "\n  "))
	}
}

func readJSON(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func asObject(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// docQueryForwarded is what an operation says when its handler hands the query string on unread.
const docQueryForwarded = "The query string is passed to the identity provider as it arrives"

// TestOpenAPIQueryParametersMatchHandlers ties three things together that drift apart silently
// (#869, AC4): what each handler's code reads from the query string today, what the route
// manifest says it reads, and what the published document declares.
//
// A handler that starts reading a parameter changes no response, so no recording notices; the
// document would simply not mention it. So the code is read again here and compared. The same
// goes the other way: a parameter a handler stopped reading has to leave the document.
//
// Like the rest of this plan's checks it runs under the local switch, by the owner's decision.
func TestOpenAPIQueryParametersMatchHandlers(t *testing.T) {
	if os.Getenv(envWritePhase) == "" {
		t.Skip(writePhaseSkipHelp)
	}
	repoRoot, err := filepath.Abs("../../../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			Description string `json:"description"`
			Parameters  []struct {
				Name string `json:"name"`
				In   string `json:"in"`
			} `json:"parameters"`
		} `json:"paths"`
	}
	readJSON(t, filepath.Join(repoRoot, "backend/internal/api/v2/openapi/spec.json"), &doc)
	var man routeManifest
	readJSON(t, filepath.Join(goldenDir, "routes.json"), &man)
	recorded := map[string]routeManifestEntry{}
	for _, e := range man.Routes {
		recorded[e.Method+" "+e.Path] = e
	}

	routes := buildRealRouter(t).Routes()
	fresh := routeQueries(t, routes)

	var problems []string
	reading := 0
	for _, rt := range routes {
		key := rt.Method + " " + rt.Path
		want := fresh[key]
		if len(want.Names) > 0 {
			reading++
		}

		entry, ok := recorded[key]
		switch {
		case !ok:
			problems = append(problems, key+": is not in the route manifest")
			continue
		case entry.Handler != rt.Handler:
			problems = append(problems, fmt.Sprintf("%s: the manifest names handler %s, the router runs %s", key, entry.Handler, rt.Handler))
		case !reflect.DeepEqual(entry.Query, want.Names) || entry.QueryForwarded != want.Forwarded:
			problems = append(problems, fmt.Sprintf("%s: the handler reads %v (forwarded: %v), the manifest says %v (forwarded: %v)",
				key, want.Names, want.Forwarded, entry.Query, entry.QueryForwarded))
		}

		op := doc.Paths[ginToOpenAPI(rt.Path)][strings.ToLower(rt.Method)]
		var declared []string
		for _, p := range op.Parameters {
			if p.In == "query" {
				declared = append(declared, p.Name)
			}
		}
		sort.Strings(declared)
		if !reflect.DeepEqual(declared, want.Names) {
			problems = append(problems, fmt.Sprintf("%s: the handler reads %v, the document declares %v", key, want.Names, declared))
		}
		if want.Forwarded != strings.Contains(op.Description, docQueryForwarded) {
			problems = append(problems, fmt.Sprintf("%s: forwards its query string: %v, and the document's description disagrees", key, want.Forwarded))
		}
	}
	if reading == 0 {
		t.Fatal("no handler was found to read any query parameter; the extraction is broken")
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("%d problem(s):\n  %s\n\nRewrite the manifest with `go test -tags integration ./internal/api/v2/routes/ -run 'TestGoldenResponses$' -args -update`, "+
			"then regenerate with `go run ./cmd/openapi-gen`.", len(problems), strings.Join(problems, "\n  "))
	}
}
