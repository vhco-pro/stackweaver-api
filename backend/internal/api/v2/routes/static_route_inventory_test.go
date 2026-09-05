// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Equality test between the static route inventory and the real router (#731, AC11).
//
// scripts/check-api-reference.js parses routes.go and ansible_routes.go textually so the
// API-reference gate can run in the pre-commit hook and on every PR without a database. That is
// an approximation of the router by construction: it must chain nested groups, survive
// empty-string groups that add middleware but no path segment, and follow groups passed across
// function boundaries into SetupAnsibleRoutes, where over a hundred registrations live with no
// locally visible prefix.
//
// An approximation that silently under-reports is exactly the failure the gate exists to prevent -
// it would pass a document describing endpoints nobody serves. So this test builds the REAL
// surface the way org_wall_completeness_test.go does, and asserts the static inventory matches.
// When routing grows a shape the parser cannot see, this fails loudly instead.

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
	v2routes "github.com/michielvha/stackweaver/backend/internal/api/v2/routes"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// conditionalRoutes are registered behind a runtime feature check, so the router does not build
// them in this test's configuration while a textual parser sees them unconditionally. Each entry
// is a real route that a correctly-configured deployment serves - the parser is right and the
// runtime set is simply narrower here.
//
// Keep this list short and justified. An entry that is NOT feature-gated is a parser bug being
// papered over, which would defeat the point of this test.
var conditionalRoutes = map[string]bool{
	// Registered only when the GitHub App is configured:
	//   if githubAppManager != nil && githubAppManager.IsEnabled() { ... }
	// SetupV2Routes is called here with a nil manager, so it is absent at runtime.
	"POST /api/v2/vcs-connections/github/webhook": true,
}

type staticRoute struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	File   string `json:"file"`
}

// normalisePath mirrors the checker's normalisation: gin writes params as :name, the docs and
// swagger annotations write {name}, and only the shape is comparable.
func normalisePath(p string) string {
	var out []string
	for _, seg := range strings.Split(p, "/") {
		switch {
		case strings.HasPrefix(seg, ":"), strings.HasPrefix(seg, "*"):
			out = append(out, ":param")
		case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}"):
			out = append(out, ":param")
		default:
			out = append(out, seg)
		}
	}
	joined := strings.TrimRight(strings.Join(out, "/"), "/")
	if joined == "" {
		return "/"
	}
	return joined
}

func TestStaticRouteInventoryMatchesRouter(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	if os.Getenv("DEV_INSECURE_KEY") == "" {
		// SetupV2Routes initialises the OIDC signing key and refuses an absent one.
		t.Setenv("DEV_INSECURE_KEY", "1")
	}

	repoRoot, err := filepath.Abs("../../../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	// --- static inventory, from the same script the gate runs ---
	cmd := exec.Command("node", filepath.Join(repoRoot, "scripts", "check-api-reference.js"), "--json")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		t.Fatalf("run check-api-reference.js --json: %v", err)
	}
	var payload struct {
		Routes []staticRoute `json:"routes"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("parse checker JSON: %v", err)
	}
	if len(payload.Routes) == 0 {
		t.Fatal("static inventory is empty - the checker did not emit routes")
	}

	// Compare like with like. This test builds only the surface SetupV2Routes assembles, so the
	// static side must be scoped to the files that function covers. backend/internal/api/routes/
	// registers a further 59 routes - the /api/v2/settings/* family, the CLI oauth endpoints and
	// the VCS webhooks - from the ROOT router in SetupRoutes, which this test never calls.
	// Including them reports 24 phantom "invented" routes that are in fact real, which is exactly
	// what the first run of this test did.
	//
	// Those root-registered routes are still verified by the checker itself (it parses that file
	// too); they are simply outside this equality check's scope. Widening it means standing up
	// SetupRoutes with its auth service and dependencies - worth doing if that family ever grows
	// a documentation problem.
	staticSet := map[string]bool{}
	for _, r := range payload.Routes {
		if !strings.HasPrefix(r.Path, "/api/v2/") {
			continue
		}
		if !strings.Contains(filepath.ToSlash(r.File), "api/v2/routes/") {
			continue
		}
		staticSet[r.Method+" "+normalisePath(r.Path)] = true
	}

	// --- runtime inventory, the authority ---
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2routes.SetupV2Routes(r, db, nil, nil)

	runtimeSet := map[string]bool{}
	for _, rt := range r.Routes() {
		if !strings.HasPrefix(rt.Path, "/api/v2/") {
			continue
		}
		runtimeSet[rt.Method+" "+normalisePath(rt.Path)] = true
	}
	if len(runtimeSet) < 100 {
		t.Fatalf("only %d /api/v2 routes from the router - SetupV2Routes did not build the full surface", len(runtimeSet))
	}

	var missing, extra []string
	for k := range runtimeSet {
		if !staticSet[k] {
			missing = append(missing, k)
		}
	}
	for k := range staticSet {
		if !runtimeSet[k] && !conditionalRoutes[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("static inventory MISSES %d route(s) the router registers - the API-reference gate would not catch a document describing them:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	if len(extra) > 0 {
		t.Errorf("static inventory INVENTS %d route(s) the router does not register - the gate would accept documentation for endpoints nobody serves:\n  %s",
			len(extra), strings.Join(extra, "\n  "))
	}
	t.Logf("static %d, runtime %d /api/v2 routes", len(staticSet), len(runtimeSet))
}
