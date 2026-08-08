// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Registry-completeness test for the org-resolution wall (#615). The wall is
// fail-closed: an api-key request to any /api/v2 route absent from
// middleware's wallRegistry is denied with 403. That is the right security
// default, but it means a route added without a registry entry silently
// breaks API-token automation (the UI keeps working - JWT sessions bypass
// the wall - so the gap is invisible in browser testing). Exactly that
// happened to ~10 Ansible/VCS routes.
//
// This test builds the REAL /api/v2 surface via SetupV2Routes (which wires
// every sub-router, including SetupAnsibleRoutes/SetupAnsibleWorkflowRoutes)
// and asserts every walled route is classified. Routes that SetupV2Routes
// deliberately registers on the ROOT router - token-in-query, signature- or
// callback-authenticated endpoints that never pass the wall - are listed in
// wallExemptions with their justification; a new /api/v2 route must either
// be classified or consciously added there.

//go:build integration
// +build integration

package routes_test

import (
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	v2routes "github.com/michielvha/stackweaver/backend/internal/api/v2/routes"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// wallExemptions are /api/v2 route patterns registered on the root router
// (outside the walled v2 group) on purpose. Each carries its own request
// authentication and never reaches the org wall.
var wallExemptions = []string{
	"/api/v2/plans/:id/json-output",             // run-scoped log-read token in query
	"/api/v2/configuration-versions/:id/download", // run-scoped token in query
	"/api/v2/configuration-versions/:id/upload",   // TFE upload contract: token in query
	"/api/v2/task-results/:id/callback",           // run-task HMAC callback
	"/api/v2/ansible/job-templates/:id/callback",  // provisioning callback (host_config_key)
	"/api/v2/vcs-connections/github/",             // prefix: VCS webhooks (signature-validated)
	"/api/v2/vcs-connections/azure-devops/",       // prefix: VCS webhooks (basic-auth secret)
	"/api/v2/zitadel/actions/",                    // prefix: Zitadel Actions webhooks (signing key)
	"/api/v2/webhooks/",                           // prefix: GitHub webhooks (signature-validated)
	"/api/v2/settings/",                           // prefix: account-scoped settings (JWT-only surface, mounted in SetupRoutes)
}

func exempt(path string) bool {
	for _, e := range wallExemptions {
		if strings.HasSuffix(e, "/") {
			if strings.HasPrefix(path, e) {
				return true
			}
		} else if path == e {
			return true
		}
	}
	return false
}

func TestOrgWallRegistryCompleteness(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	// Route REGISTRATION must not require production key material.
	t.Setenv("DEV_INSECURE_KEY", "1")

	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2routes.SetupV2Routes(r, db, nil, nil)

	var walked, missing int
	for _, rt := range r.Routes() {
		if !strings.HasPrefix(rt.Path, "/api/v2/") || exempt(rt.Path) {
			continue
		}
		walked++
		if !middleware.WallClassified(rt.Path) {
			missing++
			t.Errorf("unclassified walled route: %s %s - api-key tokens get a fail-closed 403 here; add it to wallRegistry (org_wall_registry.go) or, if it is deliberately root-registered with its own auth, to wallExemptions in this test", rt.Method, rt.Path)
		}
	}

	// Sanity floor: if the router failed to assemble, the loop above would
	// vacuously pass. The real surface is far larger than this.
	if walked < 100 {
		t.Fatalf("only %d /api/v2 routes walked - SetupV2Routes did not build the full surface", walked)
	}
	t.Logf("walked %d walled routes, %d unclassified", walked, missing)
}
