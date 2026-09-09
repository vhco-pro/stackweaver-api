// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Golden response harness (#755, Phase 1).
//
// This is a before-and-after photo of the API. It drives every route the router registers
// against a freshly seeded database, records the status and body of each response, and
// compares them to committed fixtures. Its whole purpose is to make the typed-response
// migration safe: 2278 of 2321 response sites currently build anonymous gin.H maps, and
// converting them to Go structs must not change what any client receives.
//
// Two properties matter more than convenience here:
//
//   - **Nothing is silently skipped.** Every registered route is either covered by a fixture
//     or named in goldenExclusions with a reason, and TestGoldenCoverage fails when a route
//     is neither. A route quietly missing from the fixtures would refactor with no safety
//     net while the suite still reported green, which is the exact failure this exists to
//     prevent.
//   - **Comparison is on parsed values, not bytes.** encoding/json sorts map keys but
//     marshals struct fields in declaration order, so replacing a map with a struct
//     necessarily reorders keys. Byte equality is therefore unachievable by construction;
//     deep equality after normalisation pins every key, value, type and null while letting
//     order move. See the spec for why that is safe (no test or client string-matches a
//     response body).
//
// The database is a throwaway, created and dropped by this test, never $TEST_DATABASE_URL
// itself - that URL points at a development database with no backup.
//
//	go test -tags integration ./internal/api/v2/routes/ -run TestGolden
//	go test -tags integration ./internal/api/v2/routes/ -run TestGolden -args -update

//go:build integration
// +build integration

package routes_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/routes"
	v2handlers "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/profile"
	"github.com/michielvha/stackweaver/backend/internal/services/sessions"
	"github.com/michielvha/stackweaver/backend/internal/services/totp"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden fixtures from the current responses")

const goldenDir = "testdata/golden"

// goldenSeedInstant anchors the seeded history. It is a constant rather than a computed value
// on purpose: the whole point is that it does not move.
const goldenSeedInstant = "2026-09-01T12:00:00Z"

// goldenExclusions names every route deliberately not covered by a fixture, with the reason.
// This list is the spec's "gaps are named" rule made executable: TestGoldenCoverage fails on
// any registered route that is neither covered nor listed here, so a gap cannot open silently.
//
// Keep each entry justified. An entry that is merely inconvenient to fixture is a hole in the
// safety net for the typed-response migration.
var goldenExclusions = map[string]string{
	// Long-poll / streaming endpoints: the response is a stream whose content depends on
	// runner activity, so there is no stable body to record.
	// Reads through the Redis log buffer and object storage. The harness stands up neither, so
	// the handler dereferences a dependency production always wires and there is no
	// representative body to record.
	// Recording this would embed a second copy of the 557 KB OpenAPI document in the fixtures,
	// and every regeneration of the spec would then churn a fixture that adds nothing: the
	// document is already committed, diffable and gated by its own drift check.
	"GET /openapi/stable.json": "serves the committed OpenAPI document, which has its own drift check",

	// DEV_INSECURE_KEY auto-generates an ephemeral RSA key pair per process, so the published
	// modulus is different on every run. There is no stable body to record and nothing to
	// normalise - the key material is opaque base64.
	"GET /.well-known/jwks": "publishes an ephemeral per-process RSA key; the modulus differs every run",

	"GET /api/v2/runs/:id/logs":       "needs the Redis log buffer and object storage, which the harness does not stand up",
	"GET /api/v2/runs/:id/logs/plan":  "same log backend as /logs; recovers to a 500 with an empty body",
	"GET /api/v2/runs/:id/logs/apply": "same log backend as /logs; recovers to a 500 with an empty body",

	// Terminal state mutations on seeded data: recording these would destroy the fixture set
	// mid-run and make every later route's response depend on test ordering.
	"DELETE /api/v2/organizations/:name": "destroys the seeded organization the rest of the fixtures depend on",
}

// timeSensitiveRoutes aggregate over calendar windows or live status, so their numbers move with
// the wall clock. Their shape is pinned; their numbers are not.
//
// This was found the hard way. The fixtures were first recorded and re-verified within a few
// hours, which hid it entirely; a day later ten endpoints reported spurious diffs
// (completed_terraform_runs_this_month 5 -> 3, errored_workspaces 2 -> 0) with no code change
// behind them - the flaky-test failure mode the harness exists to avoid.
//
// Pinning the SEED clock was the obvious fix and it is done (goldenSeedInstant), which removed
// the daily component: the dataset is now byte-reproducible for a given --seed and --now. It is
// NOT sufficient, and that was measured rather than assumed. Moving the anchor from September to
// June changed completed_terraform_runs_this_month from 1 to 0, because these handlers evaluate
// "this month" against the SERVER's clock, not against the data. The harness drives the router
// in-process over HTTP and has no way to pin that.
//
// So the numbers are normalised away for these routes while every key, nesting level, type and
// null is still pinned - which is the property a representational refactor can actually break.
// Removing this list entirely would need the handlers to take an injectable clock, which is a
// change to production code for a test's benefit and is not obviously worth it.
//
// Blanking numbers alone turned out to be incomplete for the same reason, one layer down. The
// analytics daily series labels each bucket with a calendar date ("2026-09-06"), which is a
// string, so blankNumbers left it pinned and the fixture failed on the next calendar day with
// the whole window shifted by one entry - exactly the spurious diff this list exists to
// prevent. Whole-string dates are therefore blanked too, and only whole-string ones: a date
// embedded in a seeded name ("baseline-compliance - 2026-08-23 11:01") comes from the pinned
// seed clock, is stable, and stays pinned.
var timeSensitiveRoutes = map[string]string{
	"GET /api/v2/dashboard/stats":                          "counts runs and jobs per calendar month",
	"GET /api/v2/dashboard/operations":                     "counts live operations by status",
	"GET /api/v2/organizations/:name/analytics":            "aggregates over a rolling window",
	"GET /api/v2/organizations/:name/analytics/executions": "aggregates over a rolling window",
	"GET /api/v2/organizations/:name/ansible/jobs":         "job status depends on elapsed time",
	"GET /api/v2/organizations/:name/ansible/jobs/queue":   "queue contents depend on elapsed time",
	"GET /api/v2/ansible/jobs/:id":                         "job status depends on elapsed time",
	"GET /api/v2/organizations/:name/runs":                 "run status depends on elapsed time",
	"GET /api/v2/organizations/:name/workspaces":           "carries each workspace's latest-run status",
	"GET /api/v2/workspaces/:id/runs":                      "run status depends on elapsed time",
}

// calendarDateRe matches a value that is entirely a calendar date, the label form the
// analytics daily series uses. Anchored on both ends so a date inside a longer string is
// left alone.
var calendarDateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// blankTimeVarying replaces every number and every whole-string calendar date in a parsed
// value with a placeholder, leaving keys, nesting, types and nulls intact.
func blankTimeVarying(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = blankTimeVarying(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = blankTimeVarying(val)
		}
		return out
	case float64:
		return "<number>"
	case string:
		if calendarDateRe.MatchString(t) {
			return "<date>"
		}
		return t
	default:
		return v
	}
}

// --- throwaway database -----------------------------------------------------
//
// Modelled on cmd/demoseed/freshdb_test.go: the name is prefixed and UUID-suffixed so the
// DROP can never match anything a human cares about, and so concurrent runs cannot collide.

func goldenDB(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}

	name := "golden_api_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

	adminURL := *u
	adminURL.Path = "/postgres"
	admin, err := gorm.Open(postgres.Open(adminURL.String()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect admin db: %v", err)
	}
	if err := admin.Exec(fmt.Sprintf("CREATE DATABASE %q", name)).Error; err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}

	targetURL := *u
	targetURL.Path = "/" + name
	db, err := gorm.Open(postgres.Open(targetURL.String()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect %s: %v", name, err)
	}
	// uuid-ossp is created by the API on startup; a throwaway database has to do it itself.
	db.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`)
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate %s: %v", name, err)
	}

	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		// Scoped to the single generated name, never an unqualified DROP.
		if err := admin.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %q (FORCE)", name)).Error; err != nil {
			t.Logf("drop database %s: %v", name, err)
		}
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	return db, name
}

// seedGolden fills the throwaway database using the real demoseed tool, so the fixtures
// exercise realistic data rather than a hand-built approximation that drifts from what the
// product actually stores. demoseed lives in package main, so it is invoked as a binary.
func seedGolden(t *testing.T, dbName string) {
	t.Helper()
	repoRoot, err := filepath.Abs("../../../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	u, _ := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	pw, _ := u.User.Password()

	// --now pins the history anchor so the calendar buckets ("completed this month", "active")
	// fall the same way regardless of when the fixtures are recorded. With --seed alone the data
	// was reproducible in shape but not in those aggregates, and fixtures recorded one day
	// reported spurious diffs the next.
	cmd := exec.Command("go", "run", "./cmd/demoseed",
		"--org", "demo", "--days", "10", "--seed", "20260817", "--now", goldenSeedInstant)
	cmd.Dir = filepath.Join(repoRoot, "backend")
	cmd.Env = append(os.Environ(),
		"DATABASE_HOST="+u.Hostname(),
		"DATABASE_PORT="+u.Port(),
		"DATABASE_USER="+u.User.Username(),
		"DATABASE_PASSWORD="+pw,
		"DATABASE_NAME="+dbName,
		"DATABASE_SSLMODE=disable",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("seed %s: %v\n%s", dbName, err, out)
	}
}

// --- fixture identity -------------------------------------------------------

// goldenFixture is what gets committed: the status and the normalised body. Headers are
// deliberately excluded - they are not what this migration changes, and Date/Content-Length
// would make every fixture volatile.
type goldenFixture struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Body   any    `json:"body"`
}

var (
	uuidRe      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	timestampRe = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b`)
	// TFE-style identifiers are a short lowercase prefix and 16 base62 characters: ws-, run-,
	// var-, varset-, cv-, sv-. Matching the SHAPE rather than an enumerated prefix list is
	// deliberate - the enumeration missed `var-` and those identifiers reached the fixtures
	// verbatim, so they differed on every reseed and ten fixtures failed to reproduce.
	tfeIDRe = regexp.MustCompile(`\b[a-z]{2,8}-[A-Za-z0-9]{16}\b`)
	tokenRe = regexp.MustCompile(`\btfe-[A-Za-z0-9_\-]{16,}\b`)
	// Signed log-read URLs carry an HMAC token with an embedded expiry, so the query value is
	// different on every run and every key rotation.
	logTokenRe = regexp.MustCompile(`token=[A-Za-z0-9_\-.]+`)
)

// normalise replaces values that differ between runs with stable placeholders, recursing
// through the parsed value tree rather than editing raw JSON.
//
// This targets values only: keys, types, nulls and structure are all preserved, which is
// exactly what the typed-response migration must not change. A field that changed from a
// UUID string to null, or from a string to a number, still fails the comparison because the
// placeholder is a string and the shape around it is untouched.
func normalise(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normalise(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = normalise(val)
		}
		// Collections are sorted by their serialised form, because the API does not guarantee
		// an order to preserve. The list handlers query without ORDER BY, so Postgres returns
		// rows in heap order and the same request yields a different sequence between runs -
		// GET /api/v2/teams/:id/relationships/organization-memberships led with tom.okafor on
		// one run and priya.raman on the next.
		//
		// The cost is real and worth stating: this harness cannot catch a change in list
		// ordering. It is accepted because the typed-response migration replaces how a payload
		// is BUILT, not the query that orders it, and because pinning an order the product
		// does not define would make the suite flaky rather than strict. Unstable ordering is
		// its own defect - it also makes paginated results able to repeat or skip rows - and
		// is tracked separately.
		sort.Slice(out, func(i, j int) bool {
			a, _ := json.Marshal(out[i])
			b, _ := json.Marshal(out[j])
			return string(a) < string(b)
		})
		return out
	case string:
		s := t
		s = tokenRe.ReplaceAllString(s, "<token>")
		s = logTokenRe.ReplaceAllString(s, "token=<signed>")
		s = uuidRe.ReplaceAllString(s, "<uuid>")
		s = timestampRe.ReplaceAllString(s, "<timestamp>")
		s = tfeIDRe.ReplaceAllString(s, "<id>")
		return s
	default:
		return v
	}
}

// fixtureName turns a method and route pattern into a stable filename.
func fixtureName(method, routePath string) string {
	p := strings.TrimPrefix(routePath, "/")
	p = strings.ReplaceAll(p, "/", "_")
	p = strings.ReplaceAll(p, ":", "")
	p = strings.ReplaceAll(p, "*", "wildcard_")
	if p == "" {
		p = "root"
	}
	return fmt.Sprintf("%s_%s.json", strings.ToLower(method), p)
}

// --- harness ----------------------------------------------------------------

type goldenHarness struct {
	db       *gorm.DB
	router   *gin.Engine
	token    string
	families map[string]string            // resource-family segment -> identifier from seeded data
	named    map[string]string            // parameter name -> value, for self-describing parameters
	prefixed map[string]map[string]string // path prefix -> parameter name -> value
}

// buildHarnessRouter mounts the router the SERVER mounts, not just its v2 half.
//
// This used to call v2routes.SetupV2Routes directly, which registered 406 of the 465 routes the
// binary serves. Production calls routes.SetupRoutes, which registers 59 of its own - all of
// /api/v2/settings (2FA, API keys, profile, sessions, password) and the entire /auth proxy - and
// then delegates to SetupV2Routes for the rest.
//
// The consequence was not confined to this file. The manifest this harness writes is what
// openapi-gen builds the published document from, so those 59 endpoints were absent from the
// artifact we publish as the API's description: a consumer generating a client from it could not
// enrol a second factor, list their API keys or change their password. They had no fixtures
// either, so no response shape or error envelope of theirs had ever been pinned, and they were
// invisible to every fixture-derived gate - the pagination census, the query-parameter
// derivation, the response-typing guard's fixture half (#790).
//
// SetupRoutes nil-guards each service and simply omits its routes when one is absent, so the
// services have to be real instances rather than nils. They are constructed against the Zitadel
// coordinates in the environment; the gRPC clients they build are lazy, so construction succeeds
// without a reachable instance and the routes register either way. A service that cannot be
// constructed is logged and passed as nil, which loses its routes rather than the whole run - the
// alternative is a harness that refuses to record anything at all when Zitadel is down.
func buildHarnessRouter(t *testing.T, db *gorm.DB, authService *auth.Service) *gin.Engine {
	t.Helper()

	// The recording pass drives every route back to back from one address, which is exactly the
	// shape the per-IP limiters exist to stop: AUTH_RATE_LIMIT defaults to 10rps/burst 20 and the
	// /auth surface alone is 40 routes. The first pass recorded a 429 for whichever route
	// happened to be ~21st, which is a fixture whose value depends on how many requests preceded
	// it - it would have compared unequal on any run that ordered them differently. Raising the
	// ceilings here keeps the recorded status a property of the endpoint rather than of its
	// position in the run.
	// The names are <PREFIX>_RPS / <PREFIX>_BURST - rateLimitFromEnv("AUTH_RATE_LIMIT", ...) in
	// routes.go reads AUTH_RATE_LIMIT_RPS, not AUTH_RATE_LIMIT.
	t.Setenv("RATE_LIMIT_RPS", "100000")
	t.Setenv("RATE_LIMIT_BURST", "100000")
	t.Setenv("AUTH_RATE_LIMIT_RPS", "100000")
	t.Setenv("AUTH_RATE_LIMIT_BURST", "100000")

	issuer := os.Getenv("ZITADEL_ISSUER")
	if issuer == "" {
		issuer = "http://localhost:8080"
	}
	internalAddr := os.Getenv("ZITADEL_INTERNAL_ADDR")
	pat := os.Getenv("ZITADEL_LOGIN_SERVICE_USER_TOKEN")

	totpService, err := totp.NewService(issuer, internalAddr, pat)
	if err != nil {
		t.Logf("harness: TOTP service unavailable (%v); its routes will not be recorded", err)
		totpService = nil
	}
	profileService, err := profile.NewService(issuer, internalAddr, pat)
	if err != nil {
		t.Logf("harness: profile service unavailable (%v); its routes will not be recorded", err)
		profileService = nil
	}
	sessionsService, err := sessions.NewService(issuer, internalAddr, pat)
	if err != nil {
		t.Logf("harness: sessions service unavailable (%v); its routes will not be recorded", err)
		sessionsService = nil
	}

	apiKeyService := apikey.NewService(
		repository.NewAPIKeyRepository(db),
		repository.NewOrganizationRepository(db),
		repository.NewProjectRepository(db),
		repository.NewTeamRepository(db),
	)

	authProxy := v2handlers.NewAuthProxy(v2handlers.AuthProxyConfig{
		ZitadelIssuer:      issuer,
		ZitadelInternalURL: issuer,
		PAT:                pat,
	})

	// SetupRoutes builds its own engine with gin.Default(), which installs Recovery - the same
	// thing the previous hand-rolled router had to add explicitly. Without it a panicking handler
	// aborts the binary and discards every fixture recorded so far, instead of producing the 500
	// a real client sees.
	return routes.SetupRoutes(
		db, authService, totpService, profileService, sessionsService, apiKeyService, nil, authProxy,
	)
}

func setupGoldenHarness(t *testing.T) *goldenHarness {
	t.Helper()
	if os.Getenv("DEV_INSECURE_KEY") == "" {
		// SetupV2Routes initialises the OIDC signing key and refuses an absent one.
		t.Setenv("DEV_INSECURE_KEY", "1")
	}

	db, name := goldenDB(t)
	seedGolden(t, name)

	// The tofu-version catalogue is written by SeedOfficialVersions at API startup, which a
	// throwaway database never sees - and calling it here would fetch the live version index
	// over the network, which a test must not. Inserting the static fallback list reproduces
	// exactly what a freshly booted, offline deployment holds, deterministically.
	for _, ver := range models.OfficialTofuVersions {
		if err := db.Create(&models.TofuVersion{
			Version:  ver,
			Official: true,
			Enabled:  true,
		}).Error; err != nil {
			t.Fatalf("seed tofu version %s: %v", ver, err)
		}
	}

	// Real auth, not an impersonation shim: `tfe-` tokens are verified against the database
	// by apikey.Service with no Zitadel involvement, so the harness can exercise the same
	// middleware chain production uses.
	userRepo := repository.NewUserRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	apiKeyRepo := repository.NewAPIKeyRepository(db)

	authService := auth.NewService(userRepo)
	apiKeyService := apikey.NewService(apiKeyRepo, orgRepo, projectRepo, teamRepo)
	authService.SetAPIKeyService(apiKeyService)

	// Authenticate as a member of the seeded "owners" team. The first user in the table is
	// usually not one, and the first recording pass produced 20 forbidden responses on the
	// Ansible resources as a result - fixtures that pin the 403 envelope but say nothing about
	// the resource shapes this migration changes.
	var seedUser models.User
	err := db.Raw(`
		SELECT u.* FROM users u
		JOIN team_members tm ON tm.user_id = u.id
		JOIN teams t ON t.id = tm.team_id
		WHERE t.name = 'owners'
		ORDER BY u.email LIMIT 1`).Scan(&seedUser).Error
	if err != nil || seedUser.ID == uuid.Nil {
		if err := db.Order("email").First(&seedUser).Error; err != nil {
			t.Fatalf("no seeded user to authenticate as: %v", err)
		}
		t.Logf("no owners-team member found; falling back to the first user, expect forbidden responses")
	}
	_, token, tokErr := apiKeyService.CreateUserToken(seedUser.ID, "golden-harness", nil)
	if tokErr != nil {
		t.Fatalf("mint user token: %v", tokErr)
	}

	grantHarnessAccess(t, db, seedUser.ID)

	gin.SetMode(gin.TestMode)
	router := buildHarnessRouter(t, db, authService)

	return &goldenHarness{
		db:       db,
		router:   router,
		token:    token,
		families: resolveFamilies(db),
		named:    resolveNamedParams(db),
		prefixed: resolvePrefixParams(t, db),
	}
}

// --- path parameter resolution ----------------------------------------------
//
// `:id` appears on 110 routes and `:name` on 62, and both mean something different on each
// one: `:id` is a workspace under /workspaces/:id, a run under /runs/:id, a team under
// /teams/:id. Resolving by parameter NAME therefore cannot work - the first recording pass
// did exactly that and produced 137 not-found responses out of 196 fixtures, which pins the
// error envelope but says nothing about the resource shapes this migration actually changes.
//
// So resolution keys on the path segment PRECEDING the parameter, which is the resource
// family, and falls back to an explicit table for parameters whose name already says what
// they are (`:workspace_name`, `:namespace`, `:version`).

// familyTables maps a route's resource-family segment to the table its identifier lives in.
// Identifiers are read as text so a single helper covers both the uuid primary keys and the
// TFE-style prefixed string ones (ws-..., run-..., varset-...).
var familyTables = map[string]string{
	"workspaces":      "workspaces",
	"projects":        "projects",
	"runs":            "runs",
	"teams":           "teams",
	"varsets":         "variable_sets",
	"agent-pools":     "agent_pools",
	"runners":         "runners",
	"users":           "users",
	"change-requests": "change_requests",
	"variables":       "variables",
	"inventories":     "ansible_inventories",
	// These were recorded at their not-found path while the rows existed all along - the
	// resolver simply had no entry, which #758 had attributed to the seeder.
	"authentication-tokens": "api_keys",
	"registry-providers":    "providers",
	"registry-modules":      "modules",
	// Families seeded by demoseed's coverage extras (#758 Phase 3).
	"run-triggers":                "run_triggers",
	"tasks":                       "run_tasks",
	"task-stages":                 "task_stages",
	"task-results":                "task_results",
	"task-result-outcomes":        "task_results",
	"notification-configurations": "notification_configurations",
	"credentials":                 "ansible_credentials",
	"inventory-sources":           "ansible_inventory_sources",
	"inventory-syncs":             "ansible_inventory_syncs",
	"workflows":                   "ansible_workflows",
	"workflow-jobs":               "ansible_workflow_jobs",
	"team-projects":               "team_project_accesses",
	"team-workspaces":             "team_workspace_accesses",
	// The admin tofu-version catalogue is auto-migrated with 65 rows; only the resolver entry
	// was missing. Groups and hosts are seeded by the coverage extras.
	"terraform-versions": "tofu_versions",
	"groups":             "ansible_inventory_groups",
	"hosts":              "ansible_inventory_hosts",
	"job-templates":      "ansible_job_templates",
	"jobs":               "ansible_jobs",
	"playbooks":          "ansible_playbooks",
	"schedules":          "ansible_schedules",
}

// orderColumn picks a deterministic sort key for a table.
//
// Ordering by `id` looks obvious and is wrong: primary keys here are uuid_generate_v4() or
// randomly generated TFE-style strings, so they are freshly random on every seed and
// "ORDER BY id LIMIT 1" selects a DIFFERENT row each run. That produced fixtures that failed
// to reproduce on the very next run - the harness authenticated as lena.fischer once and
// priya.raman the next time. A golden harness that cannot reproduce its own recording is worse
// than none, because every real regression arrives buried in noise.
//
// So order by a stable business key: `name` where the table has one, otherwise `created_at`
// (whose absolute value moves between runs but whose ordering does not), and only then `id`.
func orderColumn(db *gorm.DB, table string) string {
	var cols []string
	if err := db.Raw(`
		SELECT column_name FROM information_schema.columns WHERE table_name = ?`, table).Scan(&cols).Error; err != nil {
		return "id"
	}
	has := map[string]bool{}
	for _, c := range cols {
		has[c] = true
	}
	switch {
	case has["name"]:
		return "name"
	case has["created_at"]:
		return "created_at"
	default:
		return "id"
	}
}

// firstID returns one table's identifier as text, chosen deterministically.
func firstID(db *gorm.DB, table string) (string, bool) {
	return firstCol(db, table, "id")
}

func firstCol(db *gorm.DB, table, col string) (string, bool) {
	var v string
	q := fmt.Sprintf("SELECT %q::text FROM %q ORDER BY %q, id LIMIT 1", col, table, orderColumn(db, table))
	if err := db.Raw(q).Scan(&v).Error; err != nil || v == "" {
		return "", false
	}
	return v, true
}

// grantHarnessAccess gives the authenticating principal every permission in the model.
//
// The harness records RESPONSE SHAPES, and a 403 pins the error envelope rather than the
// resource. The first pass with a seeded owners-team member still returned 403 on all 20
// Ansible resource routes, because those go through CheckAnsibleResourcePermission with the
// inventory's project scope and the seeded team carries no project access. Authorization
// itself is not this harness's job - authz_matrix_test.go owns that, and deliberately runs
// under-privileged principals - so here the principal is maximally privileged and the
// fixtures capture payloads instead of denials.
//
// The organization flags are read from the schema rather than listed, so a new permission
// column cannot silently reintroduce a 403 and quietly shrink coverage.
func grantHarnessAccess(t *testing.T, db *gorm.DB, userID uuid.UUID) {
	t.Helper()

	var teamIDs []string
	if err := db.Raw(`SELECT team_id::text FROM team_members WHERE user_id = ?`, userID).Scan(&teamIDs).Error; err != nil {
		t.Fatalf("look up harness teams: %v", err)
	}
	if len(teamIDs) == 0 {
		t.Fatalf("harness user %s belongs to no team; fixtures would record authorization failures", userID)
	}

	var boolCols []string
	if err := db.Raw(`
		SELECT column_name FROM information_schema.columns
		WHERE table_name = 'team_organization_accesses' AND data_type = 'boolean'
		ORDER BY column_name`).Scan(&boolCols).Error; err != nil {
		t.Fatalf("read permission columns: %v", err)
	}
	if len(boolCols) == 0 {
		t.Fatal("team_organization_accesses has no boolean permission columns - schema assumption broken")
	}
	sets := make([]string, 0, len(boolCols))
	for _, c := range boolCols {
		sets = append(sets, fmt.Sprintf("%q = true", c))
	}
	if err := db.Exec(fmt.Sprintf(
		"UPDATE team_organization_accesses SET %s WHERE team_id IN (?)", strings.Join(sets, ", ")),
		teamIDs).Error; err != nil {
		t.Fatalf("grant organization access: %v", err)
	}

	// Project-scoped checks read TeamProjectAccess; "admin" is the highest fixed level.
	for _, teamID := range teamIDs {
		if err := db.Exec(`
			INSERT INTO team_project_accesses (id, team_id, project_id, access)
			SELECT uuid_generate_v4(), ?, p.id, 'admin' FROM projects p
			ON CONFLICT (team_id, project_id) DO UPDATE SET access = 'admin'`, teamID).Error; err != nil {
			t.Fatalf("grant project access: %v", err)
		}
	}
}

// resolveFamilies builds the family-segment lookup from the seeded data. A family with no
// seeded rows is simply absent, and its routes record the not-found path - which is still a
// real fixture pinning the shared error envelope, and is reported by TestGoldenResolution so
// the gap is visible rather than assumed.
func resolveFamilies(db *gorm.DB) map[string]string {
	out := map[string]string{}
	for family, table := range familyTables {
		if id, ok := firstID(db, table); ok {
			out[family] = id
		}
	}
	if name, ok := firstCol(db, "organizations", "name"); ok {
		out["organizations"] = name
	}
	return out
}

// prefixParams resolves parameters by WHERE they appear, and resolves them as a SET.
//
// Two problems live here, and the second is the subtle one.
//
// First, the registry protocol reuses parameter names across resources:
// /v1/modules/:namespace/:name/:provider and /v1/providers/:namespace/:name/:version. A lookup
// keyed on the parameter name alone cannot tell them apart, so every /v1/providers route
// resolved :namespace from the MODULES table and :name fell through to the organization name.
//
// Second, and this is what a per-parameter resolver cannot fix at all: these routes need values
// that BELONG TOGETHER. Picking the first namespace, the first name and the first version
// independently yields a coordinate triple that may name nothing, and the endpoint answers 404
// while every individual row exists. The same defeats
// /varsets/:id/relationships/vars/:variable_id, where the first variable set and the first
// variable-set variable are usually unrelated.
//
// So each entry resolves one CONSISTENT row with a single joined query.
func resolvePrefixParams(t *testing.T, db *gorm.DB) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}

	// One real provider coordinate: namespace, name and a version that exists for it.
	var prov struct {
		Namespace string
		Name      string
		Version   string
	}
	if err := db.Raw(`
		SELECT p.namespace, p.name, pv.version
		FROM providers p JOIN provider_versions pv ON pv.provider_id = p.id
		ORDER BY p.namespace, p.name, pv.version LIMIT 1`).Scan(&prov).Error; err == nil && prov.Name != "" {
		out["/v1/providers"] = map[string]string{
			"namespace": prov.Namespace,
			"name":      prov.Name,
			"version":   prov.Version,
		}
	}

	// One real module coordinate.
	var mod struct {
		Namespace string
		Name      string
		Provider  string
		Version   string
	}
	if err := db.Raw(`
		SELECT m.namespace, m.name, m.provider, mv.version
		FROM modules m JOIN module_versions mv ON mv.module_id = m.id
		ORDER BY m.namespace, m.name, mv.version LIMIT 1`).Scan(&mod).Error; err == nil && mod.Name != "" {
		out["/v1/modules"] = map[string]string{
			"namespace": mod.Namespace,
			"name":      mod.Name,
			"provider":  mod.Provider,
			"version":   mod.Version,
		}
	}

	// A variable set together with a variable that actually belongs to it.
	var vs struct {
		SetID string
		VarID string
	}
	if err := db.Raw(`
		SELECT vs.id AS set_id, vsv.id AS var_id
		FROM variable_sets vs JOIN variable_set_variables vsv ON vsv.variable_set_id = vs.id
		-- ORDER BY the variable's KEY, not its id: TFE-style ids are randomly generated, so
		-- ordering by one picks a different row on each seeding run and the fixture churns.
		ORDER BY vs.name, vsv.key LIMIT 1`).Scan(&vs).Error; err == nil && vs.VarID != "" {
		pair := map[string]string{"id": vs.SetID, "variable_id": vs.VarID}
		out["/api/v2/varsets"] = pair
		out["/api/v2/organizations/:name/varsets"] = pair
	}

	// A workspace variable that belongs to the workspace the family lookup resolves. The
	// name-based fallback would hand this route a variable-set variable id, and an arbitrary
	// variable would not belong to the resolved workspace either way.
	var wv struct {
		WsID  string
		VarID string
	}
	if err := db.Raw(`
		SELECT w.id AS ws_id, v.id AS var_id
		FROM workspaces w JOIN variables v ON v.workspace_id = w.id
		ORDER BY w.name, v.key LIMIT 1`).Scan(&wv).Error; err == nil && wv.VarID != "" {
		out["/api/v2/workspaces/:id/vars"] = map[string]string{"id": wv.WsID, "variable_id": wv.VarID}
	}

	return out
}

// namedParams covers parameters whose own name determines the value, independent of family.
func resolveNamedParams(db *gorm.DB) map[string]string {
	p := map[string]string{}
	if name, ok := firstCol(db, "organizations", "name"); ok {
		p["name"] = name // only reached when the family lookup misses
		p["org_name"] = name
		p["organization_name"] = name
	}
	if v, ok := firstCol(db, "workspaces", "name"); ok {
		p["workspace_name"] = v
	}
	if v, ok := firstCol(db, "projects", "name"); ok {
		p["project_name"] = v
	}
	if v, ok := firstCol(db, "teams", "name"); ok {
		p["teamName"] = v
		p["team_name"] = v
	}
	if v, ok := firstID(db, "runs"); ok {
		p["run_id"] = v
	}
	if v, ok := firstID(db, "workspaces"); ok {
		p["workspace_id"] = v
	}
	if v, ok := firstID(db, "ansible_schedules"); ok {
		p["schedule_id"] = v
	}
	// :variable_id under a varset means a variable-set variable, not a workspace variable.
	// Resolving it from the workspace `variables` table made every varset relationship route
	// answer 404 even though the variable sets themselves resolved fine.
	if v, ok := firstID(db, "variable_set_variables"); ok {
		p["variable_id"] = v
	} else if v, ok := firstID(db, "variables"); ok {
		p["variable_id"] = v
	}
	if v, ok := firstID(db, "teams"); ok {
		p["tid"] = v
	}
	// Registry coordinates: the seeded module/provider namespace and names.
	if v, ok := firstCol(db, "modules", "namespace"); ok {
		p["namespace"] = v
	}
	if v, ok := firstCol(db, "modules", "name"); ok {
		p["module_name"] = v
	}
	if v, ok := firstCol(db, "modules", "provider"); ok {
		p["provider"] = v
	}
	if v, ok := firstCol(db, "providers", "name"); ok {
		p["provider_name"] = v
	}
	p["registry"] = "private"
	p["registry_name"] = "private"
	p["version"] = "1.0.0"
	p["os"] = "linux"
	p["arch"] = "amd64"
	p["owner"] = "stackweaver"
	p["repo"] = "demo"
	return p
}

// buildPath substitutes concrete values into a gin route pattern, preferring the resource
// family (the preceding segment) over the bare parameter name.
func (h *goldenHarness) buildPath(routePath string) string {
	segs := strings.Split(routePath, "/")
	for i, seg := range segs {
		if !strings.HasPrefix(seg, ":") && !strings.HasPrefix(seg, "*") {
			continue
		}
		key := strings.TrimLeft(seg, ":*")

		// Where the parameter sits wins over what it is called: /v1/providers/:namespace is a
		// provider namespace even though /v1/modules/:namespace is a module namespace.
		matched := false
		for prefix, params := range h.prefixed {
			if !strings.HasPrefix(routePath, prefix) {
				continue
			}
			if v, ok := params[key]; ok {
				segs[i] = v
				matched = true
				break
			}
		}
		if matched {
			continue
		}

		// An explicitly named parameter says what it is regardless of position.
		if v, ok := h.named[key]; ok && (key != "name" || i == 0) {
			segs[i] = v
			continue
		}
		// Otherwise the preceding segment names the resource family.
		if i > 0 {
			if v, ok := h.families[segs[i-1]]; ok {
				segs[i] = v
				continue
			}
		}
		if v, ok := h.named[key]; ok {
			segs[i] = v
			continue
		}
		// Deterministic placeholder: a fixed UUID keeps the recorded 404 stable across runs.
		segs[i] = missingID
	}
	return strings.Join(segs, "/")
}

// missingID is a syntactically valid identifier that no seeded row can carry, so a mutating
// request using it is rejected before it changes anything.
const missingID = "00000000-0000-4000-8000-000000000000"

// errorPath fills every parameter with missingID rather than a resolved value.
func errorPath(routePath string) string {
	segs := strings.Split(routePath, "/")
	for i, seg := range segs {
		if strings.HasPrefix(seg, ":") || strings.HasPrefix(seg, "*") {
			segs[i] = missingID
		}
	}
	return strings.Join(segs, "/")
}

func (h *goldenHarness) captureError(t *testing.T, method, routePath string) goldenFixture {
	t.Helper()
	req := httptest.NewRequest(method, errorPath(routePath), strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/vnd.api+json")
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)

	var body any
	if raw := rec.Body.Bytes(); len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			body = string(raw)
		}
	}
	return goldenFixture{Method: method, Path: routePath, Status: rec.Code, Body: normalise(body)}
}

func (h *goldenHarness) capture(t *testing.T, method, routePath string) goldenFixture {
	t.Helper()
	req := httptest.NewRequest(method, h.buildPath(routePath), nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/vnd.api+json")
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)

	var body any
	raw := rec.Body.Bytes()
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			// Not JSON (HTML error page, plain text): record it as a string so the fixture
			// still pins the response rather than silently dropping it.
			body = string(raw)
		}
	}
	normalised := normalise(body)
	if _, timeSensitive := timeSensitiveRoutes[method+" "+routePath]; timeSensitive {
		normalised = blankTimeVarying(normalised)
	}
	return goldenFixture{
		Method: method,
		Path:   routePath,
		Status: rec.Code,
		Body:   normalised,
	}
}

// --- tests ------------------------------------------------------------------

// safeMethods are the methods the harness records by default. Mutating verbs are captured
// only through their error paths (see TestGoldenErrorEnvelope), because replaying them
// against the seeded data would make every later fixture depend on test ordering.
var safeMethods = map[string]bool{http.MethodGet: true, http.MethodHead: true}

func TestGoldenResponses(t *testing.T) {
	h := setupGoldenHarness(t)

	routes := h.router.Routes()
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})

	if err := os.MkdirAll(goldenDir, 0o755); err != nil {
		t.Fatalf("create golden dir: %v", err)
	}

	var captured int
	for _, rt := range routes {
		if !safeMethods[rt.Method] {
			continue
		}
		if _, excluded := goldenExclusions[rt.Method+" "+rt.Path]; excluded {
			continue
		}
		rt := rt
		t.Run(rt.Method+" "+rt.Path, func(t *testing.T) {
			got := h.capture(t, rt.Method, rt.Path)
			path := filepath.Join(goldenDir, fixtureName(rt.Method, rt.Path))

			if *updateGolden {
				buf, err := json.MarshalIndent(got, "", "  ")
				if err != nil {
					t.Fatalf("marshal fixture: %v", err)
				}
				if err := os.WriteFile(path, append(buf, '\n'), 0o644); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
				return
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden fixture %s - run with -args -update to record it: %v", path, err)
			}
			var want goldenFixture
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatalf("parse fixture %s: %v", path, err)
			}

			if got.Status != want.Status {
				t.Errorf("status changed: got %d, want %d", got.Status, want.Status)
			}
			// Deep equality on parsed values: key order may move, nothing else may.
			if !reflect.DeepEqual(got.Body, want.Body) {
				gotJSON, _ := json.MarshalIndent(got.Body, "", "  ")
				wantJSON, _ := json.MarshalIndent(want.Body, "", "  ")
				t.Errorf("response body changed\n--- want ---\n%s\n--- got ---\n%s", wantJSON, gotJSON)
			}
		})
		captured++
	}

	if *updateGolden {
		writeRouteManifest(t, routes)
	}

	if captured == 0 {
		t.Fatal("captured no routes - the router did not build, or every route was excluded")
	}
	t.Logf("captured %d safe-method routes", captured)
}

// unseededFamilies are resource families the demo seeder does not create, so their routes are
// recorded at their not-found path. That is still a real fixture - it pins the shared error
// envelope, which this migration replaces with a single type - but it does not pin the
// resource payload, so the list is written down rather than left to be discovered.
//
// Shrinking this list is how Ansible-workflow, VCS-connection, task and registry-provider
// payload coverage improves; it needs the seeder to create those resources, not a change here.
// Every entry here is a deliberate honesty boundary, not a backlog (#758). Each of these
// resources implies an artefact the seeder cannot create: a state version implies a completed
// apply with state in object storage, a configuration version an uploaded archive, a VCS
// connection an OAuth token from a real provider, and a plan a runner execution with output in
// storage. A row without the artefact produces a payload no real deployment serves, and a
// fixture pinning a fiction is worse than one pinning a 404 - it reads as coverage.
var unseededFamilies = []string{
	"vcs-connections",
	"state-versions",
	"configuration-versions",
	"plans",
	"applies",
}

// TestGoldenFamiliesResolve fails when a family the harness claims to resolve has no seeded
// row. Without it, a seeder change could silently drop a whole family to its not-found path
// and the suite would still be green: 193 fixtures, quietly covering far less than before.
// This is the difference between enforcing coverage and reporting it.
func TestGoldenFamiliesResolve(t *testing.T) {
	h := setupGoldenHarness(t)

	var missing []string
	for family, table := range familyTables {
		if _, ok := h.families[family]; !ok {
			missing = append(missing, fmt.Sprintf("%s (table %s has no rows)", family, table))
		}
	}
	// The other direction (#758 AC2): a family listed as unseedable that actually has rows is a
	// stale honesty boundary - either the seeder grew support and the list was not updated, or
	// the entry never belonged. Both mean the 404 fixtures under it are hiding real coverage.
	unseedableTables := map[string]string{
		"vcs-connections":        "vcs_connections",
		"state-versions":         "state_versions",
		"configuration-versions": "configuration_versions",
	}
	for _, fam := range unseededFamilies {
		table, known := unseedableTables[fam]
		if !known {
			continue // no backing table to check (plans, applies)
		}
		var n int64
		if err := h.db.Table(table).Count(&n).Error; err == nil && n > 0 {
			missing = append(missing, fmt.Sprintf("%s is listed as unseedable but %s has %d row(s)", fam, table, n))
		}
	}

	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d resource famil(ies) the harness claims to resolve are unseeded, so their routes "+
			"record only the not-found path and the migration would touch their payloads blind:\n  %s\n\n"+
			"Either seed them in cmd/demoseed or move them to unseededFamilies with a reason.",
			len(missing), strings.Join(missing, "\n  "))
	}
	t.Logf("resolved %d/%d resource families; %d known-unseeded families recorded at their not-found path",
		len(h.families)-1, len(familyTables), len(unseededFamilies))
}

// TestGoldenErrorEnvelopeComplete is #757's regression guard: every recorded error body on a
// surface Stackweaver defines must carry the full JSON:API envelope - non-empty status, title
// and detail on every member of `errors`.
//
// Before the convergence there were four shapes, and which one a client got depended on which
// endpoint it called: 43 responses carried only a detail, 85 carried a bare {"error"}, five
// had no title, four spelled the status as a number under a different key. The helpers that
// produced those shapes are deleted, and this test is what fails if any of them is
// reinvented inline.
//
// Exempt by external specification, not by choice: the OAuth endpoints (RFC 6749 fixes their
// error body, and terraform login parses it) and the registry protocol (an array of plain
// strings, per HashiCorp's API docs, parsed by terraform init).
func TestGoldenErrorEnvelopeComplete(t *testing.T) {
	exempt := func(path string) bool {
		return strings.HasPrefix(path, "/v1/") ||
			strings.HasPrefix(path, "/v2/") || // registry download summaries share the protocol
			strings.Contains(path, "/oauth/") ||
			// The auth proxy is deliberately not JSON:API. routes.go says so where it mounts
			// these: "NOT under /api/v2/* - responses use Zitadel's v2 API shape, not JSON:API"
			// (DR-5). They pass Zitadel's own error bodies through - {code, details, message},
			// or {error, error_description} on the OIDC endpoints - because the custom login UI
			// is written against Zitadel's shapes. Rewrapping them in a JSON:API envelope would
			// be a breaking change to that client for the sake of a rule these routes were
			// never under.
			//
			// This exemption arrived with #790, which widened the harness to mount the router
			// production mounts rather than only its v2 half. The rule did not change; the
			// corpus it is applied to did, so its scope had to be stated rather than implied.
			strings.HasPrefix(path, "/auth/")
	}

	var violations []string
	for _, dir := range []string{goldenDir, filepath.Join(goldenDir, "errors")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || e.Name() == "routes.json" {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", e.Name(), err)
			}
			var fx goldenFixture
			if err := json.Unmarshal(raw, &fx); err != nil {
				t.Fatalf("parse %s: %v", e.Name(), err)
			}
			if fx.Status < 400 || exempt(fx.Path) {
				continue
			}
			body, ok := fx.Body.(map[string]any)
			if !ok {
				if fx.Body != nil {
					violations = append(violations, fmt.Sprintf("%s %s (%d): error body is not an object", fx.Method, fx.Path, fx.Status))
				}
				continue
			}
			errs, ok := body["errors"].([]any)
			if !ok || len(errs) == 0 {
				violations = append(violations, fmt.Sprintf("%s %s (%d): no errors array (members: %v)", fx.Method, fx.Path, fx.Status, keysOf(body)))
				continue
			}
			for _, el := range errs {
				obj, ok := el.(map[string]any)
				if !ok {
					violations = append(violations, fmt.Sprintf("%s %s (%d): errors element is not an object", fx.Method, fx.Path, fx.Status))
					continue
				}
				// status and title are required; detail is optional per the JSON:API spec,
				// and the title-only class (WriteErrorNoDetail, 117 sites) is legitimate.
				// What is NOT allowed is a detail key that is present but empty - that is a
				// bug, not brevity.
				for _, member := range []string{"status", "title"} {
					if v, _ := obj[member].(string); v == "" {
						violations = append(violations, fmt.Sprintf("%s %s (%d): %s missing or empty", fx.Method, fx.Path, fx.Status, member))
					}
				}
				if v, present := obj["detail"]; present {
					if str, _ := v.(string); str == "" {
						violations = append(violations, fmt.Sprintf("%s %s (%d): detail present but empty", fx.Method, fx.Path, fx.Status))
					}
				}
			}
		}
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Errorf("%d recorded error response(s) do not carry the full JSON:API envelope:\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestGoldenExclusionsAreLive fails on an exclusion that matches no registered route.
//
// This is not pedantry: the first version of goldenExclusions named
// "GET /api/v2/runs/:run_id/logs" while the route is registered as ":id", so the entry
// silently excluded nothing, the handler ran, and its panic destroyed a whole recording pass.
// A stale exclusion is worse than no exclusion, because it reads as deliberate coverage.
func TestGoldenExclusionsAreLive(t *testing.T) {
	h := setupGoldenHarness(t)

	registered := map[string]bool{}
	for _, rt := range h.router.Routes() {
		registered[rt.Method+" "+rt.Path] = true
	}

	var stale []string
	for key := range goldenExclusions {
		if !registered[key] {
			stale = append(stale, key)
		}
	}
	// Same standard for the time-sensitive list: an entry naming no real route silently
	// normalises nothing while reading as a deliberate decision.
	for key := range timeSensitiveRoutes {
		if !registered[key] {
			stale = append(stale, key+"  (timeSensitiveRoutes)")
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%d exclusion(s) match no registered route, so they exclude nothing:\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}

// routeManifest is the authoritative list of what the router serves, written alongside the
// fixtures so the OpenAPI generator does not have to re-derive it by parsing Go source.
//
// It comes from r.Routes() rather than a static scan, which makes it the same authority the
// coverage gate uses. A generator working from a second, weaker inventory would quietly
// document a different API than the one running.
type routeManifest struct {
	Routes []routeManifestEntry `json:"routes"`
}

type routeManifestEntry struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Excluded string `json:"excluded,omitempty"`
	Mutating bool   `json:"mutating"`
}

func writeRouteManifest(t *testing.T, routes gin.RoutesInfo) {
	t.Helper()
	m := routeManifest{}
	for _, rt := range routes {
		m.Routes = append(m.Routes, routeManifestEntry{
			Method:   rt.Method,
			Path:     rt.Path,
			Excluded: goldenExclusions[rt.Method+" "+rt.Path],
			Mutating: !safeMethods[rt.Method],
		})
	}
	sort.Slice(m.Routes, func(i, j int) bool {
		if m.Routes[i].Path == m.Routes[j].Path {
			return m.Routes[i].Method < m.Routes[j].Method
		}
		return m.Routes[i].Path < m.Routes[j].Path
	})
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshal route manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(goldenDir, "routes.json"), append(buf, '\n'), 0o644); err != nil {
		t.Fatalf("write route manifest: %v", err)
	}
	t.Logf("wrote route manifest with %d routes", len(m.Routes))
}

// TestGoldenErrorEnvelope records the error-path response of every mutating route.
//
// Replaying real mutations against the seeded data would make each fixture depend on the order
// the previous ones ran in, and would destroy the resources the GET fixtures describe. So every
// path parameter is deliberately set to a non-existent identifier and the body is empty: the
// handler rejects the request before touching anything, and what gets recorded is the envelope
// - status, `errors` array, object shape.
//
// That envelope is not a consolation prize. AC2 replaces 632 hand-built error payloads with one
// shared type, and this fixture set is what proves that substitution changed nothing. It runs
// against its own freshly seeded database so a mutation that slips through cannot contaminate
// the response fixtures.
func TestGoldenErrorEnvelope(t *testing.T) {
	h := setupGoldenHarness(t)

	dir := filepath.Join(goldenDir, "errors")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create error fixture dir: %v", err)
	}

	routes := h.router.Routes()
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})

	var captured int
	for _, rt := range routes {
		if safeMethods[rt.Method] {
			continue
		}
		if _, excluded := goldenExclusions[rt.Method+" "+rt.Path]; excluded {
			continue
		}
		rt := rt
		t.Run(rt.Method+" "+rt.Path, func(t *testing.T) {
			got := h.captureError(t, rt.Method, rt.Path)
			path := filepath.Join(dir, fixtureName(rt.Method, rt.Path))

			if *updateGolden {
				buf, err := json.MarshalIndent(got, "", "  ")
				if err != nil {
					t.Fatalf("marshal fixture: %v", err)
				}
				if err := os.WriteFile(path, append(buf, '\n'), 0o644); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
				return
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing error fixture %s - run with -args -update to record it: %v", path, err)
			}
			var want goldenFixture
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatalf("parse fixture %s: %v", path, err)
			}
			if got.Status != want.Status {
				t.Errorf("status changed: got %d, want %d", got.Status, want.Status)
			}
			if !reflect.DeepEqual(got.Body, want.Body) {
				gotJSON, _ := json.MarshalIndent(got.Body, "", "  ")
				wantJSON, _ := json.MarshalIndent(want.Body, "", "  ")
				t.Errorf("error envelope changed\n--- want ---\n%s\n--- got ---\n%s", wantJSON, gotJSON)
			}
		})
		captured++
	}
	t.Logf("captured %d mutating routes at their error path", captured)
}

// TestGoldenCoverage is the "nothing is skipped" gate. Every route the router registers must
// be covered by a fixture or named in goldenExclusions. A route that is neither would
// refactor with no safety net while the suite still reported green.
func TestGoldenCoverage(t *testing.T) {
	h := setupGoldenHarness(t)

	var uncovered []string
	for _, rt := range h.router.Routes() {
		key := rt.Method + " " + rt.Path
		if _, excluded := goldenExclusions[key]; excluded {
			continue
		}
		if safeMethods[rt.Method] {
			if _, err := os.Stat(filepath.Join(goldenDir, fixtureName(rt.Method, rt.Path))); err != nil {
				uncovered = append(uncovered, key+"  (no fixture)")
			}
			continue
		}
		// Mutating verbs are covered by the error-envelope fixture set.
		if _, err := os.Stat(filepath.Join(goldenDir, "errors", fixtureName(rt.Method, rt.Path))); err != nil {
			uncovered = append(uncovered, key+"  (no error-path fixture)")
		}
	}
	sort.Strings(uncovered)

	if len(uncovered) > 0 {
		t.Errorf("%d registered route(s) have neither a fixture nor a named exclusion - "+
			"the typed-response migration would touch them with no safety net:\n  %s",
			len(uncovered), strings.Join(uncovered, "\n  "))
	}
}

var _ = time.Now // retained for fixture timestamp work in later phases
