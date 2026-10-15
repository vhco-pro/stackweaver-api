// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Golden write recorder (#869).
//
// TestGoldenResponses records what the API answers to a read, and TestGoldenErrorEnvelope what it
// answers to a write it refuses. Neither says what a write must SEND or what it gets back when it
// succeeds, so the OpenAPI document built from them describes 244 mutating operations by their
// refusal alone. This recorder performs one real, accepted write per mutating route and records
// the request and the response.
//
// It is a local gate and not a CI workload. It needs a queue and object storage that are not the
// dev stack's own, and it gets them from the worktree's slot (scripts/agent-slot.sh), so it runs
// only where there is one:
//
//	make test-integration        # from a worktree with a slot: compares
//	make record-golden-writes    # from a worktree with a slot: re-records
//
// A bare `go test -tags integration`, which is what the GitHub job runs, skips it and says why.
// See docs/internal/plans/infrastructure/api/openapi-write-side-and-single-reference-plan.md.

//go:build integration
// +build integration

package routes_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/queue"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/storage"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// The write phase reads its settings under names nothing else reads. The queue and storage
// clients are configured from REDIS_DB, STORAGE_BUCKET and friends, and so is every other
// recorder's router; if `make` exported those for the whole test run, the read and error
// recorders would be pointed at the slot too and their fixtures would stop describing what they
// describe today. The recorder copies these into the real names with t.Setenv, for its own test
// only.
const (
	envWritePhase     = "GOLDEN_WRITE_PHASE"
	envWriteRedisDB   = "GOLDEN_WRITE_REDIS_DB"
	envWriteRedisHost = "GOLDEN_WRITE_REDIS_HOST"
	envWriteBucket    = "GOLDEN_WRITE_STORAGE_BUCKET"
	envWriteEndpoint  = "GOLDEN_WRITE_STORAGE_ENDPOINT"
	envWriteAccessKey = "GOLDEN_WRITE_STORAGE_ACCESS_KEY"
	envWriteSecretKey = "GOLDEN_WRITE_STORAGE_SECRET_KEY"
	// envWriteSeed fixes the order the cases run in, to reproduce a run. Unset, every run
	// shuffles differently and logs the seed it used.
	envWriteSeed = "GOLDEN_WRITE_SEED"
	// envWriteOnly narrows a run to the routes that contain it, while a family of cases is written.
	envWriteOnly = "GOLDEN_WRITE_ONLY"

	writePhaseSkipHelp  = "the golden write recorder is a local gate: run `make test-integration` from a worktree that has a slot (`scripts/agent-slot.sh create`)"
	provisionSlotAdvice = "run `scripts/agent-slot.sh create` in this worktree, then `make test-integration`"

	mainStackBucket  = "stackweaver"
	mainStackRedisDB = 0
	slotBucketPrefix = "sw-wt-"
)

// writeSettings is where the write recorder's queue and object storage live.
type writeSettings struct {
	RedisDB   string // as given; check parses it, because the queue's own parser falls back to 0
	RedisHost string
	Bucket    string
	Endpoint  string
	AccessKey string
	SecretKey string
}

func writeSettingsFromEnv() writeSettings {
	return writeSettings{
		RedisDB:   os.Getenv(envWriteRedisDB),
		RedisHost: os.Getenv(envWriteRedisHost),
		Bucket:    os.Getenv(envWriteBucket),
		Endpoint:  os.Getenv(envWriteEndpoint),
		AccessKey: os.Getenv(envWriteAccessKey),
		SecretKey: os.Getenv(envWriteSecretKey),
	}
}

// slot returns the worktree slot the Redis database names. It is strict on purpose: core/queue
// reads REDIS_DB with a parser that returns 0 for anything it cannot read, and 0 is the main
// stack's live queue, so "three", "" and " 3" must be refusals here rather than a silent 0 there.
func (s writeSettings) slot() (int, error) {
	n, err := strconv.Atoi(s.RedisDB)
	if err != nil || n < 0 || strconv.Itoa(n) != s.RedisDB {
		return 0, fmt.Errorf("Redis database %q is not a slot number; %s", s.RedisDB, provisionSlotAdvice)
	}
	if n == mainStackRedisDB {
		return 0, fmt.Errorf("Redis logical database 0 is the main stack's live queue, and a job enqueued there is executed by its orchestrator; %s", provisionSlotAdvice)
	}
	return n, nil
}

// check refuses every setting that is not a worktree slot's own Redis database and bucket. It is
// an allow-list: the bucket must be exactly the one scripts/agent-slot.sh names for that slot.
func (s writeSettings) check() error {
	n, err := s.slot()
	if err != nil {
		return err
	}
	want := slotBucketPrefix + strconv.Itoa(n)
	if s.Bucket != want {
		if s.Bucket == mainStackBucket || s.Bucket == "" {
			return fmt.Errorf("bucket %q is the main stack's (%s), not slot %d's %s; %s", s.Bucket, mainStackBucket, n, want, provisionSlotAdvice)
		}
		return fmt.Errorf("bucket %q is not slot %d's bucket %s; %s", s.Bucket, n, want, provisionSlotAdvice)
	}
	return nil
}

// applyToEnv points the queue and storage clients of every router this test builds at the slot.
//
// SetupRoutes reads these from the process environment itself, so they cannot be handed to it
// as an argument the way the identity settings are. t.Setenv scopes them to this test: the read
// and error recorders, in the same package, never see them.
func (s writeSettings) applyToEnv(t *testing.T) {
	t.Helper()
	t.Setenv("REDIS_DB", s.RedisDB)
	if s.RedisHost != "" {
		t.Setenv("REDIS_HOST", s.RedisHost)
	}
	t.Setenv("STORAGE_BACKEND", "s3")
	t.Setenv("STORAGE_BUCKET", s.Bucket)
	if s.Endpoint != "" {
		t.Setenv("STORAGE_ENDPOINT", s.Endpoint)
	}
	t.Setenv("STORAGE_ACCESS_KEY", s.AccessKey)
	t.Setenv("STORAGE_SECRET_KEY", s.SecretKey)
}

// writeCase is one mutating route and how to make a request it accepts.
//
// The cases are Go rather than a file of request bodies because a successful write cannot be
// written down ahead of time: seeded identifiers are freshly random on every seed, so a body
// that names a workspace or an inventory has to be built from what the run finds, and many
// writes need another write first (an upload needs the version it uploads to).
type writeCase struct {
	// route is "METHOD /path" exactly as gin registers it, which is how fixtures are keyed.
	route string
	// prepare readies the case's own database copy and returns the request to record. It may
	// send earlier requests through w.send, mint a credential the way the server does, or write
	// to w.db directly. None of that is recorded under this route.
	prepare func(t *testing.T, w *writeRun) *http.Request

	// requestSecrets and responseSecrets are dotted paths (a field name, for a form) to every
	// value that is a secret: a credential the request sends, a token the server generates and
	// returns once. Each is committed and published as the secret placeholder, and a declared
	// path that is not there fails the case. Secrets are declared, never guessed from a name.
	requestSecrets  []string
	responseSecrets []string

	// responseVaries are dotted paths to response members the server fills with a fresh random
	// value on every call and that are not secrets: the challenge a passkey registration asks
	// the authenticator to sign. Each is committed as the varies placeholder, and like a secret,
	// a declared path that is not there fails the case.
	responseVaries []string

	// env is set in the process environment while this case's router is built and its request
	// served, and put back afterwards. The server reads some settings once, when it starts (a
	// webhook's signing secret, whether a run task may live on a private address), so a case
	// that needs one has to have it in place before the router exists.
	env map[string]string
}

// The four reasons a mutating route may be named instead of recorded. The list is closed: "it
// was hard to set up" is not on it, and a route that fits none of these and cannot be recorded
// is a question for the owner, not a fifth reason.
type namedReason string

const (
	// needsOutsideSystem: success reaches a system outside the machine - a VCS provider
	// answering an OAuth exchange or registering a webhook, an external identity provider, a
	// notification delivered to a configured target.
	needsOutsideSystem namedReason = "needs a system outside the machine"
	// needsAuthenticator: success needs a passkey or security key, which a test cannot hold.
	needsAuthenticator namedReason = "needs a physical authenticator"
	// needsRunnerArtefact: success needs something only a runner produces, the same boundary
	// unseededFamilies draws for reads.
	needsRunnerArtefact namedReason = "needs an artefact only a runner produces"
	// needsInstanceSetting: success needs an identity-provider setting the whole instance
	// shares to be changed, which the recorder never does.
	needsInstanceSetting namedReason = "needs an instance-wide identity-provider setting changed"
)

// namedWrite is a mutating route the recorder does not record, and why. A named route is never
// sent.
type namedWrite struct {
	reason namedReason
	// detail says what, specifically, this route would need. It is published in the
	// operation's description.
	detail string
}

// writeNamed is every mutating route that is named instead of recorded, keyed like a case.
var writeNamed = map[string]namedWrite{}

// registerWriteCases adds a family's cases to the table. The families live in files of their
// own, golden_write_cases_*_test.go, and register from init.
func registerWriteCases(cases ...writeCase) { writeCases = append(writeCases, cases...) }

// nameWrites adds routes that are named instead of recorded.
func nameWrites(named map[string]namedWrite) {
	for route, n := range named {
		writeNamed[route] = n
	}
}

// writeRun is one case's world: a private copy of the seeded database and a router over it.
type writeRun struct {
	t       *testing.T
	db      *gorm.DB
	router  *gin.Engine
	token   string
	resolve *goldenHarness // path parameters, resolved once from the seed; the copies are identical

	// What the case may do at the identity provider. See golden_write_identity_test.go.
	rec   *writeRecorder
	n     int
	guard *identityGuard
	users []identityUser // created for this case, deleted when it ends

	// published maps a value that exists only in this run to what the fixture shows in its
	// place. See publishAs.
	published [][2]string
}

// publishAs makes the fixture show placeholder wherever value appears, in the request and in the
// response.
//
// It is for a value the case had to invent for the run and that a reader would be misled by: the
// address of a stand-in for a service outside the machine, which is a loopback port here and a
// real host for anyone calling the API. The request the server accepted is still what is
// recorded; one value in it is named for what it stands for.
func (w *writeRun) publishAs(value, placeholder string) {
	w.published = append(w.published, [2]string{value, placeholder})
}

// path fills a registered route's parameters from the seeded data.
func (w *writeRun) path(routePath string) string { return w.resolve.buildPath(routePath) }

// id is the identifier of the seeded row a route family resolves to ("workspaces", "teams",
// "job-templates": the keys of familyTables), the same row w.path puts in a URL.
func (w *writeRun) id(family string) string {
	v, ok := w.resolve.families[family]
	if !ok {
		panic("golden write case asked for a seeded " + family + " and the seed has none")
	}
	return v
}

// org is the seeded organization's name.
func (w *writeRun) org() string { return w.id("organizations") }

// dataID is the `data.id` of a JSON:API document a preparation step got back.
func dataID(t *testing.T, doc map[string]any) string {
	t.Helper()
	data, _ := doc["data"].(map[string]any)
	id, _ := data["id"].(string)
	if id == "" {
		t.Fatalf("preparation returned a document with no data.id: %v", doc)
	}
	return id
}

// document is a JSON:API request document, which is what nearly every write sends.
func document(resourceType string, attributes map[string]any) map[string]any {
	data := map[string]any{"type": resourceType}
	if attributes != nil {
		data["attributes"] = attributes
	}
	return map[string]any{"data": data}
}

// related adds a to-one relationship to a document built by document.
func related(doc map[string]any, name, resourceType, id string) map[string]any {
	data := doc["data"].(map[string]any)
	rels, _ := data["relationships"].(map[string]any)
	if rels == nil {
		rels = map[string]any{}
		data["relationships"] = rels
	}
	rels[name] = map[string]any{"data": map[string]any{"type": resourceType, "id": id}}
	return doc
}

// jsonRequest builds an authenticated JSON:API request. body may be nil for a write that takes none.
func (w *writeRun) jsonRequest(t *testing.T, method, target string, body any) *http.Request {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
	}
	return w.rawRequest(method, target, "application/vnd.api+json", raw)
}

func (w *writeRun) rawRequest(method, target, contentType string, body []byte) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+w.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

// send performs a request against this case's router. Preparation uses it for the writes that
// have to happen first; the recorder uses it for the write being recorded.
//
// Every request passes the identity guard first: one that names a user, a session or a token
// subject this run did not create is a mistake in a case that could lock a real person out of
// the shared identity provider, so it ends the test before the router sees it.
func (w *writeRun) send(req *http.Request) *httptest.ResponseRecorder {
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = io.ReadAll(req.Body); err != nil {
			w.t.Fatalf("read the body of %s %s: %v", req.Method, req.URL.Path, err)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	if err := w.guard.check(req, body); err != nil {
		w.t.Fatalf("identity guard: %v", err)
	}
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	return rec
}

// mustSend is send for a preparation step, which has to succeed for the case to mean anything.
func (w *writeRun) mustSend(t *testing.T, req *http.Request) map[string]any {
	t.Helper()
	rec := w.send(req)
	if rec.Code < 200 || rec.Code > 299 {
		t.Fatalf("preparation %s %s answered %d: %s", req.Method, req.URL.Path, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("preparation %s %s returned a body that is not JSON: %v", req.Method, req.URL.Path, err)
		}
	}
	return out
}

// writeCases is the table: one entry per mutating route. The entries live in a file per family,
// golden_write_cases_*_test.go, each registering from init.
var writeCases []writeCase

// tinyConfigArchive is the smallest tar.gz a configuration version upload can carry: one
// main.tf. The handler stores the bytes as it gets them, so the content only has to be real.
func tinyConfigArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("# recorded by the golden write harness\n")
	if err := tw.WriteHeader(&tar.Header{Name: "main.tf", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatalf("write archive header: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("write archive body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

// writeRecorder owns the seeded database every case is copied from.
type writeRecorder struct {
	admin    *gorm.DB // connected to the maintenance database, to create and drop copies
	baseURL  url.URL
	seedName string
	token    string
	resolve  *goldenHarness

	binds *bindObserver // what the handler behind the recorded request bound

	// The identity provider: its settings, the one client that holds the owner token, and the
	// part of a user name that is this run's own.
	identity *writeIdentity
	owner    *ownerClient
	runID    string

	started time.Time // when this run began, which bounds what counts as its clock in a fixture

	// store is the slot's bucket, and bucketAtStart what it held before the first case. The
	// slot is the developer's, so what was there stays; what the run adds is the run's to remove.
	store         storage.Client
	bucketAtStart map[string]bool

	// Copies are dropped behind the run by a few workers.
	//
	// A few, and not one goroutine per copy: DROP DATABASE forces a checkpoint and waits for it,
	// from a tenth of a second to several seconds on a busy server, holding a connection all the
	// while. The server is shared with the development stack and with other sessions and allows
	// a hundred connections in all, so the number waiting has to be bounded. Not one worker
	// either: drops that wait together are released by the same checkpoint, and one at a time
	// they took 1.3s each where six together kept pace with the cases (measured).
	//
	// The queue is bounded so that a server slow to checkpoint slows the recorder down instead
	// of letting copies pile up on disk.
	dropQueue chan string
	drops     sync.WaitGroup
	stopDrops sync.Once
	dropMu    sync.Mutex
	dropErrs  map[string]error
}

// Bounds on what the recorder may hold on the shared Postgres at once.
const (
	dropWorkers           = 6
	maxCopiesAwaitingDrop = 16              // about 13 MB each
	maxAdminConns         = dropWorkers + 1 // and one creating copies
	maxCaseConns          = 8               // one case's router and its handlers
)

// dropWorker drops queued copies. It is scoped to the names run created.
func (r *writeRecorder) dropWorker() {
	defer r.drops.Done()
	for name := range r.dropQueue {
		// FORCE ends whatever a handler's leftover goroutine still holds; its next query fails,
		// which is the intended end.
		if err := r.admin.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %q (FORCE)", name)).Error; err != nil {
			r.dropMu.Lock()
			r.dropErrs[name] = err
			r.dropMu.Unlock()
		}
	}
}

// finishDrops lets the workers drain the queue and waits for them. Safe to call more than once.
func (r *writeRecorder) finishDrops() {
	r.stopDrops.Do(func() { close(r.dropQueue) })
	r.drops.Wait()
}

// waitForDrops blocks until every copy is gone and fails the test for any that is not: a
// database this recorder created and could not drop is litter on a server other sessions share.
func (r *writeRecorder) waitForDrops(t *testing.T) {
	t.Helper()
	r.finishDrops()
	for _, name := range sortedKeys(r.dropErrs) {
		t.Errorf("drop database %s: %v", name, r.dropErrs[name])
	}
}

// newWriteRecorder seeds a database the way the read recorder does, takes from it everything a
// case needs to know (the token, the identifiers path parameters resolve to), and then closes
// every connection to it: Postgres refuses to copy a database anything is connected to.
func newWriteRecorder(t *testing.T) *writeRecorder {
	t.Helper()
	h := setupGoldenHarness(t)

	var seedName string
	if err := h.db.Raw("SELECT current_database()").Scan(&seedName).Error; err != nil || seedName == "" {
		t.Fatalf("read the seeded database's name: %v", err)
	}
	if !strings.HasPrefix(seedName, "golden_api_") {
		t.Fatalf("seeded database is %q; the write recorder only ever copies and drops golden_api_ databases", seedName)
	}

	// The API reconciles its ON DELETE rules on every startup, and AutoMigrate, which is all a
	// throwaway database gets, leaves the constraints bare. A read never notices. A delete does:
	// removing an organization is one DELETE that relies on the cascade, and without the rules
	// it fails on the first child row. The copies inherit them from the seed.
	if _, err := models.ReconcileFKDeleteRules(h.db); err != nil {
		t.Fatalf("reconcile the delete rules on the seeded database: %v", err)
	}

	if sqlDB, err := h.db.DB(); err == nil {
		_ = sqlDB.Close()
	}

	u, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	adminURL := *u
	adminURL.Path = "/postgres"
	admin, err := dbtest.Open(t, adminURL.String(), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect admin db: %v", err)
	}
	if sqlDB, err := admin.DB(); err == nil {
		sqlDB.SetMaxOpenConns(maxAdminConns)
	}
	r := &writeRecorder{
		started: time.Now(),
		admin:   admin, baseURL: *u, seedName: seedName, token: h.token, resolve: h,
		dropQueue: make(chan string, maxCopiesAwaitingDrop),
		dropErrs:  map[string]error{},
	}
	r.drops.Add(dropWorkers)
	for range dropWorkers {
		go r.dropWorker()
	}
	t.Cleanup(func() {
		// Also on a fatal exit: the drops use this connection, and the seed's own cleanup,
		// registered earlier and so run later, drops the template they were copied from.
		r.finishDrops()
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return r
}

// bucketKeys lists the slot's bucket.
func (r *writeRecorder) bucketKeys(t *testing.T) map[string]bool {
	t.Helper()
	objects, err := r.store.List(context.Background(), "")
	if err != nil {
		t.Fatalf("list the slot's bucket: %v", err)
	}
	keys := make(map[string]bool, len(objects))
	for _, o := range objects {
		keys[o.Key] = true
	}
	return keys
}

// removeAddedSince deletes every object in the bucket that is not in before, and returns how
// many there were.
//
// A listing and not a naming rule decides what is the run's: handlers choose their own keys
// (a workspace's state, a configuration archive, a registry upload), and no prefix a case
// could impose covers them all. This is also why one recorder runs in a slot at a time, with
// the slot's own API stopped: anything else writing to the bucket meanwhile would be taken
// for the run's and removed.
func (r *writeRecorder) removeAddedSince(t *testing.T, before map[string]bool) int {
	t.Helper()
	removed := 0
	for key := range r.bucketKeys(t) {
		if before[key] {
			continue
		}
		if err := r.store.Delete(context.Background(), key); err != nil {
			t.Errorf("remove %s, which this run stored in the slot's bucket: %v", key, err)
			continue
		}
		removed++
	}
	return removed
}

// open gives a case its world: a copy of the seeded database and a router over it. done throws
// both away, and removes whatever the case created at the identity provider.
func (r *writeRecorder) open(t *testing.T, n int, label string) (w *writeRun, done func()) {
	t.Helper()
	name := fmt.Sprintf("%s_w%03d", r.seedName, n)
	if err := r.admin.Exec(fmt.Sprintf("CREATE DATABASE %q TEMPLATE %q", name, r.seedName)).Error; err != nil {
		t.Fatalf("copy the seeded database for %s: %v", label, err)
	}
	target := r.baseURL
	target.Path = "/" + name
	db, err := dbtest.Open(t, target.String(), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect %s: %v", name, err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(maxCaseConns)
	}
	w = &writeRun{t: t, db: db, token: r.token, resolve: r.resolve, rec: r, n: n, guard: newIdentityGuard()}
	// The copy is dropped behind the run, not in its way: a drop waits for a checkpoint, which
	// takes from a tenth of a second to several seconds on a busy server, more than every other
	// step of a case put together. See dropQueue.
	done = func() {
		for _, u := range w.users {
			if err := r.owner.deleteUser(context.Background(), u.ID); err != nil {
				t.Errorf("%s: %v", label, err)
			}
		}
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		r.dropQueue <- name
	}

	// The services are built on the copy, not shared: the ones the seed harness built hold a
	// pool on the seeded database, which is closed.
	authService := auth.NewService(repository.NewUserRepository(db))
	authService.SetAPIKeyService(apikey.NewService(
		repository.NewAPIKeyRepository(db),
		repository.NewOrganizationRepository(db),
		repository.NewProjectRepository(db),
		repository.NewTeamRepository(db),
	))
	settings := identityFromEnv()
	if r.identity != nil {
		// What backend/cmd/api/main.go does at startup, so that a token the identity provider
		// issued to a signed-in user is one this router can verify.
		id := r.identity
		if err := authService.InitializeZitadel(id.Issuer, id.APIClientID, id.APIClientSecret, id.Addr); err != nil {
			done()
			t.Fatalf("initialise the auth service for %s: %v", label, err)
		}
		authService.RegisterAudience(id.APIClientID)
		authService.RegisterAudience(id.FrontendClientID)
		settings = id.harness()
	}
	w.router = buildHarnessRouter(t, db, authService, settings)
	return w, done
}

// run gives one case its own copy of the seeded database and its own router, runs it, and
// throws both away.
//
// A copy per case is what makes a write as safe to record as a read: every case sees the same
// pristine data, so the result cannot depend on what ran before it, and a case may destroy
// anything. A router per case, rather than one router over a database swapped underneath it,
// is deliberate too. Handlers start goroutines that outlive their response, and on a shared
// pool that late work would land in the next case's data; and a pool does not notice that its
// connections were killed until they have been idle for a second.
func (r *writeRecorder) run(t *testing.T, n int, wc writeCase) (fx writeFixture, body []byte, ok bool) {
	t.Helper()
	for name, value := range wc.env {
		previous, had := os.LookupEnv(name)
		if err := os.Setenv(name, value); err != nil {
			t.Fatalf("%s: set %s: %v", wc.route, name, err)
		}
		defer func() {
			if had {
				_ = os.Setenv(name, previous)
			} else {
				_ = os.Unsetenv(name)
			}
		}()
	}
	copyStart := time.Now()
	// Each case leaves the bucket as it found it, so that no case sees what another stored.
	held := r.bucketKeys(t)
	defer r.removeAddedSince(t, held)
	w, done := r.open(t, n, wc.route)
	defer done()
	routerStart := time.Now()

	req := wc.prepare(t, w)
	var sent []byte
	var err error
	if req.Body != nil {
		if sent, err = io.ReadAll(req.Body); err != nil {
			t.Fatalf("%s: read the request the case built: %v", wc.route, err)
		}
		req.Body = io.NopCloser(bytes.NewReader(sent))
	}

	// Only the recorded request's bind counts; preparation binds too.
	r.binds.reset()
	requestStart := time.Now()
	rec := w.send(req)
	bound := r.binds.bound()
	t.Logf("%-55s copy and router %s, preparation %s, request %s", wc.route,
		routerStart.Sub(copyStart).Round(time.Millisecond), requestStart.Sub(routerStart).Round(time.Millisecond),
		time.Since(requestStart).Round(time.Millisecond))

	method, path, _ := strings.Cut(wc.route, " ")
	fx = writeFixture{Method: method, Path: path, Status: rec.Code}
	if rec.Code < 200 || rec.Code > 299 {
		return fx, rec.Body.Bytes(), false
	}
	idn := w.identityNormaliser()
	if fx.Request, err = describeRequest(req, sent, bound, wc.requestSecrets, idn); err != nil {
		t.Errorf("%s: %v", wc.route, err)
		return fx, rec.Body.Bytes(), false
	}
	if fx.Response, err = describeResponse(rec.Body.Bytes(), wc.responseSecrets, wc.responseVaries, idn); err != nil {
		t.Errorf("%s: %v", wc.route, err)
		return fx, rec.Body.Bytes(), false
	}
	return fx, rec.Body.Bytes(), true
}

// TestGoldenWrites is the write recorder. It is skipped unless the local switch is set.
//
// The switch is explicit rather than inferred from "Redis is reachable": the GitHub integration
// job has a Redis service and must not run this, and a local run with the stack down must fail
// rather than pass by skipping.
func TestGoldenWrites(t *testing.T) {
	if os.Getenv(envWritePhase) == "" {
		t.Skip(writePhaseSkipHelp)
	}
	settings := writeSettingsFromEnv()
	if err := settings.check(); err != nil {
		t.Fatalf("golden write recorder: %v", err)
	}
	settings.applyToEnv(t)

	// A marker in the worktree means a slot was claimed, not that it was provisioned. The
	// storage client fails to construct when its bucket is missing (the dev key may not create
	// one), and a router built without storage answers 500 on every upload, so check first.
	store, err := storage.NewClient(context.Background(), storage.ConfigFromEnv())
	if err != nil || store == nil {
		t.Fatalf("golden write recorder: slot bucket %s is not usable (%v); %s", settings.Bucket, err, provisionSlotAdvice)
	}

	r := newWriteRecorder(t)
	r.binds = observeBinds(t)
	r.attachIdentity(t)
	r.store = store
	r.bucketAtStart = r.bucketKeys(t)

	// A shuffled order on every run, from a seed that is logged: a case that depended on an
	// earlier one would show up as a result that changes between runs.
	seed := time.Now().UnixNano()
	if v := os.Getenv(envWriteSeed); v != "" {
		if seed, err = strconv.ParseInt(v, 10, 64); err != nil {
			t.Fatalf("%s %q is not a number", envWriteSeed, v)
		}
	}
	order := rand.New(rand.NewSource(seed)).Perm(len(writeCases)) //nolint:gosec // ordering, not security
	t.Logf("golden write recorder: %d cases, order seed %d", len(writeCases), seed)

	// While a family of cases is being written, GOLDEN_WRITE_ONLY narrows the run to the routes
	// it matches: a regular expression over "METHOD /path", so a plain piece of a route selects
	// every route containing it and `^POST /api/v2/organizations$` selects exactly one. A
	// narrowed run never rewrites or judges the routes it left out.
	only := os.Getenv(envWriteOnly)
	onlyRe, err := regexp.Compile(only)
	if err != nil {
		t.Fatalf("%s %q is not a regular expression: %v", envWriteOnly, only, err)
	}
	selected := func(route string) bool { return only == "" || onlyRe.MatchString(route) }

	goroutinesBefore, redisBefore := runtime.NumGoroutine(), redisClients(t)
	started := time.Now()
	ran := 0
	for n, i := range order {
		wc := writeCases[i]
		if !selected(wc.route) {
			continue
		}
		ran++
		caseStart := time.Now()
		fx, body, ok := r.run(t, n, wc)
		if fx.Status < 200 || fx.Status > 299 {
			t.Errorf("%s answered %d, not a 2xx; a case has to be a write the server accepts:\n%s", wc.route, fx.Status, body)
			continue
		}
		if !ok {
			continue // run reported why
		}
		saveOrCompare(t, fx)
		t.Logf("%-55s %d  %s", wc.route, fx.Status, time.Since(caseStart).Round(time.Millisecond))
	}
	cases := time.Since(started)
	r.waitForDrops(t)
	// Every case removes what it stored. A handler that writes an object after it has answered
	// can still do so once its case has moved on, so the whole run is swept once more here, now
	// that every copy is dropped and nothing of the run is left running; anything still there
	// after that is a failure.
	if late := r.removeAddedSince(t, r.bucketAtStart); late > 0 {
		t.Logf("golden write recorder: removed %d object(s) stored after their case had ended", late)
	}
	for key := range r.bucketKeys(t) {
		if !r.bucketAtStart[key] {
			t.Errorf("the run left %s in the slot's bucket", key)
		}
	}
	// Every case deletes the users it created. This looks, under this run's own prefix only:
	// the provider's whole user list changes whenever another session's browser tests run.
	if left := r.identityLeftovers(t); len(left) > 0 {
		t.Errorf("users this run created are still at the identity provider: %v", left)
	}

	// A named route has a fixture too, holding its reason, so the generator can say why the
	// operation has no recorded request or success response. Nothing is sent for it.
	named := 0
	for _, route := range sortedKeys(writeNamed) {
		if !selected(route) {
			continue
		}
		named++
		method, path, _ := strings.Cut(route, " ")
		n := writeNamed[route]
		saveOrCompare(t, writeFixture{Method: method, Path: path, Named: &writeFixtureNamed{Reason: string(n.reason), Detail: n.detail}})
	}
	if ran == 0 && named == 0 {
		t.Fatalf("no case matched %s=%q", envWriteOnly, only)
	}
	if ran == 0 {
		return
	}
	t.Logf("golden write recorder: %d cases in %s (%s per case), plus %s waiting for the last copies to drop; goroutines %d -> %d, Redis clients %d -> %d",
		ran, cases.Round(time.Millisecond), (cases / time.Duration(ran)).Round(time.Millisecond),
		(time.Since(started) - cases).Round(time.Millisecond),
		goroutinesBefore, runtime.NumGoroutine(), redisBefore, redisClients(t))
}

// TestGoldenWriteCoverage is the "nothing is silently skipped" rule for writes: every mutating
// route the server registers is either recorded by a case or named with one of the four reasons.
//
// It reads the committed route manifest, so it needs no service. It is still part of the write
// phase and runs only under the local switch, by the owner's decision that nothing about writes
// runs on GitHub.
func TestGoldenWriteCoverage(t *testing.T) {
	if os.Getenv(envWritePhase) == "" {
		t.Skip(writePhaseSkipHelp)
	}
	raw, err := os.ReadFile(filepath.Join(goldenDir, "routes.json"))
	if err != nil {
		t.Fatalf("read the route manifest: %v", err)
	}
	var man routeManifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatalf("parse the route manifest: %v", err)
	}
	mutating := map[string]bool{}
	for _, rt := range man.Routes {
		if rt.Mutating {
			mutating[rt.Method+" "+rt.Path] = true
		}
	}

	routes := make([]string, 0, len(writeCases))
	for _, wc := range writeCases {
		routes = append(routes, wc.route)
	}
	for _, problem := range writeCoverageProblems(mutating, routes, writeNamed) {
		t.Error(problem)
	}

	// And the other way round: a fixture nothing produces any more would still be read by the
	// generator and published.
	expected := map[string]bool{}
	for _, route := range routes {
		expected[filepath.Base(writeFixturePath(route))] = true
	}
	for route := range writeNamed {
		expected[filepath.Base(writeFixturePath(route))] = true
	}
	entries, err := os.ReadDir(goldenWriteDir)
	if err != nil {
		t.Fatalf("read %s: %v", goldenWriteDir, err)
	}
	for _, e := range entries {
		if !expected[e.Name()] {
			t.Errorf("%s/%s belongs to no case and no named route; delete it", goldenWriteDir, e.Name())
		}
	}
}

// writeCoverageProblems is the coverage rule itself, apart from where the three lists come from:
// every mutating route is recorded once or named once, never both; a case or a name that matches
// no route is stale; and a name carries one of the four reasons and says what the route needs.
func writeCoverageProblems(mutating map[string]bool, cases []string, named map[string]namedWrite) []string {
	var problems []string
	recorded := map[string]bool{}
	for _, route := range cases {
		if recorded[route] {
			problems = append(problems, fmt.Sprintf("%s has more than one case; a route is recorded once", route))
		}
		recorded[route] = true
		if !mutating[route] {
			problems = append(problems, fmt.Sprintf("case %s matches no mutating route the server registers", route))
		}
	}
	reasons := map[namedReason]bool{needsOutsideSystem: true, needsAuthenticator: true, needsRunnerArtefact: true, needsInstanceSetting: true}
	for _, route := range sortedKeys(named) {
		n := named[route]
		if !mutating[route] {
			problems = append(problems, fmt.Sprintf("named route %s matches no mutating route the server registers; a stale name reads as deliberate coverage", route))
		}
		if recorded[route] {
			problems = append(problems, fmt.Sprintf("%s is both recorded and named", route))
		}
		if !reasons[n.reason] {
			problems = append(problems, fmt.Sprintf("%s is named for %q, which is not one of the four reasons a route may be named", route, n.reason))
		}
		if strings.TrimSpace(n.detail) == "" {
			problems = append(problems, fmt.Sprintf("%s is named without saying what it would need", route))
		}
	}

	var missing []string
	for route := range mutating {
		if _, isNamed := named[route]; !recorded[route] && !isNamed {
			missing = append(missing, route)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		problems = append(problems, fmt.Sprintf("%d of %d mutating routes are neither recorded nor named:\n  %s",
			len(missing), len(mutating), strings.Join(missing, "\n  ")))
	}
	return problems
}

// redisClients is how many connections the slot's Redis reports, for the feasibility report:
// every router build opens clients and closes none.
func redisClients(t *testing.T) int {
	t.Helper()
	q, err := queue.NewRedisQueueFromEnv()
	if err != nil {
		t.Fatalf("connect to the slot's Redis: %v", err)
	}
	info, err := q.Client().Info(context.Background(), "clients").Result()
	if err != nil {
		t.Fatalf("read Redis client count: %v", err)
	}
	for _, line := range strings.Split(info, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "connected_clients:"); ok {
			n, _ := strconv.Atoi(v)
			return n
		}
	}
	return -1
}
