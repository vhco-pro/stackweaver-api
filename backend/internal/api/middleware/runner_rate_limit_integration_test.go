// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test for the runner-route rate limits through the production chain (#933, D3,
// AC74): the global per-IP limiter at its defaults, the real API-key authentication against the
// database, the real RunnerAuth and the per-principal limiter at its defaults. Three hundred
// launchers, each with its own database-backed runner token, all from one source address,
// heartbeat and their executors stream output with no 429; one executor far over its budget is
// throttled alone; and the per-IP limiter still governs every route outside /api/v2/runner/.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Every row is created under a
// unique name and removed by primary key. Run with:
//
//	go test -tags integration ./internal/api/middleware/ -run TestRunnerRateLimit_ThreeHundredLaunchersBehindOneAddress

//go:build integration

package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

const (
	launchers   = 300
	executors   = 20
	natAddress  = "203.0.113.7:4000" // every request from one address, as behind a NAT
	parallelism = 16
)

// rateLimitFixture is one organization with one pool of three hundred runners, a token for each,
// and a job token for the first twenty runners' executors.
type rateLimitFixture struct {
	runners    []*models.Runner
	tokens     []string // runner tokens, by runner
	jobTokens  []string // job tokens, by job (runner i runs job i)
	jobIDs     []string
	noisyToken string
	noisyJob   string
}

func setupRateLimitFixture(t *testing.T, db *gorm.DB, svc *apikey.Service) *rateLimitFixture {
	t.Helper()
	sfx := uuid.NewString()[:8]
	org := &models.Organization{ID: uuid.New(), Name: "ratelimit-" + sfx}
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: org.ID, Name: "ratelimit-pool-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "ratelimit-" + sfx, Name: "ratelimit-" + sfx}
	for _, obj := range []any{org, pool, owner} {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seeding %T: %v", obj, err)
		}
	}
	f := &rateLimitFixture{}
	runnerIDs := make([]uuid.UUID, 0, launchers)
	for i := range launchers {
		r := &models.Runner{ID: uuid.New(), OrganizationID: &org.ID, AgentPoolID: &pool.ID, Name: "ratelimit-" + strconv.Itoa(i) + "-" + sfx, Status: models.RunnerStatusOnline, MaxConcurrentJobs: 1}
		f.runners = append(f.runners, r)
		runnerIDs = append(runnerIDs, r.ID)
	}
	if err := db.CreateInBatches(f.runners, 100).Error; err != nil {
		t.Fatalf("seeding runners: %v", err)
	}
	t.Cleanup(func() {
		db.Where("organization_id = ?", org.ID).Delete(&models.APIKey{})
		db.Where("id IN ?", runnerIDs).Delete(&models.Runner{})
		db.Where("id = ?", pool.ID).Delete(&models.AgentPool{})
		db.Where("id = ?", owner.ID).Delete(&models.User{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
	})

	// Each runner's token, minted as registration mints it (bcrypt-hashed, stored), in parallel.
	f.tokens = make([]string, launchers)
	parallel(t, launchers, func(i int) error {
		_, raw, err := svc.CreateRunnerToken(owner.ID, f.runners[i].ID, org.ID, "ratelimit runner "+strconv.Itoa(i))
		f.tokens[i] = raw
		return err
	})
	// A job token for the executors of the first twenty runners, and a noisy one of runner 0.
	expires := time.Now().Add(time.Hour)
	f.jobIDs = make([]string, executors)
	f.jobTokens = make([]string, executors)
	parallel(t, executors+1, func(i int) error {
		if i == executors {
			f.noisyJob = "run-rlnoisy" + sfx
			_, raw, err := svc.CreateJobToken(org.ID, apikey.JobPrincipal{Kind: models.JobTypeTofuRun, JobID: f.noisyJob, RunnerID: f.runners[0].ID, Attempt: 1}, expires)
			f.noisyToken = raw
			return err
		}
		f.jobIDs[i] = "run-rl" + strconv.Itoa(100+i) + sfx
		_, raw, err := svc.CreateJobToken(org.ID, apikey.JobPrincipal{Kind: models.JobTypeTofuRun, JobID: f.jobIDs[i], RunnerID: f.runners[i].ID, Attempt: 1}, expires)
		f.jobTokens[i] = raw
		return err
	})
	return f
}

// parallel runs fn(0..n-1) on parallelism goroutines and fails the test on any error.
func parallel(t *testing.T, n int, fn func(i int) error) {
	t.Helper()
	parallelOn(t, parallelism, n, fn)
}

func parallelOn(t *testing.T, width, n int, fn func(i int) error) {
	t.Helper()
	var wg sync.WaitGroup
	sem := make(chan struct{}, width)
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := fn(i); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// productionChain is the API's middleware order for these routes: the global per-IP limiter with
// the runner control plane carved out, API-key authentication, then on /api/v2/runner RunnerAuth
// and the per-principal limiter, each at its deployment default.
func productionChain(db *gorm.DB, svc *apikey.Service) *gin.Engine {
	gin.SetMode(gin.TestMode)
	authSvc := auth.NewService(repository.NewUserRepository(db))
	authSvc.SetAPIKeyService(svc)

	r := gin.New()
	r.Use(NewIPRateLimiter(100, 200).MiddlewareExcept("/api/v2/runner/")) // RATE_LIMIT defaults
	v2 := r.Group("/api/v2")
	v2.Use(AuthMiddleware(authSvc))
	v2.GET("/organizations", func(c *gin.Context) { c.Status(http.StatusOK) })
	runner := v2.Group("/runner")
	runner.Use(RunnerAuth(repository.NewRunnerRepository(db)), RunnerPrincipalRateLimit(RunnerRateBudgetsFrom(func(string) string { return "" })))
	runner.POST("/heartbeat", RequireRunnerToken(), func(c *gin.Context) { c.Status(http.StatusOK) })
	runner.POST("/jobs/:id/output", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func send(r *gin.Engine, method, path, token string) int {
	req := httptest.NewRequest(method, path, nil) //nolint:noctx // an in-process request
	req.RemoteAddr = natAddress
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

func TestRunnerRateLimit_ThreeHundredLaunchersBehindOneAddress(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	svc := apikey.NewService(repository.NewAPIKeyRepository(db), nil, nil, nil)
	f := setupRateLimitFixture(t, db, svc)
	r := productionChain(db, svc)

	// Every launcher heartbeats twice, and twenty executors stream a burst of output each: 1,400
	// requests from one address, seven times the per-IP burst, and none is refused.
	var refused atomic.Int64
	for round := range 2 {
		parallel(t, launchers, func(i int) error {
			if code := send(r, http.MethodPost, "/api/v2/runner/heartbeat", f.tokens[i]); code != http.StatusOK {
				refused.Add(1)
				t.Errorf("round %d: launcher %d heartbeat = %d, want 200", round, i, code)
			}
			return nil
		})
	}
	parallel(t, executors, func(i int) error {
		for line := range 40 { // the per-job burst at its default
			if code := send(r, http.MethodPost, "/api/v2/runner/jobs/"+f.jobIDs[i]+"/output", f.jobTokens[i]); code != http.StatusOK {
				refused.Add(1)
				t.Errorf("executor %d output line %d = %d, want 200", i, line, code)
				return nil
			}
		}
		return nil
	})
	if n := refused.Load(); n > 0 {
		t.Fatalf("%d requests of launchers and executors within their budgets were refused", n)
	}

	// One executor far over its budget is throttled; its runner's other executor, its launcher and
	// every other launcher are not. The burst arrives concurrently, as a runaway executor's would,
	// so it outpaces the refill even though each request is authenticated against the database.
	var throttled atomic.Int64
	parallelOn(t, 48, 400, func(int) error {
		if send(r, http.MethodPost, "/api/v2/runner/jobs/"+f.noisyJob+"/output", f.noisyToken) == http.StatusTooManyRequests {
			throttled.Add(1)
		}
		return nil
	})
	if throttled.Load() == 0 {
		t.Error("an executor that sent 400 outputs at once was never throttled")
	}
	t.Logf("the noisy executor was throttled on %d of 400 outputs", throttled.Load())
	if code := send(r, http.MethodPost, "/api/v2/runner/jobs/"+f.jobIDs[0]+"/output", f.jobTokens[0]); code == http.StatusTooManyRequests {
		t.Error("the noisy executor's neighbour on the same runner was throttled")
	}
	if code := send(r, http.MethodPost, "/api/v2/runner/heartbeat", f.tokens[0]); code != http.StatusOK {
		t.Errorf("the noisy executor's launcher heartbeat = %d, want 200", code)
	}
	if code := send(r, http.MethodPost, "/api/v2/runner/heartbeat", f.tokens[launchers-1]); code != http.StatusOK {
		t.Errorf("another launcher's heartbeat = %d, want 200", code)
	}

	// The same address on a route outside the runner control plane meets the per-IP limiter.
	limited := false
	for range 260 {
		// An unknown token is refused after the limiter has counted it, without a bcrypt compare.
		if send(r, http.MethodGet, "/api/v2/organizations", "tfe-not-a-stored-token") == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("the per-IP limiter no longer governs /api/v2/organizations")
	}
}
