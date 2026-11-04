// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test for a rolling upgrade (#933, D14, AC72): two API replicas serve the same
// launchers' executors behind one round-robin proxy. Release N+1 is the API of this tree; release
// N is simulated as a replica that predates the job token and so advertises no job-token
// capability: it answers every job token 401, as an older replica does. Twenty in-flight jobs,
// each run by the real executor client (artifacts, output, completion, and the status watcher the
// executor runs beside its engine), all complete and none is stopped by a bare 401 or 403, while
// an executor whose token the API revokes stops on the first status poll a release N+1 replica
// answers.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Rows are created under unique
// names and removed by primary key. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestMixedVersion

//go:build integration

package handlers

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/executor"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

const mixedVersionJobs = 20

// mixedVersionAPI is the two replicas behind one proxy.
type mixedVersionAPI struct {
	proxy     *httptest.Server
	svc       *apikey.Service
	jobTokens sync.Map // the raw job tokens, which release N does not know
	servedN   atomic.Int64
	servedN1  atomic.Int64

	mu      sync.Mutex
	n1Polls []time.Time // when each status poll release N+1 answered was sent
}

// n1PollsSince counts the status polls release N+1 answered that were sent at or after t.
func (m *mixedVersionAPI) n1PollsSince(t time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, at := range m.n1Polls {
		if !at.Before(t) {
			n++
		}
	}
	return n
}

// releaseN1 is this tree's API: real API-key authentication, RunnerAuth and the job-data guards.
func (f *agentPrepFixture) releaseN1(svc *apikey.Service) *gin.Engine {
	authSvc := auth.NewService(repository.NewUserRepository(f.db))
	authSvc.SetAPIKeyService(svc)
	h := &RunnerAgentHandler{
		db: f.db, apiKeyService: svc, runnerRepo: repository.NewRunnerRepository(f.db),
		jobExecRepo: repository.NewRunnerJobExecutionRepository(f.db), ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
		storageClient: newSnapshotStore(),
	}
	r := gin.New()
	runner := r.Group("/api/v2/runner")
	runner.Use(middleware.AuthMiddleware(authSvc), middleware.RunnerAuth(repository.NewRunnerRepository(f.db)))
	runner.GET("/jobs/:id/status", h.GetJobStatus)
	runner.GET("/jobs/:id/artifacts", middleware.JobData(), h.GetJobArtifacts)
	runner.POST("/jobs/:id/output", h.JobOutput)
	runner.POST("/jobs/:id/complete", middleware.JobData(), h.JobComplete)
	return r
}

// releaseN answers a job token as a replica that predates it: an unknown credential, 401. A runner
// token, which both releases know, is served as release N+1 serves it.
func (m *mixedVersionAPI) releaseN(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, isJobToken := m.jobTokens.Load(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); isJobToken {
			w.Header().Set("Content-Type", "application/vnd.api+json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":[{"status":"401","title":"Unauthorized","detail":"invalid or revoked API token"}]}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (f *agentPrepFixture) mixedVersionAPI(t *testing.T) *mixedVersionAPI {
	t.Helper()
	m := &mixedVersionAPI{svc: apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)}
	n1 := f.releaseN1(m.svc)
	n := m.releaseN(n1)
	// Each request reaches either replica at random, as behind a balancer that many clients share.
	// A strict alternation would couple one executor's requests to its own status polls: the
	// watcher retries a 401 until release N+1 answers, so it always leaves the alternation on
	// release N for the next request, and a completion sent between polls would only ever reach N.
	m.proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rand.IntN(2) == 0 {
			m.servedN.Add(1)
			n.ServeHTTP(w, r)
			return
		}
		m.servedN1.Add(1)
		if strings.HasSuffix(r.URL.Path, "/status") {
			m.mu.Lock()
			m.n1Polls = append(m.n1Polls, time.Now())
			m.mu.Unlock()
		}
		n1.ServeHTTP(w, r)
	}))
	t.Cleanup(m.proxy.Close)
	return m
}

// mint mints the job token of a run claimed by runner, as the launcher's /token call does.
func (m *mixedVersionAPI) mint(t *testing.T, f *agentPrepFixture, run *models.Run, runner *models.Runner) string {
	t.Helper()
	key, raw, err := m.svc.CreateJobToken(f.orgA, apikey.JobPrincipal{Kind: models.JobTypeTofuRun, JobID: run.ID, RunnerID: runner.ID, Attempt: 1}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })
	m.jobTokens.Store(raw, struct{}{})
	return raw
}

// executorRun is what one executor observed of its job.
type executorRun struct {
	err             error
	stoppedInFlight bool // the watcher stopped the job before its completion was reported
}

// runExecutor drives one job the way an executor does: the status watcher beside the work, the
// artifacts, three output posts and the completion.
func runExecutor(ctx context.Context, proxyURL, token, runnerID, runID string) executorRun {
	c := executor.NewClient(proxyURL, token, runnerID)
	jobCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	go c.WatchCancellation(jobCtx, runID, 20*time.Millisecond, cancel)

	var arts runnercontract.TofuArtifacts
	if err := c.Artifacts(jobCtx, runID, &arts, func() int { return arts.ContractVersion }); err != nil {
		return executorRun{err: fmt.Errorf("artifacts: %w", err), stoppedInFlight: errors.Is(context.Cause(jobCtx), executor.ErrJobStopped)}
	}
	for i := range 3 {
		if err := c.Output(jobCtx, runID, runnercontract.JobOutputRequest{Output: fmt.Sprintf("line %d\n", i), Stream: "plan"}); err != nil {
			return executorRun{err: fmt.Errorf("output %d: %w", i, err), stoppedInFlight: errors.Is(context.Cause(jobCtx), executor.ErrJobStopped)}
		}
	}
	stopped := errors.Is(context.Cause(jobCtx), executor.ErrJobStopped)
	// The completion is reported on a context of its own, as tofuexec reports it.
	reportCtx, done := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer done()
	if err := c.Complete(reportCtx, runID, runnercontract.JobCompleteRequest{Status: "completed"}); err != nil {
		return executorRun{err: fmt.Errorf("complete: %w", err), stoppedInFlight: stopped}
	}
	return executorRun{stoppedInFlight: stopped}
}

func TestMixedVersion_TwentyJobsCompleteAcrossTwoReleases(t *testing.T) {
	f := setupAgentPrepFixture(t)
	f.declareCapabilities(t, f.runnerA1, runnercontract.CapabilityJobToken)
	m := f.mixedVersionAPI(t)

	runs := make([]*models.Run, mixedVersionJobs)
	tokens := make([]string, mixedVersionJobs)
	for i := range runs {
		runs[i] = f.seedRun(t, f.runnerA1)
		tokens[i] = m.mint(t, f, runs[i], f.runnerA1)
	}

	results := make([]executorRun, mixedVersionJobs)
	var wg sync.WaitGroup
	for i := range runs {
		wg.Go(func() {
			results[i] = runExecutor(t.Context(), m.proxy.URL, tokens[i], f.runnerA1.ID.String(), runs[i].ID)
		})
	}
	wg.Wait()

	for i, res := range results {
		if res.err != nil {
			t.Errorf("job %d (%s): %v", i, runs[i].ID, res.err)
		}
		if res.stoppedInFlight {
			t.Errorf("job %d (%s) was stopped while in flight: a bare refusal of release N stopped it", i, runs[i].ID)
		}
	}
	var planned int64
	ids := make([]string, 0, len(runs))
	for _, r := range runs {
		ids = append(ids, r.ID)
	}
	if err := f.db.Model(&models.Run{}).Where("id IN ? AND status = ?", ids, models.RunStatusPlanned).Count(&planned).Error; err != nil {
		t.Fatal(err)
	}
	if planned != mixedVersionJobs {
		t.Errorf("%d of %d runs completed their plan phase", planned, mixedVersionJobs)
	}
	if m.servedN.Load() == 0 || m.servedN1.Load() == 0 {
		t.Fatalf("release N served %d requests and release N+1 %d: the jobs did not run across both", m.servedN.Load(), m.servedN1.Load())
	}
	t.Logf("release N answered %d requests 401, release N+1 served %d", m.servedN.Load(), m.servedN1.Load())
}

func TestMixedVersion_ARevokedTokenStopsItsExecutorOnTheFirstNewReleasePoll(t *testing.T) {
	f := setupAgentPrepFixture(t)
	f.declareCapabilities(t, f.runnerA1, runnercontract.CapabilityJobToken)
	m := f.mixedVersionAPI(t)
	run := f.seedRun(t, f.runnerA1)
	token := m.mint(t, f, run, f.runnerA1)

	const interval = 200 * time.Millisecond
	c := executor.NewClient(m.proxy.URL, token, f.runnerA1.ID.String())
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	go c.WatchCancellation(ctx, run.ID, interval, cancel)

	// In flight across both releases for a few polls: not stopped.
	time.Sleep(5 * interval)
	if ctx.Err() != nil {
		t.Fatalf("the executor stopped before its token was revoked: %v", context.Cause(ctx))
	}

	if err := m.svc.RevokeJobTokens(models.JobTypeTofuRun, run.ID); err != nil {
		t.Fatal(err)
	}
	// Counted from when the revocation has taken effect: a poll that reached release N+1 while it
	// was still being written may be answered as before.
	revoked := time.Now()
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), executor.ErrJobStopped) {
			t.Fatalf("stopped with %v, want ErrJobStopped", context.Cause(ctx))
		}
		// The first poll after the revocation may reach release N, which answers 401, and the
		// executor sends it again. The first poll release N+1
		// answers stops the executor: no later one was needed.
		if n := m.n1PollsSince(revoked); n > 1 {
			t.Errorf("release N+1 answered %d status polls after the revocation, want the executor stopped by the first", n)
		}
		t.Logf("stopped %s after the revocation, %d release N+1 polls after it", time.Since(revoked), m.n1PollsSince(revoked))
	case <-time.After(30 * time.Second):
		t.Fatal("the executor of a revoked token never stopped")
	}
}
