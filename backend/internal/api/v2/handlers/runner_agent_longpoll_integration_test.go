// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the long-poll heartbeat (#933, D3, AC70, AC19): a heartbeat with a wait is
// held until an offer exists or the wait (capped by the API) ends, woken by a Redis publish from
// any replica, re-queries when the wait ends so a lost publish costs one interval, and holds no
// database connection while it waits.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestLongPoll

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/wakeup"
	"github.com/redis/go-redis/v9"
)

func (f *agentPrepFixture) longPollRouter(t *testing.T, maxWait time.Duration) (*gin.Engine, *redis.Client, *wakeup.Hub) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	hub := wakeup.NewHub(rdb)
	hub.Start(t.Context())
	for deadline := time.Now().Add(2 * time.Second); !hub.Subscribed(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the wakeup hub never subscribed")
		}
	}
	h := &RunnerAgentHandler{
		db: f.db, runnerRepo: repository.NewRunnerRepository(f.db), ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
	}
	h.SetWakeup(hub, rdb, maxWait)
	return f.router(func(authed *gin.RouterGroup) {
		authed.POST("/heartbeat", middleware.RequireRunnerToken(), h.Heartbeat)
	}), rdb, hub
}

// seedQueuedJob is a pending job of pool A that a launcher of the pool may be offered.
func (f *agentPrepFixture) seedQueuedJob(t *testing.T) *models.AnsibleJob {
	t.Helper()
	now := time.Now()
	return f.seedJobRow(t, &models.AnsibleJob{Status: models.AnsibleJobStatusPending, AgentPoolID: &f.poolA, QueuedAt: &now})
}

func heartbeatWithWait(t *testing.T, r *gin.Engine, key string, runner *models.Runner, wait int) (runnercontract.HeartbeatResponse, time.Duration) {
	t.Helper()
	start := time.Now()
	rec := runnerDo(t, r, key, http.MethodPost, "/api/v2/runner/heartbeat", runnercontract.HeartbeatRequest{RunnerID: runner.ID.String(), Status: "online", WaitSeconds: wait})
	took := time.Since(start)
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d (%s)", rec.Code, rec.Body.String())
	}
	var resp runnercontract.HeartbeatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp, took
}

// A publish for the pool answers a waiting heartbeat at once with the new offer (AC19).
func TestLongPoll_WokenByAPublish(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, rdb, _ := f.longPollRouter(t, 20*time.Second)

	var job *models.AnsibleJob
	go func() {
		time.Sleep(300 * time.Millisecond)
		job = f.seedQueuedJob(t)
		wakeup.Publish(t.Context(), rdb, f.poolA.String())
	}()
	resp, took := heartbeatWithWait(t, r, "a1", f.runnerA1, 15)
	if len(resp.PendingJobs) != 1 || job == nil || resp.PendingJobs[0].JobID != job.ID.String() {
		t.Fatalf("offers = %+v, want the job created while waiting", resp.PendingJobs)
	}
	if took > 3*time.Second {
		t.Errorf("the woken heartbeat took %s, want it answered on the publish", took)
	}
}

// Without a publish the heartbeat re-queries when its wait ends, so a lost wakeup costs one
// interval and the offer still arrives (AC70).
func TestLongPoll_RequeriesWhenTheWaitEnds(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _, _ := f.longPollRouter(t, 20*time.Second)

	go func() {
		time.Sleep(300 * time.Millisecond)
		f.seedQueuedJob(t) // no publish: the wakeup is lost
	}()
	resp, took := heartbeatWithWait(t, r, "a1", f.runnerA1, 2)
	if len(resp.PendingJobs) != 1 {
		t.Fatalf("offers = %+v, want the job found by the re-query at the end of the wait", resp.PendingJobs)
	}
	if took < 1500*time.Millisecond {
		t.Errorf("the heartbeat answered after %s, before its wait ended", took)
	}
}

// The API caps the wait below the proxies between launcher and API (AC70).
func TestLongPoll_WaitIsCapped(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _, _ := f.longPollRouter(t, time.Second)

	resp, took := heartbeatWithWait(t, r, "a1", f.runnerA1, 600)
	if len(resp.PendingJobs) != 0 {
		t.Fatalf("offers = %+v, want none", resp.PendingJobs)
	}
	if took > 4*time.Second {
		t.Errorf("a 600 s wait was held %s, want it capped at 1 s", took)
	}
}

// A heartbeat with an offer waiting is answered at once, and one without a wait as today.
func TestLongPoll_AnOfferIsAnsweredAtOnce(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _, _ := f.longPollRouter(t, 20*time.Second)
	f.seedQueuedJob(t)
	resp, took := heartbeatWithWait(t, r, "a1", f.runnerA1, 15)
	if len(resp.PendingJobs) != 1 || took > 3*time.Second {
		t.Fatalf("offers = %+v after %s, want the waiting job at once", resp.PendingJobs, took)
	}
}

// A thousand held heartbeats hold no database connection: each waits on a channel, not a query
// (AC70).
func TestLongPoll_WaitersHoldNoDatabaseConnection(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, rdb, hub := f.longPollRouter(t, 20*time.Second)
	sqlDB, err := f.db.DB()
	if err != nil {
		t.Fatal(err)
	}

	const waiters = 1000
	var wg sync.WaitGroup
	for range waiters {
		wg.Go(func() {
			runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/heartbeat", runnercontract.HeartbeatRequest{RunnerID: f.runnerA1.ID.String(), WaitSeconds: 15})
		})
	}
	deadline := time.Now().Add(60 * time.Second)
	for hub.Waiting() < waiters {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d heartbeats are waiting", hub.Waiting(), waiters)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A waiter registers before its second query, so give the last queries a moment to return;
	// after that a thousand held heartbeats hold no connection at all.
	inUse := sqlDB.Stats().InUse
	for settle := time.Now().Add(5 * time.Second); inUse > 0 && time.Now().Before(settle); inUse = sqlDB.Stats().InUse {
		time.Sleep(20 * time.Millisecond)
	}
	if inUse > 0 {
		t.Errorf("%d database connections in use while %d heartbeats wait, want none held by the waiters", inUse, waiters)
	}
	wakeup.Publish(t.Context(), rdb, f.poolA.String())
	wg.Wait()
}

// A held heartbeat stamps the runner again when it answers, so the monitor measures the time a
// launcher spends between requests (its claims), not that plus the wait it was held for (AC17).
// Both stamps are read back from the database, so the comparison holds in any time zone.
func TestLongPoll_TheRunnerIsSeenWhenTheWaitEnds(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _, _ := f.longPollRouter(t, 20*time.Second)
	stamp := func() time.Time {
		t.Helper()
		var runner models.Runner
		if err := f.db.First(&runner, "id = ?", f.runnerA1.ID).Error; err != nil {
			t.Fatal(err)
		}
		if runner.LastHeartbeatAt == nil {
			t.Fatal("the runner has no heartbeat")
		}
		return *runner.LastHeartbeatAt
	}

	heartbeatWithWait(t, r, "a1", f.runnerA1, 0)
	before := stamp()
	if _, took := heartbeatWithWait(t, r, "a1", f.runnerA1, 2); took < 1500*time.Millisecond {
		t.Fatalf("the heartbeat answered after %s, before its wait ended", took)
	}
	if after := stamp(); after.Sub(before) < 1500*time.Millisecond {
		t.Fatalf("last heartbeat moved %s, want it stamped when the wait ended, at least 1.5 s later", after.Sub(before))
	}
}
