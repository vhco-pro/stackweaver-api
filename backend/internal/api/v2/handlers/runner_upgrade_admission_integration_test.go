// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

func TestRunnerUpgradePause_BlocksNewOffersAndOutstandingStarts(t *testing.T) {
	f := setupClaimRouteFixture(t)
	if err := f.db.Model(f.runnerA1).UpdateColumn("max_concurrent_jobs", 4).Error; err != nil {
		t.Fatal(err)
	}
	cfg := startRouteCases[0]
	active, _, token := f.startCompletion(t, cfg)
	offered, table := f.seedStart(t, cfg)
	if err := f.db.Table(table).Where("id = ?", offered).UpdateColumn("runner_id", f.runnerA1.ID).Error; err != nil {
		t.Fatal(err)
	}
	queued, _ := f.seedStart(t, cfg)

	type reservedRow struct {
		id, table string
	}
	reservations := []reservedRow{{id: offered, table: table}}
	for _, other := range []startRouteCase{startRouteCases[1], startRouteCases[2]} {
		id, table := f.seedStart(t, other)
		if err := f.db.Table(table).Where("id = ?", id).UpdateColumn("runner_id", f.runnerA1.ID).Error; err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, reservedRow{id: id, table: table})
	}
	ambiguous, _ := f.seedStart(t, cfg)
	if err := f.db.Table(table).Where("id = ?", ambiguous).
		Updates(map[string]any{"runner_id": f.runnerA1.ID, "started_at": time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	otherOwner, _ := f.seedStart(t, cfg)
	if err := f.db.Table(table).Where("id = ?", otherOwner).UpdateColumn("runner_id", f.runnerA2.ID).Error; err != nil {
		t.Fatal(err)
	}
	f.handler.pauseRegistration = true
	rec := f.do(t, f.token, http.MethodPost, "/heartbeat", runnercontract.HeartbeatRequest{
		RunnerID: f.runnerA1.ID.String(), CurrentJobs: 1, AvailableCapacity: 3,
	})
	var heartbeat runnercontract.HeartbeatResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &heartbeat) != nil {
		t.Fatalf("paused heartbeat returned %d %s", rec.Code, rec.Body.String())
	}
	if len(heartbeat.ActiveClaims) != 1 || heartbeat.ActiveClaims[0].JobID != active {
		t.Fatal("paused heartbeat did not report the already started claim")
	}
	for _, row := range reservations {
		if state := f.state(t, row.table, row.id); state.Owner != "" {
			t.Errorf("paused launcher still owns an unstarted reservation: %+v", state)
		}
	}
	if retained := f.state(t, table, ambiguous); retained.Owner != f.runnerA1.ID.String() {
		t.Error("pause released a job with evidence of a possible start")
	}
	if retained := f.state(t, table, otherOwner); retained.Owner != f.runnerA2.ID.String() {
		t.Error("pause released a different launcher's reservation")
	}
	if len(heartbeat.PendingJobs) != 0 {
		t.Error("paused heartbeat returned launchable work")
	}
	if state := f.state(t, table, queued); state.Owner != "" {
		t.Error("paused heartbeat reserved newly queued work")
	}
	path := "/jobs/" + offered + "/start"
	start := f.do(t, f.token, http.MethodPost, path, f.expected(cfg))
	if start.Code != http.StatusServiceUnavailable || !strings.Contains(start.Body.String(), "runner-upgrade-admission-paused") {
		t.Errorf("a start from an existing offer returned %d %s", start.Code, start.Body.String())
	}
	staleFailure := runnercontract.JobCompleteRequest{
		RunnerID: f.runnerA1.ID.String(), Attempt: 1, Status: "failed",
	}
	if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+offered+"/complete", staleFailure); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("paused startup failure consumed an unstarted job: %d %s", rec.Code, rec.Body.String())
	}
	if state := f.state(t, table, offered); state.Status != string(models.AnsibleJobStatusPending) || state.Attempt != 0 {
		t.Errorf("paused start changed the pending claim: status %s, attempt %d", state.Status, state.Attempt)
	}
	for _, cfg := range []startRouteCase{startRouteCases[1], startRouteCases[2]} {
		id, table := f.seedStart(t, cfg)
		before := f.state(t, table, id)
		rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", f.expected(cfg))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("paused %s returned %d %s", cfg.name, rec.Code, rec.Body.String())
		}
		after := f.state(t, table, id)
		if before != after {
			t.Errorf("paused %s changed claim state: before %+v, after %+v", cfg.name, before, after)
		}
	}
	complete := runnercontract.JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Status: "completed", Attempt: token.Attempt}
	if rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+active+"/complete", complete); rec.Code != http.StatusOK {
		t.Errorf("paused API denied the already started completion: %d %s", rec.Code, rec.Body.String())
	}
}
