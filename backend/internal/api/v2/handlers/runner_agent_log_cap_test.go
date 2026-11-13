// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the job log cap (#933, D2, AC73): one job's stored output is bounded by
// job_log_max_bytes. Past it the head and the last part are kept, a log_truncated event records the
// dropped bytes, and the job carries on; one output request over the body cap is refused with 413.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestLogCap

//go:build integration

package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/logbuffer"
)

func (f *agentPrepFixture) logCapRouter(store *snapshotStore) *gin.Engine {
	h := &RunnerAgentHandler{
		db:             f.db,
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
		storageClient:  store,
		logLimits:      logbuffer.Limits{MaxBytes: 2000, TailBytes: 500},
		outputBodyCap:  4096,
	}
	return f.router(func(authed *gin.RouterGroup) {
		authed.POST("/jobs/:id/output", h.JobOutput)
	})
}

func postOutput(t *testing.T, r *gin.Engine, runnerID, jobID, stream, line string) int {
	t.Helper()
	return runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+jobID+"/output", map[string]any{"runner_id": runnerID, "output": line, "stream": stream}).Code
}

func TestLogCap_OpenTofuLogKeepsHeadAndTail(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r := f.logCapRouter(store)
	run := f.seedRun(t, f.runnerA1)
	for i := range 100 {
		if code := postOutput(t, r, f.runnerA1.ID.String(), run.ID, "plan", fmt.Sprintf("line %03d %s", i, strings.Repeat("x", 40))); code != http.StatusOK {
			t.Fatalf("output %d: %d", i, code)
		}
	}
	if err := logbuffer.FinalizeStorageLog(t.Context(), store, run.ID, "plan"); err != nil {
		t.Fatal(err)
	}
	logData, err := store.Get(t.Context(), "runs/"+run.ID+"/logs/plan.log")
	if err != nil {
		t.Fatal(err)
	}
	log := string(logData)
	if len(log) > 2200 {
		t.Errorf("the stored log is %d bytes, beyond the 2000-byte cap", len(log))
	}
	for _, want := range []string{"line 000", "bytes of output were dropped", "line 099"} {
		if !strings.Contains(log, want) {
			t.Errorf("the capped log lacks %q", want)
		}
	}
	if strings.Contains(log, "line 050") {
		t.Error("the middle of the output was kept")
	}
}

// TestLogCap_OpenTofuRunCompletesWithTheTruncationRecorded drives an OpenTofu run past the cap and
// then completes it, as an executor does: the run completes, and its finalized log carries the
// truncation record (a run has no event stream, so the record is the marker line between the head
// and the kept tail, naming the dropped bytes), the head, and at most TailBytes of the end.
func TestLogCap_OpenTofuRunCompletesWithTheTruncationRecorded(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	limits := logbuffer.Limits{MaxBytes: 2000, TailBytes: 500}
	h := &RunnerAgentHandler{
		db: f.db, runnerRepo: repository.NewRunnerRepository(f.db), jobExecRepo: repository.NewRunnerJobExecutionRepository(f.db),
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db), storageClient: store, logLimits: limits, outputBodyCap: 4096,
	}
	r := f.router(func(authed *gin.RouterGroup) {
		authed.POST("/jobs/:id/output", h.JobOutput)
		authed.POST("/jobs/:id/complete", h.JobComplete)
	})
	run := f.seedRun(t, f.runnerA1)
	posted := 0
	for i := range 100 {
		line := fmt.Sprintf("line %03d %s\n", i, strings.Repeat("x", 40))
		posted += len(line)
		if code := postOutput(t, r, f.runnerA1.ID.String(), run.ID, "plan", line); code != http.StatusOK {
			t.Fatalf("output %d past the cap: %d, want the job to carry on", i, code)
		}
	}
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+run.ID+"/complete", map[string]any{"runner_id": f.runnerA1.ID.String(), "status": "completed"}); rec.Code != http.StatusOK {
		t.Fatalf("completing the run after its output was truncated: %d %s", rec.Code, rec.Body.String())
	}
	var done models.Run
	if err := f.db.First(&done, "id = ?", run.ID).Error; err != nil {
		t.Fatal(err)
	}
	// The completion reports no plan changes, so the plan phase ends at planned_and_finished
	// (TFE's status for a plan with nothing to apply, #1072); what matters here is that the run
	// completed despite its truncated output.
	if done.Status != models.RunStatusPlannedAndFinished {
		t.Errorf("run status after completion = %s, want planned_and_finished", done.Status)
	}

	logData, err := store.Get(t.Context(), "runs/"+run.ID+"/logs/plan.log")
	if err != nil {
		t.Fatal(err)
	}
	log := string(logData)
	m := regexp.MustCompile(`\[stackweaver: (\d+) bytes of output were dropped; the end of the output follows\]\n`).FindStringSubmatchIndex(log)
	if m == nil {
		t.Fatalf("the finalized log has no truncation record:\n%s", log)
	}
	dropped, _ := strconv.Atoi(log[m[2]:m[3]])
	head, tail := log[:m[0]], log[m[1]:]
	if !strings.Contains(head, "line 000") || !strings.Contains(tail, "line 099") {
		t.Errorf("the head or the end of the output is lost: head ends %q, tail ends %q", head[max(0, len(head)-60):], tail[max(0, len(tail)-60):])
	}
	if int64(len(strings.TrimRight(tail, "\x03"))) > limits.TailBytes {
		t.Errorf("kept %d bytes of the end, beyond TailBytes %d", len(tail), limits.TailBytes)
	}
	if dropped <= 0 || dropped >= posted {
		t.Errorf("the truncation record names %d dropped bytes of %d posted", dropped, posted)
	}
	if strings.Contains(log, "line 050") {
		t.Error("the middle of the output was kept")
	}
}

func TestLogCap_AnsibleEventsKeepHeadAndTail(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := f.logCapRouter(newSnapshotStore())
	job := f.seedJob(t, nil, f.runnerA1)
	for i := range 100 {
		if code := postOutput(t, r, f.runnerA1.ID.String(), job.ID.String(), "stdout", fmt.Sprintf("raw line %03d %s", i, strings.Repeat("y", 40))); code != http.StatusOK {
			t.Fatalf("output %d: %d", i, code)
		}
	}
	var events []models.AnsibleJobEvent
	if err := f.db.Where("job_id = ?", job.ID).Order("counter ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	var stored int
	var marker *models.AnsibleJobEvent
	for i := range events {
		stored += len(events[i].Stdout) + len(events[i].Stderr)
		if events[i].Event == "log_truncated" {
			marker = &events[i]
		}
	}
	if marker == nil {
		t.Fatal("no log_truncated event")
	}
	if dropped, _ := marker.EventData["dropped_bytes"].(float64); dropped <= 0 {
		t.Errorf("log_truncated dropped_bytes = %v, want positive", marker.EventData["dropped_bytes"])
	}
	if stored > 2200 {
		t.Errorf("stored event output is %d bytes, beyond the cap", stored)
	}
	if !strings.Contains(events[0].Stdout, "raw line 000") || !strings.Contains(events[len(events)-1].Stdout, "raw line 099") {
		t.Errorf("head or tail lost: first %q last %q", events[0].Stdout, events[len(events)-1].Stdout)
	}
}

func TestLogCap_BodyOverTheCapIs413(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := f.logCapRouter(newSnapshotStore())
	run := f.seedRun(t, f.runnerA1)
	body := fmt.Sprintf(`{"runner_id":%q,"stream":"plan","output":%q}`, f.runnerA1.ID.String(), strings.Repeat("z", 5000))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runner/jobs/"+run.ID+"/output", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Key", "a1")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("an output body over the cap: %d, want 413", rec.Code)
	}
}
