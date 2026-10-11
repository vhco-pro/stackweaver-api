// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the edges of the runner playbook-preparation endpoints: a slow
// snapshot stream, jobs a runner has no business reading, oversized event fields, and a
// sync request racing an edit. Same fixture and cleanup rules as
// runner_agent_events_test.go. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run 'TestRunnerHardening'

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// slowStore serves snapshots whose first byte arrives only after delay, the way a large
// object on a slow link does.
type slowStore struct {
	*snapshotStore
	delay time.Duration
}

type delayedReader struct {
	io.ReadCloser
	delay time.Duration
	once  sync.Once
}

func (r *delayedReader) Read(p []byte) (int, error) {
	r.once.Do(func() { time.Sleep(r.delay) })
	return r.ReadCloser.Read(p)
}

func (s slowStore) GetStream(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, err := s.snapshotStore.GetStream(ctx, key)
	if err != nil {
		return nil, err
	}
	return &delayedReader{ReadCloser: rc, delay: s.delay}, nil
}

// The API server runs with a write timeout far shorter than a large snapshot takes on a
// slow link. The snapshot response must not be cut by it.
func TestRunnerHardening_SnapshotOutlivesTheServerWriteTimeout(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := slowStore{snapshotStore: newSnapshotStore(), delay: 700 * time.Millisecond}

	snapshot := bytes.Repeat([]byte("snapshot-bytes-"), 4096)
	capturedAt := time.Now().UTC()
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached, cachedAt: &capturedAt, commit: "abc1234"})
	if err := store.Put(t.Context(), ansible.PlaybookSnapshotKey(pb.ID), snapshot); err != nil {
		t.Fatalf("storing snapshot: %v", err)
	}
	job := f.seedJob(t, &pb.ID, nil)

	srv := httptest.NewUnstartedServer(f.artifactsRouter(store, &recordingQueue{}))
	srv.Config.WriteTimeout = 200 * time.Millisecond
	srv.Start()
	defer srv.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v2/runner/jobs/"+job.ID.String()+"/playbook-snapshot", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("X-Test-Key", "a1")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("snapshot request failed (cut by the server write timeout?): %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading snapshot body: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, snapshot) {
		t.Errorf("status = %d, body is %d bytes; want 200 with all %d bytes", resp.StatusCode, len(body), len(snapshot))
	}
}

// seedJobRow inserts a job exactly as given (seedJob always puts it in pool A).
func (f *agentPrepFixture) seedJobRow(t *testing.T, job *models.AnsibleJob) *models.AnsibleJob {
	t.Helper()
	job.ID = uuid.New()
	job.ProjectID = f.projectA
	job.InventoryID = f.inventory
	if err := f.db.Create(job).Error; err != nil {
		t.Fatalf("seeding job: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("job_id = ?", job.ID).Delete(&models.AnsibleJobEvent{})
		f.db.Where("id = ?", job.ID).Delete(&models.AnsibleJob{})
	})
	return job
}

// A job with no agent pool runs on the platform runner, which never uses this API. No
// self-hosted runner may read or write it, whatever organization it is in.
func TestRunnerHardening_JobWithoutAgentPoolIsOffLimits(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	capturedAt := time.Now().UTC()
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached, cachedAt: &capturedAt, commit: "abc1234"})
	if err := store.Put(t.Context(), ansible.PlaybookSnapshotKey(pb.ID), []byte("snapshot")); err != nil {
		t.Fatalf("storing snapshot: %v", err)
	}
	read := f.artifactsRouter(store, &recordingQueue{})
	write := f.eventsRouter()

	platformJob := f.seedJobRow(t, &models.AnsibleJob{PlaybookID: &pb.ID, Status: models.AnsibleJobStatusRunning})
	// Even a platform job that somehow names the runner as its assignee stays off limits.
	assigned := f.seedJobRow(t, &models.AnsibleJob{PlaybookID: &pb.ID, Status: models.AnsibleJobStatusRunning, RunnerID: &f.runnerA1.ID})

	for name, job := range map[string]*models.AnsibleJob{"unassigned": platformJob, "naming the runner": assigned} {
		t.Run(name, func(t *testing.T) {
			base := "/api/v2/runner/jobs/" + job.ID.String()
			if rec := runnerGet(t, read, "a1", base+"/artifacts"); rec.Code != http.StatusForbidden {
				t.Errorf("artifacts: status = %d, want 403 (body %.160s)", rec.Code, rec.Body.String())
			}
			if rec := runnerGet(t, read, "a1", base+"/playbook-snapshot"); rec.Code != http.StatusForbidden {
				t.Errorf("playbook-snapshot: status = %d, want 403 (body %.160s)", rec.Code, rec.Body.String())
			}
			if rec := postJobEvent(t, write, "a1", job.ID, JobEventRequest{Event: "playbook_source", Stdout: "forged\n"}); rec.Code != http.StatusForbidden {
				t.Errorf("events: status = %d, want 403 (body %.160s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// Artifacts carry decrypted credentials and the snapshot carries the repository: once a
// job has finished there is nothing left to prepare, so neither is served any more.
func TestRunnerHardening_FinishedJobServesNoArtifactsOrSnapshot(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	capturedAt := time.Now().UTC()
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached, cachedAt: &capturedAt, commit: "abc1234"})
	if err := store.Put(t.Context(), ansible.PlaybookSnapshotKey(pb.ID), []byte("snapshot")); err != nil {
		t.Fatalf("storing snapshot: %v", err)
	}
	r := f.artifactsRouter(store, &recordingQueue{})

	for _, status := range []models.AnsibleJobStatus{
		models.AnsibleJobStatusSuccessful, models.AnsibleJobStatusFailed, models.AnsibleJobStatusCanceled, models.AnsibleJobStatusError,
	} {
		t.Run(string(status), func(t *testing.T) {
			job := f.seedJobRow(t, &models.AnsibleJob{PlaybookID: &pb.ID, Status: status, AgentPoolID: &f.poolA, RunnerID: &f.runnerA1.ID})
			base := "/api/v2/runner/jobs/" + job.ID.String()
			for _, path := range []string{"/artifacts", "/playbook-snapshot"} {
				rec := runnerGet(t, r, "a1", base+path)
				if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "finished") {
					t.Errorf("%s: status = %d, body %.160s; want 403 saying the job has finished", path, rec.Code, rec.Body.String())
				}
			}
		})
	}

	// The control: the same job while it is running is served to its runner.
	running := f.seedJobRow(t, &models.AnsibleJob{PlaybookID: &pb.ID, Status: models.AnsibleJobStatusRunning, AgentPoolID: &f.poolA, RunnerID: &f.runnerA1.ID})
	if rec := runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+running.ID.String()+"/playbook-snapshot"); rec.Code != http.StatusOK {
		t.Errorf("running job: status = %d, want 200", rec.Code)
	}
}

// The task column holds 500 characters. A longer task is the caller's mistake and is
// answered as one, not as a server error from the insert.
func TestRunnerHardening_OverlongEventTaskIsRejected(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := f.eventsRouter()
	job := f.seedJob(t, nil, f.runnerA1)

	if rec := postJobEvent(t, r, "a1", job.ID, JobEventRequest{Event: "galaxy_install", Task: strings.Repeat("t", 501)}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("501-character task: status = %d, want 422 (body %.160s)", rec.Code, rec.Body.String())
	}
	if rec := postJobEvent(t, r, "a1", job.ID, JobEventRequest{Event: "galaxy_install", Task: strings.Repeat("t", 500)}); rec.Code != http.StatusOK {
		t.Errorf("500-character task: status = %d, want 200 (body %.160s)", rec.Code, rec.Body.String())
	}
	if events := f.jobEvents(t, job.ID); len(events) != 1 {
		t.Errorf("stored %d events, want only the one that fits", len(events))
	}
}

// Requesting a sync must write the sync status only. The playbook it was handed can be
// stale: an edit that landed after it was loaded must survive.
func TestRunnerHardening_SyncRequestDoesNotOverwriteAConcurrentEdit(t *testing.T) {
	f := setupAgentPrepFixture(t)
	playbookRepo := repository.NewAnsiblePlaybookRepository(f.db)
	q := &recordingQueue{}
	requester := ansible.NewPlaybookSyncRequester(vcs.NewProviderRegistry(nil, nil, nil, nil), repository.NewVCSConnectionRepository(f.db), playbookRepo, q)

	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached})
	stale, err := playbookRepo.GetByID(pb.ID)
	if err != nil {
		t.Fatalf("loading playbook: %v", err)
	}
	// The edit that races the request: a user repoints the playbook.
	if err := f.db.Model(&models.AnsiblePlaybook{}).Where("id = ?", pb.ID).
		Updates(map[string]any{"playbook_path": "edited.yml", "description": "edited meanwhile"}).Error; err != nil {
		t.Fatalf("editing playbook: %v", err)
	}

	if err := requester.Request(t.Context(), stale); err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	after := f.reloadPlaybook(t, pb.ID)
	if after.PlaybookPath != "edited.yml" || after.Description != "edited meanwhile" {
		t.Errorf("playbook path = %q, description = %q; the concurrent edit was overwritten", after.PlaybookPath, after.Description)
	}
	if after.LastSyncStatus != "syncing" || after.LastSyncError != "" {
		t.Errorf("sync status = %q, error = %q; want syncing with the error cleared", after.LastSyncStatus, after.LastSyncError)
	}
	if len(q.queues) != 1 {
		t.Errorf("enqueued %d message(s), want 1", len(q.queues))
	}
}
