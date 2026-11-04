// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the playbook-source half of the runner control plane: what
// GET /api/v2/runner/jobs/:id/artifacts tells a self-hosted Ansible agent about the
// playbook's source mode, and GET /api/v2/runner/jobs/:id/playbook-snapshot, which
// streams the cached snapshot to it.
//
// Object storage and the queue are in-memory fakes; the tenant graph is real rows. Gated
// behind `integration`; skips unless $TEST_DATABASE_URL is set. Every row is created
// under a unique name and removed by primary key (see setupAgentPrepFixture). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run 'TestRunnerJobArtifacts|TestRunnerPlaybookSnapshot'

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/oidc"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"github.com/michielvha/stackweaver/core/storage"
	"github.com/michielvha/stackweaver/core/storage/storagetest"
)

// snapshotStore is an in-memory storage.Client whose GetStream honours the documented
// contract (storage.ErrNotFound for a missing object) and counts opened and closed
// streams, so a test can prove a probe did not leak its reader.
type snapshotStore struct {
	*storagetest.Memory
	opened, closed int
}

func newSnapshotStore() *snapshotStore {
	return &snapshotStore{Memory: storagetest.NewMemory()}
}

type countingCloser struct {
	io.Reader
	store *snapshotStore
}

func (c countingCloser) Close() error {
	c.store.closed++
	return nil
}

func (s *snapshotStore) GetStream(ctx context.Context, key string) (io.ReadCloser, error) {
	data, err := s.Get(ctx, key)
	if err != nil {
		return nil, storage.ErrNotFound
	}
	s.opened++
	return countingCloser{Reader: bytes.NewReader(data), store: s}, nil
}

// recordingQueue is a queue.Queue that records what was enqueued where.
type recordingQueue struct {
	queues   []string
	payloads []any
	err      error
}

func (q *recordingQueue) Enqueue(_ context.Context, queueName string, job any) error {
	if q.err != nil {
		return q.err
	}
	q.queues = append(q.queues, queueName)
	q.payloads = append(q.payloads, job)
	return nil
}

func (q *recordingQueue) Close() error { return nil }

// playbookSpec describes the playbook a test needs.
type playbookSpec struct {
	mode     string // "" keeps the column default (cached)
	cachedAt *time.Time
	commit   string
	size     int64
	noVCS    bool
}

func (f *agentPrepFixture) seedPlaybook(t *testing.T, spec playbookSpec) *models.AnsiblePlaybook {
	t.Helper()
	pb := &models.AnsiblePlaybook{
		ID:              uuid.New(),
		ProjectID:       f.projectA,
		Name:            "agentprep-pb-" + uuid.NewString()[:8],
		PlaybookPath:    "site.yml",
		SourceMode:      spec.mode,
		CachedAt:        spec.cachedAt,
		CachedCommit:    spec.commit,
		CachedSizeBytes: spec.size,
		LastSyncStatus:  "failed",
	}
	if !spec.noVCS {
		pb.VCSConnectionID = &f.vcsConn
		pb.VCSRepository = "acme/playbooks"
		pb.VCSBranch = "release"
	}
	if err := f.db.Create(pb).Error; err != nil {
		t.Fatalf("seeding playbook: %v", err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", pb.ID).Delete(&models.AnsiblePlaybook{}) })
	return pb
}

func (f *agentPrepFixture) reloadPlaybook(t *testing.T, id uuid.UUID) *models.AnsiblePlaybook {
	t.Helper()
	var pb models.AnsiblePlaybook
	if err := f.db.First(&pb, "id = ?", id).Error; err != nil {
		t.Fatalf("reloading playbook: %v", err)
	}
	return &pb
}

// artifactsRouter wires the two playbook-source endpoints the way SetupV2Routes does,
// over the given fake store and queue.
func (f *agentPrepFixture) artifactsRouter(store storage.Client, q *recordingQueue) *gin.Engine {
	playbookRepo := repository.NewAnsiblePlaybookRepository(f.db)
	registryNoNetwork := vcs.NewProviderRegistry(nil, nil, nil, nil)
	h := &RunnerAgentHandler{
		db:             f.db,
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
		playbookRepo:   playbookRepo,
		vcsRegistry:    registryNoNetwork,
		storageClient:  store,
		syncRequester:  ansible.NewPlaybookSnapshotRequester(ansible.NewWorkItemService(f.db, nil), playbookRepo),
	}
	if q != nil && q.err != nil {
		// A requester that cannot request anything, the failure a sync request can meet.
		h.syncRequester = ansible.NewPlaybookSnapshotRequester(nil, playbookRepo)
	}
	return f.router(func(authed *gin.RouterGroup) {
		authed.GET("/jobs/:id/artifacts", h.GetJobArtifacts)
		authed.GET("/jobs/:id/playbook-snapshot", h.GetPlaybookSnapshot)
	})
}

// snapshotSyncs counts the playbook_snapshot work items requested for a playbook (#933, D2: a sync
// is a work item; these tests counted messages on the ansible_sync queue before).
func (f *agentPrepFixture) snapshotSyncs(t *testing.T, playbookID uuid.UUID) int {
	t.Helper()
	var n int64
	if err := f.db.Model(&models.WorkItem{}).Where("playbook_id = ? AND kind = ?", playbookID, models.WorkItemPlaybookSnapshot).Count(&n).Error; err != nil {
		t.Fatalf("counting sync work items: %v", err)
	}
	return int(n)
}

func runnerGet(t *testing.T, r *gin.Engine, key, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	req.Header.Set("X-Test-Key", key)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// getArtifacts fetches a job's artifacts as runner a1, announcing snapshot support the
// way a current agent does, and returns the decoded document. It is decoded into a map
// on purpose: the tests assert on which keys are present.
func getArtifacts(t *testing.T, r *gin.Engine, jobID uuid.UUID) map[string]any {
	t.Helper()
	return getArtifactsAnnouncing(t, r, jobID, "playbook-snapshot")
}

// getArtifactsAnnouncing fetches a job's artifacts as runner a1 with the given
// X-Stackweaver-Runner-Capabilities value; "" sends no header at all, which is what an
// agent built before capability negotiation does.
func getArtifactsAnnouncing(t *testing.T, r *gin.Engine, jobID uuid.UUID, capabilities string) map[string]any {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/runner/jobs/"+jobID.String()+"/artifacts", nil)
	req.Header.Set("X-Test-Key", "a1")
	if capabilities != "" {
		req.Header.Set("X-Stackweaver-Runner-Capabilities", capabilities)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET artifacts: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decoding artifacts: %v", err)
	}
	return doc
}

func playbookSourceOf(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	src, ok := doc["playbook_source"].(map[string]any)
	if !ok {
		t.Fatalf("artifacts carry no playbook_source object: %v", doc)
	}
	return src
}

func TestRunnerJobArtifacts_CachedPlaybookWithSnapshot(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store, q := newSnapshotStore(), &recordingQueue{}
	r := f.artifactsRouter(store, q)

	capturedAt := time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached, cachedAt: &capturedAt, commit: "0123456789abcdef0123456789abcdef01234567", size: 4096})
	if err := store.Put(t.Context(), ansible.PlaybookSnapshotKey(pb.ID), []byte("snapshot")); err != nil {
		t.Fatalf("storing snapshot: %v", err)
	}
	job := f.seedJob(t, &pb.ID, nil)

	doc := getArtifacts(t, r, job.ID)

	if got := doc["project_id"]; got != f.projectA.String() {
		t.Errorf("project_id = %v, want %s", got, f.projectA)
	}
	src := playbookSourceOf(t, doc)
	if src["mode"] != "cached" || src["commit"] != "0123456789abcdef0123456789abcdef01234567" || src["size_bytes"] != float64(4096) {
		t.Errorf("playbook_source = %v, want mode cached with the snapshot's commit and size", src)
	}
	// Compared as an instant: the database driver hands the timestamp back in its own zone.
	raw, _ := src["captured_at"].(string)
	if got, err := time.Parse(time.RFC3339, raw); err != nil || !got.Equal(capturedAt) {
		t.Errorf("playbook_source.captured_at = %v (parse error %v), want the instant %s", src["captured_at"], err, capturedAt.Format(time.RFC3339))
	}
	// The agent runs the snapshot, so it must not be handed a token-embedded clone URL.
	if vcsInfo, present := doc["vcs"]; present {
		t.Errorf("artifacts carry vcs = %v for a cached playbook with a snapshot, want the key absent", vcsInfo)
	}
	if strings.Contains(fmtJSON(t, doc), "glpat-") {
		t.Error("artifacts leak the VCS access token for a cached playbook with a snapshot")
	}
	if store.opened != 1 || store.closed != 1 {
		t.Errorf("snapshot probe opened %d stream(s) and closed %d, want one opened and closed", store.opened, store.closed)
	}
	if n := f.snapshotSyncs(t, pb.ID); n != 0 {
		t.Errorf("requested %d sync(s), want none for a playbook that has its snapshot", n)
	}
}

func TestRunnerJobArtifacts_FreshPlaybook(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store, q := newSnapshotStore(), &recordingQueue{}
	r := f.artifactsRouter(store, q)

	// A fresh playbook may still have a snapshot from when it was cached; it is ignored.
	capturedAt := time.Now().UTC()
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeFresh, cachedAt: &capturedAt, commit: "abc1234"})
	if err := store.Put(t.Context(), ansible.PlaybookSnapshotKey(pb.ID), []byte("stale snapshot")); err != nil {
		t.Fatalf("storing snapshot: %v", err)
	}
	job := f.seedJob(t, &pb.ID, nil)

	doc := getArtifacts(t, r, job.ID)

	vcsInfo, ok := doc["vcs"].(map[string]any)
	if !ok {
		t.Fatalf("artifacts carry no vcs object for a fresh playbook: %v", doc)
	}
	repoURL, _ := vcsInfo["repo_url"].(string)
	if !strings.HasPrefix(repoURL, "https://oauth2:glpat-") || !strings.HasSuffix(repoURL, "@gitlab.com/acme/playbooks.git") {
		t.Errorf("vcs.repo_url = %q, want the token-embedded clone URL", repoURL)
	}
	if vcsInfo["branch"] != "release" || vcsInfo["repository"] != "acme/playbooks" {
		t.Errorf("vcs = %v, want branch release of acme/playbooks", vcsInfo)
	}
	src := playbookSourceOf(t, doc)
	if len(src) != 1 || src["mode"] != "fresh" {
		t.Errorf("playbook_source = %v, want only mode fresh", src)
	}
	if n := f.snapshotSyncs(t, pb.ID); n != 0 {
		t.Errorf("requested %d sync(s), want none for a fresh playbook", n)
	}
}

func TestRunnerJobArtifacts_CachedPlaybookWithoutSnapshot(t *testing.T) {
	capturedAt := time.Now().UTC()
	tests := []struct {
		name string
		spec playbookSpec
	}{
		{"never synced (cached_at unset)", playbookSpec{mode: models.PlaybookSourceModeCached}},
		{"metadata says synced but the object is gone", playbookSpec{mode: models.PlaybookSourceModeCached, cachedAt: &capturedAt, commit: "abc1234"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := setupAgentPrepFixture(t)
			store, q := newSnapshotStore(), &recordingQueue{}
			r := f.artifactsRouter(store, q)
			pb := f.seedPlaybook(t, tt.spec)
			job := f.seedJob(t, &pb.ID, nil)

			doc := getArtifacts(t, r, job.ID)

			if _, ok := doc["vcs"].(map[string]any); !ok {
				t.Fatalf("artifacts carry no vcs object, want the clone URL so this run can clone: %v", doc)
			}
			// mode cached without commit or captured_at is the agent's signal that this
			// cached run clones.
			src := playbookSourceOf(t, doc)
			if len(src) != 1 || src["mode"] != "cached" {
				t.Errorf("playbook_source = %v, want only mode cached", src)
			}

			if got := f.reloadPlaybook(t, pb.ID).LastSyncStatus; got != "syncing" {
				t.Errorf("playbook last_sync_status = %q, want syncing", got)
			}
			if n := f.snapshotSyncs(t, pb.ID); n != 1 {
				t.Fatalf("requested %d sync work item(s), want exactly one", n)
			}

			// The job is offered again, or the agent retries the download: no second sync.
			getArtifacts(t, r, job.ID)
			if n := f.snapshotSyncs(t, pb.ID); n != 1 {
				t.Errorf("after a second artifacts call %d sync(s) are requested, want still 1", n)
			}
		})
	}
}

func TestRunnerJobArtifacts_EmptySourceModeCountsAsCached(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store, q := newSnapshotStore(), &recordingQueue{}
	r := f.artifactsRouter(store, q)
	pb := f.seedPlaybook(t, playbookSpec{})
	// Rows written before the column existed carry an empty mode; the column default
	// hides that on insert, so blank it for this one row.
	if err := f.db.Model(&models.AnsiblePlaybook{}).Where("id = ?", pb.ID).Update("source_mode", "").Error; err != nil {
		t.Fatalf("blanking source_mode: %v", err)
	}
	job := f.seedJob(t, &pb.ID, nil)

	if src := playbookSourceOf(t, getArtifacts(t, r, job.ID)); src["mode"] != "cached" {
		t.Errorf("playbook_source.mode = %v, want cached for an empty source mode", src["mode"])
	}
}

func TestRunnerJobArtifacts_SyncQueueFailureDoesNotFailTheCall(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store, q := newSnapshotStore(), &recordingQueue{err: errors.New("redis unavailable")}
	r := f.artifactsRouter(store, q)
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached})
	job := f.seedJob(t, &pb.ID, nil)

	doc := getArtifacts(t, r, job.ID)

	if _, ok := doc["vcs"].(map[string]any); !ok {
		t.Errorf("artifacts carry no vcs object after a failed sync enqueue, want the run to clone anyway: %v", doc)
	}
	if got := f.reloadPlaybook(t, pb.ID).LastSyncStatus; got != "failed" {
		t.Errorf("playbook last_sync_status = %q, want failed (not stuck in syncing)", got)
	}
}

func TestRunnerJobArtifacts_NoPlaybookSourceWithoutVCS(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store, q := newSnapshotStore(), &recordingQueue{}
	r := f.artifactsRouter(store, q)
	pb := f.seedPlaybook(t, playbookSpec{noVCS: true})

	for name, job := range map[string]*models.AnsibleJob{
		"playbook without a VCS connection": f.seedJob(t, &pb.ID, nil),
		"job without a playbook":            f.seedJob(t, nil, nil),
	} {
		t.Run(name, func(t *testing.T) {
			doc := getArtifacts(t, r, job.ID)
			if src, present := doc["playbook_source"]; present {
				t.Errorf("playbook_source = %v, want the key absent", src)
			}
			if got := doc["project_id"]; got != f.projectA.String() {
				t.Errorf("project_id = %v, want %s", got, f.projectA)
			}
		})
	}
	if n := f.snapshotSyncs(t, pb.ID); n != 0 {
		t.Errorf("requested %d sync(s), want none", n)
	}
}

func TestRunnerPlaybookSnapshot_StreamsTheStoredObject(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r := f.artifactsRouter(store, &recordingQueue{})

	// Not valid gzip on purpose: the endpoint must hand over the stored bytes untouched.
	snapshot := bytes.Repeat([]byte{0x1f, 0x8b, 0x00, 0xff, 0x7a}, 20_000)
	capturedAt := time.Now().UTC()
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached, cachedAt: &capturedAt, commit: "abc1234", size: 1}) // size lags on purpose
	if err := store.Put(t.Context(), ansible.PlaybookSnapshotKey(pb.ID), snapshot); err != nil {
		t.Fatalf("storing snapshot: %v", err)
	}

	for name, job := range map[string]*models.AnsibleJob{
		"job offered to the pool, not yet claimed": f.seedJob(t, &pb.ID, nil),
		"job claimed by the calling runner":        f.seedJob(t, &pb.ID, f.runnerA1),
	} {
		t.Run(name, func(t *testing.T) {
			rec := runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+job.ID.String()+"/playbook-snapshot")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %.200s)", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); got != "application/gzip" {
				t.Errorf("Content-Type = %q, want application/gzip", got)
			}
			// The metadata's size can lag the object, so the response must not promise one.
			if got := rec.Header().Get("Content-Length"); got != "" {
				t.Errorf("Content-Length = %q, want none (chunked)", got)
			}
			if !bytes.Equal(rec.Body.Bytes(), snapshot) {
				t.Errorf("body is %d bytes and differs from the %d stored bytes", rec.Body.Len(), len(snapshot))
			}
		})
	}
	if store.opened != store.closed {
		t.Errorf("opened %d snapshot stream(s) but closed %d", store.opened, store.closed)
	}
}

func TestRunnerPlaybookSnapshot_Refusals(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r := f.artifactsRouter(store, &recordingQueue{})

	capturedAt := time.Now().UTC()
	withSnapshot := func(mode string) *models.AnsiblePlaybook {
		pb := f.seedPlaybook(t, playbookSpec{mode: mode, cachedAt: &capturedAt, commit: "abc1234"})
		if err := store.Put(t.Context(), ansible.PlaybookSnapshotKey(pb.ID), []byte("snapshot")); err != nil {
			t.Fatalf("storing snapshot: %v", err)
		}
		return pb
	}
	cached := withSnapshot(models.PlaybookSourceModeCached)
	fresh := withSnapshot(models.PlaybookSourceModeFresh)
	neverSynced := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached})
	objectGone := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached, cachedAt: &capturedAt, commit: "abc1234"})
	noVCS := f.seedPlaybook(t, playbookSpec{noVCS: true})

	offered := f.seedJob(t, &cached.ID, nil)
	claimedByA1 := f.seedJob(t, &cached.ID, f.runnerA1)

	tests := []struct {
		name       string
		key        string
		job        *models.AnsibleJob
		want       int
		wantDetail string
	}{
		{"runner in another organization", "b1", offered, http.StatusForbidden, "different organization"},
		{"runner in another pool of the same organization", "a3", offered, http.StatusForbidden, "different agent pool"},
		{"job claimed by another runner", "a2", claimedByA1, http.StatusForbidden, "different runner"},
		{"API key that is not a runner token", "org", offered, http.StatusForbidden, "not a runner token"},
		{"no API key", "", offered, http.StatusUnauthorized, ""},
		{"playbook never synced", "a1", f.seedJob(t, &neverSynced.ID, nil), http.StatusNotFound, "no snapshot yet"},
		{"snapshot object missing from storage", "a1", f.seedJob(t, &objectGone.ID, nil), http.StatusNotFound, "no snapshot yet"},
		{"fresh playbook", "a1", f.seedJob(t, &fresh.ID, nil), http.StatusNotFound, "fresh"},
		{"playbook without a VCS connection", "a1", f.seedJob(t, &noVCS.ID, nil), http.StatusNotFound, ""},
		{"job without a playbook", "a1", f.seedJob(t, nil, nil), http.StatusNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := runnerGet(t, r, tt.key, "/api/v2/runner/jobs/"+tt.job.ID.String()+"/playbook-snapshot")
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.want, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantDetail) {
				t.Errorf("body %s does not mention %q", rec.Body.String(), tt.wantDetail)
			}
			if strings.Contains(rec.Body.String(), "snapshot\x00") || rec.Header().Get("Content-Type") == "application/gzip" {
				t.Errorf("a refused request was answered with snapshot content")
			}
		})
	}

	t.Run("unknown job", func(t *testing.T) {
		rec := runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+uuid.NewString()+"/playbook-snapshot")
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})
	t.Run("malformed job id", func(t *testing.T) {
		rec := runnerGet(t, r, "a1", "/api/v2/runner/jobs/not-a-uuid/playbook-snapshot")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}

// An agent built before capability negotiation sends no X-Stackweaver-Runner-Capabilities
// header. It can only clone, so it must get what it has always got: the clone URL, no
// playbook_source, no project_id, and no side effect on the playbook. The same goes for
// a header that lists other capabilities but not playbook-snapshot.
func TestRunnerJobArtifacts_WithoutSnapshotCapabilityIsTheOldContract(t *testing.T) {
	capturedAt := time.Now().UTC()
	playbooks := []struct {
		name         string
		spec         playbookSpec
		withSnapshot bool
	}{
		{"cached with a snapshot", playbookSpec{mode: models.PlaybookSourceModeCached, cachedAt: &capturedAt, commit: "abc1234", size: 8}, true},
		{"cached without a snapshot", playbookSpec{mode: models.PlaybookSourceModeCached}, false},
		{"fresh", playbookSpec{mode: models.PlaybookSourceModeFresh}, false},
	}
	for _, announced := range []string{"", "some-future-capability, another-one"} {
		for _, pbCase := range playbooks {
			t.Run("header="+announced+"/"+pbCase.name, func(t *testing.T) {
				f := setupAgentPrepFixture(t)
				store, q := newSnapshotStore(), &recordingQueue{}
				r := f.artifactsRouter(store, q)
				pb := f.seedPlaybook(t, pbCase.spec)
				if pbCase.withSnapshot {
					if err := store.Put(t.Context(), ansible.PlaybookSnapshotKey(pb.ID), []byte("snapshot")); err != nil {
						t.Fatalf("storing snapshot: %v", err)
					}
				}
				job := f.seedJob(t, &pb.ID, nil)

				doc := getArtifactsAnnouncing(t, r, job.ID, announced)

				vcsInfo, ok := doc["vcs"].(map[string]any)
				if !ok {
					t.Fatalf("artifacts carry no vcs object, want the clone URL an older agent needs: %v", doc)
				}
				repoURL, _ := vcsInfo["repo_url"].(string)
				if !strings.HasSuffix(repoURL, "@gitlab.com/acme/playbooks.git") || vcsInfo["branch"] != "release" || vcsInfo["repository"] != "acme/playbooks" {
					t.Errorf("vcs = %v, want the token-embedded clone URL, branch release, repository acme/playbooks", vcsInfo)
				}
				for _, key := range []string{"playbook_source", "project_id"} {
					if value, present := doc[key]; present {
						t.Errorf("artifacts carry %s = %v, want the key absent for an agent that did not announce playbook-snapshot", key, value)
					}
				}
				if n := f.snapshotSyncs(t, pb.ID); n != 0 {
					t.Errorf("requested %d sync(s), want none: an older agent clones regardless", n)
				}
				if got := f.reloadPlaybook(t, pb.ID).LastSyncStatus; got != "failed" {
					t.Errorf("playbook last_sync_status = %q, want it left at the seeded %q", got, "failed")
				}
				if store.opened != 0 {
					t.Errorf("the snapshot was probed %d time(s), want storage left alone", store.opened)
				}
			})
		}
	}
}

func TestRunnerCapabilities(t *testing.T) {
	tests := []struct {
		header string
		want   bool
	}{
		{"playbook-snapshot", true},
		{" Playbook-Snapshot ", true},
		{"other, playbook-snapshot,third", true},
		{"", false},
		{"playbook-snapshots", false},
		{"other,another", false},
	}
	for _, tt := range tests {
		t.Run("header="+tt.header, func(t *testing.T) {
			c, _ := ctxWithRunner(nil)
			if tt.header != "" {
				c.Request.Header.Set("X-Stackweaver-Runner-Capabilities", tt.header)
			}
			if got := runnerCapabilities(c)[runnerCapabilityPlaybookSnapshot]; got != tt.want {
				t.Errorf("playbook-snapshot announced = %v, want %v", got, tt.want)
			}
		})
	}
}

func fmtJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	return string(raw)
}

// TestRunnerJobArtifacts_CarryContractVersion pins that the artifacts document names the contract
// major it is shaped by (#933, D2, AC72), so an executor can refuse one it does not know.
func TestRunnerJobArtifacts_CarryContractVersion(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := f.artifactsRouter(newSnapshotStore(), &recordingQueue{})
	pb := f.seedPlaybook(t, playbookSpec{noVCS: true})
	job := f.seedJob(t, &pb.ID, nil)

	doc := getArtifacts(t, r, job.ID)
	if got := doc["contract_version"]; got != float64(1) {
		t.Fatalf("contract_version = %v, want 1", got)
	}
}

// TestRunnerJobArtifacts_AnsibleCarriesEveryPerRunToken pins that an Ansible job's artifacts carry
// the platform-minted per-run tokens for AWS, GCP and Vault beside Azure, exactly as an OpenTofu
// run's do (#933, D2, D8, AC37), and that both engines carry the deployment's mirror block.
func TestRunnerJobArtifacts_AnsibleCarriesEveryPerRunToken(t *testing.T) {
	t.Setenv("DEV_INSECURE_KEY", "1")
	f := setupAgentPrepFixture(t)
	signingKey, err := oidc.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	sfx := uuid.NewString()[:8]
	azure := &models.AzureOIDCConfiguration{ClientID: "az-client-" + sfx, SubscriptionID: "sub", TenantID: "tenant", OrganizationID: f.orgA}
	aws := &models.AWSOIDCConfiguration{RoleARN: "arn:aws:iam::123456789012:role/sw-" + sfx, OrganizationID: f.orgA}
	gcp := &models.GCPOIDCConfiguration{ServiceAccountEmail: "sw-" + sfx + "@p.iam.gserviceaccount.com", ProjectNumber: "42", WorkloadProviderName: "projects/42/locations/global/workloadIdentityPools/p/providers/sw", OrganizationID: f.orgA}
	vault := &models.VaultOIDCConfiguration{Address: "https://vault.example.test:8200", RoleName: "sw-" + sfx, OrganizationID: f.orgA}
	for _, cfg := range []any{azure, aws, gcp, vault} {
		if err := f.db.Create(cfg).Error; err != nil {
			t.Fatalf("seeding %T: %v", cfg, err)
		}
	}
	t.Cleanup(func() {
		f.db.Where("id = ?", azure.ID).Delete(&models.AzureOIDCConfiguration{})
		f.db.Where("id = ?", aws.ID).Delete(&models.AWSOIDCConfiguration{})
		f.db.Where("id = ?", gcp.ID).Delete(&models.GCPOIDCConfiguration{})
		f.db.Where("id = ?", vault.ID).Delete(&models.VaultOIDCConfiguration{})
	})

	playbookRepo := repository.NewAnsiblePlaybookRepository(f.db)
	registry := vcs.NewProviderRegistry(nil, nil, nil, nil)
	h := &RunnerAgentHandler{
		db: f.db, ansibleJobRepo: repository.NewAnsibleJobRepository(f.db), playbookRepo: playbookRepo,
		vcsRegistry: registry, storageClient: newSnapshotStore(),
		syncRequester: ansible.NewPlaybookSnapshotRequester(ansible.NewWorkItemService(f.db, nil), playbookRepo),
	}
	h.SetOIDCServices(repository.NewAzureOIDCConfigurationRepository(f.db), repository.NewAWSOIDCConfigurationRepository(f.db),
		repository.NewGCPOIDCConfigurationRepository(f.db), repository.NewVaultOIDCConfigurationRepository(f.db),
		oidc.NewTokenService(signingKey, "https://stackweaver.example.com"))
	h.SetMirror(&runnercontract.Mirror{ProviderNetworkMirror: "https://mirror.example.test/providers/", PipIndexURL: "https://pip.example.test/simple"})
	r := f.router(func(authed *gin.RouterGroup) { authed.GET("/jobs/:id/artifacts", h.GetJobArtifacts) })

	job := f.seedJob(t, nil, nil)
	doc := getArtifacts(t, r, job.ID)
	env, _ := doc["environment_vars"].(map[string]any)
	for _, k := range []string{"AZURE_FEDERATED_TOKEN", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN", "GCP_OIDC_RAW_TOKEN", "GCP_OIDC_SERVICE_ACCOUNT_EMAIL", "VAULT_OIDC_RAW_TOKEN", "VAULT_OIDC_ADDRESS"} {
		if v, _ := env[k].(string); v == "" {
			t.Errorf("Ansible artifacts lack %s", k)
		}
	}
	if env["AWS_ROLE_ARN"] != aws.RoleARN {
		t.Errorf("AWS_ROLE_ARN = %v, want %s", env["AWS_ROLE_ARN"], aws.RoleARN)
	}
	mirror, _ := doc["mirror"].(map[string]any)
	if mirror["provider_network_mirror"] != "https://mirror.example.test/providers/" || mirror["pip_index_url"] != "https://pip.example.test/simple" {
		t.Errorf("mirror block = %v", doc["mirror"])
	}
}
