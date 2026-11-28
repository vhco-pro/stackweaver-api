// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the runner lifecycle of a work item (#933, D2, decision 18, AC10): a sync
// is offered to a runner that declared it runs work items, claimed as a new attempt, given a job
// token, fed its artifacts (a clone whose credential travels beside the URL, never inside it, and
// never for a connection of another organization), streams output into its sync history and
// completes, its result persisted on its target. A snapshot kind is offered to an OpenTofu-only
// runner; an inventory kind only to an Ansible-capable one.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration

package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

type workItemRunnerFixture struct {
	*agentPrepFixture
	h     *RunnerAgentHandler
	r     *gin.Engine
	svc   *apikey.Service
	store *snapshotStore
	items *ansible.WorkItemService
	// registration is the raw agent token launcherAPI minted for pool A.
	registration string
}

func setupWorkItemRunner(t *testing.T) *workItemRunnerFixture {
	t.Helper()
	f := setupAgentPrepFixture(t)
	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	store := newSnapshotStore()
	inventoryRepo := repository.NewAnsibleInventoryRepository(f.db)
	export := ansible.NewInventoryService(inventoryRepo, repository.NewOrganizationRepository(f.db))
	h := &RunnerAgentHandler{
		db: f.db, apiKeyService: svc, runnerRepo: repository.NewRunnerRepository(f.db),
		jobExecRepo:    repository.NewRunnerJobExecutionRepository(f.db),
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
		playbookRepo:   repository.NewAnsiblePlaybookRepository(f.db),
		inventoryRepo:  inventoryRepo,
		vcsRegistry:    vcs.NewProviderRegistry(nil, nil, nil, nil),
		storageClient:  store,
	}
	h.SetWorkItems(ansible.NewWorkItemRuntime(f.db, export, nil))
	// The pool's runners declare that they run work items, as a launcher does, and place pods, so
	// the API issues them an identity binding (#1113, D3).
	for _, r := range []*models.Runner{f.runnerA1, f.runnerA2} {
		f.declareCapabilities(t, r, runnercontract.CapabilityJobToken, runnercontract.CapabilityWorkItems)
		if err := f.db.Model(r).Update("driver", "kubernetes").Error; err != nil {
			t.Fatal(err)
		}
	}
	// Pool A lets project A use it, and organization A allows its GitLab connection's stored
	// credential on agent pools, so file syncs bound to pool A queue there (#1113, D2).
	if err := f.db.Exec("INSERT INTO agent_pool_allowed_projects (agent_pool_id, project_id) VALUES (?, ?) ON CONFLICT DO NOTHING", f.poolA, f.projectA).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Exec("DELETE FROM agent_pool_allowed_projects WHERE agent_pool_id = ?", f.poolA) })
	if err := f.db.Model(&models.Organization{}).Where("id = ?", f.orgA).Update("allow_stored_vcs_credentials_on_agent_pools", true).Error; err != nil {
		t.Fatal(err)
	}
	r := f.router(func(authed *gin.RouterGroup) {
		authed.POST("/heartbeat", middleware.RequireRunnerToken(), h.Heartbeat)
		authed.POST("/jobs/:id/start", middleware.RequireRunnerToken(), h.JobStart)
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.GET("/jobs/:id/artifacts", middleware.JobData(), h.GetJobArtifacts)
		authed.GET("/jobs/:id/playbook-snapshot", middleware.JobData(), h.GetPlaybookSnapshot)
		authed.GET("/jobs/:id/status", h.GetJobStatus)
		authed.POST("/jobs/:id/output", h.JobOutput)
		authed.POST("/jobs/:id/snapshot", middleware.JobData(), h.UploadSnapshot)
		authed.POST("/jobs/:id/complete", middleware.JobData(), h.JobComplete)
	})
	return &workItemRunnerFixture{agentPrepFixture: f, h: h, r: r, svc: svc, store: store, items: ansible.NewWorkItemService(f.db, nil)}
}

// onPool moves a work item onto organization A's pool A, where runners a1 and a2 are.
func (f *workItemRunnerFixture) onPool(t *testing.T, item *models.WorkItem) *models.WorkItem {
	t.Helper()
	if err := f.db.Model(&models.WorkItem{}).Where("id = ?", item.ID).Update("agent_pool_id", f.poolA).Error; err != nil {
		t.Fatal(err)
	}
	item.AgentPoolID = &f.poolA
	return item
}

func (f *workItemRunnerFixture) offered(t *testing.T, key string) []string {
	t.Helper()
	runner := map[string]*models.Runner{"a1": f.runnerA1, "a2": f.runnerA2, "a3": f.runnerA3}[key]
	rec := runnerDo(t, f.r, key, http.MethodPost, "/api/v2/runner/heartbeat", runnercontract.HeartbeatRequest{RunnerID: runner.ID.String(), Status: "online"})
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat as %s: %d %s", key, rec.Code, rec.Body.String())
	}
	var resp runnercontract.HeartbeatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, o := range resp.PendingJobs {
		if o.JobType == runnercontract.JobTypeWorkItem {
			ids = append(ids, o.JobID)
		}
	}
	return ids
}

// claim starts a work item as the runner behind key and mints its job token under name.
func (f *workItemRunnerFixture) claim(t *testing.T, key, id, name string) runnercontract.JobToken {
	t.Helper()
	if rec := runnerDo(t, f.r, key, http.MethodPost, "/api/v2/runner/jobs/"+id+"/start", runnercontract.JobStartRequest{RunnerID: f.keyRunner(key)}); rec.Code != http.StatusOK {
		t.Fatalf("claiming %s as %s: %d %s", id, key, rec.Code, rec.Body.String())
	}
	code, tok := f.mintJobToken(t, f.r, f.svc, key, id, name)
	if code != http.StatusOK {
		t.Fatalf("minting the job token of %s: %d", id, code)
	}
	return tok
}

func (f *workItemRunnerFixture) keyRunner(key string) string {
	return map[string]*models.Runner{"a1": f.runnerA1, "a2": f.runnerA2, "a3": f.runnerA3}[key].ID.String()
}

func (f *workItemRunnerFixture) reload(t *testing.T, id string) models.WorkItem {
	t.Helper()
	var item models.WorkItem
	if err := f.db.First(&item, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	return item
}

func TestWorkItemRunner_PlaybookSnapshotLifecycle(t *testing.T) {
	f := setupWorkItemRunner(t)
	cachedAt := time.Now().UTC()
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached, cachedAt: &cachedAt, commit: "previous", size: 8})
	key := ansible.PlaybookSnapshotKey(pb.ID)
	if err := f.store.Put(t.Context(), key, []byte("previous")); err != nil {
		t.Fatal(err)
	}
	item, err := f.items.RequestPlaybookSnapshot(t.Context(), pb, "manual")
	if err != nil {
		t.Fatal(err)
	}
	f.onPool(t, item)

	// Offered once, to one runner of the pool: a second runner's poll does not see it.
	if got := f.offered(t, "a1"); !slices.Contains(got, item.ID) {
		t.Fatalf("a1 was offered %v, want the work item %s", got, item.ID)
	}
	if got := f.offered(t, "a2"); slices.Contains(got, item.ID) {
		t.Errorf("a2 was offered %s too, reserved by a1", item.ID)
	}

	tok := f.claim(t, "a1", item.ID, "wi")
	if tok.Attempt != 1 {
		t.Errorf("first claim is attempt %d, want 1", tok.Attempt)
	}
	if got := f.reload(t, item.ID); got.Status != models.WorkItemStatusRunning || got.RunnerID == nil || *got.RunnerID != f.runnerA1.ID {
		t.Errorf("claimed work item is %q on %v, want running on a1", got.Status, got.RunnerID)
	}
	if rec := runnerDo(t, f.r, "a2", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/start", runnercontract.JobStartRequest{RunnerID: f.runnerA2.ID.String()}); rec.Code == http.StatusOK {
		t.Error("a second runner claimed a work item a1 holds")
	}
	if got := f.reloadPlaybook(t, pb.ID).LastSyncStatus; got != "syncing" {
		t.Errorf("the playbook is %q while its snapshot is captured, want syncing", got)
	}

	// The artifacts: the clone and its credential apart, the credential nowhere in the URL.
	rec := runnerDo(t, f.r, "wi", http.MethodGet, "/api/v2/runner/jobs/"+item.ID+"/artifacts", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("artifacts: %d %s", rec.Code, rec.Body.String())
	}
	var art runnercontract.WorkItemArtifacts
	if err := json.Unmarshal(rec.Body.Bytes(), &art); err != nil {
		t.Fatal(err)
	}
	if art.Kind != models.WorkItemPlaybookSnapshot || art.Clone == nil || art.PlaybookPath != "site.yml" {
		t.Fatalf("artifacts = %+v, want a playbook snapshot clone of site.yml", art)
	}
	if art.Clone.URL != "https://gitlab.com/acme/playbooks.git" || art.Clone.Branch != "release" {
		t.Errorf("clone = %s @ %s, want the bare repository URL on release", art.Clone.URL, art.Clone.Branch)
	}
	if art.Clone.Username != "oauth2" || !strings.HasPrefix(art.Clone.Token, "glpat-") || strings.Contains(art.Clone.URL, "glpat-") {
		t.Errorf("clone credential = %q/%q in URL %q, want the token beside the URL", art.Clone.Username, art.Clone.Token, art.Clone.URL)
	}

	// Output, the snapshot, the completion.
	if rec := runnerDo(t, f.r, "wi", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/output", JobOutputRequest{RunnerID: f.runnerA1.ID.String(), Output: "Cloning acme/playbooks\n"}); rec.Code != http.StatusOK {
		t.Fatalf("output: %d %s", rec.Code, rec.Body.String())
	}
	done := JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Status: "completed", WorkResult: &runnercontract.WorkResult{Commit: "0123456789abcdef"}}
	complete := "/api/v2/runner/jobs/" + item.ID + "/complete"
	if rec := runnerDo(t, f.r, "wi", http.MethodPost, complete, done); rec.Code != http.StatusInternalServerError {
		t.Fatalf("completion before upload returned %d, want retryable failure", rec.Code)
	}
	upload := func(data string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/snapshot", strings.NewReader(data))
		req.Header.Set("X-Test-Key", "wi")
		req.Header.Set(runnercontract.HeaderSnapshotCommit, "0123456789abcdef")
		rec := httptest.NewRecorder()
		f.r.ServeHTTP(rec, req)
		return rec
	}
	up := upload("tarball")
	if up.Code != http.StatusOK {
		t.Fatalf("snapshot upload: %d %s", up.Code, up.Body.String())
	}
	if data, err := f.store.Get(t.Context(), key); err != nil || string(data) != "previous" {
		t.Fatalf("an unfinished capture changed the published archive to %q (%v)", data, err)
	}
	if afterUpload := f.reloadPlaybook(t, pb.ID); afterUpload.CachedCommit != "previous" || afterUpload.CachedSizeBytes != 8 {
		t.Fatalf("an unfinished capture changed the published metadata to %q (%d bytes)", afterUpload.CachedCommit, afterUpload.CachedSizeBytes)
	}
	accepted := f.reload(t, item.ID)
	if accepted.PlaybookSnapshotUploadID == nil {
		t.Fatal("the capture did not record a selected upload")
	}
	if rec := upload("tarball"); rec.Code != http.StatusOK {
		t.Fatalf("same upload retry returned %d", rec.Code)
	}
	if rec := upload("changed"); rec.Code != http.StatusBadRequest {
		t.Fatalf("different upload retry returned %d", rec.Code)
	}
	if rec := runnerDo(t, f.r, "wi", http.MethodPost, complete, done); rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	got := f.reload(t, item.ID)
	if got.Status != models.WorkItemStatusCompleted || got.Commit != "0123456789abcdef" || !strings.Contains(got.Output, "Cloning acme/playbooks") {
		t.Errorf("work item = %q at %q with output %q, want completed at the commit with its output", got.Status, got.Commit, got.Output)
	}
	after := f.reloadPlaybook(t, pb.ID)
	if after.PublishedSnapshotID == nil || *after.PublishedSnapshotID != *accepted.PlaybookSnapshotUploadID {
		t.Fatal("completion did not publish the originally selected upload")
	}
	job := f.seedJob(t, &pb.ID, f.runnerA1)
	if err := f.db.Model(job).UpdateColumn("playbook_snapshot_upload_id", after.PublishedSnapshotID).Error; err != nil {
		t.Fatal(err)
	}
	snapshot := runnerGet(t, f.artifactsRouter(f.store), "a1", "/api/v2/runner/jobs/"+job.ID.String()+"/playbook-snapshot")
	if snapshot.Code != http.StatusOK || snapshot.Body.String() != "tarball" {
		t.Fatalf("download returned %d %q, want the originally selected archive", snapshot.Code, snapshot.Body.String())
	}
	if after.LastSyncStatus != "successful" || after.CachedCommit != "0123456789abcdef" || after.CachedAt == nil || after.CachedSizeBytes != int64(len("tarball")) {
		t.Errorf("playbook = %q, cached %q at %v (%d bytes), want the snapshot recorded", after.LastSyncStatus, after.CachedCommit, after.CachedAt, after.CachedSizeBytes)
	}
	// The job token ends with the work item.
	if rec := runnerDo(t, f.r, "wi", http.MethodGet, "/api/v2/runner/jobs/"+item.ID+"/artifacts", nil); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Errorf("artifacts after completion with the job token = %d, want it refused", rec.Code)
	}
}

func TestWorkItemRunner_PlaybookPublicationKeepsNewerCapture(t *testing.T) {
	f := setupWorkItemRunner(t)
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached})
	reserve := func(runner string) *models.WorkItem {
		t.Helper()
		item, err := f.items.RequestPlaybookSnapshot(t.Context(), pb, "manual")
		if err != nil {
			t.Fatal(err)
		}
		f.onPool(t, item)
		if !slices.Contains(f.offered(t, runner), item.ID) {
			t.Fatalf("%s did not reserve %s", runner, item.ID)
		}
		return item
	}
	older := reserve("a1")
	newer := reserve("a2")
	if newer.ID == older.ID || older.PlaybookSnapshotSequence <= 0 ||
		newer.PlaybookSnapshotSequence <= older.PlaybookSnapshotSequence {
		t.Fatal("the two reservations did not receive separate ordered capture identities")
	}
	uploadAndFinish := func(item *models.WorkItem, runner, token, commit string) {
		t.Helper()
		path := "/api/v2/runner/jobs/" + item.ID
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path+"/snapshot", strings.NewReader(commit))
		req.Header.Set("X-Test-Key", token)
		req.Header.Set(runnercontract.HeaderSnapshotCommit, commit)
		rec := httptest.NewRecorder()
		f.r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("upload %s returned %d %s", commit, rec.Code, rec.Body.String())
		}
		done := JobCompleteRequest{RunnerID: f.keyRunner(runner), Status: "completed", WorkResult: &runnercontract.WorkResult{Commit: commit}}
		if rec := runnerDo(t, f.r, token, http.MethodPost, path+"/complete", done); rec.Code != http.StatusOK {
			t.Fatalf("complete %s returned %d %s", commit, rec.Code, rec.Body.String())
		}
	}
	f.claim(t, "a2", newer.ID, "newer")
	uploadAndFinish(newer, "a2", "newer", "newer")
	f.claim(t, "a1", older.ID, "older")
	if got := f.reloadPlaybook(t, pb.ID).LastSyncStatus; got != "successful" {
		t.Errorf("starting the older capture changed the newer capture's status to %q", got)
	}
	uploadAndFinish(older, "a1", "older", "older")
	published := f.reloadPlaybook(t, pb.ID)
	if published.CachedCommit != "newer" || published.PublishedSnapshotSequence != newer.PlaybookSnapshotSequence ||
		published.LastSyncStatus != "successful" {
		t.Errorf("older completion changed the published capture or status: commit %q, sequence %d, status %q",
			published.CachedCommit, published.PublishedSnapshotSequence, published.LastSyncStatus)
	}
}

// A playbook deleted while its snapshot is captured stays gone: the delete pruned playbooks/<id>/,
// and the executor's upload puts nothing back there, where no playbook row would ever own it.
func TestWorkItemRunner_NoSnapshotIsStoredForADeletedPlaybook(t *testing.T) {
	f := setupWorkItemRunner(t)
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached})
	item, err := f.items.RequestPlaybookSnapshot(t.Context(), pb, "manual")
	if err != nil {
		t.Fatal(err)
	}
	f.onPool(t, item)
	f.offered(t, "a1")
	f.claim(t, "a1", item.ID, "wi")

	if err := f.db.Delete(&models.AnsiblePlaybook{}, "id = ?", pb.ID).Error; err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/snapshot", bytes.NewReader([]byte("tarball")))
	req.Header.Set("X-Test-Key", "wi")
	req.Header.Set(runnercontract.HeaderSnapshotCommit, "0123456789abcdef")
	up := httptest.NewRecorder()
	f.r.ServeHTTP(up, req)
	if up.Code != http.StatusNotFound {
		t.Errorf("snapshot of a deleted playbook: %d %s, want 404", up.Code, up.Body.String())
	}
	var allocations int64
	if err := f.db.Model(&models.PlaybookSnapshotUpload{}).Where("work_item_id = ?", item.ID).Count(&allocations).Error; err != nil {
		t.Fatal(err)
	}
	if allocations != 0 {
		t.Errorf("allocated %d uploads for a deleted playbook", allocations)
	}
}

func TestWorkItemRunner_InventoryFileSyncPersistsTheResult(t *testing.T) {
	f := setupWorkItemRunner(t)
	// A project inventory: the test moves its sync onto pool A, which lets project A use it, and an
	// organization-scoped inventory may use only an organization-scoped pool (#1113, D2).
	inv := &models.AnsibleInventory{
		ID: uuid.New(), OrganizationID: f.orgA, ProjectID: &f.projectA, Name: "wi-inv-" + uuid.NewString()[:8], Type: models.InventoryTypeVCS,
		VCSConnectionID: &f.vcsConn, VCSRepository: "acme/inventories", VCSBranch: "main", InventoryPath: "hosts.yml",
	}
	if err := f.db.Create(inv).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("inventory_id = ?", inv.ID).Delete(&models.WorkItem{})
		f.db.Where("inventory_id = ?", inv.ID).Delete(&models.AnsibleInventorySync{})
		f.db.Where("inventory_id = ?", inv.ID).Delete(&models.AnsibleInventoryHost{})
		f.db.Where("inventory_id = ?", inv.ID).Delete(&models.AnsibleInventoryGroup{})
		f.db.Where("id = ?", inv.ID).Delete(&models.AnsibleInventory{})
	})
	item, err := f.items.RequestInventorySync(t.Context(), inv, "webhook")
	if err != nil {
		t.Fatal(err)
	}
	f.onPool(t, item)
	if got := f.offered(t, "a1"); !slices.Contains(got, item.ID) {
		t.Fatalf("a1 was offered %v, want %s", got, item.ID)
	}
	f.claim(t, "a1", item.ID, "wi")
	claimed := f.reload(t, item.ID)
	if claimed.SyncRunID == nil {
		t.Fatal("the claim opened no sync history row")
	}

	rec := runnerDo(t, f.r, "wi", http.MethodGet, "/api/v2/runner/jobs/"+item.ID+"/artifacts", nil)
	var art runnercontract.WorkItemArtifacts
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &art) != nil || art.InventoryPath != "hosts.yml" || art.Clone == nil {
		t.Fatalf("artifacts: %d %s", rec.Code, rec.Body.String())
	}
	runnerDo(t, f.r, "wi", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/output", JobOutputRequest{RunnerID: f.runnerA1.ID.String(), Output: "Parsing hosts.yml\n"})
	inventory := json.RawMessage(`{"_meta":{"hostvars":{"web1":{"ansible_host":"10.0.0.1"}}},"all":{"children":["web"]},"web":{"hosts":["web1"]}}`)
	done := JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Status: "completed", WorkResult: &runnercontract.WorkResult{Inventory: inventory, Commit: "abc123"}}
	if rec := runnerDo(t, f.r, "wi", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/complete", done); rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	var hosts int64
	f.db.Model(&models.AnsibleInventoryHost{}).Where("inventory_id = ?", inv.ID).Count(&hosts)
	if hosts != 1 {
		t.Errorf("%d hosts persisted, want the one the sync found", hosts)
	}
	var stored models.AnsibleInventory
	f.db.First(&stored, "id = ?", inv.ID)
	if stored.LastSyncStatus != "successful" {
		t.Errorf("inventory sync status = %q, want successful", stored.LastSyncStatus)
	}
	var history models.AnsibleInventorySync
	f.db.First(&history, "id = ?", *claimed.SyncRunID)
	if history.Status != models.InventorySyncStatusSuccessful || history.TriggeredBy != "webhook" || !strings.Contains(history.Output, "Parsing hosts.yml") || history.HostsDiscovered != 1 {
		t.Errorf("sync history = %q by %q, %d hosts, output %q", history.Status, history.TriggeredBy, history.HostsDiscovered, history.Output)
	}
}

// A work item whose target names another organization's connection gets no credential: it fails
// with the reason and the runner is told so.
func TestWorkItemRunner_NoCredentialForAnotherOrganizationsConnection(t *testing.T) {
	f := setupWorkItemRunner(t)
	other := f.seedOtherConnection(t)
	pb := f.storedPlaybookNaming(t, playbookSpec{}, other)
	item, err := f.items.RequestPlaybookSnapshot(t.Context(), pb, "manual")
	if err != nil {
		t.Fatal(err)
	}
	f.onPool(t, item)
	f.offered(t, "a1")
	f.claim(t, "a1", item.ID, "wi")
	rec := runnerDo(t, f.r, "wi", http.MethodGet, "/api/v2/runner/jobs/"+item.ID+"/artifacts", nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("artifacts for another organization's connection = %d, want 409", rec.Code)
	}
	if strings.Contains(rec.Body.String(), other.AccessToken) {
		t.Error("the refusal carries the other organization's token")
	}
	if got := f.reload(t, item.ID); got.Status != models.WorkItemStatusFailed {
		t.Errorf("work item = %q, want failed", got.Status)
	}
	if got := f.reloadPlaybook(t, pb.ID); got.LastSyncStatus != "failed" || got.LastSyncError == "" {
		t.Errorf("playbook = %q (%q), want the failure recorded", got.LastSyncStatus, got.LastSyncError)
	}
}

// A runner that has not declared it runs work items is offered none, and an OpenTofu-only runner
// is offered the snapshot kinds only.
func TestWorkItemRunner_OfferedByCapabilityAndEngine(t *testing.T) {
	f := setupWorkItemRunner(t)
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached})
	snapshot, err := f.items.RequestPlaybookSnapshot(t.Context(), pb, "manual")
	if err != nil {
		t.Fatal(err)
	}
	inv := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.orgA, Name: "wi-con-" + uuid.NewString()[:8], Type: models.InventoryTypeConstructed}
	if err := f.db.Create(inv).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", inv.ID).Delete(&models.AnsibleInventory{}) })
	rebuild, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	f.onPool(t, snapshot)
	f.onPool(t, rebuild)

	// a1 without the capability.
	f.declareCapabilities(t, f.runnerA1, runnercontract.CapabilityJobToken)
	if got := f.offered(t, "a1"); len(got) != 0 {
		t.Errorf("a runner without the work-items capability was offered %v", got)
	}
	// a2 runs OpenTofu only, with capacity for both.
	if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA2.ID).
		Updates(map[string]any{"runner_type": models.RunnerTypeTofu, "max_concurrent_jobs": 4}).Error; err != nil {
		t.Fatal(err)
	}
	got := f.offered(t, "a2")
	if !slices.Contains(got, snapshot.ID) || slices.Contains(got, rebuild.ID) {
		t.Errorf("an OpenTofu-only runner was offered %v, want the snapshot %s and not the rebuild %s", got, snapshot.ID, rebuild.ID)
	}
}

// A VCS-backed run without a configuration version is offered to no runner until its
// configuration_snapshot work item uploads the configuration, which becomes the run's
// configuration version (#933, decision 18, AC68).
func TestWorkItemRunner_ConfigurationSnapshotGatesTheRun(t *testing.T) {
	f := setupWorkItemRunner(t)
	_, run := f.storedWorkspaceNaming(t, f.vcsConn)
	// a2 runs OpenTofu and work items with room for both.
	if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA2.ID).Update("max_concurrent_jobs", 4).Error; err != nil {
		t.Fatal(err)
	}
	offeredRuns := func() []string {
		rec := runnerDo(t, f.r, "a2", http.MethodPost, "/api/v2/runner/heartbeat", runnercontract.HeartbeatRequest{RunnerID: f.runnerA2.ID.String(), Status: "online"})
		var resp runnercontract.HeartbeatResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		var ids []string
		for _, o := range resp.PendingJobs {
			ids = append(ids, o.JobID)
		}
		return ids
	}
	if got := offeredRuns(); slices.Contains(got, run.ID) {
		t.Fatalf("a VCS-backed run without a configuration version was offered: %v", got)
	}

	item, err := f.items.RequestConfigurationSnapshot(t.Context(), run)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.items.RequestConfigurationSnapshot(t.Context(), run)
	if err != nil || again.ID != item.ID {
		t.Errorf("a second request made %v (%v), want the same work item %s", again, err, item.ID)
	}
	t.Cleanup(func() {
		// The run references the version, so it goes first.
		f.db.Where("run_id = ?", run.ID).Delete(&models.WorkItem{})
		f.db.Where("id = ?", run.ID).Delete(&models.Run{})
		f.db.Where("workspace_id = ?", run.WorkspaceID).Delete(&models.ConfigurationVersion{})
	})
	f.onPool(t, item)
	if got := offeredRuns(); !slices.Contains(got, item.ID) || slices.Contains(got, run.ID) {
		t.Fatalf("offered %v, want the configuration snapshot %s and not the run", got, item.ID)
	}
	f.claim(t, "a2", item.ID, "wi")
	rec := runnerDo(t, f.r, "wi", http.MethodGet, "/api/v2/runner/jobs/"+item.ID+"/artifacts", nil)
	var art runnercontract.WorkItemArtifacts
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &art) != nil || art.Clone == nil || art.Clone.URL != "https://gitlab.com/acme/infra.git" {
		t.Fatalf("artifacts: %d %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/snapshot", bytes.NewReader([]byte("config tarball")))
	req.Header.Set("X-Test-Key", "wi")
	req.Header.Set(runnercontract.HeaderSnapshotCommit, "feedface")
	up := httptest.NewRecorder()
	f.r.ServeHTTP(up, req)
	if up.Code != http.StatusOK {
		t.Fatalf("snapshot upload: %d %s", up.Code, up.Body.String())
	}
	done := JobCompleteRequest{RunnerID: f.runnerA2.ID.String(), Status: "completed", WorkResult: &runnercontract.WorkResult{Commit: "feedface"}}
	if rec := runnerDo(t, f.r, "wi", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/complete", done); rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	var after models.Run
	f.db.First(&after, "id = ?", run.ID)
	if after.ConfigurationVersionID == nil {
		t.Fatal("the run has no configuration version after its snapshot")
	}
	var cv models.ConfigurationVersion
	f.db.First(&cv, "id = ?", *after.ConfigurationVersionID)
	if cv.Status != models.ConfigurationVersionStatusUploaded || cv.CommitHash != "feedface" || cv.Source != "tfe-vcs" || cv.WorkspaceID != run.WorkspaceID {
		t.Errorf("configuration version = %+v", cv)
	}
	if data, err := f.store.Get(t.Context(), cv.TarballKey()); err != nil || cv.ArchiveKey == "" || string(data) != "config tarball" {
		t.Errorf("stored configuration = %q (%v)", data, err)
	}
	if got := offeredRuns(); !slices.Contains(got, run.ID) {
		t.Errorf("the run was not offered once it had its configuration: %v", got)
	}
}
