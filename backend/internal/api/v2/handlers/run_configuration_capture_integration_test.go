// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A VCS run's configuration is captured by an executor into a configuration version created with
// the run in status fetching (#938, AC-19, AC-20). The run is offered only once the capture is
// uploaded; the upload is a locked, one-way transition from fetching to uploaded at the requested
// commit; a completion counts only when that upload was accepted; and a capture that finished,
// was canceled or lost a race changes nothing.

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
)

const (
	captureCommit = "1111111111111111111111111111111111111111"
	otherCommit   = "2222222222222222222222222222222222222222"
)

// fetchingRun seeds a VCS run whose configuration version is fetching at commit (empty for the
// branch head), as run creation and the webhook paths now create them.
func (f *workItemRunnerFixture) fetchingRun(t *testing.T, commit, fetchRef string) (*models.Run, *models.ConfigurationVersion) {
	t.Helper()
	_, run := f.storedWorkspaceNaming(t, f.vcsConn)
	cv := &models.ConfigurationVersion{
		WorkspaceID: run.WorkspaceID, Status: models.ConfigurationVersionStatusFetching, Source: "tfe-vcs",
		CommitHash: commit, FetchRef: fetchRef, Speculative: true, PRNumber: 7, SourceBranch: "feature",
	}
	if err := f.db.Create(cv).Error; err != nil {
		t.Fatalf("seed configuration version: %v", err)
	}
	if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Update("configuration_version_id", cv.ID).Error; err != nil {
		t.Fatal(err)
	}
	run.ConfigurationVersionID = &cv.ID
	t.Cleanup(func() {
		// Children first: the run references the version, so it goes before it.
		f.db.Where("run_id = ?", run.ID).Delete(&models.WorkItem{})
		f.db.Where("id = ?", run.ID).Delete(&models.Run{})
		f.db.Where("workspace_id = ?", run.WorkspaceID).Delete(&models.ConfigurationVersion{})
	})
	// a2 runs OpenTofu and work items with room for both.
	if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA2.ID).Update("max_concurrent_jobs", 4).Error; err != nil {
		t.Fatal(err)
	}
	return run, cv
}

func (f *workItemRunnerFixture) offeredTo(t *testing.T, key string) []string {
	t.Helper()
	runner := map[string]*models.Runner{"a1": f.runnerA1, "a2": f.runnerA2}[key]
	rec := runnerDo(t, f.r, key, http.MethodPost, "/api/v2/runner/heartbeat", runnercontract.HeartbeatRequest{RunnerID: runner.ID.String(), Status: "online"})
	var resp runnercontract.HeartbeatResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	var ids []string
	for _, o := range resp.PendingJobs {
		ids = append(ids, o.JobID)
	}
	return ids
}

// captureClaimed requests the run's capture, puts it on pool A and claims it as a2 under "wi".
func (f *workItemRunnerFixture) captureClaimed(t *testing.T, run *models.Run) *models.WorkItem {
	t.Helper()
	item, err := f.items.RequestConfigurationSnapshot(t.Context(), run)
	if err != nil {
		t.Fatal(err)
	}
	f.onPool(t, item)
	if got := f.offeredTo(t, "a2"); !slices.Contains(got, item.ID) {
		t.Fatalf("offered %v, want the capture %s", got, item.ID)
	}
	f.claim(t, "a2", item.ID, "wi")
	return item
}

func (f *workItemRunnerFixture) upload(t *testing.T, id, commit, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runner/jobs/"+id+"/snapshot", bytes.NewReader([]byte(body)))
	req.Header.Set("X-Test-Key", "wi")
	req.Header.Set(runnercontract.HeaderSnapshotCommit, commit)
	rec := httptest.NewRecorder()
	f.r.ServeHTTP(rec, req)
	return rec
}

func (f *workItemRunnerFixture) complete(t *testing.T, id, status, commit string) {
	t.Helper()
	done := JobCompleteRequest{RunnerID: f.runnerA2.ID.String(), Status: status, WorkResult: &runnercontract.WorkResult{Commit: commit}}
	if status != "completed" {
		done.ErrorMessage = "the capture failed"
	}
	if rec := runnerDo(t, f.r, "wi", http.MethodPost, "/api/v2/runner/jobs/"+id+"/complete", done); rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
}

func (f *workItemRunnerFixture) state(t *testing.T, run *models.Run, cvID string) (models.Run, models.ConfigurationVersion) {
	t.Helper()
	var r models.Run
	var cv models.ConfigurationVersion
	f.db.First(&r, "id = ?", run.ID)
	f.db.First(&cv, "id = ?", cvID)
	return r, cv
}

// holdWorkItem holds the work item's row lock, as a concurrent upload or completion holds it,
// until the returned release is called.
func holdWorkItem(t *testing.T, db *gorm.DB, id string) (release func()) {
	t.Helper()
	held, done, holder := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		holder <- db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("SELECT id FROM work_items WHERE id = ? FOR UPDATE", id).Error; err != nil {
				return err
			}
			close(held)
			<-done
			return nil
		})
	}()
	<-held
	var once sync.Once
	release = func() {
		once.Do(func() {
			close(done)
			if err := <-holder; err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(release)
	return release
}

// sendCanceled serves req with a context canceled 300 ms in and reports whether the handler
// returned within 5 s of that.
func sendCanceled(t *testing.T, r *gin.Engine, req *http.Request) bool {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		r.ServeHTTP(httptest.NewRecorder(), req.WithContext(ctx))
		close(done)
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case <-done:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}

// A capture request whose context ends while the pool's only connection is taken stops waiting
// for one and creates nothing (R-33 F-01).
func TestConfigurationCapture_ACanceledRequestDoesNotWaitForAConnection(t *testing.T) {
	f := setupWorkItemRunner(t)
	run, _ := f.fetchingRun(t, captureCommit, "refs/pull/7/head")
	sqlDB, err := f.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	held, release, holder := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		holder <- f.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("SELECT 1").Error; err != nil {
				return err
			}
			close(held)
			<-release
			return nil
		})
	}()
	released := false
	defer func() {
		if !released {
			close(release)
			<-holder
		}
		sqlDB.SetMaxOpenConns(0)
	}()
	<-held
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := f.items.RequestConfigurationSnapshot(ctx, run)
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a canceled capture request succeeded without a connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a canceled capture request kept waiting for a database connection")
	}
	close(release)
	released = true
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
	var n int64
	f.db.Model(&models.WorkItem{}).Where("run_id = ?", run.ID).Count(&n)
	if n != 0 {
		t.Errorf("a canceled capture request created %d work item(s), want none", n)
	}
}

// An upload or a completion whose request is canceled while it waits for the work item stops
// waiting and changes nothing (R-32 F-01).
func TestConfigurationCapture_ACanceledRequestStopsWaitingForTheWorkItem(t *testing.T) {
	f := setupWorkItemRunner(t)
	run, cv := f.fetchingRun(t, captureCommit, "refs/pull/7/head")
	item := f.captureClaimed(t, run)

	release := holdWorkItem(t, f.db, item.ID)
	upload := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/snapshot", bytes.NewReader([]byte("config")))
	upload.Header.Set("X-Test-Key", "wi")
	upload.Header.Set(runnercontract.HeaderSnapshotCommit, captureCommit)
	if !sendCanceled(t, f.r, upload) {
		t.Fatal("a canceled upload kept waiting for the work item")
	}
	release()
	var got models.ConfigurationVersion
	if err := f.db.First(&got, "id = ?", cv.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != models.ConfigurationVersionStatusFetching {
		t.Errorf("the version after a canceled upload = %s, want still fetching", got.Status)
	}

	release = holdWorkItem(t, f.db, item.ID)
	body, _ := json.Marshal(JobCompleteRequest{RunnerID: f.runnerA2.ID.String(), Status: "failed", ErrorMessage: "x", WorkResult: &runnercontract.WorkResult{}})
	complete := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/complete", bytes.NewReader(body))
	complete.Header.Set("Content-Type", "application/json")
	complete.Header.Set("X-Test-Key", "wi")
	if !sendCanceled(t, f.r, complete) {
		t.Fatal("a canceled completion kept waiting for the work item")
	}
	release()
	if st := f.reload(t, item.ID).Status; st != models.WorkItemStatusRunning {
		t.Errorf("the capture after a canceled completion = %s, want still running", st)
	}
}

// A capture whose pinned version cannot be read is served no clone source rather than one with no
// commit, which would capture the branch head instead of the requested revision (R-34 F-03).
func TestConfigurationCapture_AnUnreadablePinIsAnError(t *testing.T) {
	f := setupWorkItemRunner(t)
	run, _ := f.fetchingRun(t, captureCommit, "refs/pull/7/head")
	item := f.captureClaimed(t, run)
	name := "test:fail-version-read-" + uuid.NewString()[:8]
	if err := f.db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table == "configuration_versions" {
			_ = tx.AddError(errors.New("injected read failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.db.Callback().Query().Remove(name) })
	rec := runnerDo(t, f.r, "wi", http.MethodGet, "/api/v2/runner/jobs/"+item.ID+"/artifacts", nil)
	_ = f.db.Callback().Query().Remove(name)
	if rec.Code == http.StatusOK {
		var art runnercontract.WorkItemArtifacts
		_ = json.Unmarshal(rec.Body.Bytes(), &art)
		t.Errorf("artifacts with an unreadable pin answered 200 with commit %q", func() string {
			if art.Clone == nil {
				return ""
			}
			return art.Clone.Commit
		}())
	}
}

// An artifacts request whose context ends while the pool's only connection is taken stops waiting
// for one (R-34 F-02).
func TestConfigurationCapture_ACanceledArtifactsRequestDoesNotWaitForAConnection(t *testing.T) {
	f := setupWorkItemRunner(t)
	run, _ := f.fetchingRun(t, captureCommit, "refs/pull/7/head")
	item := f.captureClaimed(t, run)
	sqlDB, err := f.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	held, release, holder := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		holder <- f.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("SELECT 1").Error; err != nil {
				return err
			}
			close(held)
			<-release
			return nil
		})
	}()
	released := false
	defer func() {
		if !released {
			close(release)
			<-holder
		}
		sqlDB.SetMaxOpenConns(0)
	}()
	<-held
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := f.h.workItemArtifacts(ctx, item)
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a canceled artifacts request succeeded without a connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a canceled artifacts request kept waiting for a database connection")
	}
	close(release)
	released = true
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationCapture_FillsTheFetchingVersion(t *testing.T) {
	f := setupWorkItemRunner(t)
	run, cv := f.fetchingRun(t, captureCommit, "refs/pull/7/head")
	if got := f.offeredTo(t, "a2"); slices.Contains(got, run.ID) {
		t.Fatalf("a run whose configuration is still fetching was offered: %v", got)
	}
	item := f.captureClaimed(t, run)
	rec := runnerDo(t, f.r, "wi", http.MethodGet, "/api/v2/runner/jobs/"+item.ID+"/artifacts", nil)
	var art runnercontract.WorkItemArtifacts
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &art) != nil || art.Clone == nil {
		t.Fatalf("artifacts: %d %s", rec.Code, rec.Body.String())
	}
	if art.Clone.Commit != captureCommit || art.Clone.FetchRef != "refs/pull/7/head" {
		t.Errorf("clone source asks for commit %q and fetch ref %q, want the version's %s and refs/pull/7/head", art.Clone.Commit, art.Clone.FetchRef, captureCommit)
	}
	if up := f.upload(t, item.ID, captureCommit, "config tarball"); up.Code != http.StatusOK {
		t.Fatalf("snapshot upload: %d %s", up.Code, up.Body.String())
	}
	f.complete(t, item.ID, "completed", captureCommit)
	after, got := f.state(t, run, cv.ID)
	if after.ConfigurationVersionID == nil || *after.ConfigurationVersionID != cv.ID {
		t.Fatalf("the run points at %v, want its fetching version %s, filled", after.ConfigurationVersionID, cv.ID)
	}
	if got.Status != models.ConfigurationVersionStatusUploaded || got.CommitHash != captureCommit || !got.Speculative || got.PRNumber != 7 {
		t.Errorf("configuration version = status %s commit %s speculative %v pr %d", got.Status, got.CommitHash, got.Speculative, got.PRNumber)
	}
	if data, err := f.store.Get(t.Context(), got.TarballKey()); err != nil || got.ArchiveKey == "" || string(data) != "config tarball" {
		t.Errorf("stored configuration = %q (%v)", data, err)
	}
	if f.reload(t, item.ID).Status != models.WorkItemStatusCompleted {
		t.Errorf("the capture ended %s, want completed", f.reload(t, item.ID).Status)
	}
	if got := f.offeredTo(t, "a2"); !slices.Contains(got, run.ID) {
		t.Errorf("the run was not offered once its configuration was uploaded: %v", got)
	}
}

func TestConfigurationCapture_BranchHeadRecordsTheCommit(t *testing.T) {
	f := setupWorkItemRunner(t)
	run, cv := f.fetchingRun(t, "", "")
	item := f.captureClaimed(t, run)
	if up := f.upload(t, item.ID, otherCommit, "head"); up.Code != http.StatusOK {
		t.Fatalf("snapshot upload: %d %s", up.Code, up.Body.String())
	}
	f.complete(t, item.ID, "completed", otherCommit)
	if _, got := f.state(t, run, cv.ID); got.Status != models.ConfigurationVersionStatusUploaded || got.CommitHash != otherCommit {
		t.Errorf("configuration version = status %s commit %q, want uploaded at %s", got.Status, got.CommitHash, otherCommit)
	}
}

func TestConfigurationCapture_RefusesAnotherCommit(t *testing.T) {
	f := setupWorkItemRunner(t)
	run, cv := f.fetchingRun(t, captureCommit, "")
	item := f.captureClaimed(t, run)
	if up := f.upload(t, item.ID, otherCommit, "wrong"); up.Code != http.StatusConflict {
		t.Errorf("a snapshot of another commit answered %d, want 409", up.Code)
	}
	f.complete(t, item.ID, "completed", otherCommit)
	after, got := f.state(t, run, cv.ID)
	if got.Status != models.ConfigurationVersionStatusErrored || after.Status != models.RunStatusErrored {
		t.Errorf("after a refused snapshot the version is %s and the run %s, want both errored", got.Status, after.Status)
	}
	if f.reload(t, item.ID).Status != models.WorkItemStatusFailed {
		t.Errorf("the capture ended %s, want failed", f.reload(t, item.ID).Status)
	}
	if _, err := f.store.Get(t.Context(), models.ConfigurationTarballKey(cv.ID)); err == nil {
		t.Error("the refused snapshot was stored")
	}
}

func TestConfigurationCapture_AnUploadedCaptureNeverChanges(t *testing.T) {
	f := setupWorkItemRunner(t)
	run, cv := f.fetchingRun(t, "", "")
	item := f.captureClaimed(t, run)
	if up := f.upload(t, item.ID, captureCommit, "first"); up.Code != http.StatusOK {
		t.Fatalf("first upload: %d %s", up.Code, up.Body.String())
	}
	// The branch moved on and a second upload arrives for the same version.
	if up := f.upload(t, item.ID, otherCommit, "second"); up.Code != http.StatusConflict {
		t.Errorf("a second upload answered %d, want 409", up.Code)
	}
	// A failure reported after the upload leaves the uploaded capture alone.
	f.complete(t, item.ID, "failed", "")
	_, got := f.state(t, run, cv.ID)
	if got.Status != models.ConfigurationVersionStatusUploaded || got.CommitHash != captureCommit {
		t.Errorf("configuration version = status %s commit %s, want the first upload kept", got.Status, got.CommitHash)
	}
	if data, _ := f.store.Get(t.Context(), got.TarballKey()); string(data) != "first" {
		t.Errorf("stored configuration = %q, want the first upload", data)
	}
}

func TestConfigurationCapture_CompletionWithoutAnUploadFails(t *testing.T) {
	f := setupWorkItemRunner(t)
	run, cv := f.fetchingRun(t, captureCommit, "")
	item := f.captureClaimed(t, run)
	f.complete(t, item.ID, "completed", captureCommit)
	after, got := f.state(t, run, cv.ID)
	if f.reload(t, item.ID).Status != models.WorkItemStatusFailed {
		t.Errorf("a completion without an upload ended %s, want failed", f.reload(t, item.ID).Status)
	}
	if got.Status != models.ConfigurationVersionStatusErrored || after.Status != models.RunStatusErrored {
		t.Errorf("the version is %s and the run %s, want both errored", got.Status, after.Status)
	}
}

func TestConfigurationCapture_OneCapturePerRun(t *testing.T) {
	f := setupWorkItemRunner(t)
	run, _ := f.fetchingRun(t, "", "")
	var wg sync.WaitGroup
	ids := make([]string, 8)
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if item, err := f.items.RequestConfigurationSnapshot(t.Context(), run); err == nil {
				ids[i] = item.ID
			} else {
				t.Errorf("request %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	var active int64
	f.db.Model(&models.WorkItem{}).Where("run_id = ? AND kind = ? AND status IN ?", run.ID, models.WorkItemConfigurationSnapshot,
		[]string{models.WorkItemStatusPending, models.WorkItemStatusRunning}).Count(&active)
	if active != 1 {
		t.Errorf("%d concurrent requests left %d active captures, want 1", len(ids), active)
	}
	for _, id := range ids {
		if id != ids[0] {
			t.Errorf("requests returned different work items: %v", ids)
			break
		}
	}
}

// A request that passed its authorization check before its capture was canceled changes nothing
// once it acts: neither an upload nor a completion fills, errors or fails the version.
func TestConfigurationCapture_ACanceledCaptureChangesNothing(t *testing.T) {
	f := setupWorkItemRunner(t)
	cancel := func(id string) {
		if err := f.db.Model(&models.WorkItem{}).Where("id = ?", id).
			Updates(map[string]any{"status": models.WorkItemStatusCanceled}).Error; err != nil {
			t.Errorf("cancel %s: %v", id, err)
		}
	}

	t.Run("upload", func(t *testing.T) {
		run, cv := f.fetchingRun(t, "", "")
		item := f.captureClaimed(t, run)
		f.h.snapshotAuthorized = cancel
		defer func() { f.h.snapshotAuthorized = nil }()
		up := f.upload(t, item.ID, captureCommit, "late")
		if up.Code == http.StatusOK {
			t.Errorf("an upload whose capture was canceled meanwhile answered 200")
		}
		if _, got := f.state(t, run, cv.ID); got.Status != models.ConfigurationVersionStatusFetching {
			t.Errorf("the version is %s, want it still fetching for the surviving capture", got.Status)
		}
	})
	t.Run("completion", func(t *testing.T) {
		run, cv := f.fetchingRun(t, "", "")
		item := f.captureClaimed(t, run)
		f.h.beforeWorkItemFinish = cancel
		defer func() { f.h.beforeWorkItemFinish = nil }()
		done := JobCompleteRequest{RunnerID: f.runnerA2.ID.String(), Status: "completed", WorkResult: &runnercontract.WorkResult{}}
		runnerDo(t, f.r, "wi", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/complete", done)
		after, got := f.state(t, run, cv.ID)
		if got.Status != models.ConfigurationVersionStatusFetching || after.Status == models.RunStatusErrored {
			t.Errorf("a completion of a canceled capture left the version %s and the run %s, want both untouched", got.Status, after.Status)
		}
		if st := f.reload(t, item.ID).Status; st != models.WorkItemStatusCanceled {
			t.Errorf("the canceled capture became %s", st)
		}
		_ = uuid.Nil
	})
}

// A capture reclaimed while a request authorized for its earlier attempt is in flight changes
// nothing (R-16 F-02): the upload and the completion check, under the work item's row lock, that
// the attempt they were authorized for is still the current one.
func TestConfigurationCapture_AReclaimedAttemptChangesNothing(t *testing.T) {
	f := setupWorkItemRunner(t)
	reclaim := func(id string) {
		if err := f.db.Model(&models.WorkItem{}).Where("id = ?", id).Update("attempt", gorm.Expr("GREATEST(attempt, 1) + 1")).Error; err != nil {
			t.Errorf("reclaim %s: %v", id, err)
		}
	}
	t.Run("upload", func(t *testing.T) {
		run, cv := f.fetchingRun(t, "", "")
		item := f.captureClaimed(t, run)
		f.h.snapshotAuthorized = reclaim
		defer func() { f.h.snapshotAuthorized = nil }()
		if up := f.upload(t, item.ID, captureCommit, "stale"); up.Code != http.StatusConflict {
			t.Errorf("an upload of a reclaimed attempt answered %d, want 409", up.Code)
		}
		if got := f.reload(t, item.ID).Commit; got != "" {
			t.Errorf("a refused upload recorded commit %q on the newer attempt, want none", got)
		}
		if _, got := f.state(t, run, cv.ID); got.Status != models.ConfigurationVersionStatusFetching {
			t.Errorf("the version is %s, want it still fetching for the newer attempt", got.Status)
		}
	})
	t.Run("completion", func(t *testing.T) {
		run, cv := f.fetchingRun(t, "", "")
		item := f.captureClaimed(t, run)
		f.h.beforeWorkItemFinish = reclaim
		defer func() { f.h.beforeWorkItemFinish = nil }()
		done := JobCompleteRequest{RunnerID: f.runnerA2.ID.String(), Status: "failed", ErrorMessage: "stale", WorkResult: &runnercontract.WorkResult{Commit: otherCommit}}
		runnerDo(t, f.r, "wi", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/complete", done)
		after, got := f.state(t, run, cv.ID)
		if got.Status != models.ConfigurationVersionStatusFetching || after.Status == models.RunStatusErrored {
			t.Errorf("a reclaimed attempt's failure left the version %s and the run %s, want fetching and not errored", got.Status, after.Status)
		}
		if st := f.reload(t, item.ID).Status; st != models.WorkItemStatusRunning {
			t.Errorf("the capture is %s, want still running for its newer attempt", st)
		}
		if got := f.reload(t, item.ID).Commit; got != "" {
			t.Errorf("a refused completion recorded commit %q on the newer attempt, want none", got)
		}
	})
	t.Run("the newer attempt keeps its token", func(t *testing.T) {
		// R-17 F-01: a stale completion is refused and revokes nothing; the newer attempt's token
		// still verifies.
		run, _ := f.fetchingRun(t, "", "")
		item := f.captureClaimed(t, run)
		var newer *models.APIKey
		f.h.beforeWorkItemFinish = func(id string) {
			reclaim(id)
			key, _, err := f.svc.CreateJobToken(f.orgA, f.runnerA2.AgentPoolID, apikey.JobPrincipal{Kind: models.JobTypeWorkItem, JobID: id, RunnerID: f.runnerA2.ID, Attempt: 2}, time.Now().Add(time.Hour))
			if err != nil {
				t.Errorf("mint the newer attempt's token: %v", err)
			}
			newer = key
		}
		defer func() { f.h.beforeWorkItemFinish = nil }()
		done := JobCompleteRequest{RunnerID: f.runnerA2.ID.String(), Status: "completed", WorkResult: &runnercontract.WorkResult{}}
		if rec := runnerDo(t, f.r, "wi", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/complete", done); rec.Code == http.StatusOK {
			t.Errorf("a stale completion was acknowledged")
		}
		if newer == nil {
			t.Fatal("no newer token was minted")
		}
		var reloaded models.APIKey
		if err := f.db.First(&reloaded, "id = ?", newer.ID).Error; err != nil {
			t.Fatal(err)
		}
		if reloaded.ExpiresAt != nil && !reloaded.ExpiresAt.After(time.Now()) {
			t.Errorf("the newer attempt's token was revoked by a stale completion")
		}
	})
}

// A failed capture's finish, its version's failure and its run's failure commit together (R-16
// F-04): when one of the writes fails, the completion is not acknowledged and nothing changed, so
// the executor's retry still finds the capture running and records all three.
func TestConfigurationCapture_AFailedCaptureFailsAtomically(t *testing.T) {
	f := setupWorkItemRunner(t)
	run, cv := f.fetchingRun(t, "", "")
	item := f.captureClaimed(t, run)
	fn := "test_fail_run_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if err := f.db.Exec(`CREATE FUNCTION ` + fn + `() RETURNS trigger AS $$ BEGIN
		IF NEW.id = '` + run.ID + `' AND NEW.status = 'errored' THEN RAISE EXCEPTION 'injected run write failure'; END IF;
		RETURN NEW; END $$ LANGUAGE plpgsql`).Error; err != nil {
		t.Fatal(err)
	}
	dropped := false
	drop := func() {
		if !dropped {
			f.db.Exec(`DROP TRIGGER IF EXISTS ` + fn + ` ON runs`)
			f.db.Exec(`DROP FUNCTION IF EXISTS ` + fn + `()`)
			dropped = true
		}
	}
	t.Cleanup(drop)
	if err := f.db.Exec(`CREATE TRIGGER ` + fn + ` BEFORE UPDATE ON runs FOR EACH ROW EXECUTE FUNCTION ` + fn + `()`).Error; err != nil {
		t.Fatal(err)
	}
	done := JobCompleteRequest{RunnerID: f.runnerA2.ID.String(), Status: "failed", ErrorMessage: "clone failed", WorkResult: &runnercontract.WorkResult{}}
	if rec := runnerDo(t, f.r, "wi", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/complete", done); rec.Code == http.StatusOK {
		t.Errorf("a completion whose run write failed was acknowledged")
	}
	after, got := f.state(t, run, cv.ID)
	if st := f.reload(t, item.ID).Status; st != models.WorkItemStatusRunning || got.Status != models.ConfigurationVersionStatusFetching || after.Status == models.RunStatusErrored {
		t.Fatalf("after a failed write the capture is %s, the version %s and the run %s; want running, fetching, not errored", st, got.Status, after.Status)
	}
	drop()
	if rec := runnerDo(t, f.r, "wi", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/complete", done); rec.Code != http.StatusOK {
		t.Fatalf("the retried completion = %d %s", rec.Code, rec.Body.String())
	}
	after, got = f.state(t, run, cv.ID)
	if st := f.reload(t, item.ID).Status; st != models.WorkItemStatusFailed || got.Status != models.ConfigurationVersionStatusErrored || after.Status != models.RunStatusErrored {
		t.Errorf("after the retry the capture is %s, the version %s and the run %s; want failed, errored, errored", st, got.Status, after.Status)
	}
}

// A capture of a run without a configuration version, requested by an older orchestrator during a
// rolling deploy, is held to the same rules as any capture (R-18 F-02, F-03): canceled while its
// upload is in flight it changes nothing, and racing the new orchestrator's conversion it fills the
// version the conversion attached, so the completion then succeeds.
func TestConfigurationCapture_ALegacyCaptureFollowsTheSameRules(t *testing.T) {
	f := setupWorkItemRunner(t)
	t.Run("canceled meanwhile", func(t *testing.T) {
		_, run := f.storedWorkspaceNaming(t, f.vcsConn)
		item := f.captureClaimed(t, run)
		f.h.snapshotAuthorized = func(id string) {
			if err := f.db.Model(&models.WorkItem{}).Where("id = ?", id).Update("status", models.WorkItemStatusCanceled).Error; err != nil {
				t.Errorf("cancel %s: %v", id, err)
			}
		}
		defer func() { f.h.snapshotAuthorized = nil }()
		if up := f.upload(t, item.ID, captureCommit, "late"); up.Code != http.StatusConflict {
			t.Errorf("a canceled legacy capture's upload answered %d, want 409", up.Code)
		}
		var after models.Run
		f.db.First(&after, "id = ?", run.ID)
		if after.ConfigurationVersionID != nil {
			t.Errorf("a canceled legacy capture attached configuration version %s", *after.ConfigurationVersionID)
		}
	})
	t.Run("racing a conversion", func(t *testing.T) {
		_, run := f.storedWorkspaceNaming(t, f.vcsConn)
		item := f.captureClaimed(t, run)
		var attached string
		f.h.snapshotAuthorized = func(string) {
			// The new orchestrator's conversion, as convertToFetching performs it.
			cv := &models.ConfigurationVersion{WorkspaceID: run.WorkspaceID, Status: models.ConfigurationVersionStatusFetching, Source: "tfe-vcs", Speculative: true}
			if err := f.db.Transaction(func(tx *gorm.DB) error {
				if err := tx.Create(cv).Error; err != nil {
					return err
				}
				return tx.Model(&models.Run{}).Where("id = ? AND configuration_version_id IS NULL", run.ID).Update("configuration_version_id", cv.ID).Error
			}); err != nil {
				t.Errorf("convert: %v", err)
			}
			attached = cv.ID
		}
		defer func() { f.h.snapshotAuthorized = nil }()
		if up := f.upload(t, item.ID, captureCommit, "raced"); up.Code != http.StatusOK {
			t.Fatalf("the raced upload answered %d %s, want 200", up.Code, up.Body.String())
		}
		f.complete(t, item.ID, "completed", captureCommit)
		after, cv := f.state(t, run, attached)
		if after.ConfigurationVersionID == nil || *after.ConfigurationVersionID != attached || cv.Status != models.ConfigurationVersionStatusUploaded {
			t.Errorf("after the race the run names %v and version %s is %s; want the converted version, uploaded", after.ConfigurationVersionID, attached, cv.Status)
		}
		if st := f.reload(t, item.ID).Status; st != models.WorkItemStatusCompleted {
			t.Errorf("the capture ended %s, want completed", st)
		}
	})
}
