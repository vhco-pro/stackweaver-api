// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Publishing a registry module version from a Git tag runs a module_tag_snapshot work item (#938,
// AC-21): the API clones nothing. The capture clones with the module's own connection, resolved
// within the module's organization, and the API publishes the version from the snapshot the
// executor uploads. A connection that cannot mint a token fails the capture; there is no
// unauthenticated clone. A tag is captured once however often it is delivered, distinct tags are
// captured apart, and tags that name one version publish it once, its metadata and archive from
// the same capture.

//go:build integration

package handlers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	coreansible "github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/gorm"
)

// moduleTarball is a module repository holding main.tf with body.
func moduleTarball(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "main.tf", Mode: 0o644, Size: int64(len(body)), ModTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A module that carries a large file publishes (R-31 F-02): the archive the publisher builds must
// not include itself while it is being written.
func TestModuleTagCapture_AModuleWithALargeFilePublishes(t *testing.T) {
	f := setupModuleCapture(t)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	// Random bytes do not compress, so the archive grows while it is written, as in R-31's probe.
	asset := make([]byte, 512*1024)
	if _, err := rand.Read(asset); err != nil {
		t.Fatal(err)
	}
	for _, file := range []struct {
		name string
		body []byte
	}{{"main.tf", []byte(`variable "a" {}`)}, {"assets.bin", asset}} {
		if err := tw.WriteHeader(&tar.Header{Name: file.name, Mode: 0o644, Size: int64(len(file.body)), ModTime: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(file.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.publisher.PublishVersionFromTarball(t.Context(), f.module.ID, "9.0.0", bytes.NewReader(buf.Bytes()), int64(buf.Len())); err != nil {
		t.Fatalf("a module with a %d byte file failed to publish: %v", len(asset), err)
	}
	if !f.versions.Exists(f.module.ID, "9.0.0") {
		t.Error("version 9.0.0 was not published")
	}
}

// mainTF returns main.tf from a stored module archive.
func mainTF(t *testing.T, archive []byte) string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("reading the stored archive: %v", err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatalf("main.tf is not in the stored archive: %v", err)
		}
		if strings.TrimPrefix(h.Name, "./") == "main.tf" {
			data, _ := io.ReadAll(tr)
			return string(data)
		}
	}
}

// seedTagModule creates a module of org publishing repo's tags through conn.
func seedTagModule(t *testing.T, f *installationWebhookFixture, org uuid.UUID, conn *uuid.UUID, repo string) *models.Module {
	t.Helper()
	m := &models.Module{
		ID: uuid.New(), OrganizationID: org, Name: "tagmod-" + uuid.NewString()[:8], Provider: "aws",
		VCSConnectionID: conn, VCSRepository: repo, AutoPublishTags: true,
	}
	if err := f.db.Create(m).Error; err != nil {
		t.Fatalf("seed module: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("module_id = ?", m.ID).Delete(&models.WorkItem{})
		f.db.Where("module_id = ?", m.ID).Delete(&models.ModuleVersion{})
		f.db.Where("id = ?", m.ID).Delete(&models.Module{})
	})
	return m
}

// tagPublishing wires the capture fixture's handler to publish tags, requesting captures as work
// items.
func (f *captureFixture) tagPublishing() {
	moduleRepo := repository.NewModuleRepository(f.db)
	versions := repository.NewModuleVersionRepository(f.db)
	orgs := repository.NewOrganizationRepository(f.db)
	conns := repository.NewVCSConnectionRepository(f.db)
	p := NewRegistryPublishingHandler(moduleRepo, versions, orgs, conns, auth.NewService(repository.NewUserRepository(f.db)),
		newProviderRBAC(f.db), f.githubManager, registry.NewModulePublisher(moduleRepo, versions, orgs, conns, newSnapshotStore()))
	p.SetWorkItems(coreansible.NewWorkItemService(f.db, nil))
	f.handler.moduleRepo, f.handler.registryPublisher = moduleRepo, p
}

func (f *captureFixture) tagPush(t *testing.T, tag string) {
	t.Helper()
	f.github(t, "push", map[string]any{
		"ref": "refs/tags/" + tag, "ref_type": "tag",
		"repository":   map[string]any{"full_name": f.repo, "id": 1},
		"installation": map[string]any{"id": f.instA},
	})
}

// captures returns the module's tag captures, oldest first.
func captures(t *testing.T, f *installationWebhookFixture, module *models.Module) []models.WorkItem {
	t.Helper()
	var items []models.WorkItem
	if err := f.db.Where("module_id = ? AND kind = ?", module.ID, models.WorkItemModuleTagSnapshot).Order("created_at").Find(&items).Error; err != nil {
		t.Fatal(err)
	}
	return items
}

func capturesOf(items []models.WorkItem, tag string) []models.WorkItem {
	var out []models.WorkItem
	for _, it := range items {
		if it.RequestedRef == tag {
			out = append(out, it)
		}
	}
	return out
}

// A tag push reports the captures it queued, not publications: the version is published later,
// when the capture uploads (R-36 F-01).
func TestModuleTagCapture_ATagPushReportsQueuedCaptures(t *testing.T) {
	f := setupCapture(t)
	f.tagPublishing()
	seedTagModule(t, f.installationWebhookFixture, f.org.ID, &f.connA.ID, f.repo)
	payload, _ := json.Marshal(map[string]any{
		"ref": "refs/tags/v2.0.0", "ref_type": "tag",
		"repository":   map[string]any{"full_name": f.repo, "id": 1},
		"installation": map[string]any{"id": f.instA},
	})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/vcs-connections/github/webhook", bytes.NewReader(payload))
	c.Request.Header.Set("X-GitHub-Event", "push")
	c.Request.Header.Set("X-Hub-Signature-256", githubSign(payload, f.secret))
	f.handler.HandleInstallationWebhook(c)
	c.Writer.WriteHeaderNow()
	if w.Code != http.StatusOK {
		t.Fatalf("tag push = %d %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "1 module capture(s) queued") || strings.Contains(body, "published") {
		t.Errorf("tag push answered %s, want it to report one queued capture and no publication", body)
	}
}

// A tag dispatch whose request is canceled while the pool's only connection is taken stops waiting
// for one and queues no capture (R-31 F-03).
func TestModuleTagCapture_ACanceledTagDispatchDoesNotWaitForAConnection(t *testing.T) {
	f := setupCapture(t)
	f.tagPublishing()
	module := seedTagModule(t, f.installationWebhookFixture, f.org.ID, &f.connA.ID, f.repo)
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
	go func() { done <- f.handler.registryPublisher.PublishFromGitTag(ctx, module.ID, "v4.5.6", f.repo) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a canceled tag dispatch succeeded without a connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a canceled tag dispatch kept waiting for a database connection")
	}
	close(release)
	released = true
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
	if got := capturesOf(captures(t, f.installationWebhookFixture, module), "v4.5.6"); len(got) != 0 {
		t.Errorf("a canceled tag dispatch queued %d capture(s), want none", len(got))
	}
}

func TestModuleTagCapture_EachTagIsCapturedOnce(t *testing.T) {
	f := setupCapture(t)
	f.tagPublishing()
	module := seedTagModule(t, f.installationWebhookFixture, f.org.ID, &f.connA.ID, f.repo)

	// Two tags pushed before either capture starts are two captures.
	f.tagPush(t, "v1.2.3")
	f.tagPush(t, "v1.3.0")
	got := captures(t, f.installationWebhookFixture, module)
	if len(capturesOf(got, "v1.2.3")) != 1 || len(capturesOf(got, "v1.3.0")) != 1 || len(got) != 2 {
		t.Fatalf("captures after two tag pushes = %+v, want one per tag", got)
	}
	for _, it := range got {
		if it.Status != models.WorkItemStatusPending || it.OrganizationID != f.org.ID || it.AgentPoolID == nil {
			t.Errorf("capture %s = status %s organization %s pool %v, want pending on the module organization's pool", it.ID, it.Status, it.OrganizationID, it.AgentPoolID)
		}
	}

	// The same tag delivered again, twice at once, and once more, while its capture is pending.
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); f.tagPush(t, "v1.2.3") }()
	}
	wg.Wait()
	f.tagPush(t, "v1.2.3")
	first := capturesOf(captures(t, f.installationWebhookFixture, module), "v1.2.3")
	if len(first) != 1 {
		t.Fatalf("a repeated tag push while its capture is pending made %d captures, want 1", len(first))
	}

	// Reserved by a runner, then running: still one.
	runner := uuid.New()
	for _, step := range []map[string]any{{"runner_id": runner}, {"status": models.WorkItemStatusRunning}} {
		if err := f.db.Model(&models.WorkItem{}).Where("id = ?", first[0].ID).Updates(step).Error; err != nil {
			t.Fatal(err)
		}
		f.tagPush(t, "v1.2.3")
		if n := len(capturesOf(captures(t, f.installationWebhookFixture, module), "v1.2.3")); n != 1 {
			t.Errorf("a repeated tag push with the capture %v made %d captures, want 1", step, n)
		}
	}

	// After a failed capture the tag is captured anew.
	if err := f.db.Model(&models.WorkItem{}).Where("id = ?", first[0].ID).Update("status", models.WorkItemStatusFailed).Error; err != nil {
		t.Fatal(err)
	}
	f.tagPush(t, "v1.2.3")
	if n := len(capturesOf(captures(t, f.installationWebhookFixture, module), "v1.2.3")); n != 2 {
		t.Errorf("a tag push after a failed capture made %d captures in all, want 2", n)
	}
}

func TestModuleTagCapture_CloneUsesTheModulesConnection(t *testing.T) {
	f := setupCapture(t)
	f.tagPublishing()
	h := &RunnerAgentHandler{db: f.db, vcsRegistry: f.handler.vcsRegistry}

	module := seedTagModule(t, f.installationWebhookFixture, f.org.ID, &f.connA.ID, f.repo)
	f.tagPush(t, "v2.0.0")
	items := captures(t, f.installationWebhookFixture, module)
	if len(items) != 1 {
		t.Fatalf("%d captures, want 1", len(items))
	}
	art, err := h.workItemArtifacts(context.Background(), &items[0])
	if err != nil || art.Clone == nil {
		t.Fatalf("artifacts of capture %s: %v", items[0].ID, err)
	}
	if want := "ghs-of-" + strconv.FormatInt(f.instA, 10); art.Clone.Token != want || art.Clone.Branch != "v2.0.0" {
		t.Errorf("served clone = token %q branch %q, want the module's connection (%s) at the tag", art.Clone.Token, art.Clone.Branch, want)
	}

	// A connection that cannot mint a token: no clone is served, so no unauthenticated clone runs.
	tokenless := &models.VCSConnection{ID: uuid.New(), OrganizationID: f.org.ID, Provider: models.VCSProviderGitHub, InstallationID: tokenlessInstallation, AccountName: "suspended"}
	if err := f.db.Create(tokenless).Error; err != nil {
		t.Fatal(err)
	}
	other := seedTagModule(t, f.installationWebhookFixture, f.org.ID, &tokenless.ID, "suspended/mod")
	item := &models.WorkItem{OrganizationID: f.org.ID, Kind: models.WorkItemModuleTagSnapshot, ModuleID: &other.ID, RequestedRef: "v1.0.0", Status: models.WorkItemStatusPending}
	if err := f.db.Create(item).Error; err != nil {
		t.Fatal(err)
	}
	if art, err := h.workItemArtifacts(context.Background(), item); err == nil {
		t.Errorf("a connection without a token served %+v, want the capture refused", art.Clone)
	}
}

// moduleCaptureFixture is the work item runner fixture with a module of organization A and the
// runner handler publishing the snapshots its captures upload.
type moduleCaptureFixture struct {
	*workItemRunnerFixture
	module    *models.Module
	publisher *registry.ModulePublisher
	versions  *repository.ModuleVersionRepository
}

func setupModuleCapture(t *testing.T) *moduleCaptureFixture {
	t.Helper()
	f := setupWorkItemRunner(t)
	moduleRepo := repository.NewModuleRepository(f.db)
	versions := repository.NewModuleVersionRepository(f.db)
	publisher := registry.NewModulePublisher(moduleRepo, versions, repository.NewOrganizationRepository(f.db), repository.NewVCSConnectionRepository(f.db), f.store)
	f.h.SetModulePublisher(publisher)
	m := &models.Module{ID: uuid.New(), OrganizationID: f.orgA, Name: "tagmod-" + uuid.NewString()[:8], Provider: "aws", VCSConnectionID: &f.vcsConn, VCSRepository: "acme/mod", AutoPublishTags: true}
	if err := f.db.Create(m).Error; err != nil {
		t.Fatalf("seed module: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("module_id = ?", m.ID).Delete(&models.WorkItem{})
		f.db.Where("module_id = ?", m.ID).Delete(&models.ModuleVersion{})
		f.db.Where("id = ?", m.ID).Delete(&models.Module{})
	})
	if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA2.ID).Update("max_concurrent_jobs", 4).Error; err != nil {
		t.Fatal(err)
	}
	return &moduleCaptureFixture{workItemRunnerFixture: f, module: m, publisher: publisher, versions: versions}
}

// claimedCapture queues a capture of tag on pool A and claims it as a2 under the token name.
func (f *moduleCaptureFixture) claimedCapture(t *testing.T, tag, name string) *models.WorkItem {
	t.Helper()
	now := time.Now()
	item := &models.WorkItem{
		OrganizationID: f.orgA, Kind: models.WorkItemModuleTagSnapshot, ModuleID: &f.module.ID, RequestedRef: tag,
		Status: models.WorkItemStatusPending, AgentPoolID: &f.poolA, QueuedAt: &now, TimeoutSeconds: 600,
	}
	if err := f.db.Create(item).Error; err != nil {
		t.Fatalf("seed capture: %v", err)
	}
	if got := f.offeredTo(t, "a2"); !slices.Contains(got, item.ID) {
		t.Fatalf("offered %v, want the capture %s", got, item.ID)
	}
	f.claim(t, "a2", item.ID, name)
	return item
}

func (f *moduleCaptureFixture) uploadAs(t *testing.T, name, id, commit string, body []byte) int {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runner/jobs/"+id+"/snapshot", bytes.NewReader(body))
	req.Header.Set("X-Test-Key", name)
	req.Header.Set(runnercontract.HeaderSnapshotCommit, commit)
	rec := httptest.NewRecorder()
	f.r.ServeHTTP(rec, req)
	return rec.Code
}

func (f *moduleCaptureFixture) completeAs(t *testing.T, name, id, commit string) {
	t.Helper()
	done := JobCompleteRequest{RunnerID: f.runnerA2.ID.String(), Status: "completed", WorkResult: &runnercontract.WorkResult{Commit: commit}}
	if rec := runnerDo(t, f.r, name, http.MethodPost, "/api/v2/runner/jobs/"+id+"/complete", done); rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
}

// published returns the module's one row for version and the main.tf of its stored archive.
func (f *moduleCaptureFixture) published(t *testing.T, version string) (*models.ModuleVersion, string) {
	t.Helper()
	var rows []models.ModuleVersion
	if err := f.db.Where("module_id = ? AND version = ?", f.module.ID, version).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d rows for version %s, want 1", len(rows), version)
	}
	data, err := f.store.Get(t.Context(), rows[0].TarballPath)
	if err != nil {
		t.Fatalf("the archive of version %s is not stored: %v", version, err)
	}
	return &rows[0], mainTF(t, data)
}

func TestModuleTagCapture_SnapshotPublishesTheVersion(t *testing.T) {
	f := setupModuleCapture(t)
	item := f.claimedCapture(t, "v1.2.3", "wi")
	if code := f.uploadAs(t, "wi", item.ID, captureCommit, moduleTarball(t, `variable "a" {}`)); code != http.StatusOK {
		t.Fatalf("the capture's snapshot answered %d, want 200", code)
	}
	f.completeAs(t, "wi", item.ID, captureCommit)
	if got := f.reload(t, item.ID).Status; got != models.WorkItemStatusCompleted {
		t.Errorf("the capture ended %s, want completed", got)
	}
	version, body := f.published(t, "1.2.3")
	if body != `variable "a" {}` || !strings.Contains(version.Source, captureCommit) {
		t.Errorf("version 1.2.3 = source %q main.tf %q, want the capture's snapshot at %s", version.Source, body, captureCommit)
	}

	// A capture that completes without uploading publishes nothing and fails.
	empty := f.claimedCapture(t, "v1.4.0", "wi2")
	f.completeAs(t, "wi2", empty.ID, captureCommit)
	if got := f.reload(t, empty.ID).Status; got != models.WorkItemStatusFailed {
		t.Errorf("a capture that uploaded nothing ended %s, want failed", got)
	}
	if f.versions.Exists(f.module.ID, "1.4.0") {
		t.Error("a capture that uploaded nothing published its version")
	}
}

func TestModuleTagCapture_OneVersionPublishesOnce(t *testing.T) {
	f := setupModuleCapture(t)

	// v1.2.3 and 1.2.3 name one version and point at different commits.
	a := f.claimedCapture(t, "v1.2.3", "wa")
	b := f.claimedCapture(t, "1.2.3", "wb")
	bodies := map[string]string{a.ID: `variable "from_a" {}`, b.ID: `variable "from_b" {}`}
	codes := map[string]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for id, name := range map[string]string{a.ID: "wa", b.ID: "wb"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code := f.uploadAs(t, name, id, map[string]string{a.ID: captureCommit, b.ID: otherCommit}[id], moduleTarball(t, bodies[id]))
			mu.Lock()
			codes[id] = code
			mu.Unlock()
		}()
	}
	wg.Wait()
	winner := ""
	for id, code := range codes {
		if code == http.StatusOK {
			if winner != "" {
				t.Fatalf("both alias captures published: %v", codes)
			}
			winner = id
		} else if code != http.StatusConflict {
			t.Errorf("the losing capture answered %d, want 409", code)
		}
	}
	if winner == "" {
		t.Fatalf("no alias capture published: %v", codes)
	}
	if _, body := f.published(t, "1.2.3"); body != bodies[winner] {
		t.Errorf("version 1.2.3 serves %q, want the content of the capture that created it (%q)", body, bodies[winner])
	}
	for id, name := range map[string]string{a.ID: "wa", b.ID: "wb"} {
		f.completeAs(t, name, id, "")
		want := models.WorkItemStatusFailed
		if id == winner {
			want = models.WorkItemStatusCompleted
		}
		if got := f.reload(t, id).Status; got != want {
			t.Errorf("capture %s ended %s, want %s", id, got, want)
		}
	}

	// A capture beside a manual upload of the same version.
	c := f.claimedCapture(t, "v2.0.0", "wc")
	var manualErr error
	var captureCode int
	wg.Add(2)
	go func() {
		defer wg.Done()
		archive := moduleTarball(t, `variable "manual" {}`)
		_, manualErr = f.publisher.PublishVersionFromTarball(context.Background(), f.module.ID, "2.0.0", bytes.NewReader(archive), int64(len(archive)))
	}()
	go func() {
		defer wg.Done()
		captureCode = f.uploadAs(t, "wc", c.ID, captureCommit, moduleTarball(t, `variable "captured" {}`))
	}()
	wg.Wait()
	if (manualErr == nil) == (captureCode == http.StatusOK) {
		t.Fatalf("manual upload error %v and capture %d: want exactly one to publish", manualErr, captureCode)
	}
	want := `variable "captured" {}`
	if manualErr == nil {
		want = `variable "manual" {}`
	}
	if _, body := f.published(t, "2.0.0"); body != want {
		t.Errorf("version 2.0.0 serves %q, want the content of the publisher that created it (%q)", body, want)
	}
}

// A module capture canceled after its upload was authorized publishes nothing (R-16 F-03): the
// publication holds the work item's row and finds it no longer running.
func TestModuleTagCapture_ACanceledCapturePublishesNothing(t *testing.T) {
	f := setupModuleCapture(t)
	item := f.claimedCapture(t, "v3.0.0", "wd")
	f.h.snapshotAuthorized = func(id string) {
		if err := f.db.Model(&models.WorkItem{}).Where("id = ?", id).Update("status", models.WorkItemStatusCanceled).Error; err != nil {
			t.Errorf("cancel %s: %v", id, err)
		}
	}
	defer func() { f.h.snapshotAuthorized = nil }()
	if code := f.uploadAs(t, "wd", item.ID, captureCommit, moduleTarball(t, `variable "late" {}`)); code != http.StatusConflict {
		t.Errorf("a canceled capture's upload answered %d, want 409", code)
	}
	if f.versions.Exists(f.module.ID, "3.0.0") {
		t.Error("a canceled capture published its version")
	}
}

// A stale module completion finishes nothing (R-17 F-02): the completion is bound to the attempt it
// was authorized for, as a configuration capture's is.
func TestModuleTagCapture_AStaleCompletionFinishesNothing(t *testing.T) {
	f := setupModuleCapture(t)
	item := f.claimedCapture(t, "v5.0.0", "we")
	f.h.beforeWorkItemFinish = func(id string) {
		if err := f.db.Model(&models.WorkItem{}).Where("id = ?", id).Update("attempt", gorm.Expr("GREATEST(attempt, 1) + 1")).Error; err != nil {
			t.Errorf("reclaim %s: %v", id, err)
		}
	}
	defer func() { f.h.beforeWorkItemFinish = nil }()
	done := JobCompleteRequest{RunnerID: f.runnerA2.ID.String(), Status: "failed", ErrorMessage: "stale", WorkResult: &runnercontract.WorkResult{}}
	if rec := runnerDo(t, f.r, "we", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/complete", done); rec.Code == http.StatusOK {
		t.Errorf("a stale module completion was acknowledged")
	}
	if st := f.reload(t, item.ID).Status; st != models.WorkItemStatusRunning {
		t.Errorf("the capture is %s, want still running for its newer attempt", st)
	}
}

// A module upload whose proof cannot be recorded publishes nothing (R-17 F-04): the version, its
// archive and the work item's commit commit together or not at all.
func TestModuleTagCapture_APublicationWithoutItsProofIsRolledBack(t *testing.T) {
	f := setupModuleCapture(t)
	item := f.claimedCapture(t, "v4.0.0", "wf")
	fn := "test_fail_commit_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if err := f.db.Exec(`CREATE FUNCTION ` + fn + `() RETURNS trigger AS $$ BEGIN
		IF NEW.id = '` + item.ID + `' AND NEW.commit IS DISTINCT FROM OLD.commit THEN RAISE EXCEPTION 'injected commit write failure'; END IF;
		RETURN NEW; END $$ LANGUAGE plpgsql`).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Exec(`DROP TRIGGER IF EXISTS ` + fn + ` ON work_items`)
		f.db.Exec(`DROP FUNCTION IF EXISTS ` + fn + `()`)
	})
	if err := f.db.Exec(`CREATE TRIGGER ` + fn + ` BEFORE UPDATE ON work_items FOR EACH ROW EXECUTE FUNCTION ` + fn + `()`).Error; err != nil {
		t.Fatal(err)
	}
	if code := f.uploadAs(t, "wf", item.ID, captureCommit, moduleTarball(t, `variable "a" {}`)); code == http.StatusOK {
		t.Errorf("an upload whose commit could not be recorded answered 200")
	}
	if f.versions.Exists(f.module.ID, "4.0.0") {
		t.Error("the version was published although its capture's proof was not recorded")
	}
	var module models.Module
	f.db.Preload("Organization").First(&module, "id = ?", f.module.ID)
	left, err := f.store.List(t.Context(), "modules/"+module.Organization.Name+"/"+module.Name+"/"+module.Provider+"/4.0.0")
	if err != nil {
		t.Fatal(err)
	}
	// The proof is recorded before the archive is written, so this failure writes no archive.
	// (A failure after the write leaves its archive in place under owner decision Q13; see
	// TestModuleTagCapture_AFailedPublicationLeavesTheSuccessfulArchive.)
	if len(left) != 0 {
		t.Errorf("a publication refused before its archive write left %v in storage", left)
	}
}

// A publisher whose request is canceled while the pool's only connection is taken gives up
// without waiting for one, before the lock as well as at it (R-30 F-01).
func TestModuleTagCapture_ACanceledPublisherDoesNotWaitForAConnection(t *testing.T) {
	f := setupModuleCapture(t)
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
		_, err := f.publisher.PublishVersionFromTarball(ctx, f.module.ID, "8.0.0", bytes.NewReader(moduleTarball(t, `variable "a" {}`)), 0)
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a canceled publisher published without a connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a canceled publisher kept waiting for a database connection")
	}
	close(release)
	released = true
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
	if f.versions.Exists(f.module.ID, "8.0.0") {
		t.Error("the canceled publisher's version exists")
	}
}

// A publisher waiting for another publication of the same version gives up when its request is
// canceled (R-23 F-03): it returns promptly, holds no connection and writes nothing.
func TestModuleTagCapture_ACanceledWaiterGivesUpItsTurn(t *testing.T) {
	f := setupModuleCapture(t)
	held, release := make(chan struct{}), make(chan struct{})
	holder := make(chan error, 1)
	go func() {
		// The publication lock's own key, held the way WithPublishLock holds it.
		holder <- f.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", "module-version:"+f.module.ID.String()+":5.0.0").Error; err != nil {
				return err
			}
			close(held)
			<-release
			return nil
		})
	}()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		<-holder
	}()
	<-held
	ctx, cancel := context.WithCancel(t.Context())
	waiter := make(chan error, 1)
	go func() {
		_, err := f.publisher.PublishVersionFromTarball(ctx, f.module.ID, "5.0.0", bytes.NewReader(moduleTarball(t, `variable "a" {}`)), 0)
		waiter <- err
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-waiter:
		if err == nil {
			t.Fatal("a canceled waiter published")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a canceled waiter kept waiting for the lock")
	}
	close(release)
	if f.versions.Exists(f.module.ID, "5.0.0") {
		t.Error("the canceled waiter's version exists")
	}
	var module models.Module
	f.db.Preload("Organization").First(&module, "id = ?", f.module.ID)
	left, err := f.store.List(t.Context(), "modules/"+module.Organization.Name+"/"+module.Name+"/"+module.Provider+"/5.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("the canceled waiter wrote %v", left)
	}
}

// A failed publication of a version and a successful one write archives of their own (R-18 F-01):
// the failed attempt's cleanup removes only its archive, and the published version's survives.
func TestModuleTagCapture_AFailedPublicationLeavesTheSuccessfulArchive(t *testing.T) {
	f := setupModuleCapture(t)
	fn := "test_fail_manual_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	// A manual upload (no source) of this module's version 6.0.0 fails at its insert, after its
	// archive was written.
	if err := f.db.Exec(`CREATE FUNCTION ` + fn + `() RETURNS trigger AS $$ BEGIN
		IF NEW.module_id = '` + f.module.ID.String() + `' AND COALESCE(NEW.source, '') = '' THEN RAISE EXCEPTION 'injected insert failure'; END IF;
		RETURN NEW; END $$ LANGUAGE plpgsql`).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Exec(`DROP TRIGGER IF EXISTS ` + fn + ` ON module_versions`)
		f.db.Exec(`DROP FUNCTION IF EXISTS ` + fn + `()`)
	})
	if err := f.db.Exec(`CREATE TRIGGER ` + fn + ` BEFORE INSERT ON module_versions FOR EACH ROW EXECUTE FUNCTION ` + fn + `()`).Error; err != nil {
		t.Fatal(err)
	}
	archive := moduleTarball(t, `variable "manual" {}`)
	if _, err := f.publisher.PublishVersionFromTarball(context.Background(), f.module.ID, "6.0.0", bytes.NewReader(archive), int64(len(archive))); err == nil {
		t.Fatal("the manual upload published although its insert fails")
	}
	item := f.claimedCapture(t, "v6.0.0", "wg")
	if code := f.uploadAs(t, "wg", item.ID, captureCommit, moduleTarball(t, `variable "captured" {}`)); code != http.StatusOK {
		t.Fatalf("the capture's upload answered %d, want 200", code)
	}
	version, body := f.published(t, "6.0.0")
	if body != `variable "captured" {}` {
		t.Errorf("version 6.0.0 serves %q, want the capture's archive", body)
	}
	var module models.Module
	f.db.Preload("Organization").First(&module, "id = ?", f.module.ID)
	left, err := f.store.List(t.Context(), "modules/"+module.Organization.Name+"/"+module.Name+"/"+module.Provider+"/6.0.0")
	if err != nil {
		t.Fatal(err)
	}
	// Owner decision Q13 (R-26 F-01) replaced the cleanup this test once asserted: the failed
	// attempt deletes nothing, so its archive stays beside the published one, and the version
	// names the published archive.
	keys := make([]string, 0, len(left))
	for _, o := range left {
		keys = append(keys, o.Key)
	}
	if len(left) != 2 || !slices.Contains(keys, version.TarballPath) {
		t.Errorf("archives of version 6.0.0 = %v, want the failed attempt's and the published one at %s", keys, version.TarballPath)
	}
}

// A completion persists its result through the transaction that holds the work item (R-18 F-04):
// with a pool of one connection it still finishes instead of waiting for a second one.
func TestModuleTagCapture_ACompletionNeedsOneConnection(t *testing.T) {
	f := setupModuleCapture(t)
	item := f.claimedCapture(t, "v7.0.0", "wh")
	if code := f.uploadAs(t, "wh", item.ID, captureCommit, moduleTarball(t, `variable "a" {}`)); code != http.StatusOK {
		t.Fatalf("the upload answered %d, want 200", code)
	}
	sqlDB, err := f.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.SetMaxOpenConns(0) })
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.completeAs(t, "wh", item.ID, captureCommit)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the completion waited for a second connection while it held the only one")
	}
	if st := f.reload(t, item.ID).Status; st != models.WorkItemStatusCompleted {
		t.Errorf("the capture ended %s, want completed", st)
	}
}
