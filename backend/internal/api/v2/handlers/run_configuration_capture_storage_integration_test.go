// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Object storage is not part of the upload's transaction (#938, AC-19, R-48 and R-49). A canceled
// upload's PutObject can still complete after its transaction rolled back, and S3 keeps whichever
// write lands last, so a late write must never land on the object an accepted capture is read
// from: neither a capture of another work item nor the next attempt of the same work item after a
// redispatch. The accepted capture is sealed at rest like every configuration archive.

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/handlers/terraform"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/storage"
	"gorm.io/gorm"
)

// lateStore is object storage whose armed Put fails as a canceled request does, while the write
// itself is still in flight: flush lands it later, after the caller's transaction is gone.
type lateStore struct {
	storage.Client
	mu      sync.Mutex
	armed   bool
	pending []func()
}

func (s *lateStore) Put(ctx context.Context, key string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.armed {
		return s.Client.Put(ctx, key, data)
	}
	s.armed = false
	held := bytes.Clone(data)
	s.pending = append(s.pending, func() { _ = s.Client.Put(context.Background(), key, held) })
	return context.Canceled
}

func (s *lateStore) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, write := range s.pending {
		write()
	}
	s.pending = nil
}

func (f *workItemRunnerFixture) uploadAs(t *testing.T, name, id, commit, body string) int {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runner/jobs/"+id+"/snapshot", bytes.NewReader([]byte(body)))
	req.Header.Set("X-Test-Key", name)
	req.Header.Set(runnercontract.HeaderSnapshotCommit, commit)
	rec := httptest.NewRecorder()
	f.r.ServeHTTP(rec, req)
	return rec.Code
}

func TestConfigurationCapture_ALateWriteNeverReplacesTheAcceptedCapture(t *testing.T) {
	f := setupWorkItemRunner(t)
	cs, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	raw := newSnapshotStore()
	late := &lateStore{Client: raw}
	f.h.storageClient = storage.NewSealed(late, cs, storage.ArtifactSealRules()...)
	f.h.cryptoService = cs
	artifacts := f.router(func(authed *gin.RouterGroup) { authed.GET("/jobs/:id/artifacts", f.h.GetJobArtifacts) })
	download := terraform.NewConfigurationVersionHandlerV2(repository.NewConfigurationVersionRepository(f.db), repository.NewWorkspaceRepository(f.db), nil, f.h.storageClient, nil)
	stale := "\x1f\x8b stale capture"
	accepted := "\x1f\x8b accepted capture"

	check := func(t *testing.T, run *models.Run, cvID string) {
		t.Helper()
		late.flush()
		var reloaded models.Run
		if err := f.db.First(&reloaded, "id = ?", run.ID).Error; err != nil {
			t.Fatal(err)
		}
		got, err := f.h.configTarball(t.Context(), &reloaded)
		if err != nil {
			t.Fatalf("reading the run's configuration: %v", err)
		}
		if string(got) != accepted {
			t.Errorf("the run downloads %q, want the accepted capture %q", got, accepted)
		}
		// The run artifacts response the executor plans from (R-51 F-02).
		if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Updates(map[string]any{
			"status": models.RunStatusPlanning, "runner_id": f.runnerA1.ID, "attempt": 1,
		}).Error; err != nil {
			t.Fatal(err)
		}
		arts, _ := artifactsAs(t, artifacts, "a1", run.ID, "")
		if tarball, err := base64.StdEncoding.DecodeString(arts.ConfigTarball); err != nil || string(tarball) != accepted {
			t.Errorf("the run artifacts carry %q (%v), want the accepted capture", tarball, err)
		}
		// The configuration download (go-tfe ConfigurationVersions.Download), as a run's task token
		// reaches it.
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/configuration-versions/"+cvID+"/download", nil)
		c.Params = gin.Params{{Key: "id", Value: cvID}}
		c.Set("task_token_result_id", run.ID)
		download.DownloadConfigurationVersion(c)
		if rec.Code != http.StatusOK || rec.Body.String() != accepted {
			t.Errorf("the configuration download answered %d %q, want 200 and the accepted capture", rec.Code, rec.Body.String())
		}
		objects, err := raw.List(t.Context(), models.ConfigurationVersionStoragePrefix(cvID))
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range objects {
			data, _ := raw.Get(t.Context(), o.Key)
			if bytes.Contains(data, []byte("capture")) {
				t.Errorf("%s is stored in plaintext, want it sealed", o.Key)
			}
		}
	}

	t.Run("another work item", func(t *testing.T) {
		run, cv := f.fetchingRun(t, "", "")
		first := f.captureClaimed(t, run)
		late.armed = true
		if code := f.uploadAs(t, "wi", first.ID, captureCommit, stale); code == http.StatusOK {
			t.Fatalf("an upload whose write failed was acknowledged")
		}
		if err := f.db.Model(&models.WorkItem{}).Where("id = ?", first.ID).Updates(map[string]any{"status": models.WorkItemStatusCanceled}).Error; err != nil {
			t.Fatal(err)
		}
		second, err := f.items.RequestConfigurationSnapshot(t.Context(), run)
		if err != nil {
			t.Fatal(err)
		}
		if second.ID == first.ID {
			t.Fatal("the canceled capture was reused")
		}
		f.onPool(t, second)
		f.offeredTo(t, "a2")
		f.claim(t, "a2", second.ID, "wi-next")
		if code := f.uploadAs(t, "wi-next", second.ID, captureCommit, accepted); code != http.StatusOK {
			t.Fatalf("the replacement capture's upload answered %d", code)
		}
		check(t, run, cv.ID)
	})

	t.Run("a redispatched attempt of the same work item", func(t *testing.T) {
		run, cv := f.fetchingRun(t, "", "")
		item := f.captureClaimed(t, run)
		late.armed = true
		if code := f.uploadAs(t, "wi", item.ID, captureCommit, stale); code == http.StatusOK {
			t.Fatalf("an upload whose write failed was acknowledged")
		}
		// The runner is lost and the capture goes back to pending under its own ID, as
		// RunnerRepository's redispatch leaves it.
		if err := f.db.Model(&models.WorkItem{}).Where("id = ?", item.ID).Updates(map[string]any{
			"status": models.WorkItemStatusPending, "runner_id": nil, "started_at": nil,
		}).Error; err != nil {
			t.Fatal(err)
		}
		f.offeredTo(t, "a2")
		f.claim(t, "a2", item.ID, "wi-again")
		if code := f.uploadAs(t, "wi-again", item.ID, captureCommit, accepted); code != http.StatusOK {
			t.Fatalf("the next attempt's upload answered %d", code)
		}
		check(t, run, cv.ID)
	})
}

// Waking the run's launchers after an upload looks the pool up with the request's context, so a
// request canceled while the lookup waits for a database connection returns at once (R-51 F-01).
func TestConfigurationCapture_ACanceledWakeupDoesNotWaitForAConnection(t *testing.T) {
	f := setupWorkItemRunner(t)
	run, _ := f.fetchingRun(t, captureCommit, "")
	run.AgentPoolID = &f.poolA
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
	defer func() {
		close(release)
		<-holder
		sqlDB.SetMaxOpenConns(0)
	}()
	<-held
	ctx, cancel := context.WithCancel(t.Context())
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
	done := make(chan struct{})
	go func() {
		f.h.wakeRunPool(c, run)
		close(done)
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a canceled upload kept waiting for a connection to wake the run's launchers")
	}
}
