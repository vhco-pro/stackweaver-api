// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/storage"
	"gorm.io/gorm"
)

type pausedPlaybookPut struct {
	storage.Client
	started chan<- string
	resume  <-chan struct{}
}

func (s pausedPlaybookPut) Put(ctx context.Context, key string, data []byte) error {
	s.started <- key
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.resume:
		return s.Client.Put(ctx, key, data)
	}
}

func TestPlaybookAssignment_PrunesLateUploadAfterOwnerDeletion(t *testing.T) {
	for _, scope := range []string{"playbook", "project", "organization"} {
		t.Run(scope, func(t *testing.T) {
			f := setupWorkItemRunner(t)
			playbook := f.seedPlaybook(t, playbookSpec{})
			item, err := f.items.RequestPlaybookSnapshot(t.Context(), playbook, "manual")
			if err != nil {
				t.Fatal(err)
			}
			f.onPool(t, item)
			f.offered(t, "a1")
			f.claim(t, "a1", item.ID, "upload")
			started, resume := make(chan string, 1), make(chan struct{})
			f.h.storageClient = pausedPlaybookPut{Client: f.store, started: started, resume: resume}
			legacyKey := ansible.PlaybookSnapshotKey(playbook.ID)
			if err := f.store.Put(t.Context(), legacyKey, []byte("previous archive")); err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
				"/api/v2/runner/jobs/"+item.ID+"/snapshot", strings.NewReader("late archive"))
			req.Header.Set("X-Test-Key", "upload")
			req.Header.Set(runnercontract.HeaderSnapshotCommit, "late")
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				f.r.ServeHTTP(rec, req)
			}()
			release := sync.OnceFunc(func() { close(resume) })
			defer func() {
				release()
				<-done
			}()
			var key string
			select {
			case key = <-started:
			case <-done:
				t.Fatalf("upload returned before storage: %d %s", rec.Code, rec.Body.String())
			case <-time.After(10 * time.Second):
				t.Fatal("upload did not reach storage")
			}
			var allocation models.PlaybookSnapshotUpload
			if err := f.db.First(&allocation, "work_item_id = ?", item.ID).Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.db.Delete(&allocation) })
			if allocation.StoredAt != nil || key != ansible.PlaybookCaptureKey(playbook.ID, allocation.ID) {
				t.Fatal("upload storage started without a pending exact-key allocation")
			}
			switch scope {
			case "playbook":
				repo := repository.NewAnsiblePlaybookRepository(f.db)
				repo.SetStorage(f.store)
				err = repo.Delete(playbook.ID)
			case "project":
				repo := repository.NewProjectRepository(f.db)
				repo.SetStorage(f.store)
				err = repo.Delete(f.projectA)
			case "organization":
				repo := repository.NewOrganizationRepository(f.db)
				repo.SetStorage(f.store)
				err = repo.Delete(f.orgA)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := storage.Probe(t.Context(), f.store, legacyKey); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("owner deletion did not prune its prefix: %v", err)
			}
			if err := ansible.PrunePlaybookSnapshots(t.Context(), f.db, f.store); err != nil {
				t.Fatal(err)
			}
			if err := f.db.First(&models.PlaybookSnapshotUpload{}, "id = ?", allocation.ID).Error; err != nil {
				t.Fatalf("absence retired an upload that could still finish: %v", err)
			}

			release()
			<-done
			if rec.Code != http.StatusNotFound && rec.Code != http.StatusConflict {
				t.Fatalf("late upload returned %d %s", rec.Code, rec.Body.String())
			}
			if err := storage.Probe(t.Context(), f.store, key); err != nil {
				t.Fatalf("the late PUT did not leave its archive: %v", err)
			}
			if err := ansible.PrunePlaybookSnapshots(t.Context(), f.db, f.store); err != nil {
				t.Fatal(err)
			}
			if err := storage.Probe(t.Context(), f.store, key); !errors.Is(err, storage.ErrNotFound) {
				t.Errorf("late PUT was not cleaned up: %v", err)
			}
			if err := f.db.First(&models.PlaybookSnapshotUpload{}, "id = ?", allocation.ID).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Errorf("confirmed cleanup did not retire the ledger record: %v", err)
			}
		})
	}
}

func TestPlaybookAssignment_FirstVerifiedUploadWinsConcurrentReceipts(t *testing.T) {
	f := setupWorkItemRunner(t)
	playbook := f.seedPlaybook(t, playbookSpec{})
	item, err := f.items.RequestPlaybookSnapshot(t.Context(), playbook, "manual")
	if err != nil {
		t.Fatal(err)
	}
	f.onPool(t, item)
	f.offered(t, "a1")
	f.claim(t, "a1", item.ID, "upload")
	active := f.reload(t, item.ID)

	started, resume := make(chan string, 1), make(chan struct{})
	slow := *f.h
	slow.storageClient = pausedPlaybookPut{Client: f.store, started: started, resume: resume}
	result := make(chan error, 1)
	go func() {
		result <- slow.storePlaybookSnapshot(t.Context(), &active, "delayed", []byte("delayed archive"))
		close(result)
	}()
	release := sync.OnceFunc(func() { close(resume) })
	defer func() {
		release()
		<-result
	}()
	var delayedKey string
	select {
	case delayedKey = <-started:
	case err := <-result:
		t.Fatalf("slow put completed before reaching storage: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("slow put did not reach storage")
	}

	// Each API process gets its own transport admission slot. Call the storage paths
	// separately here to test their shared SQL claim and allocation state.
	if err := f.h.storePlaybookSnapshot(t.Context(), &active, "winner", []byte("winner archive")); err != nil {
		t.Fatal(err)
	}
	chosen := f.reload(t, item.ID)
	if chosen.PlaybookSnapshotUploadID == nil || chosen.Commit != "winner" {
		t.Fatal("the upload that finished storage first was not accepted")
	}
	release()
	var refused *snapshotUploadRefusal
	if err := <-result; !errors.As(err, &refused) || refused.status != http.StatusBadRequest {
		t.Fatalf("late different upload returned %v", err)
	}
	done := JobCompleteRequest{RunnerID: f.keyRunner("a1"), Status: "completed", WorkResult: &runnercontract.WorkResult{Commit: "winner"}}
	if rec := runnerDo(t, f.r, "upload", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/complete", done); rec.Code != http.StatusOK {
		t.Fatalf("accepted capture completion returned %d %s", rec.Code, rec.Body.String())
	}
	published := f.reloadPlaybook(t, playbook.ID)
	if published.PublishedSnapshotID == nil || *published.PublishedSnapshotID != *chosen.PlaybookSnapshotUploadID {
		t.Fatal("completion did not publish the original accepted upload")
	}
	if err := ansible.PrunePlaybookSnapshots(t.Context(), f.db, f.store); err != nil {
		t.Fatal(err)
	}
	if err := storage.Probe(t.Context(), f.store, delayedKey); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("the unselected upload was not removed: %v", err)
	}
	key := ansible.PlaybookCaptureKey(playbook.ID, *published.PublishedSnapshotID)
	if data, err := f.store.Get(t.Context(), key); err != nil || string(data) != "winner archive" {
		t.Errorf("the published archive changed during cleanup: %q %v", data, err)
	}
	t.Cleanup(func() { f.db.Delete(&models.PlaybookSnapshotUpload{}, "playbook_id = ?", playbook.ID) })
}
