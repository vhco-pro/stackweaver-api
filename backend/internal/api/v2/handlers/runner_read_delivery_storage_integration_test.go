// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/executor"
	"github.com/michielvha/stackweaver/backend/internal/launcher"
	"github.com/michielvha/stackweaver/backend/internal/launcher/cache"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/storage"
	"github.com/michielvha/stackweaver/core/storage/storagetest"
)

func runnerDeliveryCacheEntry(t *testing.T, fixture *runnerDeliveryFixture, store storage.Client) *models.CacheEntry {
	t.Helper()
	entry := &models.CacheEntry{OrganizationID: fixture.claim.orgA, Kind: string(runnercontract.CacheKindProvider), SHA256: sha256Hex(fixture.payload), SizeBytes: int64(len(fixture.payload)), Verification: models.CacheVerified}
	if err := fixture.claim.db.Create(entry).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.claim.db.Where("id = ?", entry.ID).Delete(&models.CacheEntry{}).Error; err != nil {
			t.Error(err)
		}
	})
	if err := store.Put(t.Context(), models.CacheObjectKey(entry.OrganizationID, entry.Kind, entry.SHA256), fixture.payload); err != nil {
		t.Fatal(err)
	}
	fixture.claim.handler.storageClient = store
	fixture.path = "/api/v2/runner/jobs/" + fixture.id + "/blob/cache/provider/" + entry.SHA256
	return entry
}

type runnerDeliveryStorage struct {
	storage.Client
	open func(context.Context, string) (io.ReadCloser, error)
}

func (s runnerDeliveryStorage) GetStream(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.open(ctx, key)
}

type runnerDeliveryStalledStorage struct {
	ctx     context.Context
	initial *bytes.Reader
	cause   chan error
	closed  chan struct{}
	once    sync.Once
	closes  atomic.Int32
}

func (s *runnerDeliveryStalledStorage) Read(p []byte) (int, error) {
	if s.initial.Len() > 0 {
		return s.initial.Read(p)
	}
	<-s.ctx.Done()
	err := context.Cause(s.ctx)
	select {
	case s.cause <- err:
	default:
	}
	return 0, err
}

func (s *runnerDeliveryStalledStorage) Close() error {
	s.closes.Add(1)
	s.once.Do(func() { close(s.closed) })
	return nil
}

func TestRunnerReadDelivery_StorageIdleAndParentCancellation(t *testing.T) {
	for _, mode := range []string{"idle", "parent cancellation"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			fixture := newRunnerDeliveryFixture(t, "blob", bytes.Repeat([]byte("s"), 128<<10))
			stream := &runnerDeliveryStalledStorage{initial: bytes.NewReader(fixture.payload[:64<<10]), cause: make(chan error, 1), closed: make(chan struct{})}
			var opens atomic.Int32
			store := runnerDeliveryStorage{Client: storagetest.NewMemory(), open: func(ctx context.Context, _ string) (io.ReadCloser, error) {
				stream.ctx = ctx
				opens.Add(1)
				return stream, nil
			}}
			runnerDeliveryCacheEntry(t, fixture, store)
			server := runnerReadDeliveryServer(t, runnerReadDeliveryRouter(fixture.claim, true))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+fixture.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+fixture.token.Token)
			started := time.Now()
			response, err := runnerReadSingleAttemptClient(t).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("storage fixture refused: %d", response.StatusCode)
			}
			initial := make([]byte, 64<<10)
			if _, err := io.ReadFull(response.Body, initial); err != nil || !bytes.Equal(initial, fixture.payload[:64<<10]) {
				t.Fatalf("initial storage body: %v", err)
			}
			want := context.DeadlineExceeded
			if mode == "parent cancellation" {
				want = context.Canceled
				started = time.Now()
				cancel()
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			if readErr == nil {
				t.Fatal("stalled storage returned a complete body")
			}
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case cause := <-stream.cause:
				if !errors.Is(cause, want) {
					t.Fatalf("storage cancellation cause %v, want %v", cause, want)
				}
			case <-timer.C:
				t.Fatal("storage read was not canceled")
			}
			select {
			case <-stream.closed:
			case <-timer.C:
				t.Fatal("storage stream was not closed")
			}
			elapsed := time.Since(started)
			if mode == "idle" && (elapsed < 30*time.Second || elapsed >= 40*time.Second) {
				t.Fatalf("storage idle bound: %s", elapsed)
			}
			if mode == "parent cancellation" && elapsed >= 5*time.Second {
				t.Fatalf("slow parent cancellation: %s", elapsed)
			}
			if opens.Load() != 1 || stream.closes.Load() != 1 {
				t.Fatalf("storage resources opened=%d closed=%d", opens.Load(), stream.closes.Load())
			}
		})
	}
}

func runnerDeliverySnapshot(t *testing.T, payload []byte) *runnerDeliveryFixture {
	t.Helper()
	f := setupClaimRouteFixture(t)
	id, _, token := f.startCompletion(t, startRouteCases[0])
	now := time.Now()
	playbook := &models.AnsiblePlaybook{ID: uuid.New(), ProjectID: f.projectA, Name: "delivery-" + uuid.NewString(), PlaybookPath: "site.yml", VCSConnectionID: &f.vcsConn, VCSRepository: "acme/playbooks", CachedAt: &now, CachedSizeBytes: int64(len(payload)), CachedCommit: "delivery"}
	if err := f.db.Create(playbook).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.db.Model(&models.AnsibleJob{}).Where("id = ?", id).Update("playbook_id", nil).Error; err != nil {
			t.Error(err)
		}
		if err := f.db.Where("id = ?", playbook.ID).Delete(&models.AnsiblePlaybook{}).Error; err != nil {
			t.Error(err)
		}
	})
	if err := f.db.Model(&models.AnsibleJob{}).Where("id = ?", id).Update("playbook_id", playbook.ID).Error; err != nil {
		t.Fatal(err)
	}
	store := storagetest.NewMemory()
	f.publishFixtureSnapshot(t, playbook, store, payload)
	f.bindFixtureSnapshot(t, uuid.MustParse(id), playbook)
	f.handler.storageClient = store
	return &runnerDeliveryFixture{claim: f, id: id, token: token, payload: payload, path: "/api/v2/runner/jobs/" + id + "/playbook-snapshot"}
}

func TestRunnerReadDelivery_LongStreamingPaths(t *testing.T) {
	for _, mode := range []string{"snapshot", "job cache", "launcher cache"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			size := 1 << 20
			allowance := 2 * time.Minute
			if mode == "snapshot" {
				size = 2 << 20
				allowance = 5 * time.Minute
			}
			payload := bytes.Repeat([]byte("p"), size)
			var fixture *runnerDeliveryFixture
			if mode == "snapshot" {
				fixture = runnerDeliverySnapshot(t, payload)
			} else {
				fixture = newRunnerDeliveryFixture(t, "blob", payload)
				runnerDeliveryCacheEntry(t, fixture, storagetest.NewMemory())
			}
			server := runnerReadDeliveryServer(t, runnerReadDeliveryRouter(fixture.claim, true))
			relay := pacedRunnerRelay(t, server.URL)
			ctx, cancel := context.WithTimeout(t.Context(), 9*time.Minute)
			defer cancel()
			started := time.Now()
			var err error
			var path string
			if mode == "launcher cache" {
				client := launcher.NewClient(relay.URL, fixture.claim.token)
				reader := &cache.ReadThrough{Dir: t.TempDir(), Source: deliveryCacheSource{client: client}}
				var directory string
				directory, err = reader.Prepare(ctx, &runnercontract.CacheDescriptor{OrganizationID: fixture.claim.orgA.String(), Entries: []runnercontract.CacheEntryRef{{CacheEntry: runnercontract.CacheEntry{Kind: runnercontract.CacheKindProvider, SHA256: sha256Hex(payload)}}}})
				path = filepath.Join(directory, "provider", sha256Hex(payload))
			} else {
				client := executor.NewClient(relay.URL, fixture.token.Token, fixture.claim.runnerA1.ID.String())
				path = filepath.Join(t.TempDir(), "content")
				if mode == "snapshot" {
					err = client.Download(ctx, fixture.path, path, int64(size+1))
				} else {
					reader := &executor.Cache{Client: client}
					_, err = reader.Fetch(ctx, runnercontract.CacheEntryRef{Path: fixture.path, CacheEntry: runnercontract.CacheEntry{Kind: runnercontract.CacheKindProvider, SHA256: sha256Hex(payload)}}, path)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path) //nolint:gosec // G304: path is inside this test's temporary directory.
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("long streaming body: %d bytes, error=%v", len(got), err)
			}
			if elapsed := time.Since(started); elapsed <= allowance {
				t.Fatalf("long streaming proof ended at %s before %s", elapsed, allowance)
			}
		})
	}
}
