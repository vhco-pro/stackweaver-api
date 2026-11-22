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
	"sync/atomic"
	"testing"
	"time"

	"github.com/michielvha/stackweaver/backend/internal/executor"
	"github.com/michielvha/stackweaver/backend/internal/launcher"
	"github.com/michielvha/stackweaver/backend/internal/launcher/cache"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/storage/storagetest"
	"gorm.io/gorm"
)

func runnerReadSingleAttemptClient(t *testing.T) *http.Client {
	t.Helper()
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Timeout: 45 * time.Second, Transport: transport}
}

func TestRunnerReadDelivery_SlowHeadersOtherContent(t *testing.T) {
	for _, kind := range []string{"plan", "artifacts"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			fixture := newRunnerDeliveryFixture(t, kind, []byte("verified delayed required content"))
			fixture.store.read = func(ctx context.Context, key string) ([]byte, error) {
				timer := time.NewTimer(31 * time.Second)
				defer timer.Stop()
				select {
				case <-timer.C:
					return fixture.store.Client.Get(ctx, key)
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			server := runnerReadDeliveryServer(t, runnerReadDeliveryRouter(fixture.claim, true))
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()
			if err := fixture.fetch(ctx, server.URL); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRunnerReadDelivery_AbsentPolicyRetainsProductionTimeout(t *testing.T) {
	fixture := newRunnerDeliveryFixture(t, "blob", []byte("protected required content"))
	fixture.store.read = func(ctx context.Context, key string) ([]byte, error) {
		timer := time.NewTimer(31 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			return fixture.store.Client.Get(ctx, key)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	server := runnerReadDeliveryServer(t, runnerReadDeliveryRouter(fixture.claim, false))
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+fixture.path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+fixture.token.Token)
	request.Header.Set("If-Match", "\""+sha256Hex(fixture.payload)+"\"")
	started := time.Now()
	response, err := runnerReadSingleAttemptClient(t).Do(request)
	if response != nil {
		_ = response.Body.Close()
	}
	if time.Since(started) < 30*time.Second || (!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)) {
		t.Fatalf("absent-policy control did not reproduce the server timeout: %v", err)
	}
}

func TestRunnerReadDelivery_UnrelatedStatusRetainsProductionTimeout(t *testing.T) {
	fixture := newRunnerDeliveryFixture(t, "blob", []byte("content"))
	var delayed atomic.Bool
	name := "delivery-status-" + fixture.id
	if err := fixture.claim.db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table == "runs" && delayed.CompareAndSwap(false, true) {
			timer := time.NewTimer(31 * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-tx.Statement.Context.Done():
				_ = tx.AddError(tx.Statement.Context.Err())
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.claim.db.Callback().Query().Remove(name); err != nil {
			t.Error(err)
		}
	})
	server := runnerReadDeliveryServer(t, runnerReadDeliveryRouter(fixture.claim, true))
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/api/v2/runner/jobs/"+fixture.id+"/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+fixture.token.Token)
	started := time.Now()
	response, err := runnerReadSingleAttemptClient(t).Do(request)
	if response != nil {
		_ = response.Body.Close()
	}
	if !delayed.Load() || time.Since(started) < 30*time.Second || (!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)) {
		t.Fatalf("unrelated status timeout changed: delayed=%v error=%v", delayed.Load(), err)
	}
}

type deliveryCacheSource struct{ client *launcher.Client }

func (s deliveryCacheSource) Fetch(ctx context.Context, org string, kind runnercontract.CacheKind, sum string) (io.ReadCloser, error) {
	return s.client.FetchCacheEntry(ctx, org, kind, sum)
}

func TestRunnerReadDelivery_StalledBodiesRecoverThroughNormalReaders(t *testing.T) {
	for _, mode := range []string{"required", "job cache", "launcher cache"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			payload := bytes.Repeat([]byte("c"), 128<<10)
			fixture := newRunnerDeliveryFixture(t, "blob", payload)
			if mode != "required" {
				store := storagetest.NewMemory()
				fixture.claim.handler.storageClient = store
				entry := &models.CacheEntry{OrganizationID: fixture.claim.orgA, Kind: string(runnercontract.CacheKindProvider), SHA256: sha256Hex(payload), SizeBytes: int64(len(payload)), Verification: models.CacheVerified}
				if err := fixture.claim.db.Create(entry).Error; err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := fixture.claim.db.Where("id = ?", entry.ID).Delete(&models.CacheEntry{}).Error; err != nil {
						t.Error(err)
					}
				})
				if err := store.Put(t.Context(), models.CacheObjectKey(entry.OrganizationID, entry.Kind, entry.SHA256), payload); err != nil {
					t.Fatal(err)
				}
				fixture.path = "/api/v2/runner/jobs/" + fixture.id + "/blob/cache/provider/" + entry.SHA256
			}
			server := runnerReadDeliveryServer(t, runnerReadDeliveryRouter(fixture.claim, true))
			relay, trips := runnerDeliveryRelay(t, server.URL, 0, true)
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()
			started := time.Now()
			var err error
			switch mode {
			case "required":
				err = fixture.fetch(ctx, relay.URL)
			case "job cache":
				client := executor.NewClient(relay.URL, fixture.token.Token, fixture.claim.runnerA1.ID.String())
				reader := &executor.Cache{Client: client}
				path := filepath.Join(t.TempDir(), "provider")
				var source string
				source, err = reader.Fetch(ctx, runnercontract.CacheEntryRef{Path: fixture.path, CacheEntry: runnercontract.CacheEntry{Kind: runnercontract.CacheKindProvider, SHA256: sha256Hex(payload)}}, path)
				if err == nil && source != executor.SourceBlob {
					t.Fatalf("cache did not recover through its API: %s", source)
				}
				if err == nil {
					got, readErr := os.ReadFile(path) //nolint:gosec // G304: path is inside this test's temporary cache.
					if readErr != nil || !bytes.Equal(got, payload) {
						t.Fatalf("cache retry published partial data: %v", readErr)
					}
				}
			case "launcher cache":
				client := launcher.NewClient(relay.URL, fixture.claim.token)
				reader := &cache.ReadThrough{Dir: t.TempDir(), Source: deliveryCacheSource{client: client}}
				var directory string
				directory, err = reader.Prepare(ctx, &runnercontract.CacheDescriptor{OrganizationID: fixture.claim.orgA.String(), Entries: []runnercontract.CacheEntryRef{{CacheEntry: runnercontract.CacheEntry{Kind: runnercontract.CacheKindProvider, SHA256: sha256Hex(payload)}}}})
				if err == nil {
					got, readErr := os.ReadFile(filepath.Join(directory, "provider", sha256Hex(payload))) //nolint:gosec // G304: directory is this test's temporary cache and the digest comes from its payload.
					if readErr != nil || !bytes.Equal(got, payload) {
						t.Fatalf("prefetch retry did not publish verified content: %v", readErr)
					}
				}
			}
			if err != nil || trips.Load() != 2 || time.Since(started) < 30*time.Second || time.Since(started) >= 45*time.Second {
				t.Fatalf("stalled %s read: trips=%d elapsed=%s error=%v", mode, trips.Load(), time.Since(started), err)
			}
		})
	}
}
