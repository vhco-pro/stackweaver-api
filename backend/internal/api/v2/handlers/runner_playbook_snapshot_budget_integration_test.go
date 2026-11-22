// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/storage"
)

const proofSnapshotBytes = 32 << 20

type snapshotBudgetDisk struct {
	storage.Client
	path    string
	opened  chan struct{}
	resume  chan struct{}
	started atomic.Bool
}

func (d *snapshotBudgetDisk) Put(_ context.Context, _ string, body []byte) error {
	return os.WriteFile(d.path, body, 0o600)
}

func (d *snapshotBudgetDisk) GetStream(ctx context.Context, _ string) (io.ReadCloser, error) {
	if d.started.CompareAndSwap(false, true) && d.opened != nil {
		close(d.opened)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.resume:
		}
	}
	return os.Open(d.path)
}

func (d *snapshotBudgetDisk) Get(ctx context.Context, key string) ([]byte, error) {
	body, err := d.GetStream(ctx, key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()
	return io.ReadAll(body)
}

func TestPlaybookSnapshotBudget_ReadAndConcurrentControl(t *testing.T) {
	f := setupAgentPrepFixture(t)
	capturedAt := time.Now().UTC()
	pb := f.seedPlaybook(t, playbookSpec{cachedAt: &capturedAt, commit: "fixture", size: proofSnapshotBytes})
	raw := &snapshotBudgetDisk{
		path:   filepath.Join(t.TempDir(), "sealed"),
		opened: make(chan struct{}), resume: make(chan struct{}),
	}
	sealer, err := crypto.NewCryptoService(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewSealed(raw, sealer, storage.ArtifactSealRules()...)
	input := make([]byte, proofSnapshotBytes)
	want := sha256.Sum256(input)
	f.publishFixtureSnapshot(t, pb, store, input)
	job := f.seedSnapshotJob(t, pb, f.runnerA1)
	input = nil

	server := httptest.NewServer(f.artifactsRouter(store))
	defer server.Close()
	dl := "/api/v2/runner/jobs/" + job.ID.String() + "/playbook-snapshot"
	get := func(path string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Test-Key", "a1")
		req.Header.Set(runnercontract.CapabilitiesHeader, runnercontract.CapabilityPlaybookSnapshot)
		return server.Client().Do(req)
	}
	type transfer struct {
		digest []byte
		bytes  int64
		status int
		err    error
	}
	result := make(chan transfer, 1)
	go func() {
		resp, err := get(dl)
		if err != nil {
			result <- transfer{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		digest := sha256.New()
		size, err := io.Copy(digest, resp.Body)
		result <- transfer{digest: digest.Sum(nil), bytes: size, status: resp.StatusCode, err: err}
	}()
	select {
	case <-raw.opened:
	case early := <-result:
		t.Fatalf("snapshot returned before storage opened: %+v", early)
	case <-time.After(15 * time.Second):
		close(raw.resume)
		t.Fatal("snapshot did not reach storage")
	}
	defer func() {
		select {
		case <-raw.resume:
		default:
			close(raw.resume)
		}
	}()
	for _, check := range []struct {
		path string
		code int
	}{
		{dl, http.StatusServiceUnavailable},
		{"/api/v2/runner/jobs/" + job.ID.String() + "/artifacts", http.StatusOK},
	} {
		resp, err := get(check.path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != check.code {
			t.Errorf("%s returned %d, want %d (read error: %v)", check.path, resp.StatusCode, check.code, err)
		}
	}
	close(raw.resume)
	first := <-result
	if first.err != nil || first.status != http.StatusOK || first.bytes != proofSnapshotBytes || !bytes.Equal(first.digest, want[:]) {
		t.Errorf("first snapshot returned %d and %d bytes with error %v", first.status, first.bytes, first.err)
	}
	if err := os.Truncate(raw.path, 45<<20); err != nil {
		t.Fatal(err)
	}
	resp, err := get(dl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	reason, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil || resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(reason), "32 MiB") {
		t.Errorf("oversized object returned %d %s %v", resp.StatusCode, reason, err)
	}
}

type snapshotZeroReader struct{}

func (snapshotZeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestPlaybookSnapshotBudget_UploadAtAndOverLimit(t *testing.T) {
	f := setupAtRestWriters(t)
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached})
	item, err := f.items.RequestPlaybookSnapshot(t.Context(), pb, "manual")
	if err != nil {
		t.Fatal(err)
	}
	f.claimWorkItem(t, item, "wi")
	path := "/api/v2/runner/jobs/" + item.ID + "/snapshot"
	for _, tc := range []struct {
		name  string
		size  int64
		known bool
		want  int
	}{
		{"declared oversize", proofSnapshotBytes + 1, true, http.StatusRequestEntityTooLarge},
		{"unknown oversize", proofSnapshotBytes + 1, false, http.StatusRequestEntityTooLarge},
		{"at cap", proofSnapshotBytes, true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := io.LimitReader(snapshotZeroReader{}, tc.size)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, body)
			if tc.known {
				req.ContentLength = tc.size
			}
			req.Header.Set("X-Test-Key", "wi")
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set(runnercontract.HeaderSnapshotCommit, "fixture")
			rec := httptest.NewRecorder()
			f.r.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("upload returned %d %s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
			if tc.want == http.StatusRequestEntityTooLarge && !strings.Contains(rec.Body.String(), "32 MiB") {
				t.Errorf("oversized upload response omits the cap: %s", rec.Body.String())
			}
		})
	}
}
