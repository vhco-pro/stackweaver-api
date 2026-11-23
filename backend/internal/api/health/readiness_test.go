// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package health

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakePinger stands in for the API's *sql.DB. Its behavior is chosen per test.
type fakePinger struct {
	mu       sync.Mutex
	err      error
	block    bool // wait until the context ends, then return its error
	gotCtx   context.Context
	received time.Time
	calls    int
}

func (f *fakePinger) PingContext(ctx context.Context) error {
	f.mu.Lock()
	f.gotCtx = ctx
	f.received = time.Now()
	f.calls++
	block, err := f.block, f.err
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func (f *fakePinger) context() context.Context {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotCtx
}

func newServer(t *testing.T, p Pinger) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	r := NewReadiness(p)
	mux.Handle("/readyz", r)
	mux.Handle("/livez", Livez())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// answer is what a probe request returned; the body is already read and closed.
type answer struct {
	code   int
	header http.Header
	body   string
}

func do(t *testing.T, ctx context.Context, method, url string) answer {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, url, http.NoBody)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sending %s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return answer{code: resp.StatusCode, header: resp.Header, body: string(body)}
}

func assertHeaders(t *testing.T, resp answer) {
	t.Helper()
	if got := resp.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := resp.header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

const (
	wantOK          = `{"status":"ok"}`
	wantUnavailable = `{"status":"unavailable","failing":["postgres"]}`
)

func TestReadyzAnswers(t *testing.T) {
	cases := []struct {
		name     string
		pinger   *fakePinger
		wantCode int
		wantBody string
	}{
		{"passing ping", &fakePinger{}, http.StatusOK, wantOK},
		{"failing ping", &fakePinger{err: errors.New("dial tcp 10.0.0.1:5432: connection refused")}, http.StatusServiceUnavailable, wantUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(t, tc.pinger)
			resp := do(t, context.Background(), http.MethodGet, srv.URL+"/readyz")
			if resp.code != tc.wantCode {
				t.Errorf("GET status = %d, want %d", resp.code, tc.wantCode)
			}
			if resp.body != tc.wantBody {
				t.Errorf("GET body = %q, want %q", resp.body, tc.wantBody)
			}
			assertHeaders(t, resp)

			resp = do(t, context.Background(), http.MethodHead, srv.URL+"/readyz")
			if resp.code != tc.wantCode {
				t.Errorf("HEAD status = %d, want %d", resp.code, tc.wantCode)
			}
			if resp.body != "" {
				t.Errorf("HEAD body = %q, want empty", resp.body)
			}
			assertHeaders(t, resp)
		})
	}
}

func TestReadyzTimesOutAtTwoSeconds(t *testing.T) {
	p := &fakePinger{block: true}
	srv := newServer(t, p)
	start := time.Now()
	resp := do(t, context.Background(), http.MethodGet, srv.URL+"/readyz")
	elapsed := time.Since(start)
	if resp.code != http.StatusServiceUnavailable || resp.body != wantUnavailable {
		t.Fatalf("got %d %q, want 503 %q", resp.code, resp.body, wantUnavailable)
	}
	if elapsed > 2500*time.Millisecond {
		t.Errorf("answered after %v, want within 2.5s", elapsed)
	}
	ctx := p.context()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("the ping context has no deadline")
	}
	if d := deadline.Sub(start); d < 1900*time.Millisecond || d > 2100*time.Millisecond {
		t.Errorf("deadline %v after the request, want about 2s", d)
	}
}

func TestReadyzCancelledRequestCancelsPing(t *testing.T) {
	p := &fakePinger{block: true}
	srv := newServer(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/readyz", http.NoBody)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	deadline := time.Now().Add(time.Second)
	for p.context() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if p.context() == nil {
		t.Fatal("the ping never started")
	}
	cancel()
	select {
	case <-p.context().Done():
		if !errors.Is(p.context().Err(), context.Canceled) {
			t.Errorf("ping context ended with %v, want context.Canceled", p.context().Err())
		}
	case <-time.After(1500 * time.Millisecond):
		t.Error("cancelling the request did not cancel the ping")
	}
	<-done
}

func TestLivez(t *testing.T) {
	srv := newServer(t, &fakePinger{err: errors.New("postgres is down")})
	resp := do(t, context.Background(), http.MethodGet, srv.URL+"/livez")
	if resp.code != http.StatusOK || resp.body != wantOK {
		t.Errorf("GET got %d %q, want 200 %q", resp.code, resp.body, wantOK)
	}
	assertHeaders(t, resp)
	resp = do(t, context.Background(), http.MethodHead, srv.URL+"/livez")
	if resp.code != http.StatusOK || resp.body != "" {
		t.Errorf("HEAD got %d %q, want 200 and no body", resp.code, resp.body)
	}
	assertHeaders(t, resp)
}
