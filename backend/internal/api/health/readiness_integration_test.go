// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Readiness against a real Postgres pool (AC-33 of the health probes plan): /readyz uses the pool
// it is given, opens none of its own, and turns 503 while every connection of that pool is held.
// The test creates no rows; it holds connections in open transactions and releases them.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/health/ -run TestReadinessOnTheMainPool

//go:build integration

package health

import (
	"context"
	"database/sql"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
)

// withApplicationName returns dsn with application_name set, so pg_stat_activity can count this
// pool's sessions alone.
func withApplicationName(t *testing.T, dsn, name string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parsing TEST_DATABASE_URL: %v", err)
	}
	q := u.Query()
	q.Set("application_name", name)
	u.RawQuery = q.Encode()
	return u.String()
}

func readyzStatus(t *testing.T, srvURL string) (int, time.Duration) {
	t.Helper()
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srvURL+"/readyz", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, time.Since(start)
}

func TestReadinessOnTheMainPool(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	appName := "sw-readyz-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	gdb, err := dbtest.Open(t, withApplicationName(t, dsn, appName), nil)
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	pool, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(5)
	if got := pool.Stats().MaxOpenConnections; got != 5 {
		t.Fatalf("pool limit reads back %d, want 5", got)
	}

	srv := newServer(t, pool)
	if code, _ := readyzStatus(t, srv.URL); code != http.StatusOK {
		t.Fatalf("/readyz with a free pool answered %d, want 200", code)
	}

	// Hold every connection of the pool in an open transaction.
	ctx := context.Background()
	held := make([]*sql.Tx, 0, 5)
	for range 5 {
		tx, err := pool.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("holding a connection: %v", err)
		}
		if _, err := tx.ExecContext(ctx, "SELECT 1"); err != nil {
			t.Fatalf("using a held connection: %v", err)
		}
		held = append(held, tx)
	}
	t.Cleanup(func() {
		for _, tx := range held {
			_ = tx.Rollback()
		}
	})

	// Saturation: a sixth acquisition cannot get a connection within a second.
	sixthCtx, cancel := context.WithTimeout(ctx, time.Second)
	conn, err := pool.Conn(sixthCtx)
	cancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("a sixth connection was acquired from a pool of five held connections")
	}

	// A separate connection, under another application name, counts the pool's sessions.
	observer, err := dbtest.Open(t, withApplicationName(t, dsn, appName+"-obs"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var sessions int64
	if err := observer.Raw("SELECT count(*) FROM pg_stat_activity WHERE application_name = ?", appName).Scan(&sessions).Error; err != nil {
		t.Fatalf("reading pg_stat_activity: %v", err)
	}
	if sessions != 5 {
		t.Errorf("pg_stat_activity shows %d sessions under the pool's name, want exactly 5", sessions)
	}

	code, elapsed := readyzStatus(t, srv.URL)
	if code != http.StatusServiceUnavailable {
		t.Errorf("/readyz with every connection held answered %d, want 503", code)
	}
	if elapsed > 2500*time.Millisecond {
		t.Errorf("/readyz with every connection held answered after %v, want within 2.5s", elapsed)
	}

	// Release one connection: readiness passes again.
	if err := held[0].Rollback(); err != nil {
		t.Fatal(err)
	}
	held = held[1:]
	if code, _ := readyzStatus(t, srv.URL); code != http.StatusOK {
		t.Errorf("/readyz after releasing one connection answered %d, want 200", code)
	}
}

// countingPinger counts PingContext calls.
type countingPinger struct{ calls atomic.Int64 }

func (c *countingPinger) PingContext(context.Context) error {
	c.calls.Add(1)
	return nil
}

func TestReadinessPingsOncePerRequest(t *testing.T) {
	p := &countingPinger{}
	srv := newServer(t, p)
	const requests = 100
	var wg sync.WaitGroup
	for range requests {
		wg.Go(func() {
			if code, _ := readyzStatus(t, srv.URL); code != http.StatusOK {
				t.Errorf("/readyz answered %d, want 200", code)
			}
		})
	}
	wg.Wait()
	if got := p.calls.Load(); got != requests {
		t.Errorf("%d requests made %d PingContext calls, want one each", requests, got)
	}
}

// startFaultProxy builds scripts/faultproxy and runs it in front of upstream. It returns the proxy's
// listen address and a function that switches its mode and reads the mode back.
func startFaultProxy(t *testing.T, upstream string) (string, func(mode string)) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "faultproxy")
	build := exec.CommandContext(context.Background(), "go", "build", "-o", bin, ".") //nolint:gosec // G204: builds the repository's own fault proxy
	build.Dir = filepath.Join("..", "..", "..", "..", "scripts", "faultproxy")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building scripts/faultproxy: %v\n%s", err, out)
	}
	listen, control := freeLocalAddr(t), freeLocalAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	proxy := exec.CommandContext(ctx, bin, "-listen", listen, "-upstream", upstream, "-control", control) //nolint:gosec // G204: runs the binary built above
	if err := proxy.Start(); err != nil {
		cancel()
		t.Fatalf("starting the fault proxy: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = proxy.Wait()
	})
	modeURL := "http://" + control + "/mode"
	deadline := time.Now().Add(10 * time.Second)
	for {
		if got, err := readMode(modeURL); err == nil && got == "pass" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fault proxy's control endpoint did not answer")
		}
		time.Sleep(50 * time.Millisecond)
	}
	setMode := func(mode string) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, modeURL, strings.NewReader(mode))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("setting mode %s: %v", mode, err)
		}
		_ = resp.Body.Close()
		if got, err := readMode(modeURL); err != nil || got != mode {
			t.Fatalf("the fault proxy's mode reads back %q (%v), want %q", got, err, mode)
		}
	}
	return listen, setMode
}

func readMode(modeURL string) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, modeURL, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b)), err
}

func freeLocalAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// TestReadinessOnAOneConnectionPool is AC-01's one-connection case: while Postgres refuses new
// connections, a pool whose one idle connection still works answers ready; once established
// connections are dropped too, it answers 503.
func TestReadinessOnAOneConnectionPool(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parsing TEST_DATABASE_URL: %v", err)
	}
	listen, setMode := startFaultProxy(t, u.Host)
	u.Host = listen
	gdb, err := dbtest.Open(t, u.String(), nil)
	if err != nil {
		t.Fatalf("opening the database through the fault proxy: %v", err)
	}
	pool, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(1)
	srv := newServer(t, pool)

	if code, _ := readyzStatus(t, srv.URL); code != http.StatusOK {
		t.Fatalf("/readyz through the proxy in pass mode answered %d, want 200", code)
	}
	// Idle for over a second, so reusing the connection runs the driver's session check too.
	time.Sleep(1200 * time.Millisecond)
	setMode("refuse-new")
	if code, _ := readyzStatus(t, srv.URL); code != http.StatusOK {
		t.Errorf("/readyz under refuse-new with one idle healthy connection answered %d, want 200", code)
	}
	setMode("refuse")
	code, elapsed := readyzStatus(t, srv.URL)
	if code != http.StatusServiceUnavailable {
		t.Errorf("/readyz under refuse answered %d, want 503", code)
	}
	if elapsed > 2500*time.Millisecond {
		t.Errorf("/readyz under refuse answered after %v, want within 2.5s", elapsed)
	}
}
