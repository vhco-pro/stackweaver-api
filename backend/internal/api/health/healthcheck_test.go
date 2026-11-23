// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package health

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// routeListener answers code on /readyz and 404 elsewhere, like the API's router.
func routeListener(t *testing.T, ln net.Listener, code int) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL
}

func loopbackListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	return ln
}

func runCheck(t *testing.T, url string) (int, string) {
	t.Helper()
	var stderr bytes.Buffer
	code := RunHealthcheck(context.Background(), url, &stderr)
	return code, stderr.String()
}

func assertFailureLine(t *testing.T, stderr, url string) {
	t.Helper()
	if !strings.HasPrefix(stderr, "healthcheck:") || !strings.Contains(stderr, url) {
		t.Errorf("stderr = %q, want a line starting with healthcheck: that names %s", stderr, url)
	}
}

func TestHealthcheckExitStatus(t *testing.T) {
	ready := routeListener(t, loopbackListener(t), http.StatusOK) + "/readyz"
	if code, stderr := runCheck(t, ready); code != 0 {
		t.Errorf("ready listener: exit %d (%s), want 0", code, stderr)
	}
	unready := routeListener(t, loopbackListener(t), http.StatusServiceUnavailable) + "/readyz"
	code, stderr := runCheck(t, unready)
	if code != 1 {
		t.Errorf("unready listener: exit %d, want 1", code)
	}
	assertFailureLine(t, stderr, unready)
}

func TestHealthcheckNeverAnswers(t *testing.T) {
	ln := loopbackListener(t)
	t.Cleanup(func() { _ = ln.Close() })
	// Accept connections and hold them without ever answering.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	url := "http://" + ln.Addr().String() + "/readyz"
	start := time.Now()
	code, stderr := runCheck(t, url)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("gave up after %v, want within 5s", elapsed)
	}
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	assertFailureLine(t, stderr, url)
}

func TestHealthcheckDoesNotFollowRedirects(t *testing.T) {
	target := routeListener(t, loopbackListener(t), http.StatusOK) + "/readyz"
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	})
	redirecting := httptest.NewServer(mux)
	t.Cleanup(redirecting.Close)
	url := redirecting.URL + "/readyz"
	code, stderr := runCheck(t, url)
	if code != 1 {
		t.Errorf("a 302 to a 200-answering URL gave exit %d, want 1", code)
	}
	assertFailureLine(t, stderr, url)
}

// nonLoopbackIPv4 returns an address of this host that the proxy environment does not exempt.
func nonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("listing interface addresses: %v", err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
			return n.IP.String()
		}
	}
	t.Fatal("this host has no non-loopback IPv4 address for the proxy test")
	return ""
}

func TestHealthcheckIgnoresProxyEnvironment(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(proxy.Close)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	ip := nonLoopbackIPv4(t)
	for _, tc := range []struct {
		code int
		want int
	}{{http.StatusOK, 0}, {http.StatusServiceUnavailable, 1}} {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", net.JoinHostPort(ip, "0"))
		if err != nil {
			t.Fatalf("listening on %s: %v", ip, err)
		}
		url := routeListener(t, ln, tc.code) + "/readyz"
		if got, stderr := runCheck(t, url); got != tc.want {
			t.Errorf("direct %d with a 200-answering proxy set: exit %d (%s), want %d", tc.code, got, stderr, tc.want)
		}
	}
}

func TestHealthcheckRequestsReadyz(t *testing.T) {
	ln := loopbackListener(t)
	port := ln.Addr().(*net.TCPAddr).Port
	routeListener(t, ln, http.StatusOK)
	dial, err := ResolveProbeAddr("0.0.0.0", port)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	if code, stderr := runCheck(t, ProbeURL(dial)); code != 0 {
		t.Errorf("exit %d (%s) for the default wildcard on port %s, want 0", code, stderr, strconv.Itoa(port))
	}
}
