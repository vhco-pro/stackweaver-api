// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package routes

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

const testOrigin = "https://app.example.test"

type stubPinger struct{ err error }

func (s stubPinger) PingContext(context.Context) error { return s.err }

// probeRouter builds the router's base with a limiter whose bucket holds one token and refills once
// an hour, so a fresh router per case admits exactly one limited request.
func probeRouter(t *testing.T, pinger stubPinger, log *bytes.Buffer) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("STACKWEAVER_APP_URL", testOrigin)
	return newBaseRouter(baseRouterConfig{
		Origins:   middleware.OriginPolicyFromEnv(),
		Limiter:   middleware.NewIPRateLimiterRate(rate.Every(time.Hour), 1),
		Readiness: pinger,
		LogOutput: log,
	})
}

func serve(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, path, http.NoBody)
	req.Header.Set("Origin", testOrigin)
	req.RemoteAddr = "192.0.2.10:40000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// exhaust spends the caller's one token and confirms the next limited request is refused.
func exhaust(t *testing.T, r *gin.Engine) {
	t.Helper()
	if w := serve(r, http.MethodGet, "/api/v2/organizations"); w.Code == http.StatusTooManyRequests {
		t.Fatal("the first request was rate limited")
	}
	if w := serve(r, http.MethodGet, "/api/v2/organizations"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("the second request answered %d, want 429", w.Code)
	}
}

var securityHeaders = map[string]string{
	"X-Frame-Options":         "DENY",
	"X-Content-Type-Options":  "nosniff",
	"Referrer-Policy":         "origin-when-cross-origin",
	"X-XSS-Protection":        "0",
	"Permissions-Policy":      "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
	"Content-Security-Policy": "default-src 'self'; connect-src 'self'; frame-ancestors 'none'",
}

func assertRouterHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != testOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, testOrigin)
	}
	for k, v := range securityHeaders {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestProbePathsSkipTheRateLimiter(t *testing.T) {
	cases := []struct {
		name     string
		method   string
		path     string
		pinger   stubPinger
		wantCode int
	}{
		{"livez GET", http.MethodGet, "/livez", stubPinger{}, http.StatusOK},
		{"livez HEAD", http.MethodHead, "/livez", stubPinger{}, http.StatusOK},
		{"health GET", http.MethodGet, "/health", stubPinger{}, http.StatusOK},
		{"health HEAD", http.MethodHead, "/health", stubPinger{}, http.StatusOK},
		{"readyz passing", http.MethodGet, "/readyz", stubPinger{}, http.StatusOK},
		{"readyz failing", http.MethodGet, "/readyz", stubPinger{err: errors.New("down")}, http.StatusServiceUnavailable},
		{"readyz HEAD failing", http.MethodHead, "/readyz", stubPinger{err: errors.New("down")}, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := probeRouter(t, tc.pinger, &bytes.Buffer{})
			exhaust(t, r)
			w := serve(r, tc.method, tc.path)
			if w.Code != tc.wantCode {
				t.Errorf("%s %s answered %d, want %d", tc.method, tc.path, w.Code, tc.wantCode)
			}
			assertRouterHeaders(t, w)
		})
	}
}

func TestNearbyPathsStayLimited(t *testing.T) {
	for _, path := range []string{"/healthz", "/readyz/x"} {
		t.Run(path, func(t *testing.T) {
			r := probeRouter(t, stubPinger{}, &bytes.Buffer{})
			exhaust(t, r)
			if w := serve(r, http.MethodGet, path); w.Code != http.StatusTooManyRequests {
				t.Errorf("GET %s answered %d, want 429", path, w.Code)
			}
		})
	}
	t.Run("runner prefix", func(t *testing.T) {
		r := probeRouter(t, stubPinger{}, &bytes.Buffer{})
		exhaust(t, r)
		if w := serve(r, http.MethodGet, "/api/v2/runner/heartbeat"); w.Code == http.StatusTooManyRequests {
			t.Error("a runner path was rate limited")
		}
	})
}

func TestHealthUnchangedWhileNotReady(t *testing.T) {
	r := probeRouter(t, stubPinger{err: errors.New("down")}, &bytes.Buffer{})
	if w := serve(r, http.MethodGet, "/readyz"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz answered %d, want 503", w.Code)
	}
	w := serve(r, http.MethodGet, "/health")
	if w.Code != http.StatusOK || w.Body.String() != `{"status":"ok"}` {
		t.Errorf("GET /health = %d %q, want 200 {\"status\":\"ok\"}", w.Code, w.Body.String())
	}
	if w := serve(r, http.MethodHead, "/health"); w.Code != http.StatusOK {
		t.Errorf("HEAD /health = %d, want 200", w.Code)
	}
}

func TestProbePathsStayOutOfTheRequestLog(t *testing.T) {
	var log bytes.Buffer
	r := probeRouter(t, stubPinger{}, &log)
	for _, path := range []string{"/livez", "/readyz", "/health"} {
		serve(r, http.MethodGet, path)
		serve(r, http.MethodHead, path)
	}
	if log.Len() != 0 {
		t.Errorf("probe requests wrote to the request log:\n%s", log.String())
	}
	serve(r, http.MethodGet, "/.well-known/terraform.json")
	if lines := strings.Count(log.String(), "\n"); lines != 1 {
		t.Errorf("a request to /.well-known/terraform.json wrote %d log lines, want 1:\n%s", lines, log.String())
	}
}

// TestMainPoolIsTheHandlesPool checks that /readyz pings the database/sql pool under the API's own
// GORM handle and opens none of its own.
func TestMainPoolIsTheHandlesPool(t *testing.T) {
	sqlDB, err := sql.Open("pgx", "postgres://readiness@127.0.0.1:1/none?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	// A handle over that pool, as repository.NewDatabase builds one, without connecting.
	gdb := &gorm.DB{Config: &gorm.Config{ConnPool: sqlDB}}
	pool, err := mainPool(gdb)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := pool.(*sql.DB); !ok || got != sqlDB {
		t.Errorf("readiness pings %T %p, want the handle's own *sql.DB %p", pool, pool, sqlDB)
	}
}
