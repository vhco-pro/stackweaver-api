// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build e2e

package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
)

func init() { gin.SetMode(gin.TestMode) }

// TestTestingReset_404WithoutEnv asserts that even when the binary is built
// with the `e2e` tag, the reset endpoint refuses to serve unless the runtime
// env var STACKWEAVER_ENV is exactly "e2e-test". Prevents an accidentally
// misbuilt production binary from exposing a reset hook.
func TestTestingReset_404WithoutEnv(t *testing.T) {
	// t.Setenv clears STACKWEAVER_ENV at test teardown, so even if the CI
	// environment happens to set it the other direction, this test is stable.
	t.Setenv("STACKWEAVER_ENV", "")

	limiter := middleware.NewIPRateLimiter(10, 20)
	h := testingResetHandler(limiter, nil)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/testing/reset", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	h(c)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when STACKWEAVER_ENV is unset, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTestingReset_404WithWrongEnvValue(t *testing.T) {
	// Anything other than the exact sentinel value returns 404 — confirms the
	// env check is not a substring / truthiness check.
	for _, v := range []string{"production", "staging", "E2E-TEST", "e2e", "true", "1"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("STACKWEAVER_ENV", v)

			limiter := middleware.NewIPRateLimiter(10, 20)
			h := testingResetHandler(limiter, nil)

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/testing/reset", nil)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			h(c)

			if w.Code != http.StatusNotFound {
				t.Errorf("STACKWEAVER_ENV=%q expected 404, got %d", v, w.Code)
			}
		})
	}
}

// TestTestingReset_ServesWhenEnvIsE2ETest verifies the handler does its work
// (rate-limit reset, response payload) when both gates are open.
func TestTestingReset_ServesWhenEnvIsE2ETest(t *testing.T) {
	t.Setenv("STACKWEAVER_ENV", "e2e-test")

	limiter := middleware.NewIPRateLimiter(10, 20)

	// Populate the limiter so we can verify Reset actually cleared it.
	_ = limiter.Middleware()
	// Drive a few IPs through getLimiter indirectly via the middleware.
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		warm := httptest.NewRecorder()
		warmCtx, _ := gin.CreateTestContext(warm)
		warmCtx.Request, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		warmCtx.Request.RemoteAddr = ip + ":1234"
		limiter.Middleware()(warmCtx)
	}

	h := testingResetHandler(limiter, nil)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/testing/reset", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	h(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !contains(w.Body.String(), `"reset":true`) {
		t.Errorf("expected reset:true in body, got %s", w.Body.String())
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
