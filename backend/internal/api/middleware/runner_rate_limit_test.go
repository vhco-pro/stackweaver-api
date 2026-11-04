// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
)

// TestRunnerRateLimitByPrincipal pins the runner-route rate limits (#933, D3, AC74): every
// /api/v2/runner/* route is exempt from the per-IP limiter and governed by a limiter keyed on the
// runner or the job, so many launchers behind one address never share one budget while one noisy
// executor is throttled alone; the per-IP limiter still governs every other route.
func TestRunnerRateLimitByPrincipal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(NewIPRateLimiter(100, 200).MiddlewareExcept("/api/v2/runner/"))
	// A stand-in for RunnerAuth: X-Runner names the runner, X-Job a job token's job.
	r.Use(func(c *gin.Context) {
		if id := c.GetHeader("X-Runner"); id != "" {
			c.Set(CallingRunnerKey, &models.Runner{ID: uuid.MustParse(id)})
		}
		if job := c.GetHeader("X-Job"); job != "" {
			c.Set(JobPrincipalKey, apikey.JobPrincipal{Kind: models.JobTypeTofuRun, JobID: job, Attempt: 1})
		}
	})
	runner := r.Group("/api/v2/runner")
	runner.Use(RunnerPrincipalRateLimit(RunnerRateBudgets{RunnerRPS: 10, RunnerBurst: 20, JobRPS: 5, JobBurst: 10}))
	runner.POST("/heartbeat", func(c *gin.Context) { c.Status(http.StatusOK) })
	runner.POST("/jobs/:id/output", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/api/v2/organizations", func(c *gin.Context) { c.Status(http.StatusOK) })

	do := func(method, path string, headers map[string]string) int {
		req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		req.RemoteAddr = "203.0.113.7:4000" // every request from one address, as behind a NAT
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Code
	}

	// Three hundred launchers behind one address heartbeat twice each: 600 requests, three times
	// the per-IP burst, and none is refused.
	for range 2 {
		for i := range 300 {
			id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(strconv.Itoa(i))).String()
			if code := do(http.MethodPost, "/api/v2/runner/heartbeat", map[string]string{"X-Runner": id}); code != http.StatusOK {
				t.Fatalf("launcher %d heartbeat: %d", i, code)
			}
		}
	}

	// One noisy executor exhausts its own budget and is throttled; its neighbour is not.
	noisy := uuid.NewString()
	throttled := 0
	for range 50 {
		if do(http.MethodPost, "/api/v2/runner/jobs/run-noisy/output", map[string]string{"X-Runner": noisy, "X-Job": "run-noisy"}) == http.StatusTooManyRequests {
			throttled++
		}
	}
	if throttled == 0 {
		t.Error("an executor far over its budget was never throttled")
	}
	if code := do(http.MethodPost, "/api/v2/runner/jobs/run-quiet/output", map[string]string{"X-Runner": noisy, "X-Job": "run-quiet"}); code != http.StatusOK {
		t.Errorf("the neighbouring job of the same runner was throttled: %d", code)
	}

	// The per-IP limiter still governs the rest of the API.
	limited := false
	for range 250 {
		if do(http.MethodGet, "/api/v2/organizations", nil) == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("the per-IP limiter no longer governs routes outside /api/v2/runner/")
	}
}
