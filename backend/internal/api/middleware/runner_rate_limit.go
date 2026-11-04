// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
)

// RunnerRateBudgets are the per-principal budgets of the runner control plane, in requests per
// second and burst: one budget per runner for its launcher's calls, one per job for its executor's.
// They are deployment settings (RUNNER_RATE_LIMIT_RPS and _BURST, JOB_RATE_LIMIT_RPS and _BURST).
type RunnerRateBudgets struct {
	RunnerRPS, RunnerBurst int
	JobRPS, JobBurst       int
}

// RunnerPrincipalRateLimit limits the runner control plane per principal instead of per address
// (#933, D3, AC74): a job token's requests count against its job, a runner token's against its
// runner, and a registration against the key presenting it. N launchers behind one NAT then never
// share one budget, and one runaway executor exhausts only its own. A request with no principal is
// keyed on its address. Mount it after RunnerAuth.
func RunnerPrincipalRateLimit(b RunnerRateBudgets) gin.HandlerFunc {
	runners := NewIPRateLimiter(b.RunnerRPS, b.RunnerBurst)
	jobs := NewIPRateLimiter(b.JobRPS, b.JobBurst)
	return func(c *gin.Context) {
		limiter, key := runners, "ip:"+c.ClientIP()
		if v, ok := c.Get(JobPrincipalKey); ok {
			if p, ok := v.(apikey.JobPrincipal); ok {
				limiter, key = jobs, "job:"+string(p.Kind)+":"+p.JobID
			}
		} else if v, ok := c.Get(CallingRunnerKey); ok {
			if r, ok := v.(*models.Runner); ok && r != nil {
				key = "runner:" + r.ID.String()
			}
		} else if id, ok := c.Get("api_key_id"); ok {
			if s, ok := id.(interface{ String() string }); ok {
				key = "key:" + s.String()
			}
		}
		if !limiter.getLimiter(key).Allow() {
			jsonapi.WriteError(c, http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests), "rate limit exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}

// RunnerRateBudgetsFromEnv reads the runner-route budgets: RUNNER_RATE_LIMIT_RPS and _BURST per
// runner (default 20 and 40) and JOB_RATE_LIMIT_RPS and _BURST per job (default 20 and 40).
func RunnerRateBudgetsFromEnv() RunnerRateBudgets {
	return RunnerRateBudgetsFrom(os.Getenv)
}

// RunnerRateBudgetsFrom is RunnerRateBudgetsFromEnv through getenv.
func RunnerRateBudgetsFrom(getenv func(string) string) RunnerRateBudgets {
	read := func(name string, def int) int {
		if n, err := strconv.Atoi(strings.TrimSpace(getenv(name))); err == nil && n > 0 {
			return n
		}
		return def
	}
	return RunnerRateBudgets{
		RunnerRPS: read("RUNNER_RATE_LIMIT_RPS", 20), RunnerBurst: read("RUNNER_RATE_LIMIT_BURST", 40),
		JobRPS: read("JOB_RATE_LIMIT_RPS", 20), JobBurst: read("JOB_RATE_LIMIT_BURST", 40),
	}
}
