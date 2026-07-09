// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// CallingRunnerKey is the gin-context key under which RunnerAuth stores the
// authenticated *models.Runner. Handlers read it to bind every job-scoped
// operation to the runner that owns the job (AUD-001).
const CallingRunnerKey = "calling_runner"

// RunnerAuth authenticates a caller on the /runner/* control plane as a specific
// self-hosted runner and rejects everyone else.
//
// AUD-001: the runner job handlers previously trusted a runner_id supplied in the
// request body and were classified agnostic() in the org wall — so any authenticated
// principal (including plain JWT browser sessions) could pull another tenant's
// decrypted credentials/OIDC tokens, overwrite state, or forge job output. This
// middleware closes that by requiring an API-key identity whose scopes bind it to
// exactly one runner (minted at registration via apikey.CreateRunnerToken). The
// resolved runner is the ONLY identity the handlers trust; the body runner_id is
// no longer authoritative. JWT/browser identities are refused outright — they have
// no business on the runner control plane.
//
// The /runner/register route is exempt (a runner has no identity yet): it stays on
// the org-scoped runner:register key path.
func RunnerAuth(runnerRepo *repository.RunnerRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only API-key identities may act as runners. Block JWT/browser sessions.
		if method, _ := c.Get("auth_method"); method != "api_key" {
			c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{
				"status": "401", "title": "Unauthorized",
				"detail": "runner control plane requires a runner API key",
			}}})
			c.Abort()
			return
		}

		raw, exists := c.Get("api_key")
		apiKey, ok := raw.(*models.APIKey)
		if !exists || !ok || apiKey == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{
				"status": "401", "title": "Unauthorized", "detail": "missing API key",
			}}})
			c.Abort()
			return
		}

		checker, err := apikey.NewScopeChecker(apiKey.Scopes)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{
				"status": "401", "title": "Unauthorized", "detail": "invalid API key scopes",
			}}})
			c.Abort()
			return
		}

		// The token must bind to exactly one runner. GetScopedRunners returns one
		// entry per runner-scoped permission (e.g. :heartbeat and :jobs), so dedupe
		// to distinct runner ids. A registration key (org-scoped runner:register) or
		// any non-runner token yields zero and is refused here.
		distinct := make(map[uuid.UUID]struct{})
		for _, id := range checker.GetScopedRunners() {
			distinct[id] = struct{}{}
		}
		if len(distinct) != 1 {
			c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{
				"status": "403", "title": "Forbidden",
				"detail": "this API key is not a runner token",
			}}})
			c.Abort()
			return
		}
		var runnerID uuid.UUID
		for id := range distinct {
			runnerID = id
		}

		runner, err := runnerRepo.GetByID(runnerID)
		if err != nil || runner == nil {
			// The runner the token names no longer exists — treat as unauthorized.
			logger.Debugf("RunnerAuth: token references unknown runner %s: %v", runnerID, err)
			c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{
				"status": "401", "title": "Unauthorized", "detail": "runner not found",
			}}})
			c.Abort()
			return
		}

		// Defence in depth: the runner's org must match the token's bound org.
		if apiKey.OrganizationID != nil && *apiKey.OrganizationID != runner.OrganizationID {
			c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{
				"status": "403", "title": "Forbidden", "detail": "runner/token organization mismatch",
			}}})
			c.Abort()
			return
		}

		c.Set(CallingRunnerKey, runner)
		c.Next()
	}
}
