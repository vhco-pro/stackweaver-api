// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

// CallingRunnerKey is the gin-context key under which RunnerAuth stores the
// authenticated *models.Runner. Handlers read it to bind every job-scoped
// operation to the runner that owns the job (AUD-001).
const CallingRunnerKey = "calling_runner"

// JobPrincipalKey is the gin-context key under which RunnerAuth stores the apikey.JobPrincipal of a
// job token (#933, D1). Its presence means the caller is an executor holding a token for one job;
// the handlers then authorize the request against that job alone.
const JobPrincipalKey = "job_principal"

// RunnerAuth authenticates a caller on the /runner/* control plane as a specific
// self-hosted runner and rejects everyone else.
//
// AUD-001: the runner job handlers previously trusted a runner_id supplied in the
// request body and were classified agnostic() in the org wall - so any authenticated
// principal (including plain JWT browser sessions) could pull another tenant's
// decrypted credentials/OIDC tokens, overwrite state, or forge job output. This
// middleware closes that by requiring an API-key identity whose scopes bind it to
// exactly one runner (minted at registration via apikey.CreateRunnerToken). The
// resolved runner is the ONLY identity the handlers trust; the body runner_id is
// no longer authoritative. JWT/browser identities are refused outright - they have
// no business on the runner control plane.
//
// The /runner/register route is exempt (a runner has no identity yet): it stays on
// the org-scoped runner:register key path.
//
// A customer launcher token minted at registration carries the launcher's pool as its
// AgentPoolID (apikey.CreateRunnerToken), which says registration checked the credential for
// agent pool permission. A token without that mark was issued before the check, so it stands only
// while its owner, the user whose key registered the launcher, may still manage the
// organization's agent pools. permissions answers that; with none, such tokens are refused.
func RunnerAuth(runnerRepo *repository.RunnerRepository, permissions AgentPoolPermission) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only API-key identities may act as runners. Block JWT/browser sessions.
		if method, _ := c.Get("auth_method"); method != "api_key" {
			jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "the launcher control plane requires a launcher API key")
			c.Abort()
			return
		}

		raw, exists := c.Get("api_key")
		apiKey, ok := raw.(*models.APIKey)
		if !exists || !ok || apiKey == nil {
			jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "missing API key")
			c.Abort()
			return
		}

		// A job token names its job, its runner and its attempt. It stands for that runner on the
		// job-data routes only, and the handlers bind every request to the job it names.
		if apiKey.Kind == models.APIKeyKindJob {
			principal, ok := apikey.ParseJobPrincipal(apiKey.Scopes)
			if !ok {
				jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "invalid job token")
				c.Abort()
				return
			}
			runner, err := runnerRepo.GetByID(principal.RunnerID)
			if err != nil || runner == nil {
				jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "launcher not found")
				c.Abort()
				return
			}
			// A job token is bound to its job's organization. A customer runner serves its own
			// organization only; a hosted runner serves every organization's hosted pool, and the
			// handlers hold the token to its job's organization (#933, D9).
			if apiKey.OrganizationID == nil || (!runner.IsHosted() && (runner.OrganizationID == nil || *apiKey.OrganizationID != *runner.OrganizationID)) {
				jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "launcher and token organizations do not match")
				c.Abort()
				return
			}
			// Every job-data route names its job in the path; a job token is refused on any other
			// job before a handler reads anything.
			if id := c.Param("id"); id != "" && id != principal.JobID {
				jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "this job token is for a different job")
				c.Abort()
				return
			}
			c.Set(CallingRunnerKey, runner)
			c.Set(JobPrincipalKey, principal)
			c.Next()
			return
		}

		checker, err := apikey.NewScopeChecker(apiKey.Scopes)
		if err != nil {
			jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "invalid API key scopes")
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
		if len(distinct) != 1 || !onlyRunnerScopes(apiKey.Scopes) {
			jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "this API key is not a launcher token")
			c.Abort()
			return
		}
		var runnerID uuid.UUID
		for id := range distinct {
			runnerID = id
		}

		runner, err := runnerRepo.GetByID(runnerID)
		if err != nil || runner == nil {
			// The runner the token names no longer exists - treat as unauthorized.
			logger.Debugf("RunnerAuth: token references unknown runner %s: %v", runnerID, err)
			jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "launcher not found")
			c.Abort()
			return
		}

		// Defence in depth: a customer runner's token is an organization key bound to the runner's
		// organization; a hosted runner's is an ownerless hosted key bound to none (#933, D9). Any
		// other pairing, a NULL on one side with the other kind included, is refused.
		if !runnerTokenMatches(apiKey, runner) {
			jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "launcher and token organizations do not match")
			c.Abort()
			return
		}
		if !runner.IsHosted() && apiKey.AgentPoolID == nil {
			if status, detail := unmarkedTokenVerdict(c, permissions, apiKey, runner); status != 0 {
				jsonapi.WriteError(c, status, http.StatusText(status), detail)
				c.Abort()
				return
			}
		}

		c.Set(CallingRunnerKey, runner)
		c.Next()
	}
}

// runnerTokenMatches reports whether a runner token's kind and organization fit its runner.
// AgentPoolPermission answers whether a user may manage an organization's agent pools
// (rbac.Service.CheckOrgManageAgentPools).
type AgentPoolPermission interface {
	CheckOrgManageAgentPools(ctx context.Context, userID, organizationID uuid.UUID) (bool, error)
}

// unmarkedTokenVerdict holds a launcher token issued before registration checked agent pool
// permission to its owner's current permission. It answers 0 when the token may act, or the
// status and detail to refuse with.
func unmarkedTokenVerdict(c *gin.Context, permissions AgentPoolPermission, key *models.APIKey, runner *models.Runner) (int, string) {
	const refused = "this launcher token was issued before launcher registration required permission to manage agent pools, and its owner does not have it; restart the launcher to register it again"
	if permissions == nil || key.UserID == nil || runner.OrganizationID == nil {
		return http.StatusForbidden, refused
	}
	may, err := permissions.CheckOrgManageAgentPools(c.Request.Context(), *key.UserID, *runner.OrganizationID)
	if err != nil {
		return http.StatusInternalServerError, "the launcher token owner's agent pool permission could not be read"
	}
	if !may {
		return http.StatusForbidden, refused
	}
	return 0, ""
}

// onlyRunnerScopes reports whether every scope is a runner scope. CreateRunnerToken mints launcher
// tokens with runner scopes alone, while a key created on request must bind an organization with
// an org, project or team scope; so a key that mixes the two was not issued at registration and
// does not stand for the launcher it names.
func onlyRunnerScopes(scopes models.StringArray) bool {
	for _, raw := range scopes {
		if typ, _, _ := strings.Cut(raw, ":"); typ != "runner" {
			return false
		}
	}
	return len(scopes) > 0
}

func runnerTokenMatches(key *models.APIKey, runner *models.Runner) bool {
	if runner.IsHosted() {
		return key.Kind == models.APIKeyKindHosted && key.OrganizationID == nil && runner.OrganizationID == nil
	}
	return key.Kind != models.APIKeyKindHosted && key.OrganizationID != nil && runner.OrganizationID != nil &&
		*key.OrganizationID == *runner.OrganizationID
}

// RequireRunnerToken refuses a job token on the routes only a runner token may use: heartbeat,
// claim, job-token minting, drain and deregistration. A job token reaches one job's data and
// nothing that acts for the runner.
func RequireRunnerToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, isJob := c.Get(JobPrincipalKey); isJob {
			jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "a job token may not use this endpoint")
			c.Abort()
			return
		}
		c.Next()
	}
}

// JobData guards a route that hands out or accepts one job's data: its artifacts, its playbook
// snapshot, its state, its plan, its completion (#933, D1, AC3). A runner that declared the
// job-token capability at registration reaches them only through the job token its executor holds,
// so a stolen runner token reads no job's credentials. A runner that did not declare it, an agent
// built before the job token, keeps its runner token on these routes for the deprecation window
// (D14).
func JobData() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, isJob := c.Get(JobPrincipalKey); isJob {
			c.Next()
			return
		}
		v, _ := c.Get(CallingRunnerKey)
		if runner, ok := v.(*models.Runner); ok && runner.HasCapability(runnercontract.CapabilityJobToken) {
			jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "this launcher reaches job data with a job token")
			c.Abort()
			return
		}
		c.Next()
	}
}
