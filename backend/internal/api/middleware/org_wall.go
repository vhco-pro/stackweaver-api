// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
)

// OrgResolver resolves the target organization of a request from its URL
// parameters. Each method takes the raw path-parameter string (the wall
// does not know whether a given id is a uuid or a prefixed string id) and
// returns the owning organization's uuid, or an error if the resource does
// not exist. UserInOrg answers the membership question for user-bound
// tokens and JWT identities.
//
// The interface is intentionally one-method-per-resource so it can be faked
// in unit tests without a database — see org_wall_test.go.
type OrgResolver interface {
	ByOrgName(name string) (uuid.UUID, error)
	ByOrgMembershipID(id string) (uuid.UUID, error)
	ByProjectID(id string) (uuid.UUID, error)
	ByWorkspaceID(id string) (uuid.UUID, error)
	ByRunID(id string) (uuid.UUID, error)
	ByRunTriggerID(id string) (uuid.UUID, error)
	ByConfigVersionID(id string) (uuid.UUID, error)
	ByStateVersionID(id string) (uuid.UUID, error)
	ByVariableID(id string) (uuid.UUID, error)
	ByVariableSetID(id string) (uuid.UUID, error)
	ByVariableSetVariableID(id string) (uuid.UUID, error)
	ByTeamID(id string) (uuid.UUID, error)
	ByTeamWorkspaceAccessID(id string) (uuid.UUID, error)
	ByTeamProjectAccessID(id string) (uuid.UUID, error)
	ByAgentPoolID(id string) (uuid.UUID, error)
	ByRunnerID(id string) (uuid.UUID, error)
	ByVCSConnectionID(id string) (uuid.UUID, error)
	ByOIDCConfigID(id string) (uuid.UUID, error)
	ByGPGKeyID(id string) (uuid.UUID, error)
	ByRegistryProviderID(id string) (uuid.UUID, error)
	ByAnsibleInventoryID(id string) (uuid.UUID, error)
	ByAnsibleHostID(id string) (uuid.UUID, error)
	ByAnsibleGroupID(id string) (uuid.UUID, error)
	ByAnsibleInventorySourceID(id string) (uuid.UUID, error)
	ByAnsibleCredentialID(id string) (uuid.UUID, error)
	ByAnsiblePlaybookID(id string) (uuid.UUID, error)
	ByAnsibleJobTemplateID(id string) (uuid.UUID, error)
	ByAnsibleJobTemplateVariableID(id string) (uuid.UUID, error)
	ByAnsibleJobID(id string) (uuid.UUID, error)
	ByAnsibleScheduleID(id string) (uuid.UUID, error)
	ByAnsibleWorkflowID(id string) (uuid.UUID, error)
	ByAnsibleWorkflowNodeID(id string) (uuid.UUID, error)
	ByAnsibleWorkflowEdgeID(id string) (uuid.UUID, error)

	// UserInOrg reports whether the user is a member of the org (directly
	// or via a team). It is the membership boundary user-bound tokens and
	// JWT identities are held to.
	UserInOrg(userID, orgID uuid.UUID) (bool, error)
}

// resolverFunc resolves the target org from a single path parameter value.
type resolverFunc func(r OrgResolver, paramValue string) (uuid.UUID, error)

// routeEntry classifies one gin route (keyed by its c.FullPath() pattern)
// for the org-resolution wall.
type routeEntry struct {
	// agnostic routes carry no single target org (own-token routes, global
	// reads, runner-agent control plane). They are explicitly whitelisted
	// to pass the wall; they are NOT a fail-closed default.
	agnostic bool
	// orgNameParam, when set, resolves the org by name from this path param.
	orgNameParam string
	// param + resolve resolve a RESOURCE_ID route: load the resource named
	// by `param` and chain to its org.
	param   string
	resolve resolverFunc
}

// OrgResolutionWall enforces tenant isolation for programmatic (api-key)
// tokens. It runs after AuthMiddleware on the /api/v2 group.
//
// For every api-key request it resolves the request's target organization
// (org-by-name for org-in-URL routes, or a resource load for resource-id
// routes) and authorizes it against the token's kind:
//
//   - org-bound token  → the target org MUST equal the token's bound org.
//   - user-bound token → the user MUST be a member of the target org.
//
// Routes are matched against a fail-closed registry: any api-key request to
// a route that is not classified is denied, so a newly added route cannot
// silently bypass the wall. JWT / session identities (no token_kind in
// context) pass straight through — the wall never widens or narrows their
// access; existing per-handler authorization continues to apply to them.
func OrgResolutionWall(resolver OrgResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		kindVal, isToken := c.Get("token_kind")
		if !isToken {
			// Not an api-key request (JWT, session, query-token, or
			// unauthenticated log-read). Out of scope for the token wall.
			c.Next()
			return
		}
		kind, _ := kindVal.(string)

		fullPath := c.FullPath()
		entry, classified := wallRegistry[fullPath]
		if !classified {
			// Fail-closed: an api-key token may not reach a route that has
			// not been explicitly classified.
			logger.Warnf("org-wall: denying api-key access to unclassified route %s %s", c.Request.Method, fullPath)
			denyWall(c, http.StatusForbidden, "this token may not access this endpoint")
			return
		}

		if entry.agnostic {
			c.Next()
			return
		}

		var targetOrg uuid.UUID
		var err error
		if entry.orgNameParam != "" {
			targetOrg, err = resolver.ByOrgName(c.Param(entry.orgNameParam))
		} else {
			targetOrg, err = entry.resolve(resolver, c.Param(entry.param))
		}
		if err != nil {
			// Resource (or org) does not exist. Return 404 rather than 403
			// so the wall does not disclose the existence of resources in
			// other tenants.
			denyWall(c, http.StatusNotFound, "resource not found")
			return
		}

		switch kind {
		case models.APIKeyKindOrg:
			boundVal, ok := c.Get("token_org_id")
			boundOrg, _ := boundVal.(uuid.UUID)
			if !ok || boundOrg != targetOrg {
				logger.Warnf("org-wall: org-bound token (org %s) blocked from org %s on %s", boundOrg, targetOrg, fullPath)
				denyWall(c, http.StatusForbidden, "this token is scoped to a different organization")
				return
			}
			// Token-side scope enforcement: a read-only token may not perform
			// a mutating request even within its own org. Only enforced when
			// the token carries an org-level scope; project/team-scoped tokens
			// are deferred to per-handler checks (the wall cannot match the
			// resource to the scoped project/team here).
			if !scopeAllowsMethod(c, targetOrg) {
				logger.Warnf("org-wall: org-bound token scope denies %s on %s (org %s)", c.Request.Method, fullPath, targetOrg)
				denyWall(c, http.StatusForbidden, "this token's scope does not permit this action")
				return
			}
		case models.APIKeyKindUser:
			userVal, ok := c.Get("user_id")
			userID, _ := userVal.(uuid.UUID)
			if !ok {
				denyWall(c, http.StatusForbidden, "token is not associated with a user")
				return
			}
			member, memberErr := resolver.UserInOrg(userID, targetOrg)
			if memberErr != nil || !member {
				logger.Warnf("org-wall: user-bound token (user %s) blocked from org %s on %s", userID, targetOrg, fullPath)
				denyWall(c, http.StatusForbidden, "you are not a member of this organization")
				return
			}
		default:
			denyWall(c, http.StatusForbidden, "unrecognized token kind")
			return
		}

		// Cache the resolved org for downstream handlers.
		c.Set("resolved_org_id", targetOrg)
		c.Next()
	}
}

// scopeAllowsMethod reports whether the org-bound token in context may perform
// the current request's HTTP method within targetOrg (the token has already been
// confirmed bound to targetOrg by the caller). It enforces the token's coarse
// scope level and, per AUD-042, fails closed for mutating methods when it cannot
// affirmatively authorize the request:
//
//   - malformed/unparseable scopes → deny mutations (allow reads);
//   - unrestricted (empty or wildcard) scopes → allow (backward compatible);
//   - an org-level scope for targetOrg → honor it (read < write < admin);
//   - no org-level scope but a project/team scope → defer to per-handler
//     authorization (the wall cannot match the resource to the scoped
//     project/team here);
//   - no org-level and no project/team scope → deny mutations (allow reads),
//     rather than defer to a handler that may not check.
func scopeAllowsMethod(c *gin.Context, targetOrg uuid.UUID) bool {
	required := apikey.CoarseLevelForMethod(c.Request.Method)
	mutating := required != "read"

	apiKeyVal, ok := c.Get("api_key")
	if !ok {
		return true
	}
	apiKey, ok := apiKeyVal.(*models.APIKey)
	if !ok {
		return true
	}
	checker, err := apikey.NewScopeChecker([]string(apiKey.Scopes))
	if err != nil {
		// Malformed scopes cannot authorize a mutating request.
		return !mutating
	}
	// Empty or wildcard scopes are unrestricted by design (backward compatible).
	if checker.IsUnrestricted() {
		return true
	}
	granted, hasOrgScope := checker.GrantsOrgLevel(targetOrg, required)
	if hasOrgScope {
		return granted
	}
	// No org-level scope for targetOrg. Project/team-scoped tokens are deferred to
	// per-handler authorization; a token with neither has no basis to mutate here.
	if len(checker.GetScopedProjects()) > 0 || len(checker.GetScopedTeams()) > 0 {
		return true
	}
	return !mutating
}

func denyWall(c *gin.Context, status int, detail string) {
	c.JSON(status, gin.H{
		"errors": []gin.H{
			{
				"status": strconv.Itoa(status),
				"title":  http.StatusText(status),
				"detail": detail,
			},
		},
	})
	c.Abort()
}
