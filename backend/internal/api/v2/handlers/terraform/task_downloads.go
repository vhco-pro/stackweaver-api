// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
)

// The two run-task download surfaces: the machine-readable plan JSON (webhook payload's
// plan_json_api_url — fixes the links.json-output URL the plan document has always advertised but
// never served) and the configuration archive (configuration_version_download_url — pre_plan
// services have no plan yet and scan source instead; also closes the standing TFE gap, go-tfe's
// ConfigurationVersions.Download).
//
// Both are registered on the ROOT router with a dual-auth chain: TaskTokenGate serves valid
// task-token requests directly (external services send `Authorization: Bearer <access_token>`),
// and everything else falls through to the normal AuthMiddleware + OrgResolutionWall before the
// same final handler runs with authorizeRun/workspace checks.

// taskTokenContextKey marks a request already authorized by a run-task access token.
const taskTokenContextKey = "task_token_result_id" //nolint:gosec // G101: a gin context key, not a credential

// TaskTokenGate returns a route-level middleware implementing the dual auth described above.
// match receives the verified token's (taskResultID, runID) and reports whether the token
// authorizes THIS request's resource; final is the serving handler.
func TaskTokenGate(match func(c *gin.Context, taskResultID, runID string) bool, final gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		tok := taskTokenFromAuthHeader(c.GetHeader("Authorization"))
		if tok == "" {
			c.Next() // not a task token: normal auth chain, then `final` as the last chain element
			return
		}
		trID, runID, ok := verifyTaskResultToken(tok)
		if !ok || !match(c, trID, runID) {
			// A PRESENTED task token that fails verification or scope is a hard 401; falling
			// through to Zitadel with it would only produce a confusing JWT parse error.
			taskError(c, http.StatusUnauthorized, "Unauthorized", "Invalid or expired run task access token")
			c.Abort()
			return
		}
		c.Set(taskTokenContextKey, trID)
		final(c)
		c.Abort()
	}
}

// taskTokenAuthorized reports whether the request already passed the task-token gate.
func taskTokenAuthorized(c *gin.Context) bool {
	_, ok := c.Get(taskTokenContextKey)
	return ok
}

// planJSONComputedKeys are Stackweaver-computed additions stored alongside the raw
// `terraform show -json` output in runs.plan_output; the json-output endpoint strips them so the
// body approximates the raw plan JSON that TFE serves.
var planJSONComputedKeys = map[string]bool{
	"AddCount": true, "ChangeCount": true, "DestroyCount": true, "OutputChangeCount": true,
}

// GetPlanJSONOutput handles GET /plans/:id/json-output (plan ID = run ID). TFE redirects to an
// archivist URL; we serve the JSON directly (a valid, documented variation — go-tfe follows either).
func (h *RunHandlerV2) GetPlanJSONOutput(c *gin.Context) {
	runID := c.Param("id")
	var run *models.Run
	if taskTokenAuthorized(c) {
		loaded, err := h.runRepo.GetByID(runID)
		if err != nil {
			taskError(c, http.StatusNotFound, "Not Found", "Plan not found")
			return
		}
		run = loaded
	} else {
		authed, ok := h.authorizeRun(c, runID, "read")
		if !ok {
			return
		}
		run = authed
	}

	if len(run.PlanOutput) == 0 {
		taskError(c, http.StatusNotFound, "Not Found", "No plan JSON output is available for this run yet")
		return
	}
	out := make(map[string]interface{}, len(run.PlanOutput))
	for k, v := range run.PlanOutput {
		if planJSONComputedKeys[k] {
			continue
		}
		out[k] = v
	}
	c.JSON(http.StatusOK, out)
}

// DownloadConfigurationVersion handles GET /configuration-versions/:id/download, streaming the
// config tar.gz (go-tfe ConfigurationVersions.Download).
func (h *ConfigurationVersionHandlerV2) DownloadConfigurationVersion(c *gin.Context) {
	cvID := c.Param("id")
	cv, err := h.configVersionRepo.GetByID(cvID)
	if err != nil {
		taskError(c, http.StatusNotFound, "Not Found", "Configuration version not found")
		return
	}

	if taskTokenAuthorized(c) {
		// The gate matched the token's run to this configuration version already (see routes.go).
	} else {
		user, uerr := h.authService.GetUserFromContext(c)
		if uerr != nil {
			taskError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
			return
		}
		ws, werr := h.workspaceRepo.GetByID(cv.WorkspaceID)
		if werr != nil {
			taskError(c, http.StatusNotFound, "Not Found", "Configuration version not found")
			return
		}
		allowed, perr := h.rbacService.CheckWorkspacePermission(c.Request.Context(), user.ID, ws.ID, rbac.PermissionWorkspaceRead, ws.ProjectID)
		if perr != nil || !allowed {
			if owner, oerr := h.rbacService.IsOrgOwner(c.Request.Context(), user.ID, ws.Project.OrganizationID); oerr != nil || !owner {
				taskError(c, http.StatusForbidden, "Forbidden", "You do not have permission to download this configuration version")
				return
			}
		}
	}

	if h.storageClient == nil {
		taskError(c, http.StatusServiceUnavailable, "Service Unavailable", "Object storage is not configured")
		return
	}
	storageKey := fmt.Sprintf("configuration-versions/%s/config.tar.gz", cv.ID)
	stream, err := h.storageClient.GetStream(c.Request.Context(), storageKey)
	if err != nil {
		taskError(c, http.StatusNotFound, "Not Found", "Configuration archive not found (was it uploaded?)")
		return
	}
	defer func() { _ = stream.Close() }()
	c.Header("Content-Type", "application/gzip")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", cv.ID+".tar.gz"))
	c.Status(http.StatusOK)
	_, _ = io.Copy(c.Writer, stream)
}
