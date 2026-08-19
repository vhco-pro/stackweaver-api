// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/repository"
)

// DashboardHandler serves `/dashboard/*`: the signed-in user's view across every organization they
// belong to.
//
// This is the only part of the API that is deliberately cross-organization. Everything under
// `/organizations/:name/...` answers "what is happening in this tenant"; the dashboard answers
// "which of my tenants needs me", which no per-organization endpoint can, because you would have to
// already know the answer to pick the organization to ask.
type DashboardHandler struct {
	orgRepo       *repository.OrganizationRepository
	dashboardRepo *repository.DashboardRepository
	authService   *auth.Service
	rbacService   *rbac.Service
}

func NewDashboardHandler(
	orgRepo *repository.OrganizationRepository,
	dashboardRepo *repository.DashboardRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *DashboardHandler {
	return &DashboardHandler{
		orgRepo:       orgRepo,
		dashboardRepo: dashboardRepo,
		authService:   authService,
		rbacService:   rbacService,
	}
}

const (
	// recentFailureWindow bounds the "failed recently" attention count. A failure from three weeks
	// ago is history; a workspace still sitting broken is reported separately and without a window.
	recentFailureWindow = 14 * 24 * time.Hour
	// liveExecutionLimit bounds the live-operations list. Past this many concurrent executions the
	// list has stopped being something a person reads.
	liveExecutionLimit = 25
)

// GetStats returns the cross-organization roll-up behind the dashboard.
// GET /api/v2/dashboard/stats
//
// Scope: the organizations are the caller's memberships, and every count within an organization is
// organization-wide. Runs and jobs used to be filtered to the requesting user while projects,
// workspaces and playbooks were not, so "active operations" meant *my* operations sitting beside a
// workspace count that meant everyone's. One organization, one population: what the team has.
func (h *DashboardHandler) GetStats(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		dashboardError(c, http.StatusUnauthorized, "Unauthorized", "User not authenticated")
		return
	}

	ctx := c.Request.Context()
	orgs, err := h.orgRepo.WithContext(ctx).ListByUser(user.ID)
	if err != nil {
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to load organizations")
		return
	}

	orgIDs := make([]uuid.UUID, 0, len(orgs))
	for _, org := range orgs {
		orgIDs = append(orgIDs, org.ID)
	}

	// First instant of the current month, in UTC. Every timestamp in the database is stored in UTC,
	// so deriving the boundary from the server's local zone moved "this month" by the server's
	// offset - an install running at UTC+2 counted from 22:00 on the last day of the previous month.
	now := time.Now().UTC()
	firstDayOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	repo := h.dashboardRepo.WithContext(ctx)
	summaries, err := repo.OrgSummaries(orgIDs, firstDayOfMonth, now.Add(-recentFailureWindow))
	if err != nil {
		// A partial roll-up would under-report exactly the thing the page exists to surface, so the
		// whole request fails loudly rather than rendering a plausible lie.
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to aggregate organization statistics")
		return
	}

	// The admin-only signals are resolved server-side, per organization, so the page never has to
	// ask for something it will be refused - and never renders a 403 as if it were "nothing to do".
	changeRequestOrgs := h.orgsWhere(ctx, user.ID, orgIDs, h.rbacService.CheckOrgManageWorkspaces)
	runnerOrgs := h.orgsWhere(ctx, user.ID, orgIDs, h.rbacService.CheckOrgManageAgentPools)

	openChangeRequests, err := repo.CountOpenChangeRequests(changeRequestOrgs)
	if err != nil {
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to count change requests")
		return
	}
	totalRunners, offlineRunners, err := repo.RunnerHealth(runnerOrgs)
	if err != nil {
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to count runners")
		return
	}

	var totals repository.OrgCounts
	orgStats := make([]gin.H, 0, len(orgs))
	for _, org := range orgs {
		counts := summaries[org.ID]
		if counts == nil {
			counts = &repository.OrgCounts{OrganizationID: org.ID}
		}
		addCounts(&totals, counts)

		entry := gin.H{
			"id":                                  org.ID.String(),
			"name":                                org.Name,
			"description":                         org.Description,
			"projects":                            counts.Projects,
			"terraform_workspaces":                counts.Workspaces,
			"ansible_playbooks":                   counts.Playbooks,
			"active_terraform_runs":               counts.ActiveRuns,
			"pending_terraform_runs":              counts.PendingRuns,
			"awaiting_approval":                   counts.AwaitingApproval,
			"pending_workflow_approvals":          counts.PendingWorkflowApprovals,
			"errored_workspaces":                  counts.ErroredWorkspaces,
			"errored_job_templates":               counts.ErroredJobTemplates,
			"failed_inventory_syncs":              counts.FailedInventorySyncs,
			"recent_run_failures":                 counts.RecentRunFailures,
			"recent_job_failures":                 counts.RecentJobFailures,
			"active_ansible_jobs":                 counts.ActiveJobs,
			"completed_terraform_runs_this_month": counts.SucceededRunsSince,
			"completed_ansible_jobs_this_month":   counts.SucceededJobsSince,
		}
		// Absent rather than zero where the caller cannot see it: a hard zero would read as "no
		// runners offline" to a member who simply is not allowed to know.
		if n, ok := openChangeRequests[org.ID]; ok {
			entry["open_change_requests"] = n
		} else if containsOrg(changeRequestOrgs, org.ID) {
			entry["open_change_requests"] = int64(0)
		}
		if containsOrg(runnerOrgs, org.ID) {
			entry["runners_total"] = totalRunners[org.ID]
			entry["runners_offline"] = offlineRunners[org.ID]
		}
		orgStats = append(orgStats, entry)
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"type": "dashboard-stats",
			"attributes": gin.H{
				"projects":                            totals.Projects,
				"terraform_workspaces":                totals.Workspaces,
				"ansible_playbooks":                   totals.Playbooks,
				"active_terraform_runs":               totals.ActiveRuns,
				"pending_terraform_runs":              totals.PendingRuns,
				"awaiting_approval":                   totals.AwaitingApproval,
				"pending_workflow_approvals":          totals.PendingWorkflowApprovals,
				"errored_workspaces":                  totals.ErroredWorkspaces,
				"errored_job_templates":               totals.ErroredJobTemplates,
				"failed_inventory_syncs":              totals.FailedInventorySyncs,
				"recent_run_failures":                 totals.RecentRunFailures,
				"recent_job_failures":                 totals.RecentJobFailures,
				"active_ansible_jobs":                 totals.ActiveJobs,
				"completed_terraform_runs_this_month": totals.SucceededRunsSince,
				"completed_ansible_jobs_this_month":   totals.SucceededJobsSince,
				"recent_failure_window_days":          int(recentFailureWindow / (24 * time.Hour)),
				"organizations":                       orgStats,
			},
		},
	})
}

// GetOperations returns the executions running right now across the caller's organizations.
// GET /api/v2/dashboard/operations
//
// Separate from GetStats because it is a list, not a roll-up, and because the dashboard polls it on
// a much shorter interval than it refreshes the counts.
func (h *DashboardHandler) GetOperations(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		dashboardError(c, http.StatusUnauthorized, "Unauthorized", "User not authenticated")
		return
	}

	ctx := c.Request.Context()
	orgs, err := h.orgRepo.WithContext(ctx).ListByUser(user.ID)
	if err != nil {
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to load organizations")
		return
	}
	orgIDs := make([]uuid.UUID, 0, len(orgs))
	for _, org := range orgs {
		orgIDs = append(orgIDs, org.ID)
	}

	executions, err := h.dashboardRepo.WithContext(ctx).LiveExecutions(orgIDs, liveExecutionLimit)
	if err != nil {
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to load live operations")
		return
	}

	formatted := make([]gin.H, 0, len(executions))
	for _, execution := range executions {
		formatted = append(formatted, gin.H{
			"id":                execution.ID,
			"platform":          execution.Platform,
			"organization_id":   execution.OrganizationID.String(),
			"organization_name": execution.OrganizationName,
			"name":              execution.Name,
			"detail":            execution.Detail,
			"status":            execution.Status,
			"started_at":        execution.StartedAt.UTC().Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"type": "dashboard-operations",
			"attributes": gin.H{
				"executions": formatted,
				// True when more work is in flight than the list returns, so the UI can say so
				// rather than implying the list is everything.
				"truncated": len(executions) == liveExecutionLimit,
			},
		},
	})
}

// orgsWhere returns the subset of orgIDs for which check grants the caller permission. A failing
// check excludes the organization rather than failing the request: one unreadable signal must not
// cost the reader the whole page.
func (h *DashboardHandler) orgsWhere(
	ctx context.Context,
	userID uuid.UUID,
	orgIDs []uuid.UUID,
	check func(ctx context.Context, userID, orgID uuid.UUID) (bool, error),
) []uuid.UUID {
	allowed := make([]uuid.UUID, 0, len(orgIDs))
	for _, orgID := range orgIDs {
		ok, err := check(ctx, userID, orgID)
		if err == nil && ok {
			allowed = append(allowed, orgID)
		}
	}
	return allowed
}

func containsOrg(orgIDs []uuid.UUID, id uuid.UUID) bool {
	for _, orgID := range orgIDs {
		if orgID == id {
			return true
		}
	}
	return false
}

func addCounts(into *repository.OrgCounts, from *repository.OrgCounts) {
	into.Projects += from.Projects
	into.Workspaces += from.Workspaces
	into.Playbooks += from.Playbooks
	into.ActiveRuns += from.ActiveRuns
	into.ActiveJobs += from.ActiveJobs
	into.PendingRuns += from.PendingRuns
	into.AwaitingApproval += from.AwaitingApproval
	into.PendingWorkflowApprovals += from.PendingWorkflowApprovals
	into.ErroredWorkspaces += from.ErroredWorkspaces
	into.ErroredJobTemplates += from.ErroredJobTemplates
	into.FailedInventorySyncs += from.FailedInventorySyncs
	into.RecentRunFailures += from.RecentRunFailures
	into.RecentJobFailures += from.RecentJobFailures
	into.SucceededRunsSince += from.SucceededRunsSince
	into.SucceededJobsSince += from.SucceededJobsSince
}

func dashboardError(c *gin.Context, status int, title, detail string) {
	c.JSON(status, gin.H{
		"errors": []gin.H{
			{"status": strconv.Itoa(status), "title": title, "detail": detail},
		},
	})
}
