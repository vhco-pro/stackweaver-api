// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
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
	workspaceRepo *repository.WorkspaceRepository
	projectRepo   *repository.ProjectRepository
}

func NewDashboardHandler(
	orgRepo *repository.OrganizationRepository,
	dashboardRepo *repository.DashboardRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	workspaceRepo *repository.WorkspaceRepository,
	projectRepo *repository.ProjectRepository,
) *DashboardHandler {
	return &DashboardHandler{
		orgRepo:       orgRepo,
		dashboardRepo: dashboardRepo,
		authService:   authService,
		rbacService:   rbacService,
		workspaceRepo: workspaceRepo,
		projectRepo:   projectRepo,
	}
}

// visibleOrgs returns the organizations the caller may see on the dashboard. A user sees every
// organization they belong to. A token sees less: an organization token only the organization it
// is bound to, and a team or project token only its subject's organization (rbac.UserInOrg), so
// the cross-organization roll-up never lends a token its owner's other memberships.
func (h *DashboardHandler) visibleOrgs(c *gin.Context, userID uuid.UUID) ([]models.Organization, error) {
	ctx := c.Request.Context()
	orgs, err := h.orgRepo.WithContext(ctx).ListByUser(userID)
	if err != nil {
		return nil, err
	}
	kind, _ := c.Get("token_kind")
	bound, isBound := c.Get("token_org_id")
	visible := make([]models.Organization, 0, len(orgs))
	for _, org := range orgs {
		if kind == models.APIKeyKindOrg && (!isBound || bound != org.ID) {
			continue
		}
		in, err := rbac.UserInOrg(ctx, h.orgRepo, userID, org.ID)
		if err != nil {
			return nil, err
		}
		if in {
			visible = append(visible, org)
		}
	}
	return visible, nil
}

// readScope returns what the caller can read in orgs, as the dashboard counts it. Every caller, a
// user or a team or project token, is judged by the rule a single read is: a caller whose
// organization-level permissions read the whole of every organization gets a nil scope, whose
// roll-up is organization-wide; anyone else gets the workspaces, projects and Ansible resources it
// can read in each.
func (h *DashboardHandler) readScope(c *gin.Context, userID uuid.UUID, orgs []models.Organization) (scope *repository.DashboardScope, err error) {
	ctx := c.Request.Context()
	orgIDs := make([]uuid.UUID, 0, len(orgs))
	for _, org := range orgs {
		orgIDs = append(orgIDs, org.ID)
	}
	perms, err := h.rbacService.OrgPermissionsForOrganizations(ctx, userID, orgIDs)
	if err != nil {
		return nil, err
	}
	whole := true
	for _, org := range orgs {
		whole = whole && rbac.ReadsWholeOrganization(perms[org.ID])
	}
	if whole {
		return scope, nil
	}
	scope = &repository.DashboardScope{}
	for _, org := range orgs {
		workspaces, _, err := h.workspaceRepo.WithContext(ctx).ListByOrganization(org.Name, -1, 0)
		if err != nil {
			return nil, err
		}
		projects, _, err := h.projectRepo.WithContext(ctx).ListByOrganization(org.ID, 10000, 0)
		if err != nil {
			return nil, err
		}
		if err := h.rbacService.AddDashboardScope(ctx, userID, org.ID, workspaces, projects, scope); err != nil {
			return nil, err
		}
	}
	return scope, nil
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
// of what the caller can read there, the same population its listings hold: the whole organization
// for an owner or a member who may view all of it. Runs and jobs used to be filtered to the
// requesting user while projects, workspaces and playbooks were not, so "active operations" meant
// *my* operations sitting beside a workspace count that meant everyone's.
func (h *DashboardHandler) GetStats(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		dashboardError(c, http.StatusUnauthorized, "Unauthorized", "User not authenticated")
		return
	}

	ctx := c.Request.Context()
	orgs, err := h.visibleOrgs(c, user.ID)
	if err != nil {
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to load organizations")
		return
	}
	scope, err := h.readScope(c, user.ID, orgs)
	if err != nil {
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to resolve permissions")
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
	summaries, err := repo.OrgSummariesScoped(orgIDs, firstDayOfMonth, now.Add(-recentFailureWindow), scope)
	if err != nil {
		// A partial roll-up would under-report exactly the thing the page exists to surface, so the
		// whole request fails loudly rather than rendering a plausible lie.
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to aggregate organization statistics")
		return
	}

	// The admin-only signals are resolved server-side, per organization, so the page never has to
	// ask for something it will be refused - and never renders a 403 as if it were "nothing to do".
	// Resolved in one query for every organization at once: the per-organization Check* helpers each
	// cost a membership lookup plus a team fetch, so two permissions across a dozen memberships was
	// ~48 queries on a page whose whole point is spanning organizations.
	permissions, err := h.rbacService.OrgPermissionsForOrganizations(ctx, user.ID, orgIDs)
	if err != nil {
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to resolve permissions")
		return
	}
	changeRequestOrgs := orgsWithPermission(orgIDs, permissions, rbac.PermissionOrgManageWorkspaces)
	runnerOrgs := orgsWithPermission(orgIDs, permissions, rbac.PermissionOrgManageAgentPools)

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
	orgStats := make([]DashboardOrgCounts, 0, len(orgs))
	for _, org := range orgs {
		counts := summaries[org.ID]
		if counts == nil {
			counts = &repository.OrgCounts{OrganizationID: org.ID}
		}
		addCounts(&totals, counts)

		entry := DashboardOrgCounts{
			ID:                              org.ID.String(),
			Name:                            org.Name,
			Description:                     org.Description,
			Projects:                        counts.Projects,
			TerraformWorkspaces:             counts.Workspaces,
			AnsiblePlaybooks:                counts.Playbooks,
			ActiveTerraformRuns:             counts.ActiveRuns,
			PendingTerraformRuns:            counts.PendingRuns,
			AwaitingApproval:                counts.AwaitingApproval,
			PendingWorkflowApprovals:        counts.PendingWorkflowApprovals,
			ErroredWorkspaces:               counts.ErroredWorkspaces,
			ErroredJobTemplates:             counts.ErroredJobTemplates,
			FailedInventorySyncs:            counts.FailedInventorySyncs,
			RecentRunFailures:               counts.RecentRunFailures,
			RecentJobFailures:               counts.RecentJobFailures,
			ActiveAnsibleJobs:               counts.ActiveJobs,
			CompletedTerraformRunsThisMonth: counts.SucceededRunsSince,
			CompletedAnsibleJobsThisMonth:   counts.SucceededJobsSince,
		}
		// Absent rather than zero where the caller cannot see it: a hard zero would read as "no
		// runners offline" to a member who simply is not allowed to know.
		if n, ok := openChangeRequests[org.ID]; ok {
			entry.OpenChangeRequests = &n
		} else if containsOrg(changeRequestOrgs, org.ID) {
			zero := int64(0)
			entry.OpenChangeRequests = &zero
		}
		if containsOrg(runnerOrgs, org.ID) {
			total := totalRunners[org.ID]
			offline := offlineRunners[org.ID]
			entry.RunnersTotal = &total
			entry.RunnersOffline = &offline
		}
		orgStats = append(orgStats, entry)
	}

	jsonapi.WriteDocument(c, http.StatusOK, DashboardStatsDocument{
		Type: "dashboard-stats",
		Attributes: DashboardStatsAttributes{
			Projects:                        totals.Projects,
			TerraformWorkspaces:             totals.Workspaces,
			AnsiblePlaybooks:                totals.Playbooks,
			ActiveTerraformRuns:             totals.ActiveRuns,
			PendingTerraformRuns:            totals.PendingRuns,
			AwaitingApproval:                totals.AwaitingApproval,
			PendingWorkflowApprovals:        totals.PendingWorkflowApprovals,
			ErroredWorkspaces:               totals.ErroredWorkspaces,
			ErroredJobTemplates:             totals.ErroredJobTemplates,
			FailedInventorySyncs:            totals.FailedInventorySyncs,
			RecentRunFailures:               totals.RecentRunFailures,
			RecentJobFailures:               totals.RecentJobFailures,
			ActiveAnsibleJobs:               totals.ActiveJobs,
			CompletedTerraformRunsThisMonth: totals.SucceededRunsSince,
			CompletedAnsibleJobsThisMonth:   totals.SucceededJobsSince,
			RecentFailureWindowDays:         int(recentFailureWindow / (24 * time.Hour)),
			Organizations:                   orgStats,
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
	orgs, err := h.visibleOrgs(c, user.ID)
	if err != nil {
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to load organizations")
		return
	}
	scope, err := h.readScope(c, user.ID, orgs)
	if err != nil {
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to resolve permissions")
		return
	}
	orgIDs := make([]uuid.UUID, 0, len(orgs))
	for _, org := range orgs {
		orgIDs = append(orgIDs, org.ID)
	}

	executions, err := h.dashboardRepo.WithContext(ctx).LiveExecutionsScoped(orgIDs, liveExecutionLimit, scope)
	if err != nil {
		dashboardError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to load live operations")
		return
	}

	formatted := make([]DashboardExecution, 0, len(executions))
	for _, execution := range executions {
		formatted = append(formatted, DashboardExecution{
			ID:               execution.ID,
			Platform:         execution.Platform,
			OrganizationID:   execution.OrganizationID.String(),
			OrganizationName: execution.OrganizationName,
			Name:             execution.Name,
			Detail:           execution.Detail,
			Status:           execution.Status,
			StartedAt:        execution.StartedAt.UTC().Format(time.RFC3339),
		})
	}

	jsonapi.WriteDocument(c, http.StatusOK, DashboardOperationsDocument{
		Type: "dashboard-operations",
		Attributes: DashboardOperationsAttributes{
			Executions: formatted,
			Truncated:  len(executions) == liveExecutionLimit,
		},
	})
}

// orgsWithPermission returns the subset of orgIDs where the caller holds the given permission.
func orgsWithPermission(
	orgIDs []uuid.UUID,
	permissions map[uuid.UUID]map[rbac.Permission]bool,
	permission rbac.Permission,
) []uuid.UUID {
	allowed := make([]uuid.UUID, 0, len(orgIDs))
	for _, orgID := range orgIDs {
		if permissions[orgID][permission] {
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
	jsonapi.WriteError(c, status, title, detail)
}
