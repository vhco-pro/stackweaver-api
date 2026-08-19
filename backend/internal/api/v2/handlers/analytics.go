// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/repository"
)

// AnalyticsHandler serves the aggregated Usage & Analytics payload for one organization.
//
// The page it backs used to assemble itself client-side: list every org, then every workspace, then
// every workspace's runs, then four Ansible list calls per org, and sum the result in the browser.
// That is one HTTP request per workspace on every page view and every filter change. This handler
// replaces the whole cascade with a single response computed from indexed aggregates.
type AnalyticsHandler struct {
	orgRepo             *repository.OrganizationRepository
	projectRepo         *repository.ProjectRepository
	workspaceRepo       *repository.WorkspaceRepository
	runRepo             *repository.RunRepository
	ansibleJobRepo      *repository.AnsibleJobRepository
	ansiblePlaybookRepo *repository.AnsiblePlaybookRepository
	ansibleTemplateRepo *repository.AnsibleJobTemplateRepository
	inventoryRepo       *repository.AnsibleInventoryRepository
	auditLogRepo        *repository.AuditLogRepository
	authService         *auth.Service
}

func NewAnalyticsHandler(
	orgRepo *repository.OrganizationRepository,
	projectRepo *repository.ProjectRepository,
	workspaceRepo *repository.WorkspaceRepository,
	runRepo *repository.RunRepository,
	ansibleJobRepo *repository.AnsibleJobRepository,
	ansiblePlaybookRepo *repository.AnsiblePlaybookRepository,
	ansibleTemplateRepo *repository.AnsibleJobTemplateRepository,
	inventoryRepo *repository.AnsibleInventoryRepository,
	auditLogRepo *repository.AuditLogRepository,
	authService *auth.Service,
) *AnalyticsHandler {
	return &AnalyticsHandler{
		orgRepo:             orgRepo,
		projectRepo:         projectRepo,
		workspaceRepo:       workspaceRepo,
		runRepo:             runRepo,
		ansibleJobRepo:      ansibleJobRepo,
		ansiblePlaybookRepo: ansiblePlaybookRepo,
		ansibleTemplateRepo: ansibleTemplateRepo,
		inventoryRepo:       inventoryRepo,
		auditLogRepo:        auditLogRepo,
		authService:         authService,
	}
}

const (
	// maxAnalyticsWindowDays caps how far back a single request may aggregate. The UI offers at most
	// 90 days; the cap exists so a hand-crafted `since` cannot turn one request into a full-table
	// scan of every run the install has ever recorded.
	maxAnalyticsWindowDays = 400
	// analyticsTopLimit bounds the "busiest" tables and the recent-failure list.
	analyticsTopLimit     = 10
	analyticsFailureLimit = 6
	// executionsPageLimit bounds the per-bar drill-down. A day with more executions than this is
	// reported as truncated rather than silently cut, so the list never implies it is complete.
	executionsPageLimit = 100
)

// GetOrganizationAnalytics returns every metric the Usage & Analytics page renders.
// GET /api/v2/organizations/:name/analytics?since=<RFC3339>&until=<RFC3339>
func (h *AnalyticsHandler) GetOrganizationAnalytics(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		analyticsError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		analyticsError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	// AUD-139: JWT/browser identities bypass the org-resolution wall, so membership must be checked
	// here too - the wall alone only covers api-key callers.
	inOrg, err := h.orgRepo.UserInOrg(user.ID, org.ID)
	if err != nil || !inOrg {
		analyticsError(c, http.StatusForbidden, "Forbidden", "You must be a member of this organization")
		return
	}

	window, prev, err := parseAnalyticsWindow(c)
	if err != nil {
		analyticsError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	// AUD-047: scope every aggregate to the request context so navigating away cancels the queries at
	// Postgres instead of running the whole set to completion.
	ctx := c.Request.Context()
	runRepo := h.runRepo.WithContext(ctx)
	jobRepo := h.ansibleJobRepo.WithContext(ctx)
	auditRepo := h.auditLogRepo.WithContext(ctx)

	// fail is the shared error exit: any aggregate failing means the page would silently render an
	// under-counted number, so the whole request fails loudly instead of rendering a plausible lie.
	fail := func(detail string, err error) bool {
		if err == nil {
			return false
		}
		analyticsError(c, http.StatusInternalServerError, "Internal Server Error", detail)
		return true
	}

	runTotals, err := runRepo.RunTotalsByOrganization(org.ID, window)
	if fail("Failed to aggregate run totals", err) {
		return
	}
	runTotalsPrev, err := runRepo.RunTotalsByOrganization(org.ID, prev)
	if fail("Failed to aggregate previous-period run totals", err) {
		return
	}
	runDurations, err := runRepo.RunDurationsByOrganization(org.ID, window)
	if fail("Failed to aggregate run durations", err) {
		return
	}
	runDurationsPrev, err := runRepo.RunDurationsByOrganization(org.ID, prev)
	if fail("Failed to aggregate previous-period run durations", err) {
		return
	}
	runDaily, err := runRepo.RunDailyByOrganization(org.ID, window)
	if fail("Failed to aggregate daily runs", err) {
		return
	}
	topWorkspaces, err := runRepo.TopWorkspacesByOrganization(org.ID, window, analyticsTopLimit)
	if fail("Failed to aggregate top workspaces", err) {
		return
	}
	runFailures, err := runRepo.RecentRunFailuresByOrganization(org.ID, window, analyticsFailureLimit)
	if fail("Failed to load recent run failures", err) {
		return
	}

	jobTotals, err := jobRepo.JobTotalsByOrganization(org.ID, window)
	if fail("Failed to aggregate job totals", err) {
		return
	}
	jobTotalsPrev, err := jobRepo.JobTotalsByOrganization(org.ID, prev)
	if fail("Failed to aggregate previous-period job totals", err) {
		return
	}
	jobDurations, err := jobRepo.JobDurationsByOrganization(org.ID, window)
	if fail("Failed to aggregate job durations", err) {
		return
	}
	jobDaily, err := jobRepo.JobDailyByOrganization(org.ID, window)
	if fail("Failed to aggregate daily jobs", err) {
		return
	}
	topTemplates, err := jobRepo.TopTemplatesByOrganization(org.ID, window, analyticsTopLimit)
	if fail("Failed to aggregate top templates", err) {
		return
	}
	jobFailures, err := jobRepo.RecentJobFailuresByOrganization(org.ID, window, analyticsFailureLimit)
	if fail("Failed to load recent job failures", err) {
		return
	}

	activityTotal, err := auditRepo.ActivityTotalByOrganization(org.ID, window)
	if fail("Failed to count activity", err) {
		return
	}
	activityByAction, err := auditRepo.ActivityByColumnForOrganization(org.ID, window, "action", analyticsTopLimit)
	if fail("Failed to aggregate activity by action", err) {
		return
	}
	activityByResource, err := auditRepo.ActivityByColumnForOrganization(org.ID, window, "resource_type", analyticsTopLimit)
	if fail("Failed to aggregate activity by resource type", err) {
		return
	}
	activityDaily, err := auditRepo.ActivityDailyByOrganization(org.ID, window)
	if fail("Failed to aggregate daily activity", err) {
		return
	}

	resources, err := h.organizationResources(ctx, org.ID)
	if fail("Failed to count organization resources", err) {
		return
	}

	// Deliberately unbounded by the selected window: this is the one live figure on an otherwise
	// historical page, and a run started before the window that is still applying is exactly the
	// thing an operator wants to see.
	runningRuns, err := runRepo.RunningNowByOrganization(org.ID)
	if fail("Failed to count running runs", err) {
		return
	}
	runningJobs, err := jobRepo.RunningNowByOrganization(org.ID)
	if fail("Failed to count running jobs", err) {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"type": "analytics",
			"id":   org.Name,
			"attributes": gin.H{
				"window": gin.H{
					"since": window.Since.UTC().Format(time.RFC3339),
					"until": window.Until.UTC().Format(time.RFC3339),
					"days":  int(window.Until.Sub(window.Since).Hours()/24 + 0.5),
				},
				"runs":            outcomePayload(runTotals, runDurations, runTotalsPrev, runDurationsPrev),
				"ansible_jobs":    outcomePayload(jobTotals, jobDurations, jobTotalsPrev, DurationStatsZero),
				"daily":           dailyPayload(runDaily, jobDaily, activityDaily, window),
				"top_workspaces":  topWorkspacePayload(topWorkspaces),
				"top_templates":   topTemplatePayload(topTemplates),
				"activity":        activityPayload(activityTotal, activityByAction, activityByResource),
				"resources":       resources,
				"recent_failures": failurePayload(runFailures, jobFailures, analyticsFailureLimit),
				"running_now": gin.H{
					"runs":  runningRuns,
					"jobs":  runningJobs,
					"total": runningRuns + runningJobs,
				},
			},
		},
	})
}

// GetOrganizationExecutions lists the individual runs and jobs behind one bar of the daily chart.
// GET /api/v2/organizations/:name/analytics/executions?since=&until=&outcome=&platform=
//
// The daily chart answers "how much ran and how much of it failed"; the obvious next question is
// "which ones", and a count alone cannot answer it. This is the drill-down behind a bar segment: the
// same window and the same outcome predicates as the aggregate, so the list always reconciles with
// the bar the reader clicked.
func (h *AnalyticsHandler) GetOrganizationExecutions(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		analyticsError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		analyticsError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	// AUD-139: same membership check as the aggregate endpoint - browser identities bypass the
	// org-resolution wall, so this drill-down must not become a way around it.
	inOrg, err := h.orgRepo.UserInOrg(user.ID, org.ID)
	if err != nil || !inOrg {
		analyticsError(c, http.StatusForbidden, "Forbidden", "You must be a member of this organization")
		return
	}

	window, _, err := parseAnalyticsWindow(c)
	if err != nil {
		analyticsError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	outcome := c.Query("outcome")
	if !repository.ValidExecutionOutcome(outcome) {
		analyticsError(c, http.StatusBadRequest, "Bad Request", "outcome must be succeeded, failed, or other")
		return
	}
	platform := c.Query("platform")
	if platform != "" && platform != "terraform" && platform != "ansible" {
		analyticsError(c, http.StatusBadRequest, "Bad Request", "platform must be terraform or ansible")
		return
	}

	ctx := c.Request.Context()
	filter := repository.ExecutionOutcome(outcome)
	rows := make([]repository.ExecutionRow, 0, executionsPageLimit)
	truncated := false

	// Each side is fetched one row past the cap purely as a probe: a query that comes back exactly
	// full is indistinguishable from one that had more to give, and reporting such a day as complete
	// would understate it. The extra row is dropped before the merge.
	if platform != "ansible" {
		runs, err := h.runRepo.WithContext(ctx).RunExecutionsByOrganization(org.ID, window, filter, executionsPageLimit+1)
		if err != nil {
			analyticsError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list run executions")
			return
		}
		if len(runs) > executionsPageLimit {
			runs = runs[:executionsPageLimit]
			truncated = true
		}
		rows = append(rows, runs...)
	}
	if platform != "terraform" {
		jobs, err := h.ansibleJobRepo.WithContext(ctx).JobExecutionsByOrganization(org.ID, window, filter, executionsPageLimit+1)
		if err != nil {
			analyticsError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list job executions")
			return
		}
		if len(jobs) > executionsPageLimit {
			jobs = jobs[:executionsPageLimit]
			truncated = true
		}
		rows = append(rows, jobs...)
	}

	// Both platforms come back newest-first independently; merge them into one timeline.
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].CreatedAt.After(rows[j].CreatedAt) })
	if len(rows) > executionsPageLimit {
		rows = rows[:executionsPageLimit]
		truncated = true
	}

	data := make([]gin.H, 0, len(rows))
	for _, row := range rows {
		entry := gin.H{
			"id":         row.ID,
			"platform":   row.Platform,
			"name":       row.Name,
			"detail":     row.Detail,
			"status":     row.Status,
			"outcome":    row.Outcome,
			"created_at": row.CreatedAt.UTC().Format(time.RFC3339),
		}
		if row.WorkspaceName != "" {
			entry["workspace_name"] = row.WorkspaceName
		}
		if row.DurationSeconds != nil {
			entry["duration_seconds"] = round1(*row.DurationSeconds)
		}
		data = append(data, entry)
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"type": "analytics-executions",
			"id":   org.Name,
			"attributes": gin.H{
				"executions": data,
				"count":      len(data),
				"truncated":  truncated,
				"window": gin.H{
					"since": window.Since.UTC().Format(time.RFC3339),
					"until": window.Until.UTC().Format(time.RFC3339),
				},
			},
		},
	})
}

// DurationStatsZero is the "no previous-period duration was requested" placeholder. Ansible KPI
// deltas are count-based only, so the previous window's duration percentile is not computed.
var DurationStatsZero = repository.DurationStats{}

// organizationResources returns the current (not window-bounded) inventory of org assets shown in
// the resource strip.
func (h *AnalyticsHandler) organizationResources(ctx context.Context, orgID uuid.UUID) (gin.H, error) {
	projects, err := h.projectRepo.WithContext(ctx).CountByOrganization(orgID)
	if err != nil {
		return nil, err
	}
	workspaces, err := h.workspaceRepo.WithContext(ctx).CountByOrganization(orgID)
	if err != nil {
		return nil, err
	}
	playbooks, err := h.ansiblePlaybookRepo.WithContext(ctx).CountByOrganization(orgID)
	if err != nil {
		return nil, err
	}
	templates, err := h.ansibleTemplateRepo.WithContext(ctx).CountByOrganization(orgID)
	if err != nil {
		return nil, err
	}
	inventories, err := h.inventoryRepo.WithContext(ctx).CountByOrganization(orgID)
	if err != nil {
		return nil, err
	}
	return gin.H{
		"projects":      projects,
		"workspaces":    workspaces,
		"playbooks":     playbooks,
		"job_templates": templates,
		"inventories":   inventories,
	}, nil
}

// parseAnalyticsWindow reads the requested window and derives the immediately preceding window of
// equal length, which the UI uses for "vs previous period" deltas.
func parseAnalyticsWindow(c *gin.Context) (repository.AnalyticsWindow, repository.AnalyticsWindow, error) {
	now := time.Now().UTC()

	until := now
	if raw := c.Query("until"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return repository.AnalyticsWindow{}, repository.AnalyticsWindow{}, errInvalidTime("until")
		}
		until = parsed.UTC()
	}

	since := until.AddDate(0, 0, -30)
	if raw := c.Query("since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return repository.AnalyticsWindow{}, repository.AnalyticsWindow{}, errInvalidTime("since")
		}
		since = parsed.UTC()
	}

	if !since.Before(until) {
		return repository.AnalyticsWindow{}, repository.AnalyticsWindow{}, errAnalyticsWindow("since must be before until")
	}
	if until.Sub(since) > maxAnalyticsWindowDays*24*time.Hour {
		return repository.AnalyticsWindow{}, repository.AnalyticsWindow{}, errAnalyticsWindow("requested window is too large")
	}

	window := repository.AnalyticsWindow{Since: since, Until: until}
	length := until.Sub(since)
	prev := repository.AnalyticsWindow{Since: since.Add(-length), Until: since}
	return window, prev, nil
}

// outcomePayload renders one platform's KPI block, including the previous-period comparison.
func outcomePayload(totals repository.OutcomeTotals, durations repository.DurationStats, prevTotals repository.OutcomeTotals, prevDurations repository.DurationStats) gin.H {
	return gin.H{
		"total":                totals.Total,
		"succeeded":            totals.Succeeded,
		"failed":               totals.Failed,
		"running":              totals.Running,
		"pending":              totals.Pending,
		"canceled":             totals.Canceled,
		"success_rate":         successRate(totals),
		"avg_duration_seconds": round1(durations.AvgSeconds),
		"p95_duration_seconds": round1(durations.P95Seconds),
		"duration_samples":     durations.Samples,
		"previous": gin.H{
			"total":                prevTotals.Total,
			"succeeded":            prevTotals.Succeeded,
			"failed":               prevTotals.Failed,
			"success_rate":         successRate(prevTotals),
			"avg_duration_seconds": round1(prevDurations.AvgSeconds),
		},
	}
}

// successRate is the share of *decided* outcomes that succeeded, or null when nothing has finished.
// Returning null rather than 0 is what keeps the UI from printing "NaN%" (the old page divided by
// succeeded+failed while guarding only on total > 0) or an equally wrong "0% success" for an org
// whose runs are all still in flight.
func successRate(t repository.OutcomeTotals) *float64 {
	decided := t.Succeeded + t.Failed
	if decided == 0 {
		return nil
	}
	rate := math.Round(float64(t.Succeeded)/float64(decided)*1000) / 10
	return &rate
}

func round1(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*10) / 10
}

// dailyPayload merges the three sparse series into one dense, zero-filled series keyed by day, so
// the chart can plot runs, jobs, and activity on a shared continuous axis.
func dailyPayload(runs, jobs []repository.DailyOutcome, activity []repository.DailyCount, w repository.AnalyticsWindow) []gin.H {
	filledRuns := repository.FillDailyOutcomes(runs, w)
	filledJobs := repository.FillDailyOutcomes(jobs, w)
	filledActivity := repository.FillDailyCounts(activity, w)

	out := make([]gin.H, 0, len(filledRuns))
	for i := range filledRuns {
		day := filledRuns[i].Day
		entry := gin.H{
			"date":           day.Format("2006-01-02"),
			"runs_succeeded": filledRuns[i].Succeeded,
			"runs_failed":    filledRuns[i].Failed,
			"runs_other":     filledRuns[i].Other,
		}
		if i < len(filledJobs) {
			entry["jobs_succeeded"] = filledJobs[i].Succeeded
			entry["jobs_failed"] = filledJobs[i].Failed
			entry["jobs_other"] = filledJobs[i].Other
		}
		if i < len(filledActivity) {
			entry["activity"] = filledActivity[i].Count
		}
		out = append(out, entry)
	}
	return out
}

func topWorkspacePayload(rows []repository.TopWorkspace) []gin.H {
	out := make([]gin.H, 0, len(rows))
	for _, row := range rows {
		out = append(out, gin.H{
			"workspace_id":         row.WorkspaceID,
			"workspace_name":       row.WorkspaceName,
			"project_name":         row.ProjectName,
			"run_count":            row.RunCount,
			"succeeded":            row.Succeeded,
			"failed":               row.Failed,
			"success_rate":         successRate(repository.OutcomeTotals{Succeeded: row.Succeeded, Failed: row.Failed}),
			"avg_duration_seconds": round1(row.AvgSeconds),
		})
	}
	return out
}

func topTemplatePayload(rows []repository.TopTemplate) []gin.H {
	out := make([]gin.H, 0, len(rows))
	for _, row := range rows {
		out = append(out, gin.H{
			"template_id":          row.TemplateID,
			"template_name":        row.TemplateName,
			"job_count":            row.JobCount,
			"succeeded":            row.Succeeded,
			"failed":               row.Failed,
			"success_rate":         successRate(repository.OutcomeTotals{Succeeded: row.Succeeded, Failed: row.Failed}),
			"avg_duration_seconds": round1(row.AvgSeconds),
		})
	}
	return out
}

func activityPayload(total int64, byAction, byResource []repository.LabeledCount) gin.H {
	return gin.H{
		"total":            total,
		"by_action":        labeledPayload(byAction),
		"by_resource_type": labeledPayload(byResource),
	}
}

func labeledPayload(rows []repository.LabeledCount) []gin.H {
	out := make([]gin.H, 0, len(rows))
	for _, row := range rows {
		out = append(out, gin.H{"label": row.Label, "count": row.Count})
	}
	return out
}

// failurePayload interleaves Terraform and Ansible failures into one most-recent-first list.
func failurePayload(runs, jobs []repository.RecentFailure, limit int) []gin.H {
	merged := make([]repository.RecentFailure, 0, len(runs)+len(jobs))
	merged = append(merged, runs...)
	merged = append(merged, jobs...)
	for i := 1; i < len(merged); i++ {
		for j := i; j > 0 && merged[j].FailedAt.After(merged[j-1].FailedAt); j-- {
			merged[j], merged[j-1] = merged[j-1], merged[j]
		}
	}
	if len(merged) > limit {
		merged = merged[:limit]
	}
	out := make([]gin.H, 0, len(merged))
	for _, f := range merged {
		out = append(out, gin.H{
			"id":             f.ID,
			"platform":       f.Platform,
			"name":           f.Name,
			"detail":         f.Detail,
			"workspace_name": f.WorkspaceName,
			"error_message":  f.ErrorMessage,
			"failed_at":      f.FailedAt.UTC().Format(time.RFC3339),
		})
	}
	return out
}

func analyticsError(c *gin.Context, status int, title, detail string) {
	c.JSON(status, gin.H{"errors": []gin.H{{
		"status": strconv.Itoa(status),
		"title":  title,
		"detail": detail,
	}}})
}

func errInvalidTime(param string) error {
	return fmt.Errorf("%s must be an RFC3339 timestamp", param)
}

func errAnalyticsWindow(detail string) error {
	return fmt.Errorf("invalid analytics window: %s", detail)
}
