// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

// Typed shapes for the organization analytics endpoints (#760). This is a StackWeaver-native
// surface (snake_case members, consumed only by the frontend dashboard); the member names are
// frozen as-is because renaming them is a wire change and not this task.

// AnalyticsWindowBlock is the resolved reporting window of the aggregate response.
type AnalyticsWindowBlock struct {
	Since string `json:"since"`
	Until string `json:"until"`
	Days  int    `json:"days"`
}

// AnalyticsOutcomePrevious is the "vs previous period" comparison inside a KPI block.
type AnalyticsOutcomePrevious struct {
	Total              int64    `json:"total"`
	Succeeded          int64    `json:"succeeded"`
	Failed             int64    `json:"failed"`
	SuccessRate        *float64 `json:"success_rate"`
	AvgDurationSeconds float64  `json:"avg_duration_seconds"`
}

// AnalyticsOutcomeBlock is one platform's KPI block. SuccessRate is a pointer without
// omitempty: null (nothing decided yet) and 0 (everything failed) mean different things.
type AnalyticsOutcomeBlock struct {
	Total              int64                    `json:"total"`
	Succeeded          int64                    `json:"succeeded"`
	Failed             int64                    `json:"failed"`
	Running            int64                    `json:"running"`
	Pending            int64                    `json:"pending"`
	Canceled           int64                    `json:"canceled"`
	SuccessRate        *float64                 `json:"success_rate"`
	AvgDurationSeconds float64                  `json:"avg_duration_seconds"`
	P95DurationSeconds float64                  `json:"p95_duration_seconds"`
	DurationSamples    int64                    `json:"duration_samples"`
	Previous           AnalyticsOutcomePrevious `json:"previous"`
}

// AnalyticsDailyEntry is one day bucket of the stacked daily chart. The jobs trio and
// activity are pointers with omitempty because the old map added them only when the
// zero-filled series covered the index - in practice always, but the conditionality is wire
// shape and is preserved.
type AnalyticsDailyEntry struct {
	Date          string `json:"date"`
	RunsSucceeded int64  `json:"runs_succeeded"`
	RunsFailed    int64  `json:"runs_failed"`
	RunsOther     int64  `json:"runs_other"`
	JobsSucceeded *int64 `json:"jobs_succeeded,omitempty"`
	JobsFailed    *int64 `json:"jobs_failed,omitempty"`
	JobsOther     *int64 `json:"jobs_other,omitempty"`
	Activity      *int64 `json:"activity,omitempty"`
}

// AnalyticsTopWorkspace is one row of the busiest-workspaces table.
type AnalyticsTopWorkspace struct {
	WorkspaceID        string   `json:"workspace_id"`
	WorkspaceName      string   `json:"workspace_name"`
	ProjectName        string   `json:"project_name"`
	RunCount           int64    `json:"run_count"`
	Succeeded          int64    `json:"succeeded"`
	Failed             int64    `json:"failed"`
	SuccessRate        *float64 `json:"success_rate"`
	AvgDurationSeconds float64  `json:"avg_duration_seconds"`
}

// AnalyticsTopTemplate is one row of the busiest-templates table.
type AnalyticsTopTemplate struct {
	TemplateID         string   `json:"template_id"`
	TemplateName       string   `json:"template_name"`
	JobCount           int64    `json:"job_count"`
	Succeeded          int64    `json:"succeeded"`
	Failed             int64    `json:"failed"`
	SuccessRate        *float64 `json:"success_rate"`
	AvgDurationSeconds float64  `json:"avg_duration_seconds"`
}

// AnalyticsLabeledCount is one row of a categorical breakdown.
type AnalyticsLabeledCount struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// AnalyticsActivityBlock is the audit-activity summary.
type AnalyticsActivityBlock struct {
	Total          int64                   `json:"total"`
	ByAction       []AnalyticsLabeledCount `json:"by_action"`
	ByResourceType []AnalyticsLabeledCount `json:"by_resource_type"`
}

// AnalyticsResourceCounts is the current (not window-bounded) org asset inventory.
type AnalyticsResourceCounts struct {
	Projects     int64 `json:"projects"`
	Workspaces   int64 `json:"workspaces"`
	Playbooks    int64 `json:"playbooks"`
	JobTemplates int64 `json:"job_templates"`
	Inventories  int64 `json:"inventories"`
}

// AnalyticsFailureEntry is one entry of the recent-failures list. Unlike the repository row,
// every member is emitted even when empty - that is what the old map did.
type AnalyticsFailureEntry struct {
	ID            string `json:"id"`
	Platform      string `json:"platform"`
	Name          string `json:"name"`
	Detail        string `json:"detail"`
	WorkspaceName string `json:"workspace_name"`
	ErrorMessage  string `json:"error_message"`
	FailedAt      string `json:"failed_at"`
}

// AnalyticsRunningNow is the live in-flight counter strip.
type AnalyticsRunningNow struct {
	Runs  int64 `json:"runs"`
	Jobs  int64 `json:"jobs"`
	Total int64 `json:"total"`
}

// AnalyticsAttributes is the attribute block of the aggregate analytics document.
type AnalyticsAttributes struct {
	Window         AnalyticsWindowBlock    `json:"window"`
	Runs           AnalyticsOutcomeBlock   `json:"runs"`
	AnsibleJobs    AnalyticsOutcomeBlock   `json:"ansible_jobs"`
	Daily          []AnalyticsDailyEntry   `json:"daily"`
	TopWorkspaces  []AnalyticsTopWorkspace `json:"top_workspaces"`
	TopTemplates   []AnalyticsTopTemplate  `json:"top_templates"`
	Activity       AnalyticsActivityBlock  `json:"activity"`
	Resources      AnalyticsResourceCounts `json:"resources"`
	RecentFailures []AnalyticsFailureEntry `json:"recent_failures"`
	RunningNow     AnalyticsRunningNow     `json:"running_now"`
}

// AnalyticsExecutionEntry is one run or job in the drill-down behind a chart bar.
// workspace_name and duration_seconds appear only when set, as before.
type AnalyticsExecutionEntry struct {
	ID              string   `json:"id"`
	Platform        string   `json:"platform"`
	Name            string   `json:"name"`
	Detail          string   `json:"detail"`
	Status          string   `json:"status"`
	Outcome         string   `json:"outcome"`
	CreatedAt       string   `json:"created_at"`
	WorkspaceName   string   `json:"workspace_name,omitempty"`
	DurationSeconds *float64 `json:"duration_seconds,omitempty"`
}

// AnalyticsExecutionsWindow is the drill-down's echo of the requested window.
type AnalyticsExecutionsWindow struct {
	Since string `json:"since"`
	Until string `json:"until"`
}

// AnalyticsExecutionsAttributes is the attribute block of the executions document.
type AnalyticsExecutionsAttributes struct {
	Executions []AnalyticsExecutionEntry `json:"executions"`
	Count      int                       `json:"count"`
	Truncated  bool                      `json:"truncated"`
	Window     AnalyticsExecutionsWindow `json:"window"`
}
