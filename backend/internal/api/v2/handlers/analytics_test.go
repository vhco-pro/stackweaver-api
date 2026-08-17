// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Usage & Analytics aggregation tests. These drive the real handler against real Postgres, because
// the whole point of the endpoint is the SQL: the numbers it reports are the ones the page prints,
// and the definitions they encode (a plan-only run is done at `planned`, an Ansible `error` is a
// failure, a period with nothing decided has no success rate at all) are exactly the ones the old
// client-side implementation got wrong.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped - the dev database this runs against has no backup. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAnalytics

//go:build integration
// +build integration

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

type analyticsFixture struct {
	router   *gin.Engine
	db       *gorm.DB
	orgName  string
	emptyOrg string
	member   *models.User
	outsider *models.User
	// dayStart is midnight UTC of the day every seeded row falls in. Tests that need an exact window
	// derive it from here rather than from wall-clock arithmetic, so they do not depend on what time
	// of day the suite happens to run.
	dayStart time.Time
	// wsID is the org's workspace, for tests that seed extra runs of their own.
	wsID string
}

// analyticsAttrs is the decoded attributes block of the JSON:API response.
type analyticsAttrs struct {
	Window struct {
		Days int `json:"days"`
	} `json:"window"`
	Runs        analyticsOutcome `json:"runs"`
	AnsibleJobs analyticsOutcome `json:"ansible_jobs"`
	Daily       []struct {
		Date          string `json:"date"`
		RunsSucceeded int64  `json:"runs_succeeded"`
		RunsFailed    int64  `json:"runs_failed"`
		RunsOther     int64  `json:"runs_other"`
		JobsSucceeded int64  `json:"jobs_succeeded"`
		JobsFailed    int64  `json:"jobs_failed"`
		Activity      int64  `json:"activity"`
	} `json:"daily"`
	TopWorkspaces []struct {
		WorkspaceName string   `json:"workspace_name"`
		ProjectName   string   `json:"project_name"`
		RunCount      int64    `json:"run_count"`
		SuccessRate   *float64 `json:"success_rate"`
	} `json:"top_workspaces"`
	TopTemplates []struct {
		TemplateName string `json:"template_name"`
		JobCount     int64  `json:"job_count"`
	} `json:"top_templates"`
	Activity struct {
		Total    int64 `json:"total"`
		ByAction []struct {
			Label string `json:"label"`
			Count int64  `json:"count"`
		} `json:"by_action"`
		ByResourceType []struct {
			Label string `json:"label"`
			Count int64  `json:"count"`
		} `json:"by_resource_type"`
	} `json:"activity"`
	Resources struct {
		Projects     int64 `json:"projects"`
		Workspaces   int64 `json:"workspaces"`
		Playbooks    int64 `json:"playbooks"`
		JobTemplates int64 `json:"job_templates"`
		Inventories  int64 `json:"inventories"`
	} `json:"resources"`
	RecentFailures []struct {
		Platform string `json:"platform"`
		Name     string `json:"name"`
	} `json:"recent_failures"`
}

type analyticsOutcome struct {
	Total       int64    `json:"total"`
	Succeeded   int64    `json:"succeeded"`
	Failed      int64    `json:"failed"`
	Running     int64    `json:"running"`
	Pending     int64    `json:"pending"`
	Canceled    int64    `json:"canceled"`
	SuccessRate *float64 `json:"success_rate"`
	AvgDuration float64  `json:"avg_duration_seconds"`
	P95Duration float64  `json:"p95_duration_seconds"`
	Samples     int64    `json:"duration_samples"`
	Previous    struct {
		Total     int64 `json:"total"`
		Succeeded int64 `json:"succeeded"`
	} `json:"previous"`
}

// setupAnalyticsFixture seeds one org with a deliberately mixed set of runs and jobs whose expected
// aggregates are known exactly, plus a second org the member does not belong to (authz) and a third
// that is empty (the "nothing has finished yet" case).
func setupAnalyticsFixture(t *testing.T) *analyticsFixture {
	t.Helper()
	db := setupAuthzTestDB(t)
	sfx := uuid.NewString()[:8]

	// All seeded rows sit at midday, 2 days back: inside the default 30-day window whenever the suite
	// runs, and comfortably inside a single UTC day bucket rather than near a boundary.
	dayStart := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour)
	base := dayStart.Add(12 * time.Hour)

	orgA := &models.Organization{ID: uuid.New(), Name: "analytics-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "analytics-b-" + sfx}
	orgEmpty := &models.Organization{ID: uuid.New(), Name: "analytics-empty-" + sfx}
	member := &models.User{ID: uuid.New(), ZitadelSubject: "an-mem-" + sfx, Email: "an-mem-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "an-out-" + sfx, Email: "an-out-" + sfx + "@test.local"}

	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "proj-" + sfx}
	wsA := &models.Workspace{ID: "ws-" + sfx + "0000000", ProjectID: projA.ID, Name: "ws-" + sfx}
	invA := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: orgA.ID, Name: "inv-" + sfx}
	playbookA := &models.AnsiblePlaybook{ID: uuid.New(), ProjectID: projA.ID, Name: "pb-" + sfx}
	templateA := &models.AnsibleJobTemplate{
		ID: uuid.New(), ProjectID: projA.ID, PlaybookID: playbookA.ID,
		InventoryID: invA.ID, Name: "tpl-" + sfx,
	}

	// Terraform runs. Expected: total 9, succeeded 4, failed 2, running 1, canceled 1, pending 1.
	// The two `planned` runs are the interesting pair - identical status, opposite meaning.
	mkRun := func(n string, status models.RunStatus, op models.RunOperation, durationSec int) *models.Run {
		run := &models.Run{
			ID:          "run-" + sfx + n,
			WorkspaceID: wsA.ID,
			Status:      status,
			Operation:   op,
			CreatedAt:   base,
		}
		if durationSec > 0 {
			start := base
			end := base.Add(time.Duration(durationSec) * time.Second)
			run.StartedAt = &start
			run.CompletedAt = &end
		}
		return run
	}
	runs := []*models.Run{
		mkRun("a000000", models.RunStatusApplied, models.RunOperationPlanAndApply, 10),
		mkRun("b000000", models.RunStatusApplied, models.RunOperationPlanAndApply, 20),
		mkRun("c000000", models.RunStatusCompleted, models.RunOperationPlanAndApply, 60),
		// Terminal for a plan-only run: it has no apply phase to reach, so it is a success.
		mkRun("d000000", models.RunStatusPlanned, models.RunOperationPlanOnly, 0),
		// Same status on a plan-and-apply run means "awaiting confirmation" - pending, not success.
		mkRun("e000000", models.RunStatusPlanned, models.RunOperationPlanAndApply, 0),
		mkRun("f000000", models.RunStatusFailed, models.RunOperationPlanAndApply, 5),
		mkRun("g000000", models.RunStatusFailed, models.RunOperationDestroy, 5),
		mkRun("h000000", models.RunStatusRunning, models.RunOperationPlanAndApply, 0),
		mkRun("i000000", models.RunStatusCancelled, models.RunOperationPlanAndApply, 0),
	}

	// Ansible jobs. Expected: total 5, succeeded 2, failed 2 (`failed` + `error`), running 1.
	mkJob := func(status models.AnsibleJobStatus, withTemplate bool, durationSec int) *models.AnsibleJob {
		job := &models.AnsibleJob{
			ID:          uuid.New(),
			ProjectID:   projA.ID,
			InventoryID: invA.ID,
			Status:      status,
			Name:        "job-" + sfx,
			CreatedAt:   base,
		}
		if withTemplate {
			job.TemplateID = &templateA.ID
		}
		if durationSec > 0 {
			start := base
			end := base.Add(time.Duration(durationSec) * time.Second)
			job.StartedAt = &start
			job.FinishedAt = &end
		}
		return job
	}
	jobs := []*models.AnsibleJob{
		mkJob(models.AnsibleJobStatusSuccessful, true, 30),
		mkJob(models.AnsibleJobStatusSuccessful, true, 90),
		mkJob(models.AnsibleJobStatusFailed, true, 10),
		mkJob(models.AnsibleJobStatusError, false, 10),
		mkJob(models.AnsibleJobStatusRunning, false, 0),
	}

	orgAID := orgA.ID
	audits := []*models.AuditLog{
		{ID: uuid.New(), OrganizationID: &orgAID, Action: "run.create", ResourceType: "run", CreatedAt: base},
		{ID: uuid.New(), OrganizationID: &orgAID, Action: "run.create", ResourceType: "run", CreatedAt: base},
		{ID: uuid.New(), OrganizationID: &orgAID, Action: "workspace.update", ResourceType: "workspace", CreatedAt: base},
	}

	seed := []interface{}{
		orgA, orgB, orgEmpty, member, outsider,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: member.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgEmpty.ID, UserID: member.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
		projA, wsA, invA, playbookA, templateA,
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	for _, r := range runs {
		if err := db.Create(r).Error; err != nil {
			t.Fatalf("seed run: %v", err)
		}
	}
	for _, j := range jobs {
		if err := db.Create(j).Error; err != nil {
			t.Fatalf("seed job: %v", err)
		}
	}
	for _, a := range audits {
		if err := db.Create(a).Error; err != nil {
			t.Fatalf("seed audit: %v", err)
		}
	}

	t.Cleanup(func() {
		runIDs := make([]string, 0, len(runs))
		for _, r := range runs {
			runIDs = append(runIDs, r.ID)
		}
		jobIDs := make([]uuid.UUID, 0, len(jobs))
		for _, j := range jobs {
			jobIDs = append(jobIDs, j.ID)
		}
		auditIDs := make([]uuid.UUID, 0, len(audits))
		for _, a := range audits {
			auditIDs = append(auditIDs, a.ID)
		}
		db.Where("id IN ?", auditIDs).Delete(&models.AuditLog{})
		db.Where("id IN ?", jobIDs).Delete(&models.AnsibleJob{})
		db.Where("id IN ?", runIDs).Delete(&models.Run{})
		db.Where("id = ?", templateA.ID).Delete(&models.AnsibleJobTemplate{})
		db.Where("id = ?", playbookA.ID).Delete(&models.AnsiblePlaybook{})
		db.Where("id = ?", invA.ID).Delete(&models.AnsibleInventory{})
		db.Where("id = ?", wsA.ID).Delete(&models.Workspace{})
		db.Where("id = ?", projA.ID).Delete(&models.Project{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID, orgEmpty.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID, orgEmpty.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{member.ID, outsider.ID}).Delete(&models.User{})
	})

	h := NewAnalyticsHandler(
		repository.NewOrganizationRepository(db),
		repository.NewProjectRepository(db),
		repository.NewWorkspaceRepository(db),
		repository.NewRunRepository(db),
		repository.NewAnsibleJobRepository(db),
		repository.NewAnsiblePlaybookRepository(db),
		repository.NewAnsibleJobTemplateRepository(db),
		repository.NewAnsibleInventoryRepository(db),
		repository.NewAuditLogRepository(db),
		auth.NewService(repository.NewUserRepository(db)),
	)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(testUserAuth())
	router.GET("/organizations/:name/analytics", h.GetOrganizationAnalytics)
	router.GET("/organizations/:name/analytics/executions", h.GetOrganizationExecutions)

	return &analyticsFixture{
		router:   router,
		db:       db,
		orgName:  orgA.Name,
		emptyOrg: orgEmpty.Name,
		member:   member,
		outsider: outsider,
		dayStart: dayStart,
		wsID:     wsA.ID,
	}
}

func analyticsGet(t *testing.T, f *analyticsFixture, org, query string, asUser uuid.UUID) (int, analyticsAttrs) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/organizations/"+org+"/analytics"+query, nil)
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	var body struct {
		Data struct {
			Type       string         `json:"type"`
			ID         string         `json:"id"`
			Attributes analyticsAttrs `json:"attributes"`
		} `json:"data"`
	}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode analytics body: %v (body=%s)", err, rec.Body.String())
		}
		if body.Data.Type != "analytics" {
			t.Fatalf("data.type = %q, want \"analytics\"", body.Data.Type)
		}
	}
	return rec.Code, body.Data.Attributes
}

// TestAnalyticsAuthz is the tenant-isolation assertion: an outsider must not read another org's
// delivery metrics, and an anonymous caller gets 401.
func TestAnalyticsAuthz(t *testing.T) {
	f := setupAnalyticsFixture(t)

	if code, _ := analyticsGet(t, f, f.orgName, "", f.outsider.ID); code != http.StatusForbidden {
		t.Fatalf("outsider GET analytics = %d, want 403", code)
	}
	if code, _ := analyticsGet(t, f, f.orgName, "", uuid.Nil); code != http.StatusUnauthorized {
		t.Fatalf("anon GET analytics = %d, want 401", code)
	}
	if code, _ := analyticsGet(t, f, f.orgName, "", f.member.ID); code != http.StatusOK {
		t.Fatalf("member GET analytics = %d, want 200", code)
	}
	if code, _ := analyticsGet(t, f, "no-such-org-"+uuid.NewString()[:8], "", f.member.ID); code != http.StatusNotFound {
		t.Fatalf("GET analytics for unknown org = %d, want 404", code)
	}
}

// TestAnalyticsRunTotals pins the Terraform status breakdown, including the plan-only distinction
// that decides whether a `planned` run counts as finished work or as waiting work.
func TestAnalyticsRunTotals(t *testing.T) {
	f := setupAnalyticsFixture(t)
	code, attrs := analyticsGet(t, f, f.orgName, "", f.member.ID)
	if code != http.StatusOK {
		t.Fatalf("GET analytics = %d, want 200", code)
	}

	got := attrs.Runs
	for _, tc := range []struct {
		name string
		got  int64
		want int64
	}{
		{"total", got.Total, 9},
		{"succeeded", got.Succeeded, 4},
		{"failed", got.Failed, 2},
		{"running", got.Running, 1},
		{"canceled", got.Canceled, 1},
		{"pending", got.Pending, 1},
	} {
		if tc.got != tc.want {
			t.Errorf("runs.%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}

	// The named buckets must account for every run: a status this code does not know about (a new
	// task gate, say) has to land in the pending remainder rather than vanish from the page.
	sum := got.Succeeded + got.Failed + got.Running + got.Canceled + got.Pending
	if sum != got.Total {
		t.Errorf("run buckets sum to %d, want total %d", sum, got.Total)
	}

	// 4 succeeded of 6 decided = 66.7%. Runs still in flight are not in the denominator.
	if got.SuccessRate == nil || *got.SuccessRate != 66.7 {
		t.Errorf("runs.success_rate = %v, want 66.7", got.SuccessRate)
	}
}

// TestAnalyticsRunDurations checks the duration stats are computed over successful, fully-timed runs
// only - a failed run's 5 seconds and an unfinished run's missing timestamps must not move them.
func TestAnalyticsRunDurations(t *testing.T) {
	f := setupAnalyticsFixture(t)
	_, attrs := analyticsGet(t, f, f.orgName, "", f.member.ID)

	if attrs.Runs.Samples != 3 {
		t.Fatalf("runs.duration_samples = %d, want 3 (only timed successes)", attrs.Runs.Samples)
	}
	if attrs.Runs.AvgDuration != 30 {
		t.Errorf("runs.avg_duration_seconds = %v, want 30 (mean of 10/20/60)", attrs.Runs.AvgDuration)
	}
	// percentile_cont(0.95) over [10,20,60] interpolates to 56.
	if attrs.Runs.P95Duration != 56 {
		t.Errorf("runs.p95_duration_seconds = %v, want 56", attrs.Runs.P95Duration)
	}
}

// TestAnalyticsJobTotals pins the Ansible breakdown, notably that `error` counts as a failure.
func TestAnalyticsJobTotals(t *testing.T) {
	f := setupAnalyticsFixture(t)
	_, attrs := analyticsGet(t, f, f.orgName, "", f.member.ID)

	got := attrs.AnsibleJobs
	if got.Total != 5 {
		t.Errorf("ansible_jobs.total = %d, want 5", got.Total)
	}
	if got.Succeeded != 2 {
		t.Errorf("ansible_jobs.succeeded = %d, want 2", got.Succeeded)
	}
	if got.Failed != 2 {
		t.Errorf("ansible_jobs.failed = %d, want 2 (failed + error)", got.Failed)
	}
	if got.Running != 1 {
		t.Errorf("ansible_jobs.running = %d, want 1", got.Running)
	}
	if got.SuccessRate == nil || *got.SuccessRate != 50 {
		t.Errorf("ansible_jobs.success_rate = %v, want 50", got.SuccessRate)
	}
	if got.AvgDuration != 60 {
		t.Errorf("ansible_jobs.avg_duration_seconds = %v, want 60 (mean of 30/90)", got.AvgDuration)
	}
}

// TestAnalyticsSuccessRateIsNullWhenNothingDecided is the regression guard for the bug this endpoint
// was built to kill: the old page divided succeeded by (succeeded+failed) while guarding only on
// "are there any jobs at all", so an org whose work was all still running rendered "NaN%". An
// undecided period has no success rate, and the API says so with null rather than a made-up 0.
func TestAnalyticsSuccessRateIsNullWhenNothingDecided(t *testing.T) {
	f := setupAnalyticsFixture(t)
	code, attrs := analyticsGet(t, f, f.emptyOrg, "", f.member.ID)
	if code != http.StatusOK {
		t.Fatalf("GET analytics for empty org = %d, want 200", code)
	}
	if attrs.Runs.SuccessRate != nil {
		t.Errorf("runs.success_rate = %v for an org with no runs, want null", *attrs.Runs.SuccessRate)
	}
	if attrs.AnsibleJobs.SuccessRate != nil {
		t.Errorf("ansible_jobs.success_rate = %v for an org with no jobs, want null", *attrs.AnsibleJobs.SuccessRate)
	}
	if attrs.Runs.Total != 0 || attrs.AnsibleJobs.Total != 0 {
		t.Errorf("empty org reported %d runs / %d jobs, want 0/0", attrs.Runs.Total, attrs.AnsibleJobs.Total)
	}
}

// TestAnalyticsDailySeriesIsDense asserts the day buckets are zero-filled across the whole window,
// so the chart's x-axis stays continuous instead of collapsing to the days that happened to have
// activity, and that the seeded day carries the expected counts.
func TestAnalyticsDailySeriesIsDense(t *testing.T) {
	f := setupAnalyticsFixture(t)
	_, attrs := analyticsGet(t, f, f.orgName, "", f.member.ID)

	// A 30-day window touches 31 UTC days inclusive.
	if len(attrs.Daily) != 31 {
		t.Fatalf("daily series has %d buckets, want 31 for the default 30-day window", len(attrs.Daily))
	}
	seenDates := make(map[string]bool, len(attrs.Daily))
	var totalRuns, totalJobs, totalActivity int64
	for _, d := range attrs.Daily {
		if seenDates[d.Date] {
			t.Fatalf("duplicate day bucket %s", d.Date)
		}
		seenDates[d.Date] = true
		totalRuns += d.RunsSucceeded + d.RunsFailed + d.RunsOther
		totalJobs += d.JobsSucceeded + d.JobsFailed
		totalActivity += d.Activity
	}
	if totalRuns != 9 {
		t.Errorf("daily run buckets sum to %d, want 9", totalRuns)
	}
	if totalJobs != 4 {
		t.Errorf("daily job buckets sum to %d, want 4 (succeeded + failed)", totalJobs)
	}
	if totalActivity != 3 {
		t.Errorf("daily activity buckets sum to %d, want 3", totalActivity)
	}
}

// TestAnalyticsBreakdownsAndResources covers the tables and counts on the Terraform, Ansible, and
// Activity tabs, including that by-action and by-resource-type are genuinely different breakdowns
// (the old page plotted the same field in both charts).
func TestAnalyticsBreakdownsAndResources(t *testing.T) {
	f := setupAnalyticsFixture(t)
	_, attrs := analyticsGet(t, f, f.orgName, "", f.member.ID)

	if len(attrs.TopWorkspaces) != 1 {
		t.Fatalf("top_workspaces has %d rows, want 1", len(attrs.TopWorkspaces))
	}
	if attrs.TopWorkspaces[0].RunCount != 9 {
		t.Errorf("top workspace run_count = %d, want 9", attrs.TopWorkspaces[0].RunCount)
	}
	if attrs.TopWorkspaces[0].ProjectName == "" {
		t.Error("top workspace project_name is empty, want the parent project's name")
	}

	// Three of the five jobs were launched from the template; the two ad hoc ones are excluded
	// rather than grouped under a synthetic "none" row.
	if len(attrs.TopTemplates) != 1 {
		t.Fatalf("top_templates has %d rows, want 1", len(attrs.TopTemplates))
	}
	if attrs.TopTemplates[0].JobCount != 3 {
		t.Errorf("top template job_count = %d, want 3", attrs.TopTemplates[0].JobCount)
	}

	if attrs.Activity.Total != 3 {
		t.Errorf("activity.total = %d, want 3", attrs.Activity.Total)
	}
	if len(attrs.Activity.ByAction) != 2 {
		t.Errorf("activity.by_action has %d rows, want 2", len(attrs.Activity.ByAction))
	}
	if attrs.Activity.ByAction[0].Label != "run.create" || attrs.Activity.ByAction[0].Count != 2 {
		t.Errorf("top action = %s/%d, want run.create/2", attrs.Activity.ByAction[0].Label, attrs.Activity.ByAction[0].Count)
	}
	if len(attrs.Activity.ByResourceType) != 2 {
		t.Errorf("activity.by_resource_type has %d rows, want 2", len(attrs.Activity.ByResourceType))
	}

	if attrs.Resources.Projects != 1 || attrs.Resources.Workspaces != 1 {
		t.Errorf("resources projects/workspaces = %d/%d, want 1/1", attrs.Resources.Projects, attrs.Resources.Workspaces)
	}
	if attrs.Resources.Playbooks != 1 || attrs.Resources.JobTemplates != 1 || attrs.Resources.Inventories != 1 {
		t.Errorf("resources playbooks/templates/inventories = %d/%d/%d, want 1/1/1",
			attrs.Resources.Playbooks, attrs.Resources.JobTemplates, attrs.Resources.Inventories)
	}

	// Both platforms' failures land in one merged list (2 failed runs + 2 failed/errored jobs).
	if len(attrs.RecentFailures) != 4 {
		t.Errorf("recent_failures has %d entries, want 4", len(attrs.RecentFailures))
	}
	platforms := map[string]bool{}
	for _, fail := range attrs.RecentFailures {
		platforms[fail.Platform] = true
	}
	if !platforms["terraform"] || !platforms["ansible"] {
		t.Errorf("recent_failures covers %v, want both terraform and ansible", platforms)
	}
}

// TestAnalyticsWindowValidation checks the request bounds: a malformed or inverted window is a 400,
// and an over-long one is refused rather than turned into a full-table scan.
func TestAnalyticsWindowValidation(t *testing.T) {
	f := setupAnalyticsFixture(t)
	now := time.Now().UTC()

	cases := []struct {
		name  string
		query string
		want  int
	}{
		{"malformed since", "?since=not-a-date", http.StatusBadRequest},
		{"malformed until", "?until=17000000", http.StatusBadRequest},
		{
			"inverted window",
			"?since=" + now.Format(time.RFC3339) + "&until=" + now.AddDate(0, 0, -1).Format(time.RFC3339),
			http.StatusBadRequest,
		},
		{
			"window too large",
			"?since=" + now.AddDate(-5, 0, 0).Format(time.RFC3339) + "&until=" + now.Format(time.RFC3339),
			http.StatusBadRequest,
		},
		{
			"valid 7-day window",
			"?since=" + now.AddDate(0, 0, -7).Format(time.RFC3339) + "&until=" + now.Format(time.RFC3339),
			http.StatusOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := analyticsGet(t, f, f.orgName, tc.query, f.member.ID)
			if code != tc.want {
				t.Errorf("GET analytics%s = %d, want %d", tc.query, code, tc.want)
			}
		})
	}
}

// executionsAttrs is the decoded drill-down response.
type executionsAttrs struct {
	Executions []struct {
		ID            string  `json:"id"`
		Platform      string  `json:"platform"`
		Name          string  `json:"name"`
		Status        string  `json:"status"`
		Outcome       string  `json:"outcome"`
		WorkspaceName string  `json:"workspace_name"`
		Duration      float64 `json:"duration_seconds"`
	} `json:"executions"`
	Count     int  `json:"count"`
	Truncated bool `json:"truncated"`
}

func executionsGet(t *testing.T, f *analyticsFixture, org, query string, asUser uuid.UUID) (int, executionsAttrs) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/organizations/"+org+"/analytics/executions"+query, nil)
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	var body struct {
		Data struct {
			Type       string          `json:"type"`
			Attributes executionsAttrs `json:"attributes"`
		} `json:"data"`
	}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode executions body: %v (body=%s)", err, rec.Body.String())
		}
		if body.Data.Type != "analytics-executions" {
			t.Fatalf("data.type = %q, want \"analytics-executions\"", body.Data.Type)
		}
	}
	return rec.Code, body.Data.Attributes
}

// TestAnalyticsExecutionsReconcileWithTheChart is the contract that makes the drill-down
// trustworthy: the rows behind a bar must be exactly the rows the bar counted. If these ever
// diverge, a reader clicking a bar showing four failures would be shown some other number of them.
func TestAnalyticsExecutionsReconcileWithTheChart(t *testing.T) {
	f := setupAnalyticsFixture(t)

	code, all := executionsGet(t, f, f.orgName, "", f.member.ID)
	if code != http.StatusOK {
		t.Fatalf("GET executions = %d, want 200", code)
	}
	// 9 runs + 5 jobs seeded in the window.
	if all.Count != 14 {
		t.Errorf("unfiltered executions count = %d, want 14", all.Count)
	}
	if all.Truncated {
		t.Error("14 executions reported as truncated")
	}

	_, succeeded := executionsGet(t, f, f.orgName, "?outcome=succeeded", f.member.ID)
	if succeeded.Count != 6 {
		t.Errorf("succeeded executions = %d, want 6 (4 runs + 2 jobs)", succeeded.Count)
	}
	_, failed := executionsGet(t, f, f.orgName, "?outcome=failed", f.member.ID)
	if failed.Count != 4 {
		t.Errorf("failed executions = %d, want 4 (2 runs + 2 jobs)", failed.Count)
	}
	_, other := executionsGet(t, f, f.orgName, "?outcome=other", f.member.ID)
	if other.Count != 4 {
		t.Errorf("other executions = %d, want 4 (3 runs + 1 job)", other.Count)
	}

	// The three segments must partition the day exactly - no row counted twice, none dropped.
	if succeeded.Count+failed.Count+other.Count != all.Count {
		t.Errorf("segments sum to %d, want %d", succeeded.Count+failed.Count+other.Count, all.Count)
	}
	for _, row := range succeeded.Executions {
		if row.Outcome != "succeeded" {
			t.Errorf("row %s in the succeeded filter has outcome %q", row.ID, row.Outcome)
		}
	}
}

// TestAnalyticsExecutionsPlatformFilter covers clicking into one platform's own chart.
func TestAnalyticsExecutionsPlatformFilter(t *testing.T) {
	f := setupAnalyticsFixture(t)

	_, terraform := executionsGet(t, f, f.orgName, "?platform=terraform", f.member.ID)
	if terraform.Count != 9 {
		t.Errorf("terraform executions = %d, want 9", terraform.Count)
	}
	for _, row := range terraform.Executions {
		if row.Platform != "terraform" {
			t.Fatalf("platform=terraform returned an %s row", row.Platform)
		}
		if row.WorkspaceName == "" {
			t.Error("terraform row carries no workspace_name, so the UI cannot link to the run")
		}
	}

	_, ansible := executionsGet(t, f, f.orgName, "?platform=ansible&outcome=failed", f.member.ID)
	if ansible.Count != 2 {
		t.Errorf("failed ansible executions = %d, want 2 (failed + error)", ansible.Count)
	}
}

// TestAnalyticsExecutionsAuthzAndValidation keeps the drill-down behind the same wall as the
// aggregate, and rejects filter values it does not understand instead of widening the query.
func TestAnalyticsExecutionsAuthzAndValidation(t *testing.T) {
	f := setupAnalyticsFixture(t)

	if code, _ := executionsGet(t, f, f.orgName, "", f.outsider.ID); code != http.StatusForbidden {
		t.Errorf("outsider GET executions = %d, want 403", code)
	}
	if code, _ := executionsGet(t, f, f.orgName, "", uuid.Nil); code != http.StatusUnauthorized {
		t.Errorf("anon GET executions = %d, want 401", code)
	}
	if code, _ := executionsGet(t, f, f.orgName, "?outcome=bogus", f.member.ID); code != http.StatusBadRequest {
		t.Errorf("unknown outcome = %d, want 400", code)
	}
	if code, _ := executionsGet(t, f, f.orgName, "?platform=bogus", f.member.ID); code != http.StatusBadRequest {
		t.Errorf("unknown platform = %d, want 400", code)
	}
}

// TestAnalyticsExecutionsRespectTheWindow confirms the drill-down is bounded by the same window as
// the bar that opened it, so clicking one day never lists another day's work.
func TestAnalyticsExecutionsRespectTheWindow(t *testing.T) {
	f := setupAnalyticsFixture(t)

	// The seeded day lists everything...
	query := "?since=" + f.dayStart.Format(time.RFC3339) +
		"&until=" + f.dayStart.AddDate(0, 0, 1).Format(time.RFC3339)
	_, seeded := executionsGet(t, f, f.orgName, query, f.member.ID)
	if seeded.Count != 14 {
		t.Errorf("executions on the seeded day = %d, want 14", seeded.Count)
	}

	// ...and the next day lists none of it. Both windows are derived from the seeded day rather than
	// from "now", so the assertion does not depend on the time of day the suite runs.
	nextDay := "?since=" + f.dayStart.AddDate(0, 0, 1).Format(time.RFC3339) +
		"&until=" + f.dayStart.AddDate(0, 0, 2).Format(time.RFC3339)
	_, empty := executionsGet(t, f, f.orgName, nextDay, f.member.ID)
	if empty.Count != 0 {
		t.Errorf("executions on the day after the seeded one = %d, want 0", empty.Count)
	}
}

// TestAnalyticsExecutionsReportTruncation covers the boundary the drill-down cap sits on. A query
// that comes back exactly full is indistinguishable from one that had more to give, so the endpoint
// probes one row past the cap. Without that probe a day of 150 runs returns 100 rows and calls
// itself complete, which is the same species of confident-but-wrong number this page was rebuilt to
// remove.
func TestAnalyticsExecutionsReportTruncation(t *testing.T) {
	f := setupAnalyticsFixture(t)

	// Fill the seeded day past the cap. One batched insert, cleaned up by id prefix.
	const extra = 101
	bulk := make([]models.Run, 0, extra)
	prefix := "run-trunc" + uuid.NewString()[:4]
	for i := 0; i < extra; i++ {
		bulk = append(bulk, models.Run{
			ID:          fmt.Sprintf("%s%06d", prefix, i),
			WorkspaceID: f.wsID,
			Status:      models.RunStatusApplied,
			Operation:   models.RunOperationPlanAndApply,
			CreatedAt:   f.dayStart.Add(time.Duration(i) * time.Minute),
		})
	}
	if err := f.db.Create(&bulk).Error; err != nil {
		t.Fatalf("seed bulk runs: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("id LIKE ?", prefix+"%").Delete(&models.Run{})
	})

	query := "?since=" + f.dayStart.Format(time.RFC3339) +
		"&until=" + f.dayStart.AddDate(0, 0, 1).Format(time.RFC3339)

	_, all := executionsGet(t, f, f.orgName, query, f.member.ID)
	if all.Count != 100 {
		t.Errorf("executions count = %d, want the 100-row cap", all.Count)
	}
	if !all.Truncated {
		t.Error("a day holding more executions than the cap reported itself as complete")
	}

	// The Ansible side is well under the cap, so filtering to it must not inherit the flag.
	_, ansible := executionsGet(t, f, f.orgName, query+"&platform=ansible", f.member.ID)
	if ansible.Truncated {
		t.Errorf("ansible-only view (%d rows) reported truncation", ansible.Count)
	}
}

// TestAnalyticsPreviousPeriodIsDisjoint confirms the comparison window sits immediately before the
// requested one and does not double-count the current period's rows - the KPI deltas are meaningless
// if the two windows overlap.
func TestAnalyticsPreviousPeriodIsDisjoint(t *testing.T) {
	f := setupAnalyticsFixture(t)
	// Ask for the whole UTC day *after* the seeded one. The requested window then holds nothing and
	// its previous period is exactly the seeded day. Both bounds are derived from the seeded day
	// rather than from "now", because a window anchored to the current clock time only straddles the
	// seeded rows for part of the day - which is how this test passed in the morning and failed in
	// the afternoon.
	since := f.dayStart.AddDate(0, 0, 1)
	until := f.dayStart.AddDate(0, 0, 2)
	query := "?since=" + since.Format(time.RFC3339) + "&until=" + until.Format(time.RFC3339)

	_, attrs := analyticsGet(t, f, f.orgName, query, f.member.ID)
	if attrs.Runs.Total != 0 {
		t.Errorf("runs.total = %d for the day after the seeded one, want 0", attrs.Runs.Total)
	}
	if attrs.Runs.Previous.Total != 9 {
		t.Errorf("runs.previous.total = %d, want 9 (the preceding day holds the seeded rows)", attrs.Runs.Previous.Total)
	}
}
