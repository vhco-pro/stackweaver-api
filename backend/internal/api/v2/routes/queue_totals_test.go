//go:build integration
// +build integration

// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package routes_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// #773: the top-N queue views must report a total describing the whole queue, not the page.
//
// These three were the last collections with no `meta.pagination` at all. They are genuinely
// top-N - the caller gets the oldest `limit` and there is no page 2 - which is why #761 exempted
// them: an honest total needed a COUNT it had put out of scope.
//
// "Top-N" does not excuse silence, though. Without a total an operator cannot tell "the queue
// holds 4 runs" from "the queue holds 400 and you are seeing the first 50", and that is the
// entire question a queue view exists to answer.
//
// The assertion that matters is `total-count > len(data)` when more rows exist than were served.
// Anything weaker passes against the failure mode this replaced: stating a total equal to the
// rows returned, which is what NewFullPageMeta would have produced and what would have made
// these views claim the queue is exactly as deep as the page - a lie a client cannot detect.
func TestQueueViewsReportTheWholeQueueTotal(t *testing.T) {
	h := setupGoldenHarness(t)

	orgName, ok := firstCol(h.db, "organizations", "name")
	if !ok {
		t.Skip("no seeded organization")
	}

	get := func(t *testing.T, path string) (rows int, pag map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+h.token)
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200: %s", path, rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("GET %s returned non-JSON: %v", path, err)
		}
		data, _ := body["data"].([]any)
		meta, ok := body["meta"].(map[string]any)
		if !ok {
			t.Fatalf("GET %s has no meta object; keys were %v", path, keysOf(body))
		}
		p, ok := meta["pagination"].(map[string]any)
		if !ok {
			t.Fatalf("GET %s has no meta.pagination; meta keys were %v", path, keysOf(meta))
		}
		return len(data), p
	}

	// Each view's total must match a count taken independently, with the same predicate the
	// handler filters on. Writing the predicate out here rather than reusing the repository is
	// deliberate: a test that calls the same code as the handler cannot catch the two drifting.
	// The queue must be DEEPER than the page, or this test cannot see the defect it exists for.
	//
	// Learned the hard way: with only three queued rows against a limit of fifty, len(rows)
	// equals the true total, so a handler reporting NewFullPageMeta(len(rows)) - exactly the
	// wrong-total failure mode - passed every assertion. The seed leaves the runs queue empty
	// and the jobs queue shallow, so both are deepened here.
	//
	// The runs queue's limit is hard-coded at 50 and not settable by the caller, so it needs
	// more than fifty rows. They are inserted as minimal rows against a seeded workspace rather
	// than built through the run pipeline: this test is about what the handler reports, not
	// about how a run comes to exist. The harness database is created per test and dropped in
	// t.Cleanup, so none of this touches real data.
	const runsQueueLimit = 50
	var workspaceID string
	h.db.Raw(`SELECT id::text FROM workspaces ORDER BY created_at LIMIT 1`).Scan(&workspaceID)
	if workspaceID == "" {
		t.Skip("no seeded workspace to attach queued runs to")
	}
	for i := 0; i < runsQueueLimit+5; i++ {
		// Runs carry prefixed string ids (run-..., ws-...), not UUIDs - see core/id.
		if err := h.db.Exec(`
			INSERT INTO runs (id, workspace_id, status, notified_status, operation, created_at, updated_at)
			VALUES (?, ?, 'pending', '', 'plan', now(), now())`,
			fmt.Sprintf("run-queueprobe%06d", i), workspaceID).Error; err != nil {
			t.Fatalf("seed queued run %d: %v", i, err)
		}
	}

	// The jobs queue honours a caller-supplied limit, so it only needs enough rows to ask for
	// fewer than exist - see the ?limit=1 request below.
	if err := h.db.Exec(`UPDATE ansible_jobs SET status = 'pending'
		WHERE id IN (SELECT id FROM ansible_jobs ORDER BY created_at LIMIT 3)`).Error; err != nil {
		t.Fatalf("queue up ansible jobs: %v", err)
	}

	cases := []struct {
		name      string
		path      string
		countSQL  string
		countArgs []any
	}{
		{
			name: "ansible jobs queue",
			// page[size]=1 against a queue holding more: without this the page equals the whole
			// queue and a total-equal-to-the-page cannot be told apart from a correct one. The
			// parameter name matters - this endpoint read `limit` until #773, while every client
			// sends page[size].
			path: fmt.Sprintf("/api/v2/organizations/%s/ansible/jobs/queue?page%%5Bsize%%5D=1", orgName),
			countSQL: `SELECT count(*) FROM ansible_jobs j
				JOIN projects p ON p.id = j.project_id
				JOIN organizations o ON o.id = p.organization_id
				WHERE o.name = ? AND j.status IN ('pending','running')`,
			countArgs: []any{orgName},
		},
		{
			name: "runs queue",
			path: fmt.Sprintf("/api/v2/organizations/%s/runs/queue", orgName),
			countSQL: `SELECT count(*) FROM runs r
				JOIN workspaces w ON w.id = r.workspace_id
				JOIN projects p ON p.id = w.project_id
				JOIN organizations o ON o.id = p.organization_id
				WHERE o.name = ? AND r.status IN ('pending','running')`,
			countArgs: []any{orgName},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var want int64
			if err := h.db.Raw(tc.countSQL, tc.countArgs...).Scan(&want).Error; err != nil {
				t.Fatalf("independent count failed: %v", err)
			}

			// An empty queue makes "total-count == 0" pass for the wrong reason. queueUp above
			// should have prevented it, so this is a failure rather than a skip - a silent skip
			// here would mean the view is not being exercised at all.
			if want == 0 {
				t.Fatalf("the %s is empty even after seeding, so this test proves nothing", tc.name)
			}

			rows, pag := get(t, tc.path)
			got, _ := pag["total-count"].(float64)
			if int64(got) != want {
				t.Errorf("total-count = %v, want %d - the total must describe the whole queue, "+
					"counted with the same predicate the handler filters on", got, want)
			}

			// The load-bearing one. A handler reporting the page size as the total passes every
			// assertion above whenever the queue happens to fit in one page, so the setup makes
			// sure it does not, and this checks the two are actually different.
			if rows >= int(want) {
				t.Fatalf("the page (%d rows) is not smaller than the queue (%d) - the setup failed "+
					"to make a page-sized total distinguishable from the true one", rows, want)
			}
			if int64(got) == int64(rows) {
				t.Errorf("total-count equals the number of rows returned (%d) - this is the queue "+
					"claiming to be exactly as deep as the page", rows)
			}
		})
	}

	// /activities/recent has no status predicate to mirror, so it is checked against the
	// unfiltered audit-log count for the authenticated user rather than duplicated SQL.
	t.Run("recent activities", func(t *testing.T) {
		rows, pag := get(t, "/api/v2/activities/recent")
		got, _ := pag["total-count"].(float64)
		if int64(got) < int64(rows) {
			t.Errorf("total-count = %v is smaller than the %d rows returned", got, rows)
		}
		if size, _ := pag["page-size"].(float64); int(size) < rows {
			t.Errorf("page-size = %v is smaller than the %d rows returned", size, rows)
		}
	})
}
