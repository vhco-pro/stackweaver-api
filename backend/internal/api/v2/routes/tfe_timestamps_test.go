// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// go-tfe reads the instants Stackweaver stored, from an API process outside UTC (utc-timestamps
// spec, AC5). go-tfe v1.112.0 parses a run's and a workspace's created-at with the layout
// "2006-01-02T15:04:05Z", which accepts only a literal Z, and every status-timestamps member
// with RFC 3339. A handler that formats with the literal-Z layout in a process outside UTC
// writes the local wall clock followed by a Z, which go-tfe reads as a different instant.
//
// It runs against the golden harness's throwaway database, which is dropped afterwards.
//
//	go test -tags integration ./internal/api/v2/routes/ -run TestTFETimestamps

//go:build integration

package routes_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	tfe "github.com/hashicorp/go-tfe"
)

func TestTFETimestamps_GoTFEReadsStoredInstants(t *testing.T) {
	requireTestDatabase(t)
	if !inProcessZone(t, brusselsZone) {
		return
	}
	h := setupGoldenHarness(t)
	srv := httptest.NewServer(h.router)
	t.Cleanup(srv.Close)
	client, err := tfe.NewClient(&tfe.Config{Address: srv.URL, Token: h.token, RetryServerErrors: false})
	if err != nil {
		t.Fatalf("go-tfe client: %v", err)
	}
	ctx := context.Background()

	// stored reads one timestamp column of one row. The harness opens the database through
	// core/dbconn, so the value is the stored instant whatever the process zone.
	stored := func(t *testing.T, table, column, id string) *time.Time {
		t.Helper()
		var v *time.Time
		if err := h.db.Table(table).Select(column).Where("id = ?", id).Scan(&v).Error; err != nil {
			t.Fatalf("reading %s.%s of %s: %v", table, column, id, err)
		}
		return v
	}
	// same compares what go-tfe parsed with what is stored, to the second the API writes.
	same := func(t *testing.T, what string, got time.Time, want *time.Time) {
		t.Helper()
		if want == nil {
			t.Fatalf("%s: nothing stored", what)
		}
		if w := want.Truncate(time.Second); !got.Equal(w) {
			t.Errorf("%s: go-tfe read %s, stored instant is %s", what, got.UTC(), w.UTC())
		}
	}

	t.Run("workspace create and read", func(t *testing.T) {
		ws, err := client.Workspaces.Create(ctx, "demo", tfe.WorkspaceCreateOptions{
			Name: tfe.String("utc-ts-" + uuid.NewString()[:8]),
		})
		if err != nil {
			t.Fatalf("Workspaces.Create: %v", err)
		}
		same(t, "create created-at", ws.CreatedAt, stored(t, "workspaces", "created_at", ws.ID))
		same(t, "create updated-at", ws.UpdatedAt, stored(t, "workspaces", "updated_at", ws.ID))

		read, err := client.Workspaces.ReadByID(ctx, ws.ID)
		if err != nil {
			t.Fatalf("Workspaces.ReadByID: %v", err)
		}
		same(t, "read created-at", read.CreatedAt, stored(t, "workspaces", "created_at", ws.ID))
		same(t, "read updated-at", read.UpdatedAt, stored(t, "workspaces", "updated_at", ws.ID))

		run, err := client.Runs.Create(ctx, tfe.RunCreateOptions{Workspace: ws})
		if err != nil {
			t.Fatalf("Runs.Create: %v", err)
		}
		created := stored(t, "runs", "created_at", run.ID)
		same(t, "run create created-at", run.CreatedAt, created)
		if run.Status == tfe.RunPending {
			same(t, "run create plan-queued-at", run.StatusTimestamps.PlanQueuedAt, created)
		}

		again, err := client.Runs.Read(ctx, run.ID)
		if err != nil {
			t.Fatalf("Runs.Read: %v", err)
		}
		same(t, "run read created-at", again.CreatedAt, created)
		if again.Status == tfe.RunPending {
			same(t, "run read plan-queued-at", again.StatusTimestamps.PlanQueuedAt, created)
		}
	})

	t.Run("applied run read", func(t *testing.T) {
		// A seeded plan-and-apply run that went the whole way. The default seed profile leaves
		// the two middle phase columns empty, so they are filled here, in the throwaway database,
		// so that every phase member is set.
		var id string
		if err := h.db.Raw(`SELECT id::text FROM runs
			WHERE status = 'applied' AND operation = 'plan-and-apply'
			  AND started_at IS NOT NULL AND completed_at IS NOT NULL
			ORDER BY id LIMIT 1`).Scan(&id).Error; err != nil || id == "" {
			t.Fatalf("no seeded applied run: %v", err)
		}
		if err := h.db.Exec(`UPDATE runs SET plan_completed_at = started_at + interval '30 seconds',
			apply_started_at = started_at + interval '40 seconds' WHERE id = ?`, id).Error; err != nil {
			t.Fatalf("filling the phase columns: %v", err)
		}
		run, err := client.Runs.Read(ctx, id)
		if err != nil {
			t.Fatalf("Runs.Read: %v", err)
		}
		same(t, "created-at", run.CreatedAt, stored(t, "runs", "created_at", id))
		ts := run.StatusTimestamps
		same(t, "planning-at", ts.PlanningAt, stored(t, "runs", "started_at", id))
		same(t, "planned-at", ts.PlannedAt, stored(t, "runs", "plan_completed_at", id))
		same(t, "applying-at", ts.ApplyingAt, stored(t, "runs", "apply_started_at", id))
		same(t, "applied-at", ts.AppliedAt, stored(t, "runs", "completed_at", id))
	})
}
