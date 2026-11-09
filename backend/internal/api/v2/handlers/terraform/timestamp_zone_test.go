// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/models"
)

// cest is two hours east of UTC, the zone a value carries when it never touched the database (a
// time.Now() in a process running in Brussels in summer).
var cest = time.FixedZone("CEST", 2*60*60)

// at returns the instant 2026-10-17T18:00:00Z plus offset, in CEST, and the UTC string the API
// must write for it.
func at(offset time.Duration) (*time.Time, string) {
	u := time.Date(2026, 10, 17, 18, 0, 0, 0, time.UTC).Add(offset)
	local := u.In(cest)
	return &local, u.Format("2006-01-02T15:04:05Z")
}

// A run's created-at, updated-at and every status-timestamps member is the UTC instant ending in
// Z, whatever zone the value carries (utc-timestamps spec, AC2 and AC5). go-tfe parses
// created-at with a literal-Z layout, so a local wall clock followed by a Z is read as a different
// instant.
func TestFormatRunResponse_TimestampsAreUTC(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	created, wantCreated := at(0)
	updated, wantUpdated := at(5 * time.Minute)
	started, wantStarted := at(10 * time.Second)
	planned, wantPlanned := at(40 * time.Second)
	applying, wantApplying := at(50 * time.Second)
	completed, wantCompleted := at(90 * time.Second)

	run := &models.Run{
		ID: "run-zone-test", WorkspaceID: "ws-zone-test",
		Operation: models.RunOperationPlanAndApply, Status: models.RunStatusApplied,
		CreatedAt: *created, UpdatedAt: *updated,
		StartedAt: started, PlanCompletedAt: planned, ApplyStartedAt: applying, CompletedAt: completed,
	}
	attrs := formatRunResponse(run, c, nil, nil).Attributes
	for name, got := range map[string][2]string{
		"created-at":   {attrs.CreatedAt, wantCreated},
		"updated-at":   {attrs.UpdatedAt, wantUpdated},
		"started-at":   {attrs.StartedAt, wantStarted},
		"completed-at": {attrs.CompletedAt, wantCompleted},
		"planning-at":  {attrs.StatusTimestamps.PlanningAt, wantStarted},
		"planned-at":   {attrs.StatusTimestamps.PlannedAt, wantPlanned},
		"applying-at":  {attrs.StatusTimestamps.ApplyingAt, wantApplying},
		"applied-at":   {attrs.StatusTimestamps.AppliedAt, wantCompleted},
	} {
		if got[0] != got[1] {
			t.Errorf("%s = %q, want %q", name, got[0], got[1])
		}
	}

	pending := &models.Run{ID: "run-zone-pending", WorkspaceID: "ws-zone-test", Status: models.RunStatusPending, CreatedAt: *created, UpdatedAt: *created}
	if got := formatRunResponse(pending, c, nil, nil).Attributes.StatusTimestamps.PlanQueuedAt; got != wantCreated {
		t.Errorf("plan-queued-at = %q, want %q", got, wantCreated)
	}
}

// A workspace's created-at, updated-at, latest-change-at and locked-at are the UTC instants
// ending in Z (AC2, AC5).
func TestFormatWorkspaceResponse_TimestampsAreUTC(t *testing.T) {
	created, wantCreated := at(0)
	updated, wantUpdated := at(time.Hour)
	locked, wantLocked := at(2 * time.Hour)
	ws := &models.Workspace{ID: "ws-zone-test", Name: "zone", CreatedAt: *created, UpdatedAt: *updated, Locked: true, LockedAt: locked}
	attrs := formatWorkspaceResponse(ws).Attributes
	for name, got := range map[string][2]string{
		"created-at":       {attrs.CreatedAt, wantCreated},
		"updated-at":       {attrs.UpdatedAt, wantUpdated},
		"latest-change-at": {attrs.LatestChangeAt, wantUpdated},
		"locked-at":        {attrs.LockedAt, wantLocked},
	} {
		if got[0] != got[1] {
			t.Errorf("%s = %q, want %q", name, got[0], got[1])
		}
	}
}
