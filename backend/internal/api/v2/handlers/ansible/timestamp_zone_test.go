// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// cest is two hours east of UTC: the zone of a time.Now() in a process running in Brussels in
// summer, or of a next-run computed in a schedule's own zone.
var cest = time.FixedZone("CEST", 2*60*60)

// at returns the instant 2026-10-17T18:00:00Z plus offset, in CEST, and the UTC string the API
// must write for it.
func at(offset time.Duration) (*time.Time, string) {
	u := time.Date(2026, 10, 17, 18, 0, 0, 0, time.UTC).Add(offset)
	local := u.In(cest)
	return &local, u.Format("2006-01-02T15:04:05Z")
}

func check(t *testing.T, got map[string][2]string) {
	t.Helper()
	for name, g := range got {
		if g[0] != g[1] {
			t.Errorf("%s = %q, want %q", name, g[0], g[1])
		}
	}
}

// A schedule's timestamps are the UTC instants ending in Z, so the create response, which holds
// in-memory values in the process or schedule zone, writes what the read writes (utc-timestamps
// spec, AC2 and AC3).
func TestFormatScheduleResponse_TimestampsAreUTC(t *testing.T) {
	created, wantCreated := at(0)
	updated, wantUpdated := at(time.Minute)
	start, wantStart := at(time.Hour)
	end, wantEnd := at(48 * time.Hour)
	next, wantNext := at(9 * time.Hour)
	last, wantLast := at(-15 * time.Hour)
	attrs := formatScheduleResponse(&models.AnsibleSchedule{
		ID: uuid.New(), Name: "zone", CreatedAt: *created, UpdatedAt: *updated,
		StartDateTime: start, EndDateTime: end, NextRunAt: next, LastRunAt: last,
	}).Attributes
	check(t, map[string][2]string{
		"created-at":      {attrs.CreatedAt, wantCreated},
		"updated-at":      {attrs.UpdatedAt, wantUpdated},
		"start-date-time": {attrs.StartDateTime, wantStart},
		"end-date-time":   {attrs.EndDateTime, wantEnd},
		"next-run-at":     {attrs.NextRunAt, wantNext},
		"last-run-at":     {attrs.LastRunAt, wantLast},
	})
}

// A job's created-at and started-at name the instants the job was created and started, so the job
// page's duration for a running job is never negative (AC2, AC4).
func TestFormatJobResponse_TimestampsAreUTC(t *testing.T) {
	created, wantCreated := at(0)
	updated, wantUpdated := at(time.Minute)
	started, wantStarted := at(30 * time.Second)
	finished, wantFinished := at(5 * time.Minute)
	attrs := formatJobResponse(&models.AnsibleJob{
		ID: uuid.New(), Name: "zone", CreatedAt: *created, UpdatedAt: *updated,
		StartedAt: started, FinishedAt: finished,
	}).Attributes
	deref := func(s *string) string {
		if s == nil {
			return "<nil>"
		}
		return *s
	}
	check(t, map[string][2]string{
		"created-at":  {attrs.CreatedAt, wantCreated},
		"updated-at":  {attrs.UpdatedAt, wantUpdated},
		"started-at":  {deref(attrs.StartedAt), wantStarted},
		"finished-at": {deref(attrs.FinishedAt), wantFinished},
	})
}
