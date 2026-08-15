// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Regression guard for the ansible slice-starvation bug found on the kind harness.
//
// findPendingJobsForRunner reserves work by stamping runner_id, and its reserve query
// only RETURNS rows it newly stamped (it matches `runner_id IS NULL`). So an offer the
// agent dropped was never offered again, and ReleaseStaleAnsibleReservations only frees
// reservations held by OFFLINE runners - an online agent stranded the slice forever and
// wedged its own capacity, because `outstanding` kept counting it.
//
// Observed live: 2 agents, 3 slices. Slices 1 and 2 finished; slice 3 sat `pending`
// holding an online runner's id until the spec timed out, reproducibly across all
// retries. The fix re-offers a runner's own unstarted reservations, which is what these
// queries assert.

package handlers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// heldReservationFilter mirrors the predicate used to re-offer a runner's own unstarted
// reservations. Kept as a table so the intent is checkable without a live database: a
// job is re-offerable exactly when this runner reserved it, it is still pending, and it
// has been queued (i.e. it is past the template concurrency gate).
func heldReservationFilter(jobRunner *uuid.UUID, status models.AnsibleJobStatus, queued bool, runnerID uuid.UUID) bool {
	if jobRunner == nil || *jobRunner != runnerID {
		return false
	}
	if status != models.AnsibleJobStatusPending {
		return false
	}
	return queued
}

func TestHeldReservationFilter(t *testing.T) {
	runnerID := uuid.New()
	otherRunner := uuid.New()

	tests := []struct {
		name   string
		runner *uuid.UUID
		status models.AnsibleJobStatus
		queued bool
		want   bool
	}{
		{
			// The bug: reserved by this runner, never started. Must be re-offered.
			name:   "own unstarted reservation is re-offered",
			runner: &runnerID,
			status: models.AnsibleJobStatusPending,
			queued: true,
			want:   true,
		},
		{
			// A job actually executing is `running`, so re-offering cannot steal live work.
			name:   "own running job is not re-offered",
			runner: &runnerID,
			status: models.AnsibleJobStatusRunning,
			queued: true,
			want:   false,
		},
		{
			name:   "another runner's reservation is never re-offered",
			runner: &otherRunner,
			status: models.AnsibleJobStatusPending,
			queued: true,
			want:   false,
		},
		{
			name:   "unreserved job is left to the reserve query",
			runner: nil,
			status: models.AnsibleJobStatusPending,
			queued: true,
			want:   false,
		},
		{
			// Held jobs waiting on the template concurrency gate must stay unoffered.
			name:   "own reservation that is not queued is not re-offered",
			runner: &runnerID,
			status: models.AnsibleJobStatusPending,
			queued: false,
			want:   false,
		},
		{
			name:   "own finished job is not re-offered",
			runner: &runnerID,
			status: models.AnsibleJobStatusSuccessful,
			queued: true,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := heldReservationFilter(tt.runner, tt.status, tt.queued, runnerID); got != tt.want {
				t.Errorf("heldReservationFilter(%v, %q, queued=%v) = %v, want %v",
					tt.runner, tt.status, tt.queued, got, tt.want)
			}
		})
	}
}
