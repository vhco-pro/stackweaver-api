// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package runner

import (
	"testing"

	"github.com/michielvha/stackweaver/core/runnercontract"
)

// OfflineAfter leaves room for several held heartbeats: the API holds one for up to 25 seconds
// (handlers.DefaultLongPollMax), and a launcher claims what it was offered before it polls again.
func TestOfflineAfterCoversSeveralHeartbeats(t *testing.T) {
	const longPollMax = runnercontract.DefaultHeartbeatWait
	if OfflineAfter < 3*longPollMax {
		t.Errorf("OfflineAfter = %s, want at least three long polls (%s)", OfflineAfter, 3*longPollMax)
	}
}

func TestRecoveryGraceCoversAHeartbeatAndMaximumBackoff(t *testing.T) {
	const heartbeatTimeout = runnercontract.DefaultHeartbeatWait + runnercontract.HeartbeatRequestOverhead
	const backoffWithJitter = runnercontract.LauncherBackoffMax + runnercontract.LauncherBackoffMax/4
	if RecoveryGrace < heartbeatTimeout+backoffWithJitter {
		t.Errorf("RecoveryGrace = %s, want at least heartbeat %s plus backoff %s", RecoveryGrace, heartbeatTimeout, backoffWithJitter)
	}
}
