// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package runner

import (
	"testing"
	"time"
)

// OfflineAfter leaves room for several held heartbeats: the API holds one for up to 25 seconds
// (handlers.DefaultLongPollMax), and a launcher claims what it was offered before it polls again.
func TestOfflineAfterCoversSeveralHeartbeats(t *testing.T) {
	const longPollMax = 25 * time.Second
	if OfflineAfter < 3*longPollMax {
		t.Errorf("OfflineAfter = %s, want at least three long polls (%s)", OfflineAfter, 3*longPollMax)
	}
}
