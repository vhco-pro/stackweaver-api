// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package routes_test

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// brusselsZone is the process zone the timestamp tests re-run themselves in: east of UTC, so a
// value formatted in it without .UTC() names a different wall clock from the UTC one.
const brusselsZone = "Europe/Brussels"

// inProcessZone re-runs the calling test in a child process started with TZ=zone, because
// time.Local is fixed when a process starts, and reports whether the caller is that child. The
// parent passes or fails with the child. A caller skips first when it has no database, so the
// parent does not start a child just to skip.
func inProcessZone(t *testing.T, zone string) bool {
	t.Helper()
	if os.Getenv("TZ") == zone {
		if time.Local.String() != zone {
			t.Fatalf("time.Local is %q in a process started with TZ=%s", time.Local, zone)
		}
		return true
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.count=1") //nolint:gosec // G204: os.Args[0] is this test binary
	cmd.Env = append(os.Environ(), "TZ="+zone)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the test failed under TZ=%s: %v\n%s", zone, err, out)
	}
	t.Logf("passed under TZ=%s", zone)
	return false
}

func requireTestDatabase(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
}
