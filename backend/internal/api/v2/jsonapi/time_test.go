// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package jsonapi

import (
	"testing"
	"time"
)

// For a UTC input the helper writes the bytes the former literal-Z layout wrote, which is what
// go-tfe's iso8601 attributes parse; for any other zone it writes the UTC instant, where the old
// layout wrote the local wall clock followed by a Z.
func TestFormatTime(t *testing.T) {
	utc := time.Date(2026, 10, 17, 18, 4, 5, 123456789, time.UTC)
	if got, want := FormatTime(utc), utc.Format("2006-01-02T15:04:05Z"); got != want {
		t.Errorf("FormatTime(UTC) = %q, want the literal-Z layout's %q", got, want)
	}

	cest := time.Date(2026, 10, 17, 20, 4, 5, 987654321, time.FixedZone("CEST", 2*60*60))
	if got, want := FormatTime(cest), "2026-10-17T18:04:05Z"; got != want {
		t.Errorf("FormatTime(+02:00) = %q, want the UTC instant in whole seconds %q", got, want)
	}

	if got := FormatTimePtr(nil); got != nil {
		t.Errorf("FormatTimePtr(nil) = %q, want nil", *got)
	}
	if got := FormatTimePtr(&cest); got == nil || *got != "2026-10-17T18:04:05Z" {
		t.Errorf("FormatTimePtr(+02:00) = %v, want the UTC instant", got)
	}
}
