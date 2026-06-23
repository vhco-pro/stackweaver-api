// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import "testing"

// TestSliceLogBytes covers the byte-offset/limit window applied to logs read in full
// from object storage (agent mode and the Redis→storage fallback). These are TFE
// semantics: offset/limit are byte positions, and an offset at/beyond the end yields an
// empty slice ("no new bytes yet") rather than an out-of-range panic. The previous
// implementation re-checked `offset >= len(logs)` against the already-windowed length,
// which wrongly returned empty for incremental polls — this guards against that.
func TestSliceLogBytes(t *testing.T) {
	const full = "alpha\nbeta\ngamma\n" // 17 bytes

	cases := []struct {
		name   string
		in     string
		offset int
		limit  int
		want   string
	}{
		{"no window returns all", full, 0, 0, full},
		{"negative offset treated as none", full, -5, 0, full},
		{"byte offset returns tail", full, 6, 0, "beta\ngamma\n"},
		{"offset mid-line not rounded", full, 2, 0, "pha\nbeta\ngamma\n"},
		{"limit clamps window", full, 0, 5, "alpha"},
		{"offset plus limit", full, 6, 4, "beta"},
		{"offset plus limit beyond end clamps", full, 11, 100, "gamma\n"},
		{"offset at final byte returns it", full, 16, 0, "\n"},
		{"offset at end is empty", full, 17, 0, ""},
		{"offset beyond end is empty", full, 999, 0, ""},
		{"empty input stays empty", "", 0, 0, ""},
		{"empty input with offset stays empty", "", 10, 5, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(sliceLogBytes([]byte(tc.in), tc.offset, tc.limit))
			if got != tc.want {
				t.Fatalf("sliceLogBytes(%q, %d, %d) = %q, want %q", tc.in, tc.offset, tc.limit, got, tc.want)
			}
		})
	}
}
