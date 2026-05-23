// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import "testing"

// TestIsLocalhostOrigin pins Round 24 Finding 2's host-boundary
// anchor — the previous prefix check (`origin[:16] == "http://
// localhost"`) accepted `http://localhost.evil.com` because there
// was no delimiter. Combined with `Allow-Credentials: true` an
// attacker who tricks a victim into navigating to a `localhost.<a>`
// host could pivot into the auth proxy with cookies attached. The
// fix anchors on a `:`/`/`/end-of-string boundary after the host.
func TestIsLocalhostOrigin(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		want   bool
	}{
		// Accepted shapes — exact host, host:port, host/path
		{"localhost no port", "http://localhost", true},
		{"localhost with port 5173", "http://localhost:5173", true},
		{"localhost with port 3000", "http://localhost:3000", true},
		{"localhost with path", "http://localhost/some-path", true},
		{"127.0.0.1 no port", "http://127.0.0.1", true},
		{"127.0.0.1 with port", "http://127.0.0.1:8080", true},
		{"IPv6 localhost no port", "http://[::1]", true},
		{"IPv6 localhost with port", "http://[::1]:5173", true},

		// THE FINDING — these used to be accepted, now rejected
		{"R24-2: localhost.evil.com", "http://localhost.evil.com", false},
		{"R24-2: localhost.evil.com:1234", "http://localhost.evil.com:1234", false},
		{"R24-2: localhostevil (no dot)", "http://localhostevil", false},
		{"R24-2: 127.0.0.1.evil.com", "http://127.0.0.1.evil.com", false},
		{"R24-2: [::1].evil.com", "http://[::1].evil.com", false},

		// Other shapes that should be rejected
		{"https localhost (we only allow http here)", "https://localhost", false},
		{"https localhost with port", "https://localhost:5173", false},
		{"localhost as path under another domain", "http://evil.com/localhost", false},
		{"empty origin", "", false},
		{"random domain", "http://example.com", false},
		{"trailing junk after host", "http://localhost?q=1", false}, // Origin headers don't carry queries; reject defensively
		{"trailing junk after host (#)", "http://localhost#frag", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isLocalhostOrigin(tc.origin)
			if got != tc.want {
				t.Errorf("isLocalhostOrigin(%q) = %v, want %v", tc.origin, got, tc.want)
			}
		})
	}
}
