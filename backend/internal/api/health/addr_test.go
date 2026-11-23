// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package health

import "testing"

func TestListenAndProbeAddresses(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		wantListen string
		wantDial   string
		wantURL    string
	}{
		{"default wildcard", "0.0.0.0", "0.0.0.0:8022", "127.0.0.1:8022", "http://127.0.0.1:8022/readyz"},
		{"empty host", "", "0.0.0.0:8022", "127.0.0.1:8022", "http://127.0.0.1:8022/readyz"},
		{"bare IPv6 wildcard", "::", "[::]:8022", "[::1]:8022", "http://[::1]:8022/readyz"},
		{"bracketed IPv6 wildcard", "[::]", "[::]:8022", "[::1]:8022", "http://[::1]:8022/readyz"},
		{"bracketed IPv6 loopback", "[::1]", "[::1]:8022", "[::1]:8022", "http://[::1]:8022/readyz"},
		{"non-loopback IPv4", "10.1.2.3", "10.1.2.3:8022", "10.1.2.3:8022", "http://10.1.2.3:8022/readyz"},
		{"host name", "api.internal", "api.internal:8022", "api.internal:8022", "http://api.internal:8022/readyz"},
		{"scoped IPv6", "fe80::1%eth0", "[fe80::1%eth0]:8022", "[fe80::1%eth0]:8022", "http://[fe80::1%25eth0]:8022/readyz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ListenAddr(tc.host, 8022); got != tc.wantListen {
				t.Errorf("ListenAddr(%q) = %q, want %q", tc.host, got, tc.wantListen)
			}
			dial, err := ResolveProbeAddr(tc.host, 8022)
			if err != nil {
				t.Fatalf("ResolveProbeAddr(%q): %v", tc.host, err)
			}
			if dial != tc.wantDial {
				t.Errorf("ResolveProbeAddr(%q) = %q, want %q", tc.host, dial, tc.wantDial)
			}
			if got := ProbeURL(dial); got != tc.wantURL {
				t.Errorf("ProbeURL(%q) = %q, want %q", dial, got, tc.wantURL)
			}
		})
	}
}

func TestPortZero(t *testing.T) {
	if got := ListenAddr("0.0.0.0", 0); got != "0.0.0.0:0" {
		t.Errorf("ListenAddr with port 0 = %q, want 0.0.0.0:0", got)
	}
	if _, err := ResolveProbeAddr("0.0.0.0", 0); err == nil {
		t.Error("ResolveProbeAddr accepted port 0")
	}
}
