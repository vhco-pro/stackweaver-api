// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-107 unit tests for the provider-upload path-segment sanitization. These are
// pure-function tests (no DB, no build tag) so they run in CI's plain `go test`.

package handlers

import "testing"

func TestSafeStorageFilename(t *testing.T) {
	ok := []string{
		"terraform-provider-test_1.0.0_linux_amd64.zip",
		"SHA256SUMS",
		"a.b-c_d.ZIP",
	}
	for _, name := range ok {
		if got, ok := safeStorageFilename(name); !ok || got != name {
			t.Errorf("safeStorageFilename(%q) = (%q, %v), want (%q, true)", name, got, ok, name)
		}
	}

	bad := []string{
		"",                         // empty
		".",                        // current dir
		"..",                       // traversal
		"../evil.zip",              // parent traversal
		"../../other-org/evil.zip", // deep traversal
		"sub/dir/evil.zip",         // separator
		`back\slash.zip`,           // windows separator
		"evil..zip",                // embedded ..
		"space file.zip",           // disallowed char
		"emoji😈.zip",               // disallowed char
	}
	for _, name := range bad {
		if got, ok := safeStorageFilename(name); ok {
			t.Errorf("safeStorageFilename(%q) = (%q, true), want ok=false", name, got)
		}
	}
}

func TestPlatformSegmentRE(t *testing.T) {
	ok := []string{"linux", "amd64", "arm64", "386", "freebsd", "solaris_amd64"}
	for _, s := range ok {
		if !platformSegmentRE.MatchString(s) {
			t.Errorf("platformSegmentRE rejected valid segment %q", s)
		}
	}
	bad := []string{"", "../evil", "linux/amd64", "AMD64", "a b", "arch;rm", ".."}
	for _, s := range bad {
		if platformSegmentRE.MatchString(s) {
			t.Errorf("platformSegmentRE accepted invalid segment %q", s)
		}
	}
}
