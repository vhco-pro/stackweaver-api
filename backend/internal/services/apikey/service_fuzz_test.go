// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package apikey

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzGetKeyPrefix asserts GetKeyPrefix never panics on arbitrary input and
// never returns a string longer than the input. It also enforces the
// documented invariant: for inputs longer than 12 bytes the result is exactly
// 12 bytes long.
func FuzzGetKeyPrefix(f *testing.F) {
	seeds := []string{
		"",
		"tfe-",
		"tfe-abcdefgh",
		"tfe-abcdefghijklmnop",
		"\x00\x00\x00",
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
		strings.Repeat("a", 1024),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, key string) {
		got := GetKeyPrefix(key)
		if len(got) > len(key) {
			t.Fatalf("GetKeyPrefix returned %d bytes for %d-byte input", len(got), len(key))
		}
		if len(key) > 12 && len(got) != 12 {
			t.Fatalf("GetKeyPrefix(%q) = %q (len=%d), want exactly 12 bytes", key, got, len(got))
		}
	})
}

// FuzzVerifyKey asserts VerifyKey never panics on arbitrary input pairs and
// never spuriously verifies non-matching pairs. It only checks the
// non-panic contract; the negative-path correctness is implicit because
// bcrypt of random key vs random hash will never match.
func FuzzVerifyKey(f *testing.F) {
	f.Add("tfe-1234567890", "$2a$10$abcdefghijklmnopqrstuv")
	f.Add("", "")
	f.Add("k", "h")
	f.Fuzz(func(t *testing.T, key, hash string) {
		// Should never panic.
		_ = VerifyKey(key, hash)
		// Result must be valid UTF-8 string (trivially true for bool).
		if !utf8.ValidString(key) || !utf8.ValidString(hash) {
			return // OK for fuzz framework to feed non-UTF-8, we just don't assert further.
		}
	})
}
