// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package platformadmin

import (
	"slices"
	"testing"
)

// AC6, AC7: the declared list comes from STACKWEAVER_PLATFORM_ADMINS, falls back to the bootstrap
// admin's email in ZITADEL_ADMIN_USERNAME, is empty when both are unset, and matches addresses
// case-insensitively.
func TestDeclaredFromEnv(t *testing.T) {
	tests := []struct {
		name      string
		admins    string
		bootstrap string
		want      []string
	}{
		{"list", "ops@example.com,lead@example.com", "admin@zitadel.localhost", []string{"lead@example.com", "ops@example.com"}},
		{"list trimmed and lower-cased", "  Ops@Example.com , ,LEAD@example.com ", "", []string{"lead@example.com", "ops@example.com"}},
		{"duplicates collapse", "a@x.io,A@X.io", "", []string{"a@x.io"}},
		{"falls back to the bootstrap admin", "", "admin@ZITADEL.localhost", []string{"admin@zitadel.localhost"}},
		{"blank list falls back too", "  ,  ", "admin@stackweaver.local", []string{"admin@stackweaver.local"}},
		{"both unset", "", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("STACKWEAVER_PLATFORM_ADMINS", tt.admins)
			t.Setenv("ZITADEL_ADMIN_USERNAME", tt.bootstrap)
			got := DeclaredFromEnv()
			if !slices.Equal(got.Emails(), tt.want) {
				t.Errorf("DeclaredFromEnv().Emails() = %v, want %v", got.Emails(), tt.want)
			}
			if got.Empty() != (len(tt.want) == 0) {
				t.Errorf("Empty() = %v with %d addresses", got.Empty(), len(tt.want))
			}
		})
	}
}

// AC7: `admin@ZITADEL.localhost` in the list matches the human whose verified email is
// `admin@zitadel.localhost`, and the other way round.
func TestDeclaredContainsIsCaseInsensitive(t *testing.T) {
	d := NewDeclared([]string{"admin@ZITADEL.localhost"})
	for _, email := range []string{"admin@zitadel.localhost", "ADMIN@zitadel.LOCALHOST", " admin@zitadel.localhost "} {
		if !d.Contains(email) {
			t.Errorf("Contains(%q) = false, want true", email)
		}
	}
	for _, email := range []string{"", "admin@zitadel.localhost.evil", "other@zitadel.localhost"} {
		if d.Contains(email) {
			t.Errorf("Contains(%q) = true, want false", email)
		}
	}
}
