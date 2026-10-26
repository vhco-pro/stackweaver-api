// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"slices"
	"testing"
)

// This file pinned ExtractUserInfo, which read the email, its verification and the SSO groups of
// a JWT bearer on every request, calling Zitadel's userinfo when the token lacked them. The bearer
// path is gone (backend-for-frontend-session-plan.md, AC32): the profile and email_verified come
// from the ID token at sign-in (TestCreateBrowserSession_EmailVerifiedComesOnlyFromTheClaim) and
// the groups from the access token verified there, read by ssoGroups below.

// The complement-token action writes sso_groups as an array of strings; anything else in it is
// ignored rather than trusted.
func TestSSOGroups(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		want   []string
	}{
		{"groups", map[string]any{"sso_groups": []any{"platform", "sre"}}, []string{"platform", "sre"}},
		{"no claim", map[string]any{"sub": "u1"}, nil},
		{"not an array", map[string]any{"sso_groups": "platform"}, nil},
		{"non-strings and empties dropped", map[string]any{"sso_groups": []any{"platform", 7, "", nil}}, []string{"platform"}},
	}
	for _, tc := range cases {
		if got := ssoGroups(tc.claims); !slices.Equal(got, tc.want) {
			t.Errorf("%s: ssoGroups = %v, want %v", tc.name, got, tc.want)
		}
	}
}
