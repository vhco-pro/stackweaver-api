// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package apikey

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestCreateAPIKey_RejectsUnboundScopes verifies the single-org token invariant
// at creation: a key with no scopes, or with scopes that do not resolve to an
// organization, must be rejected. All of these cases return before any
// repository access, so a Service with nil repositories is sufficient.
func TestCreateAPIKey_RejectsUnboundScopes(t *testing.T) {
	svc := NewService(nil, nil, nil, nil)
	userID := uuid.New()

	cases := []struct {
		name   string
		scopes []string
		// wantErrContains is a substring expected in the returned error.
		wantErrContains string
	}{
		{
			name:            "nil scopes",
			scopes:          nil,
			wantErrContains: "at least one scope",
		},
		{
			name:            "empty scopes",
			scopes:          []string{},
			wantErrContains: "at least one scope",
		},
		{
			name:            "legacy bare permission",
			scopes:          []string{"read"},
			wantErrContains: "exactly one organization",
		},
		{
			name:            "user scope",
			scopes:          []string{"user:read"},
			wantErrContains: "exactly one organization",
		},
		{
			name:            "wildcard",
			scopes:          []string{"*"},
			wantErrContains: "wildcard scopes are not permitted",
		},
		{
			name:            "wildcard permission on org scope",
			scopes:          []string{"org:" + uuid.New().String() + ":*"},
			wantErrContains: "wildcard scopes are not permitted",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, plain, err := svc.CreateAPIKey(userID, "test-key", tc.scopes, nil)
			if err == nil {
				t.Fatalf("expected error for scopes %v, got nil (key=%v plain=%q)", tc.scopes, key, plain)
			}
			if key != nil || plain != "" {
				t.Fatalf("expected no key on rejection, got key=%v plain=%q", key, plain)
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrContains)
			}
		})
	}
}
