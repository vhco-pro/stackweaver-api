// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
)

// TestGrantsRunnerRegister pins who may register a runner: only a key that names
// runner:register on the pool's organization. A key with no scopes or the wildcard is a
// user's general-purpose token and must not join any organization's pool.
func TestGrantsRunnerRegister(t *testing.T) {
	orgA := uuid.New()
	orgB := uuid.New()

	cases := []struct {
		name   string
		scopes []string
		org    uuid.UUID
		want   bool
	}{
		{"no scopes", []string{}, orgA, false},
		{"wildcard", []string{"*"}, orgA, false},
		{"runner:register on the pool's org", []string{"org:" + orgA.String() + ":runner:register"}, orgA, true},
		{"runner:register on another org", []string{"org:" + orgB.String() + ":runner:register"}, orgA, false},
		{"read on the pool's org", []string{"org:" + orgA.String() + ":read"}, orgA, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checker, err := apikey.NewScopeChecker(tc.scopes)
			if err != nil {
				t.Fatalf("NewScopeChecker(%v): %v", tc.scopes, err)
			}
			if got := grantsRunnerRegister(checker, tc.org); got != tc.want {
				t.Errorf("grantsRunnerRegister(%v) = %v, want %v", tc.scopes, got, tc.want)
			}
		})
	}
}
