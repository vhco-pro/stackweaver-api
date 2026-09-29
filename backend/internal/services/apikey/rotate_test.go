// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package apikey

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// TestRotateAgentToken_RejectsInvalidInput covers the guards that run before any repository
// access: only a pool-bound agent token can be rotated, and the grace window is bounded so a
// "rotated" credential cannot be kept alive indefinitely. A Service with nil repositories is
// sufficient because every case returns before touching one.
func TestRotateAgentToken_RejectsInvalidInput(t *testing.T) {
	svc := NewService(nil, nil, nil, nil)
	pool, org := uuid.New(), uuid.New()
	agent := &models.APIKey{ID: uuid.New(), IsAgentToken: true, AgentPoolID: &pool, OrganizationID: &org}

	cases := []struct {
		name  string
		key   *models.APIKey
		grace time.Duration
	}{
		{"ordinary org key", &models.APIKey{ID: uuid.New(), OrganizationID: &org}, time.Hour},
		{"agent token without pool", &models.APIKey{ID: uuid.New(), IsAgentToken: true, OrganizationID: &org}, time.Hour},
		{"negative grace", agent, -time.Minute},
		{"grace above cap", agent, MaxAgentTokenRotationGrace + time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := svc.RotateAgentToken(uuid.New(), tc.key, tc.grace); err == nil {
				t.Fatal("RotateAgentToken() error = nil, want rejection")
			}
		})
	}
}
