// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

// jobIdentity is the identity a job would be issued now: its resolved binding when the pool offers
// it, nil for the platform identity. It records nothing; attemptIdentity decides what a token
// carries (#1113, D3).
func (h *RunnerAgentHandler) jobIdentity(kind models.JobType, jobID string, pool *uuid.UUID) (*runnercontract.Identity, error) {
	b, _, err := h.jobBinding(kind, jobID, pool)
	if err != nil || b == nil {
		return nil, err
	}
	return tokenIdentity(bindingSnapshot(b)), nil
}
