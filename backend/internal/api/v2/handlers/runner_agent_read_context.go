// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import "context"

// artifactReadContext keeps every configured artifact repository on the selected operation's
// context. Copies retain their existing scopes and configuration; the shared handler is unchanged.
func (h *RunnerAgentHandler) artifactReadContext(ctx context.Context) *RunnerAgentHandler {
	if h.db == nil {
		return h
	}
	scoped := *h
	scoped.db = h.db.WithContext(ctx)
	if h.runnerRepo != nil {
		scoped.runnerRepo = h.runnerRepo.WithContext(ctx)
	}
	if h.jobExecRepo != nil {
		scoped.jobExecRepo = h.jobExecRepo.WithContext(ctx)
	}
	if h.poolRepo != nil {
		scoped.poolRepo = h.poolRepo.WithContext(ctx)
	}
	if h.ansibleJobRepo != nil {
		scoped.ansibleJobRepo = h.ansibleJobRepo.WithContext(ctx)
	}
	if h.playbookRepo != nil {
		scoped.playbookRepo = h.playbookRepo.WithContext(ctx)
	}
	if h.inventoryRepo != nil {
		scoped.inventoryRepo = h.inventoryRepo.WithContext(ctx)
	}
	if h.credentialRepo != nil {
		scoped.credentialRepo = h.credentialRepo.WithContext(ctx)
	}
	if h.ansibleConfigRepo != nil {
		scoped.ansibleConfigRepo = h.ansibleConfigRepo.WithContext(ctx)
	}
	if h.azureOIDCRepo != nil {
		scoped.azureOIDCRepo = h.azureOIDCRepo.WithContext(ctx)
	}
	if h.awsOIDCRepo != nil {
		scoped.awsOIDCRepo = h.awsOIDCRepo.WithContext(ctx)
	}
	if h.gcpOIDCRepo != nil {
		scoped.gcpOIDCRepo = h.gcpOIDCRepo.WithContext(ctx)
	}
	if h.vaultOIDCRepo != nil {
		scoped.vaultOIDCRepo = h.vaultOIDCRepo.WithContext(ctx)
	}
	if h.inventoryService != nil {
		scoped.inventoryService = h.inventoryService.WithContext(ctx)
	}
	if h.workItems != nil {
		scoped.workItems = h.workItems.WithContext(ctx)
	}
	return &scoped
}
