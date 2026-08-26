// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// tfe_organization policy hooks for the VCS webhook paths. The org-level flags consulted here
// (speculative_plan_management_enabled, aggregated_commit_status_enabled,
// send_passing_statuses_for_untriggered_speculative_plans) are specced in
// docs/internal/tfe-compatibility/resources/organizations/tfe_organization.md.

// orgForWorkspace resolves the owning organization of a workspace for the tfe_organization policy
// checks on the webhook paths. The webhook workspace queries (FindByVCSRepositoryAndBranch, and the
// installation filters) already preload Project.Organization, so the common path reads the preloaded
// chain with no extra query; it falls back to a fetch only when the chain is not populated. Returns
// nil only when the org genuinely cannot be resolved.
func (h *VCSAppInstallationHandlerV2) orgForWorkspace(ws *models.Workspace) *models.Organization {
	if ws != nil && ws.Project.Organization.ID != (uuid.UUID{}) {
		org := ws.Project.Organization
		return &org
	}
	id := ""
	if ws != nil {
		id = ws.ID
	}
	fetched, err := h.workspaceRepo.GetByID(id)
	if err != nil || fetched.Project.Organization.ID == (uuid.UUID{}) {
		return nil
	}
	org := fetched.Project.Organization
	return &org
}

// splitUntriggeredWorkspaces returns the members of candidates that are absent from triggered -
// the connected, speculative-enabled workspaces that path filtering skipped for this delivery.
func splitUntriggeredWorkspaces(candidates, triggered []models.Workspace) []models.Workspace {
	triggeredIDs := make(map[string]bool, len(triggered))
	for i := range triggered {
		triggeredIDs[triggered[i].ID] = true
	}
	skipped := make([]models.Workspace, 0, len(candidates))
	for i := range candidates {
		if !triggeredIDs[candidates[i].ID] {
			skipped = append(skipped, candidates[i])
		}
	}
	return skipped
}

// postUntriggeredPassingStatuses posts a passing GitHub commit status for workspaces path
// filtering skipped, when their org opts in via
// send_passing_statuses_for_untriggered_speculative_plans - so required checks don't block PRs
// that never touch a workspace's paths.
func (h *VCSAppInstallationHandlerV2) postUntriggeredPassingStatuses(ctx context.Context, skipped []models.Workspace, sha string) {
	if h.statusService == nil || len(skipped) == 0 {
		return
	}
	for i := range skipped {
		ws := skipped[i]
		org := h.orgForWorkspace(&ws)
		if org == nil || !org.SendPassingStatusesForUntriggeredSpeculativePlans {
			continue
		}
		if ws.VCSConnectionID == nil || ws.VCSRepository == "" {
			continue
		}
		vcsConn, err := h.vcsConnectionRepo.GetByID(*ws.VCSConnectionID)
		if err != nil || vcsConn == nil || vcsConn.InstallationID == "" {
			continue
		}
		parts := strings.SplitN(ws.VCSRepository, "/", 2)
		if len(parts) != 2 {
			continue
		}
		statusContext := fmt.Sprintf("terraform-plan/%s", ws.Name)
		if err := h.statusService.CreateStatusCheck(ctx, vcsConn.InstallationID, parts[0], parts[1], sha,
			statusContext, vcs.StatusStateSuccess, "Plan not required - no matching changes", ""); err != nil {
			logger.Warnf("Failed to post passing status for untriggered workspace %s: %v", ws.ID, err)
		} else {
			logger.Infof("Posted passing status for untriggered workspace %s (commit %s)", ws.ID, sha)
		}
	}
}

// postUntriggeredPassingStatusesADO is the Azure DevOps counterpart of
// postUntriggeredPassingStatuses (ADO statuses attach to the PR, not the commit).
func (h *VCSAppInstallationHandlerV2) postUntriggeredPassingStatusesADO(ctx context.Context, skipped []models.Workspace, prNumber int) {
	if h.adoStatusService == nil || len(skipped) == 0 || prNumber <= 0 {
		return
	}
	for i := range skipped {
		ws := skipped[i]
		org := h.orgForWorkspace(&ws)
		if org == nil || !org.SendPassingStatusesForUntriggeredSpeculativePlans {
			continue
		}
		if ws.VCSConnectionID == nil || ws.VCSRepository == "" {
			continue
		}
		vcsConn, err := h.vcsConnectionRepo.GetByID(*ws.VCSConnectionID)
		if err != nil || vcsConn == nil {
			continue
		}
		parts := strings.SplitN(ws.VCSRepository, "/", 2)
		if len(parts) != 2 {
			continue
		}
		token := vcsConn.AccessToken
		if h.vcsRegistry != nil {
			if provider, pErr := h.vcsRegistry.GetProvider(vcsConn); pErr == nil {
				if fresh, tErr := provider.GetFreshToken(ctx, vcsConn); tErr == nil {
					token = fresh
				}
			}
		}
		statusContext := fmt.Sprintf("terraform-plan/%s", ws.Name)
		if err := h.adoStatusService.CreateOrUpdatePRStatus(ctx, token, vcsConn.AccountName, parts[0], parts[1],
			prNumber, vcs.StatusStateSuccess, statusContext, "Plan not required - no matching changes", ""); err != nil {
			logger.Warnf("Failed to post passing ADO status for untriggered workspace %s: %v", ws.ID, err)
		}
	}
}
