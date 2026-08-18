// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"strings"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// Team access reads follow the rule Terraform Enterprise documents identically for
// workspace team access and project team access:
//
//	"Any member of an organization can view team access relative to their own team
//	 memberships, including secret teams of which they are a member."
//	"Organization owners and workspace/project admins can modify team access or view
//	 the full set of secret team accesses."
//
// So listing is gated on organization membership, not on team-management permission,
// and a caller without that permission sees only the access rows they are entitled to:
// rows for organization-visible teams, plus rows for secret teams they belong to.
// Callers who can manage teams see every row.
//
// See docs/internal/plans/features/teams/TEAMS_IMPLEMENTATION_PLAN.md and issue #679.

// teamVisibilityOrganization is the one Team.Visibility value that exposes a team to
// the whole organization. Team.Visibility defaults to "secret" (TFE's default), so
// anything else - including an empty legacy value - is treated as secret.
const teamVisibilityOrganization = "organization"

// teamIsOrganizationVisible reports whether every member of the organization may see
// that this team exists. Fails closed: an unrecognised or empty visibility is secret.
func teamIsOrganizationVisible(team models.Team) bool {
	return strings.EqualFold(strings.TrimSpace(team.Visibility), teamVisibilityOrganization)
}

// callerTeamIDs returns the set of teams within an organization that a user belongs to.
// Used to decide which secret teams' access rows that user is allowed to see.
func callerTeamIDs(teamRepo *repository.TeamRepository, userID, orgID uuid.UUID) (map[uuid.UUID]bool, error) {
	teams, err := teamRepo.GetTeamsByUserID(userID, orgID)
	if err != nil {
		return nil, err
	}
	ids := make(map[uuid.UUID]bool, len(teams))
	for i := range teams {
		ids[teams[i].ID] = true
	}
	return ids, nil
}

// teamAccessVisible reports whether a caller may see an access row belonging to team.
// Pass isTeamAdmin=true for callers with team-management permission; they see everything.
func teamAccessVisible(team models.Team, memberOf map[uuid.UUID]bool, isTeamAdmin bool) bool {
	if isTeamAdmin {
		return true
	}
	if teamIsOrganizationVisible(team) {
		return true
	}
	return memberOf[team.ID]
}
