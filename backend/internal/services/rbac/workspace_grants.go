// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package rbac

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// WorkspaceGrants is one user's access in one organization, loaded with a fixed number of
// queries, from which the user's permissions on any of the organization's workspaces are
// answered in memory. It applies the rules of CheckResourcePermission (organization membership,
// the owners team, and the union of every team's organization, project and workspace access),
// of checkOrgPermission for "Manage workspaces", and of CheckWorkspaceAdminPermission, through
// the same mapping helpers, so a list of workspaces costs the same queries as one workspace.
//
// It is a snapshot for one request: grants changed after it was loaded are not seen.
type WorkspaceGrants struct {
	s         *Service
	inOrg     bool
	owner     bool
	orgPerms  map[Permission]bool                      // from the teams' organization access
	projects  map[uuid.UUID][]models.TeamProjectAccess // project id -> the teams' rows
	workspace map[string][]models.TeamWorkspaceAccess  // workspace id -> the teams' rows
}

// LoadWorkspaceGrants loads the user's grants in the organization.
func (s *Service) LoadWorkspaceGrants(_ context.Context, userID, organizationID uuid.UUID) (*WorkspaceGrants, error) {
	g := &WorkspaceGrants{
		s: s, orgPerms: map[Permission]bool{},
		projects: map[uuid.UUID][]models.TeamProjectAccess{}, workspace: map[string][]models.TeamWorkspaceAccess{},
	}
	inOrg, err := s.orgRepo.UserInOrg(userID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("checking membership of %s: %w", organizationID, err)
	}
	if !inOrg {
		return g, nil
	}
	g.inOrg = true
	if s.teamRepo == nil {
		return nil, fmt.Errorf("team repository not available")
	}
	teams, err := s.teamRepo.GetTeamsByUserID(userID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("getting teams of user %s: %w", userID, err)
	}
	if memberOfOwnersTeam(teams) {
		g.owner = true
		return g, nil
	}
	teamIDs := make([]uuid.UUID, 0, len(teams))
	for i := range teams {
		teamIDs = append(teamIDs, teams[i].ID)
		if teams[i].OrganizationAccess != nil {
			for p := range s.getPermissionsFromOrganizationAccess(teams[i].OrganizationAccess) {
				g.orgPerms[p] = true
			}
		}
	}
	projectRows, err := s.teamRepo.ListProjectAccessForTeams(teamIDs)
	if err != nil {
		return nil, fmt.Errorf("getting project access of user %s: %w", userID, err)
	}
	for _, pa := range projectRows {
		g.projects[pa.ProjectID] = append(g.projects[pa.ProjectID], pa)
	}
	workspaceRows, err := s.teamRepo.ListWorkspaceAccessForTeams(teamIDs)
	if err != nil {
		return nil, fmt.Errorf("getting workspace access of user %s: %w", userID, err)
	}
	for _, wa := range workspaceRows {
		g.workspace[wa.WorkspaceID] = append(g.workspace[wa.WorkspaceID], wa)
	}
	return g, nil
}

// InOrganization reports whether the user belongs to the organization.
func (g *WorkspaceGrants) InOrganization() bool { return g.inOrg }

// ManagesWorkspaces answers CheckOrgManageWorkspaces.
func (g *WorkspaceGrants) ManagesWorkspaces() bool {
	return g.inOrg && (g.owner || g.orgPerms[PermissionOrgManageWorkspaces])
}

// Has answers CheckWorkspacePermission for a workspace of the organization.
func (g *WorkspaceGrants) Has(projectID uuid.UUID, workspaceID string, permission Permission) bool {
	if !g.inOrg {
		return false
	}
	if g.owner || g.orgPerms[permission] {
		return true
	}
	for i := range g.projects[projectID] {
		if g.s.getPermissionsFromProjectAccess(&g.projects[projectID][i], ResourceTypeTerraformWorkspace)[permission] {
			return true
		}
	}
	for i := range g.workspace[workspaceID] {
		if g.s.getPermissionsFromWorkspaceAccess(&g.workspace[workspaceID][i])[permission] {
			return true
		}
	}
	return false
}

// IsWorkspaceAdmin answers CheckWorkspaceAdminPermission for a workspace of the organization.
func (g *WorkspaceGrants) IsWorkspaceAdmin(projectID uuid.UUID, workspaceID string) bool {
	if g.ManagesWorkspaces() {
		return true
	}
	for _, pa := range g.projects[projectID] {
		if pa.Access != nil && (*pa.Access == "admin" || *pa.Access == "maintain") {
			return true
		}
	}
	for _, wa := range g.workspace[workspaceID] {
		if wa.Access != nil && *wa.Access == "admin" {
			return true
		}
	}
	return false
}
