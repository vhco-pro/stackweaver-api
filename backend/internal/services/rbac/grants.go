// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package rbac

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// teamGrants is what a caller's teams hold in one organization: each team's organization access
// (preloaded on the team) and the project and workspace access rows bearing on the resources
// judged. CheckResourcePermission loads the rows for one resource; a listing loads every row of
// the teams once. Both judge through permits, so a listing and a check of one of its
// items cannot disagree.
type teamGrants struct {
	teams     []models.Team
	project   map[uuid.UUID]map[uuid.UUID]*models.TeamProjectAccess // team, then project
	workspace map[uuid.UUID]map[string]*models.TeamWorkspaceAccess  // team, then workspace
}

func newTeamGrants(teams []models.Team) *teamGrants {
	return &teamGrants{
		teams:     teams,
		project:   make(map[uuid.UUID]map[uuid.UUID]*models.TeamProjectAccess, len(teams)),
		workspace: make(map[uuid.UUID]map[string]*models.TeamWorkspaceAccess, len(teams)),
	}
}

func (g *teamGrants) addProject(a *models.TeamProjectAccess) {
	if g.project[a.TeamID] == nil {
		g.project[a.TeamID] = map[uuid.UUID]*models.TeamProjectAccess{}
	}
	g.project[a.TeamID][a.ProjectID] = a
}

func (g *teamGrants) addWorkspace(a *models.TeamWorkspaceAccess) {
	if g.workspace[a.TeamID] == nil {
		g.workspace[a.TeamID] = map[string]*models.TeamWorkspaceAccess{}
	}
	g.workspace[a.TeamID][a.WorkspaceID] = a
}

// grantsFor loads the teams' grants bearing on one resource of one project.
func (s *Service) grantsFor(teams []models.Team, projectID uuid.UUID, resourceType ResourceType, resourceID string) *teamGrants {
	g := newTeamGrants(teams)
	for _, team := range teams {
		if pa, err := s.teamRepo.GetProjectAccessByTeamAndProject(team.ID, projectID); err == nil && pa != nil {
			g.addProject(pa)
		}
		if resourceID != "" && resourceType == ResourceTypeTerraformWorkspace {
			if wa, err := s.teamRepo.GetWorkspaceAccessByTeamAndWorkspace(team.ID, resourceID); err == nil && wa != nil {
				g.addWorkspace(wa)
			}
		}
	}
	return g
}

// allGrants loads every project and workspace grant the teams hold.
func (s *Service) allGrants(teams []models.Team) (*teamGrants, error) {
	g := newTeamGrants(teams)
	for _, team := range teams {
		full, err := s.teamRepo.GetByID(team.ID)
		if err != nil {
			return nil, fmt.Errorf("getting grants of team %s: %w", team.ID, err)
		}
		for i := range full.ProjectAccess {
			g.addProject(&full.ProjectAccess[i])
		}
		for i := range full.WorkspaceAccess {
			g.addWorkspace(&full.WorkspaceAccess[i])
		}
	}
	return g, nil
}

// permits reports whether the teams' grants allow permission on one resource of projectID. The
// owners team holds every permission whatever access rows it has, judged by memberOfOwnersTeam as
// the organization-level check judges it. CheckResourcePermission and a listing both decide here.
func (s *Service) permits(g *teamGrants, resourceType ResourceType, resourceID string, projectID uuid.UUID, permission Permission) bool {
	if memberOfOwnersTeam(g.teams) {
		return true
	}
	return s.resourcePermissions(g, resourceType, resourceID, projectID)[permission]
}

// resourcePermissions is the union of what the teams' organization, project and workspace access
// grant on one resource of projectID. The workspace leg applies to a workspace only.
func (s *Service) resourcePermissions(g *teamGrants, resourceType ResourceType, resourceID string, projectID uuid.UUID) map[Permission]bool {
	all := make(map[Permission]bool)
	for _, team := range g.teams {
		if orgAccess := team.OrganizationAccess; orgAccess != nil {
			for perm := range s.getPermissionsFromOrganizationAccess(orgAccess) {
				all[perm] = true
			}
		}
		if pa := g.project[team.ID][projectID]; pa != nil {
			for perm := range s.getPermissionsFromProjectAccess(pa, resourceType) {
				all[perm] = true
			}
		}
		if resourceID != "" && resourceType == ResourceTypeTerraformWorkspace {
			if wa := g.workspace[team.ID][resourceID]; wa != nil {
				for perm := range s.getPermissionsFromWorkspaceAccess(wa) {
					all[perm] = true
				}
			}
		}
	}
	return all
}

// ReadableWorkspaces returns the candidate workspaces of orgID on which the caller holds
// permission, each judged exactly as CheckResourcePermission judges it alone. It applies to every
// caller, a user, a team token or a project token, so a listing holds exactly what its single
// reads return.
func (s *Service) ReadableWorkspaces(ctx context.Context, userID, orgID uuid.UUID, candidates []models.Workspace, permission Permission) ([]models.Workspace, error) {
	keep, err := s.readable(ctx, userID, orgID, len(candidates), func(i int) (ResourceType, string, uuid.UUID) {
		return ResourceTypeTerraformWorkspace, candidates[i].ID, candidates[i].ProjectID
	}, permission)
	if err != nil {
		return nil, err
	}
	out := make([]models.Workspace, 0, len(candidates))
	for i := range candidates {
		if keep[i] {
			out = append(out, candidates[i])
		}
	}
	return out, nil
}

// ReadableProjects is ReadableWorkspaces for the read of projects.
func (s *Service) ReadableProjects(ctx context.Context, userID, orgID uuid.UUID, candidates []models.Project) ([]models.Project, error) {
	keep, err := s.readable(ctx, userID, orgID, len(candidates), func(i int) (ResourceType, string, uuid.UUID) {
		return ResourceTypeProject, candidates[i].ID.String(), candidates[i].ID
	}, PermissionProjectRead)
	if err != nil {
		return nil, err
	}
	out := make([]models.Project, 0, len(candidates))
	for i := range candidates {
		if keep[i] {
			out = append(out, candidates[i])
		}
	}
	return out, nil
}

// ReadsWholeOrganization reports whether organization-level permissions, as
// OrgPermissionsForOrganizations resolves them, read every workspace, project and Ansible resource
// of the organization, so that a roll-up of it need not be narrowed. It agrees with
// resourcePermissions: each permission it requires grants its read on every resource of the
// organization.
func ReadsWholeOrganization(perms map[Permission]bool) bool {
	for _, p := range []Permission{
		PermissionOrgReadWorkspaces, PermissionOrgReadProjects, PermissionOrgReadAnsible,
		PermissionAnsiblePlaybookRead, PermissionAnsibleJobRead, PermissionAnsibleJobTemplateRead, PermissionAnsibleInventoryRead,
	} {
		if !perms[p] {
			return false
		}
	}
	return true
}

// AddDashboardScope adds to scope what the caller can read in orgID, as the dashboard counts it:
// the workspaces and projects it can read, and for each Ansible kind the projects it can read that
// kind in, each judged as a single read is, so the counts cannot disagree with the listings.
func (s *Service) AddDashboardScope(ctx context.Context, userID, orgID uuid.UUID, workspaces []models.Workspace, projects []models.Project, scope *repository.DashboardScope) error {
	readableWorkspaces, err := s.ReadableWorkspaces(ctx, userID, orgID, workspaces, PermissionWorkspaceRead)
	if err != nil {
		return err
	}
	readableProjects, err := s.ReadableProjects(ctx, userID, orgID, projects)
	if err != nil {
		return err
	}
	for i := range readableWorkspaces {
		scope.WorkspaceIDs = append(scope.WorkspaceIDs, readableWorkspaces[i].ID)
	}
	for i := range readableProjects {
		scope.ProjectIDs = append(scope.ProjectIDs, readableProjects[i].ID)
	}
	for _, kind := range []struct {
		resourceType ResourceType
		permission   Permission
		into         *[]uuid.UUID
	}{
		{ResourceTypeAnsiblePlaybook, PermissionAnsiblePlaybookRead, &scope.PlaybookProjectIDs},
		{ResourceTypeAnsibleJob, PermissionAnsibleJobRead, &scope.JobProjectIDs},
		{ResourceTypeAnsibleJobTemplate, PermissionAnsibleJobTemplateRead, &scope.TemplateProjectIDs},
		{ResourceTypeAnsibleInventory, PermissionAnsibleInventoryRead, &scope.InventoryProjectIDs},
	} {
		keep, err := s.readable(ctx, userID, orgID, len(projects), func(i int) (ResourceType, string, uuid.UUID) {
			return kind.resourceType, "", projects[i].ID
		}, kind.permission)
		if err != nil {
			return err
		}
		for i := range projects {
			if keep[i] {
				*kind.into = append(*kind.into, projects[i].ID)
			}
		}
	}
	// An inventory that belongs to no project is read on the organization-level Ansible read.
	orgInventories, err := s.CheckOrgReadAnsible(ctx, userID, orgID)
	if err != nil {
		return err
	}
	if orgInventories {
		scope.OrgInventoryOrgIDs = append(scope.OrgInventoryOrgIDs, orgID)
	}
	return nil
}

// readable follows CheckResourcePermission step for step: a project-scoped key's cap, the
// membership check, the teams, then resourcePermissions, with the grants loaded once for all items.
func (s *Service) readable(ctx context.Context, userID, orgID uuid.UUID, n int, item func(int) (ResourceType, string, uuid.UUID), permission Permission) ([]bool, error) {
	keep := make([]bool, n)
	subj, _ := subjectFrom(ctx)
	projectKey := subj.kind == subjectProject
	evalCtx := ctx
	if projectKey {
		evalCtx = withoutSubject(ctx)
	}
	in, err := s.inOrg(evalCtx, userID, orgID)
	if err != nil || !in {
		return keep, nil //nolint:nilerr // not a member: nothing is readable, as in CheckResourcePermission
	}
	teams, err := s.teamsOf(evalCtx, userID, orgID)
	if err != nil {
		return nil, fmt.Errorf("getting teams of user %s: %w", userID, err)
	}
	g, err := s.allGrants(teams)
	if err != nil {
		return nil, err
	}
	for i := range keep {
		resourceType, resourceID, projectID := item(i)
		if projectKey && !subj.projectScopeAllows(permission, &projectID) {
			continue
		}
		keep[i] = s.permits(g, resourceType, resourceID, projectID, permission)
	}
	return keep, nil
}
