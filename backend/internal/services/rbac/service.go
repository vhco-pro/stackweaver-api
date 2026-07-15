// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package rbac

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

type Service struct {
	orgRepo     *repository.OrganizationRepository
	teamRepo    *repository.TeamRepository
	projectRepo *repository.ProjectRepository
}

func NewService(orgRepo *repository.OrganizationRepository) *Service {
	return &Service{
		orgRepo: orgRepo,
	}
}

// NewServiceWithTeams creates a new RBAC service with team support
func NewServiceWithTeams(orgRepo *repository.OrganizationRepository, teamRepo *repository.TeamRepository, projectRepo *repository.ProjectRepository) *Service {
	return &Service{
		orgRepo:     orgRepo,
		teamRepo:    teamRepo,
		projectRepo: projectRepo,
	}
}

// ResourceType represents the type of resource being checked
type ResourceType string

const (
	ResourceTypeTerraformWorkspace ResourceType = "terraform:workspace"
	ResourceTypeAnsiblePlaybook    ResourceType = "ansible:playbook"
	ResourceTypeAnsibleInventory   ResourceType = "ansible:inventory"
	ResourceTypeAnsibleCredential  ResourceType = "ansible:credential" //nolint:gosec // false positive: string constant, not actual credential
	ResourceTypeAnsibleJobTemplate ResourceType = "ansible:job-template"
	ResourceTypeAnsibleJob         ResourceType = "ansible:job"
	ResourceTypeAnsibleSchedule    ResourceType = "ansible:schedule"
	ResourceTypeVariableSet        ResourceType = "terraform:variable-set"
)

type Permission string

const (
	// Organization permissions (legacy - kept for backward compatibility)
	PermissionOrgRead  Permission = "org:read"
	PermissionOrgWrite Permission = "org:write"
	PermissionOrgAdmin Permission = "org:admin"

	// Fine-grained organization permissions (TFE-compatible)
	PermissionOrgManageMembership         Permission = "org:manage-membership"          // Manage organization memberships (add/remove users, change roles)
	PermissionOrgManageTeams              Permission = "org:manage-teams"               // Create/update/delete teams
	PermissionOrgManageOrganizationAccess Permission = "org:manage-organization-access" // Manage team organization access permissions
	PermissionOrgManageProjects           Permission = "org:manage-projects"            // Create/update/delete projects
	PermissionOrgManageWorkspaces         Permission = "org:manage-workspaces"          // Create/update/delete workspaces
	PermissionOrgReadWorkspaces           Permission = "org:read-workspaces"            // Read workspaces
	PermissionOrgReadProjects             Permission = "org:read-projects"              // Read projects
	PermissionOrgManageVCSSettings        Permission = "org:manage-vcs-settings"        // Manage VCS connections
	PermissionOrgManageProviders          Permission = "org:manage-providers"           // Manage provider registrations
	PermissionOrgManageModules            Permission = "org:manage-modules"             // Manage module registrations
	PermissionOrgManagePolicies           Permission = "org:manage-policies"            // Manage Sentinel policies
	PermissionOrgManagePolicyOverrides    Permission = "org:manage-policy-overrides"    // Manage policy overrides
	PermissionOrgManageRunTasks           Permission = "org:manage-run-tasks"           // Manage run tasks
	PermissionOrgAccessSecretTeams        Permission = "org:access-secret-teams"        //nolint:gosec // false positive: string constant, not actual credential
	PermissionOrgManageAgentPools         Permission = "org:manage-agent-pools"         // Manage agent pools
	PermissionOrgManageAnsible            Permission = "org:manage-ansible"             // Manage all Ansible resources (playbooks, inventories, credentials, job templates, jobs, schedules)
	PermissionOrgReadAnsible              Permission = "org:read-ansible"               // Read all Ansible resources

	// Project permissions
	PermissionProjectRead  Permission = "project:read"
	PermissionProjectWrite Permission = "project:write"

	// Terraform workspace permissions
	PermissionWorkspaceRead  Permission = "workspace:read"
	PermissionWorkspaceWrite Permission = "workspace:write"
	PermissionRunRead        Permission = "run:read"
	PermissionRunWrite       Permission = "run:write"

	// Terraform granular permissions (from team access)
	PermissionStateVersions    Permission = "state_versions"
	PermissionVariables        Permission = "variables"
	PermissionRuns             Permission = "runs"
	PermissionSentinelMocks    Permission = "sentinel_mocks"
	PermissionWorkspaceLocking Permission = "workspace_locking"
	PermissionRunTasks         Permission = "run_tasks"
	// Variable set permissions mirror TFE's project "Manage variable sets" (none/read/write).
	PermissionVariableSetsRead Permission = "variable_sets_read"
	PermissionVariableSets     Permission = "variable_sets" // write/manage

	// Ansible permissions (StackWeaver-specific)
	PermissionAnsiblePlaybookRead     Permission = "ansible:playbook:read"
	PermissionAnsiblePlaybookWrite    Permission = "ansible:playbook:write"
	PermissionAnsibleInventoryRead    Permission = "ansible:inventory:read"
	PermissionAnsibleInventoryWrite   Permission = "ansible:inventory:write"
	PermissionAnsibleCredentialRead   Permission = "ansible:credential:read"  //nolint:gosec // false positive: string constant, not actual credential
	PermissionAnsibleCredentialWrite  Permission = "ansible:credential:write" //nolint:gosec // false positive: string constant, not actual credential
	PermissionAnsibleJobTemplateRead  Permission = "ansible:job-template:read"
	PermissionAnsibleJobTemplateWrite Permission = "ansible:job-template:write"
	PermissionAnsibleJobRead          Permission = "ansible:job:read"
	PermissionAnsibleJobExecute       Permission = "ansible:job:execute"
	PermissionAnsibleAdHocExecute     Permission = "ansible:adhoc:execute" // Run ad hoc commands against inventories (AWX adhoc_role)
	PermissionAnsibleScheduleRead     Permission = "ansible:schedule:read"
	PermissionAnsibleScheduleWrite    Permission = "ansible:schedule:write"
)

// CheckResourcePermission checks if a user has permission for a specific resource
// NEW MODEL: Pure team-based additive permission resolution
// Resolution: Org membership check → Collect ALL permissions from ALL teams → Union (additive)
func (s *Service) CheckResourcePermission(
	ctx context.Context,
	userID uuid.UUID,
	resourceType ResourceType,
	resourceID string, // Can be workspace ID (string) or UUID for other resources
	permission Permission,
	projectID *uuid.UUID, // Optional: project ID if resource belongs to a project
) (bool, error) {
	// Get organization ID from project
	var organizationID uuid.UUID
	if projectID == nil {
		// For resources without projects, we need to get org from resource
		// This will be implemented per resource type as needed
		return false, fmt.Errorf("project ID required for resource permission check")
	}

	project, err := s.projectRepo.GetByID(*projectID)
	if err != nil {
		return false, fmt.Errorf("failed to get project: %w", err)
	}
	organizationID = project.OrganizationID

	// 1. Tenant isolation: User must have at least one team in the org (team-based access)
	inOrg, err := s.orgRepo.UserInOrg(userID, organizationID)
	if err != nil || !inOrg {
		return false, nil // Not in any team in org = no access
	}

	// 2. Collect ALL permissions from ALL team memberships (additive model)
	allPermissions := make(map[Permission]bool)

	if s.teamRepo == nil {
		return false, fmt.Errorf("team repository not available")
	}

	// Get all teams user is member of in this organization
	teams, err := s.teamRepo.GetTeamsByUserID(userID, organizationID)
	if err != nil {
		return false, fmt.Errorf("failed to get user teams: %w", err)
	}

	// Collect permissions from each team
	for _, team := range teams {
		// Team organization access permissions (org-level permissions)
		// GetTeamsByUserID already preloads OrganizationAccess, so use it directly
		if team.OrganizationAccess != nil {
			teamOrgPerms := s.getPermissionsFromOrganizationAccess(team.OrganizationAccess)
			for perm := range teamOrgPerms {
				allPermissions[perm] = true
			}
		}

		// Team project access permissions (if projectID provided)
		if projectID != nil {
			projectAccess, err := s.teamRepo.GetProjectAccessByTeamAndProject(team.ID, *projectID)
			if err == nil && projectAccess != nil {
				teamProjectPerms := s.getPermissionsFromProjectAccess(projectAccess, resourceType)
				for perm := range teamProjectPerms {
					allPermissions[perm] = true
				}
			}
		}

		// Team workspace/resource-specific access (overrides project access for this specific resource)
		if resourceID != "" && resourceType == ResourceTypeTerraformWorkspace {
			workspaceAccess, err := s.teamRepo.GetWorkspaceAccessByTeamAndWorkspace(team.ID, resourceID)
			if err == nil && workspaceAccess != nil {
				teamWorkspacePerms := s.getPermissionsFromWorkspaceAccess(workspaceAccess)
				for perm := range teamWorkspacePerms {
					allPermissions[perm] = true
				}
			}
		}
	}

	// 3. Check if permission is in union
	return allPermissions[permission], nil
}

// TeamAnsibleTemplateAccess summarizes one team's effective permissions on an
// Ansible job template (org-level access merged with project-level access).
type TeamAnsibleTemplateAccess struct {
	TeamID   uuid.UUID `json:"team_id"`
	TeamName string    `json:"team_name"`
	Read     bool      `json:"read"`
	Write    bool      `json:"write"`
	Execute  bool      `json:"execute"`
}

// GetTeamAccessForAnsibleTemplate returns every team in the org that has any
// effective permission on a job template in the given project. Read-only
// visibility for the template Access tab; enforcement stays in the Check*
// methods (see RBAC_MASTER_PLAN for per-resource grants).
// TeamWithWorkspaceAccess identifies a team that can reach a given workspace.
type TeamWithWorkspaceAccess struct {
	TeamID   uuid.UUID
	TeamName string
}

// ListTeamsWithWorkspaceAccess returns every team in the organization that can reach the given
// workspace, which is the audience for a change_request:created notification
// (tfe_team_notification_configuration applies "to all workspaces that the configured team has access
// to").
//
// Access is a UNION of four independent sources, and there is no table to join for it:
//
//  1. the owners team, which bypasses permission checks by name
//  2. org-wide access (TeamOrganizationAccess manage/read workspaces), which reaches EVERY workspace
//  3. project access on the workspace's parent project, which reaches every workspace in it
//  4. a direct TeamWorkspaceAccess grant on the workspace itself
//
// Missing any leg silently under-notifies. In particular TeamRepository.GetWorkspaceAccess covers only
// leg 4, so using it alone would miss the project-level grants that are the common case in TFE-style
// setups. The per-leg permission mapping is delegated to the same helpers the permission checks use, so
// this cannot drift from what access actually means.
//
// Note leg 2 is deliberately broad: a team with org-wide read is notified about every change request in
// the organization. That is TFE's semantics, not an accident.
func (s *Service) ListTeamsWithWorkspaceAccess(orgID, projectID uuid.UUID, workspaceID string) ([]TeamWithWorkspaceAccess, error) {
	if s.teamRepo == nil {
		return nil, fmt.Errorf("team repository not available")
	}
	teams, _, err := s.teamRepo.List(orgID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to list teams: %w", err)
	}
	out := make([]TeamWithWorkspaceAccess, 0, len(teams))
	for i := range teams {
		team := &teams[i]
		if s.teamReachesWorkspace(team, projectID, workspaceID) {
			out = append(out, TeamWithWorkspaceAccess{TeamID: team.ID, TeamName: team.Name})
		}
	}
	return out, nil
}

// teamReachesWorkspace reports whether any of the four access legs gives this team read or write on the
// workspace. Ordered cheapest-first: the owners check and the preloaded org access need no query.
func (s *Service) teamReachesWorkspace(team *models.Team, projectID uuid.UUID, workspaceID string) bool {
	reaches := func(perms map[Permission]bool) bool {
		return perms[PermissionWorkspaceRead] || perms[PermissionWorkspaceWrite]
	}

	// 1. owners bypass (same by-name rule checkOrgPermission and IsOrgOwner use).
	if team.Name == "owners" {
		return true
	}

	// 2. org-wide access. OrganizationAccess is preloaded by TeamRepository.List.
	if team.OrganizationAccess != nil && reaches(s.getPermissionsFromOrganizationAccess(team.OrganizationAccess)) {
		return true
	}

	// 3. project access on the workspace's parent project.
	if pa, err := s.teamRepo.GetProjectAccessByTeamAndProject(team.ID, projectID); err == nil && pa != nil {
		if reaches(s.getPermissionsFromProjectAccess(pa, ResourceTypeTerraformWorkspace)) {
			return true
		}
	}

	// 4. a direct grant on the workspace.
	if wa, err := s.teamRepo.GetWorkspaceAccessByTeamAndWorkspace(team.ID, workspaceID); err == nil && wa != nil {
		if reaches(s.getPermissionsFromWorkspaceAccess(wa)) {
			return true
		}
	}

	return false
}

func (s *Service) GetTeamAccessForAnsibleTemplate(orgID, projectID uuid.UUID) ([]TeamAnsibleTemplateAccess, error) {
	if s.teamRepo == nil {
		return nil, fmt.Errorf("team repository not available")
	}
	teams, _, err := s.teamRepo.List(orgID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to list teams: %w", err)
	}
	result := make([]TeamAnsibleTemplateAccess, 0, len(teams))
	for i := range teams {
		team := &teams[i]
		perms := map[Permission]bool{}
		if team.OrganizationAccess != nil {
			for perm := range s.getPermissionsFromOrganizationAccess(team.OrganizationAccess) {
				perms[perm] = true
			}
		}
		if projectAccess, err := s.teamRepo.GetProjectAccessByTeamAndProject(team.ID, projectID); err == nil && projectAccess != nil {
			for perm := range s.getPermissionsFromProjectAccess(projectAccess, ResourceTypeAnsibleJobTemplate) {
				perms[perm] = true
			}
		}
		access := TeamAnsibleTemplateAccess{
			TeamID:   team.ID,
			TeamName: team.Name,
			Read:     perms[PermissionAnsibleJobTemplateRead],
			Write:    perms[PermissionAnsibleJobTemplateWrite],
			Execute:  perms[PermissionAnsibleJobExecute],
		}
		if access.Read || access.Write || access.Execute {
			result = append(result, access)
		}
	}
	return result, nil
}

// getPermissionsFromOrganizationAccess extracts all permissions from team organization access
func (s *Service) getPermissionsFromOrganizationAccess(orgAccess *models.TeamOrganizationAccess) map[Permission]bool {
	perms := make(map[Permission]bool)

	// Map organization access fields to permissions
	if orgAccess.ManagePolicies {
		perms[PermissionOrgManagePolicies] = true
	}
	if orgAccess.ManagePolicyOverrides {
		perms[PermissionOrgManagePolicyOverrides] = true
	}
	if orgAccess.ManageWorkspaces {
		perms[PermissionOrgManageWorkspaces] = true
		// ManageWorkspaces implies all workspace-level permissions (TFE-compatible: "Manage all workspaces" grants full access)
		// This matches the behavior described in TFE docs: "Manage all workspaces" is the most permissive level
		perms[PermissionOrgReadWorkspaces] = true
		perms[PermissionWorkspaceRead] = true
		perms[PermissionWorkspaceWrite] = true
		perms[PermissionRunRead] = true
		perms[PermissionRunWrite] = true
		perms[PermissionVariables] = true
		perms[PermissionStateVersions] = true
		perms[PermissionRuns] = true
		perms[PermissionSentinelMocks] = true
		perms[PermissionWorkspaceLocking] = true
		perms[PermissionRunTasks] = true
	}
	if orgAccess.ManageVCSSettings {
		perms[PermissionOrgManageVCSSettings] = true
	}
	if orgAccess.ManageProviders {
		perms[PermissionOrgManageProviders] = true
	}
	if orgAccess.ManageModules {
		perms[PermissionOrgManageModules] = true
	}
	if orgAccess.ManageRunTasks {
		perms[PermissionOrgManageRunTasks] = true
	}
	if orgAccess.ManageProjects {
		perms[PermissionOrgManageProjects] = true
		// ManageProjects implies ReadProjects (if you can manage projects, you can read them)
		perms[PermissionOrgReadProjects] = true
		perms[PermissionProjectRead] = true
		// TFE: "Manage all projects" also manages project-owned variable sets.
		perms[PermissionVariableSets] = true
		perms[PermissionVariableSetsRead] = true
	}
	if orgAccess.ReadWorkspaces {
		perms[PermissionOrgReadWorkspaces] = true
		perms[PermissionWorkspaceRead] = true // Implies workspace read
	}
	if orgAccess.ReadProjects {
		perms[PermissionOrgReadProjects] = true
		perms[PermissionProjectRead] = true // Implies project read
		perms[PermissionVariableSetsRead] = true
	}
	if orgAccess.ManageMembership {
		perms[PermissionOrgManageMembership] = true
	}
	if orgAccess.ManageTeams {
		perms[PermissionOrgManageTeams] = true
	}
	if orgAccess.ManageOrganizationAccess {
		perms[PermissionOrgManageOrganizationAccess] = true
	}
	if orgAccess.AccessSecretTeams {
		perms[PermissionOrgAccessSecretTeams] = true
	}
	if orgAccess.ManageAgentPools {
		perms[PermissionOrgManageAgentPools] = true
	}
	if orgAccess.ManageAnsible {
		// Parent toggle: ManageAnsible grants ALL Ansible resource permissions
		perms[PermissionOrgManageAnsible] = true
		perms[PermissionOrgReadAnsible] = true
		perms[PermissionAnsiblePlaybookRead] = true
		perms[PermissionAnsiblePlaybookWrite] = true
		perms[PermissionAnsibleInventoryRead] = true
		perms[PermissionAnsibleInventoryWrite] = true
		perms[PermissionAnsibleCredentialRead] = true
		perms[PermissionAnsibleCredentialWrite] = true
		perms[PermissionAnsibleJobTemplateRead] = true
		perms[PermissionAnsibleJobTemplateWrite] = true
		perms[PermissionAnsibleJobRead] = true
		perms[PermissionAnsibleJobExecute] = true
		perms[PermissionAnsibleAdHocExecute] = true
		perms[PermissionAnsibleScheduleRead] = true
		perms[PermissionAnsibleScheduleWrite] = true
	}
	if orgAccess.ReadAnsible {
		// Parent toggle: ReadAnsible grants ALL Ansible read permissions
		perms[PermissionOrgReadAnsible] = true
		perms[PermissionAnsiblePlaybookRead] = true
		perms[PermissionAnsibleInventoryRead] = true
		perms[PermissionAnsibleCredentialRead] = true
		perms[PermissionAnsibleJobTemplateRead] = true
		perms[PermissionAnsibleJobRead] = true
		perms[PermissionAnsibleScheduleRead] = true
	}

	// Fine-grained per-resource Ansible permissions
	// These are independent of the parent toggles above — a team can have
	// ManageAnsible=false but ManageAnsiblePlaybooks=true to only manage playbooks.
	if orgAccess.ManageAnsiblePlaybooks {
		perms[PermissionAnsiblePlaybookRead] = true
		perms[PermissionAnsiblePlaybookWrite] = true
		perms[PermissionOrgReadAnsible] = true // implied: can list org-scoped playbooks
	}
	if orgAccess.ReadAnsiblePlaybooks {
		perms[PermissionAnsiblePlaybookRead] = true
		perms[PermissionOrgReadAnsible] = true
	}
	if orgAccess.ManageAnsibleInventories {
		perms[PermissionAnsibleInventoryRead] = true
		perms[PermissionAnsibleInventoryWrite] = true
		perms[PermissionOrgReadAnsible] = true
	}
	if orgAccess.ReadAnsibleInventories {
		perms[PermissionAnsibleInventoryRead] = true
		perms[PermissionOrgReadAnsible] = true
	}
	if orgAccess.ManageAnsibleCredentials {
		perms[PermissionAnsibleCredentialRead] = true
		perms[PermissionAnsibleCredentialWrite] = true
		perms[PermissionOrgReadAnsible] = true
	}
	if orgAccess.ReadAnsibleCredentials {
		perms[PermissionAnsibleCredentialRead] = true
		perms[PermissionOrgReadAnsible] = true
	}
	if orgAccess.ManageAnsibleJobTemplates {
		perms[PermissionAnsibleJobTemplateRead] = true
		perms[PermissionAnsibleJobTemplateWrite] = true
		perms[PermissionOrgReadAnsible] = true
	}
	if orgAccess.ReadAnsibleJobTemplates {
		perms[PermissionAnsibleJobTemplateRead] = true
		perms[PermissionOrgReadAnsible] = true
	}
	if orgAccess.ManageAnsibleJobs {
		perms[PermissionAnsibleJobRead] = true
		perms[PermissionAnsibleJobExecute] = true
		perms[PermissionAnsibleAdHocExecute] = true
		perms[PermissionOrgReadAnsible] = true
	}
	if orgAccess.ReadAnsibleJobs {
		perms[PermissionAnsibleJobRead] = true
		perms[PermissionOrgReadAnsible] = true
	}
	if orgAccess.ManageAnsibleSchedules {
		perms[PermissionAnsibleScheduleRead] = true
		perms[PermissionAnsibleScheduleWrite] = true
		perms[PermissionOrgReadAnsible] = true
	}
	if orgAccess.ReadAnsibleSchedules {
		perms[PermissionAnsibleScheduleRead] = true
		perms[PermissionOrgReadAnsible] = true
	}

	return perms
}

// getPermissionsFromProjectAccess extracts all permissions from team project access
func (s *Service) getPermissionsFromProjectAccess(projectAccess *models.TeamProjectAccess, resourceType ResourceType) map[Permission]bool {
	perms := make(map[Permission]bool)

	if projectAccess.Access != nil {
		accessLevel := *projectAccess.Access
		switch accessLevel {
		case "admin":
			// Admin has all permissions
			perms[PermissionProjectRead] = true
			perms[PermissionProjectWrite] = true
			perms[PermissionWorkspaceRead] = true
			perms[PermissionWorkspaceWrite] = true
			perms[PermissionRunRead] = true
			perms[PermissionRunWrite] = true
			perms[PermissionVariables] = true
			perms[PermissionStateVersions] = true
			perms[PermissionRuns] = true
			perms[PermissionSentinelMocks] = true
			perms[PermissionWorkspaceLocking] = true
			perms[PermissionRunTasks] = true
			// Ansible permissions: admin gets full access to all Ansible resources in the project
			perms[PermissionAnsiblePlaybookRead] = true
			perms[PermissionAnsiblePlaybookWrite] = true
			perms[PermissionAnsibleInventoryRead] = true
			perms[PermissionAnsibleInventoryWrite] = true
			perms[PermissionAnsibleCredentialRead] = true
			perms[PermissionAnsibleCredentialWrite] = true
			perms[PermissionAnsibleJobTemplateRead] = true
			perms[PermissionAnsibleJobTemplateWrite] = true
			perms[PermissionAnsibleJobRead] = true
			perms[PermissionAnsibleJobExecute] = true
			perms[PermissionAnsibleAdHocExecute] = true
			perms[PermissionAnsibleScheduleRead] = true
			perms[PermissionAnsibleScheduleWrite] = true
		case "maintain", "write":
			// Write has write permissions
			perms[PermissionProjectRead] = true
			perms[PermissionProjectWrite] = true
			perms[PermissionWorkspaceRead] = true
			perms[PermissionWorkspaceWrite] = true
			perms[PermissionRunRead] = true
			perms[PermissionRunWrite] = true
			perms[PermissionVariables] = true
			perms[PermissionStateVersions] = true
			perms[PermissionRuns] = true
			perms[PermissionWorkspaceLocking] = true
			perms[PermissionRunTasks] = true
			// Ansible permissions: write/maintain gets full access to Ansible resources in the project
			perms[PermissionAnsiblePlaybookRead] = true
			perms[PermissionAnsiblePlaybookWrite] = true
			perms[PermissionAnsibleInventoryRead] = true
			perms[PermissionAnsibleInventoryWrite] = true
			perms[PermissionAnsibleCredentialRead] = true
			perms[PermissionAnsibleCredentialWrite] = true
			perms[PermissionAnsibleJobTemplateRead] = true
			perms[PermissionAnsibleJobTemplateWrite] = true
			perms[PermissionAnsibleJobRead] = true
			perms[PermissionAnsibleJobExecute] = true
			perms[PermissionAnsibleAdHocExecute] = true
			perms[PermissionAnsibleScheduleRead] = true
			perms[PermissionAnsibleScheduleWrite] = true
		case "read":
			// Read has read-only permissions (PermissionRuns NOT included - that's for creating/planning)
			perms[PermissionProjectRead] = true
			perms[PermissionWorkspaceRead] = true
			perms[PermissionRunRead] = true
			perms[PermissionStateVersions] = true // Granular permission (level checked separately)
			perms[PermissionVariables] = true     // Granular permission (level checked separately)
			perms[PermissionSentinelMocks] = true
			// Ansible permissions: read gets read-only access to Ansible resources in the project
			perms[PermissionAnsiblePlaybookRead] = true
			perms[PermissionAnsibleInventoryRead] = true
			perms[PermissionAnsibleCredentialRead] = true
			perms[PermissionAnsibleJobTemplateRead] = true
			perms[PermissionAnsibleJobRead] = true
			perms[PermissionAnsibleScheduleRead] = true
		}

		// Variable sets: TFE grants project-owned variable-set management to
		// write/maintain/admin, and read visibility to read (mirrors the project
		// "Manage variable sets" permission).
		switch accessLevel {
		case "admin", "maintain", "write":
			perms[PermissionVariableSets] = true
			perms[PermissionVariableSetsRead] = true
		case "read":
			perms[PermissionVariableSetsRead] = true
		}
	}

	// Add custom permissions if access is "custom" or custom fields are set
	if projectAccess.Access != nil && *projectAccess.Access == "custom" {
		if projectAccess.WorkspaceRuns != nil {
			level := *projectAccess.WorkspaceRuns
			// WorkspaceRuns granular permission levels:
			// "read" = can view runs (PermissionRunRead)
			// "plan" = can plan runs (PermissionRuns)
			// "apply" = can apply runs (PermissionRuns + PermissionWorkspaceWrite)
			switch level {
			case "read":
				perms[PermissionRunRead] = true
			case "plan", "apply":
				perms[PermissionRuns] = true
			}
		}
		if projectAccess.WorkspaceVariables != nil {
			level := *projectAccess.WorkspaceVariables
			if level == "read" || level == "write" {
				perms[PermissionVariables] = true
			}
		}
		if projectAccess.WorkspaceStateVersions != nil {
			level := *projectAccess.WorkspaceStateVersions
			if level == "read" || level == "read-outputs" || level == "write" {
				perms[PermissionStateVersions] = true
			}
		}
		if projectAccess.WorkspaceSentinelMocks != nil {
			level := *projectAccess.WorkspaceSentinelMocks
			if level == "read" {
				perms[PermissionSentinelMocks] = true
			}
		}
		if projectAccess.WorkspaceLocking != nil && *projectAccess.WorkspaceLocking {
			perms[PermissionWorkspaceLocking] = true
		}
		if projectAccess.WorkspaceRunTasks != nil && *projectAccess.WorkspaceRunTasks {
			perms[PermissionRunTasks] = true
		}
		// Project "Manage variable sets" granular permission: none / read / write.
		if projectAccess.ProjectVariableSets != nil {
			switch *projectAccess.ProjectVariableSets {
			case "read":
				perms[PermissionVariableSetsRead] = true
			case "write":
				perms[PermissionVariableSetsRead] = true
				perms[PermissionVariableSets] = true
			}
		}
	}

	return perms
}

// getPermissionsFromWorkspaceAccess extracts all permissions from team workspace access
func (s *Service) getPermissionsFromWorkspaceAccess(workspaceAccess *models.TeamWorkspaceAccess) map[Permission]bool {
	perms := make(map[Permission]bool)

	if workspaceAccess.Access != nil {
		accessLevel := *workspaceAccess.Access
		switch accessLevel {
		case "admin":
			// Admin has all permissions
			perms[PermissionWorkspaceRead] = true
			perms[PermissionWorkspaceWrite] = true
			perms[PermissionRunRead] = true
			perms[PermissionRunWrite] = true
			perms[PermissionVariables] = true
			perms[PermissionStateVersions] = true
			perms[PermissionRuns] = true
			perms[PermissionSentinelMocks] = true
			perms[PermissionWorkspaceLocking] = true
			perms[PermissionRunTasks] = true
		case "write":
			// Write has write permissions
			perms[PermissionWorkspaceRead] = true
			perms[PermissionWorkspaceWrite] = true
			perms[PermissionRunRead] = true
			perms[PermissionRunWrite] = true
			perms[PermissionVariables] = true
			perms[PermissionStateVersions] = true
			perms[PermissionRuns] = true
			perms[PermissionWorkspaceLocking] = true
			perms[PermissionRunTasks] = true
		case "plan":
			// Plan has read and plan permissions
			perms[PermissionWorkspaceRead] = true
			perms[PermissionRunRead] = true
			perms[PermissionStateVersions] = true
			perms[PermissionVariables] = true
			perms[PermissionRuns] = true // plan level allows planning
		case "read":
			// Read has read-only permissions (PermissionRuns NOT included)
			perms[PermissionWorkspaceRead] = true
			perms[PermissionRunRead] = true
			perms[PermissionStateVersions] = true // Granular permission (level checked separately)
			perms[PermissionVariables] = true     // Granular permission (level checked separately)
			perms[PermissionSentinelMocks] = true
		}
	}

	// Add custom permissions if custom fields are set
	if workspaceAccess.Runs != nil {
		level := *workspaceAccess.Runs
		// Runs granular permission levels:
		// "read" = can view runs (PermissionRunRead)
		// "plan" = can plan runs (PermissionRuns)
		// "apply" = can apply runs (PermissionRuns + PermissionWorkspaceWrite)
		switch level {
		case "read":
			perms[PermissionRunRead] = true
		case "plan", "apply":
			perms[PermissionRuns] = true
		}
	}
	if workspaceAccess.Variables != nil {
		level := *workspaceAccess.Variables
		if level == "read" || level == "write" {
			perms[PermissionVariables] = true
		}
	}
	if workspaceAccess.StateVersions != nil {
		level := *workspaceAccess.StateVersions
		if level == "read" || level == "read-outputs" || level == "write" {
			perms[PermissionStateVersions] = true
		}
	}
	if workspaceAccess.SentinelMocks != nil {
		level := *workspaceAccess.SentinelMocks
		if level == "read" {
			perms[PermissionSentinelMocks] = true
		}
	}
	if workspaceAccess.WorkspaceLocking != nil && *workspaceAccess.WorkspaceLocking {
		perms[PermissionWorkspaceLocking] = true
	}
	if workspaceAccess.RunTasks != nil && *workspaceAccess.RunTasks {
		perms[PermissionRunTasks] = true
	}

	return perms
}

// CheckWorkspacePermission is a convenience method for checking workspace permissions
// It uses CheckResourcePermission internally with the workspace resource type
func (s *Service) CheckWorkspacePermission(
	ctx context.Context,
	userID uuid.UUID,
	workspaceID string,
	permission Permission,
	projectID uuid.UUID,
) (bool, error) {
	return s.CheckResourcePermission(
		ctx,
		userID,
		ResourceTypeTerraformWorkspace,
		workspaceID,
		permission,
		&projectID,
	)
}

// CheckStateVersionPermission checks if user can access state versions
// Granular permission: none, read, read-outputs, write
func (s *Service) CheckStateVersionPermission(
	ctx context.Context,
	userID uuid.UUID,
	workspaceID string,
	projectID uuid.UUID,
	level string, // "none", "read", "read-outputs", "write"
) (bool, error) {
	switch level {
	case "none":
		return false, nil
	case "read", "read-outputs":
		return s.CheckWorkspacePermission(ctx, userID, workspaceID, PermissionStateVersions, projectID)
	case "write":
		// Write requires both state_versions permission and workspace write
		hasStateVersions, err := s.CheckWorkspacePermission(ctx, userID, workspaceID, PermissionStateVersions, projectID)
		if err != nil || !hasStateVersions {
			return false, err
		}
		return s.CheckWorkspacePermission(ctx, userID, workspaceID, PermissionWorkspaceWrite, projectID)
	default:
		return false, fmt.Errorf("invalid state version permission level: %s", level)
	}
}

// CheckVariablePermission checks if user can access variables
// Granular permission: none, read, write
func (s *Service) CheckVariablePermission(
	ctx context.Context,
	userID uuid.UUID,
	workspaceID string,
	projectID uuid.UUID,
	level string, // "none", "read", "write"
) (bool, error) {
	switch level {
	case "none":
		return false, nil
	case "read":
		return s.CheckWorkspacePermission(ctx, userID, workspaceID, PermissionVariables, projectID)
	case "write":
		// Write requires both variables permission and workspace write
		hasVariables, err := s.CheckWorkspacePermission(ctx, userID, workspaceID, PermissionVariables, projectID)
		if err != nil || !hasVariables {
			return false, err
		}
		return s.CheckWorkspacePermission(ctx, userID, workspaceID, PermissionWorkspaceWrite, projectID)
	default:
		return false, fmt.Errorf("invalid variable permission level: %s", level)
	}
}

// CheckVariableSetPermission gates access to a variable set, mirroring TFE's model
// (see docs: managing-variables / go-tfe ProjectVariableSetsPermissionType):
//
//   - Owners always manage everything in their org.
//   - Organization-owned sets (ProjectID == nil): any org member may read; writes
//     require "Manage all workspaces" or "Manage all projects".
//   - Project-owned sets (ProjectID != nil): resolved through the project's team
//     access — read requires PermissionVariableSetsRead, write requires
//     PermissionVariableSets — which also picks up org "Manage all projects" via the
//     org-access mapping.
//
// level is "read" or "write".
func (s *Service) CheckVariableSetPermission(ctx context.Context, userID uuid.UUID, variableSet *models.VariableSet, level string) (bool, error) {
	// Owners team shortcut (CheckResourcePermission has no owner bypass of its own).
	if owner, err := s.IsOrgOwner(ctx, userID, variableSet.OrganizationID); err != nil {
		return false, err
	} else if owner {
		return true, nil
	}

	switch level {
	case "read":
		if variableSet.ProjectID != nil {
			return s.CheckResourcePermission(ctx, userID, ResourceTypeVariableSet, variableSet.ID, PermissionVariableSetsRead, variableSet.ProjectID)
		}
		// Organization-owned: any member of the org may view (sensitive values are masked).
		return s.orgRepo.UserInOrg(userID, variableSet.OrganizationID)
	case "write":
		if variableSet.ProjectID != nil {
			return s.CheckResourcePermission(ctx, userID, ResourceTypeVariableSet, variableSet.ID, PermissionVariableSets, variableSet.ProjectID)
		}
		// Organization-owned: "Manage all workspaces" or "Manage all projects".
		if ok, err := s.checkOrgPermission(ctx, userID, variableSet.OrganizationID, PermissionOrgManageWorkspaces); err != nil || ok {
			return ok, err
		}
		return s.checkOrgPermission(ctx, userID, variableSet.OrganizationID, PermissionOrgManageProjects)
	default:
		return false, fmt.Errorf("invalid variable set permission level: %s", level)
	}
}

// CheckRunPermission checks if user can access runs
// Granular permission: read, plan, apply
func (s *Service) CheckRunPermission(
	ctx context.Context,
	userID uuid.UUID,
	workspaceID string,
	projectID uuid.UUID,
	level string, // "read", "plan", "apply"
) (bool, error) {
	switch level {
	case "read":
		// Read level: Can view runs, but NOT create/plan them
		return s.CheckWorkspacePermission(ctx, userID, workspaceID, PermissionRunRead, projectID)
	case "plan":
		// Plan level: Requires PermissionRuns (can create/plan runs)
		return s.CheckWorkspacePermission(ctx, userID, workspaceID, PermissionRuns, projectID)
	case "apply":
		// Apply level: Requires both PermissionRuns (can plan) and PermissionWorkspaceWrite (can apply)
		hasRuns, err := s.CheckWorkspacePermission(ctx, userID, workspaceID, PermissionRuns, projectID)
		if err != nil || !hasRuns {
			return false, err
		}
		return s.CheckWorkspacePermission(ctx, userID, workspaceID, PermissionWorkspaceWrite, projectID)
	default:
		return false, fmt.Errorf("invalid run permission level: %s", level)
	}
}

// CheckWorkspaceLockingPermission checks if user can lock/unlock workspaces
func (s *Service) CheckWorkspaceLockingPermission(
	ctx context.Context,
	userID uuid.UUID,
	workspaceID string,
	projectID uuid.UUID,
) (bool, error) {
	return s.CheckWorkspacePermission(ctx, userID, workspaceID, PermissionWorkspaceLocking, projectID)
}

// CheckRunTasksPermission checks if user can manage run tasks
func (s *Service) CheckRunTasksPermission(
	ctx context.Context,
	userID uuid.UUID,
	workspaceID string,
	projectID uuid.UUID,
) (bool, error) {
	return s.CheckWorkspacePermission(ctx, userID, workspaceID, PermissionRunTasks, projectID)
}

// CheckAnsibleResourcePermission is a convenience method for checking Ansible resource permissions
func (s *Service) CheckAnsibleResourcePermission(
	ctx context.Context,
	userID uuid.UUID,
	resourceType ResourceType,
	resourceID string,
	permission Permission,
	projectID *uuid.UUID,
) (bool, error) {
	return s.CheckResourcePermission(ctx, userID, resourceType, resourceID, permission, projectID)
}

// CheckOrgManageMembership checks if user can manage organization memberships (add/remove users)
// Team-based: User must be in "owners" team OR have team with manage-membership permission
func (s *Service) CheckOrgManageMembership(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	// Tenant isolation: user must have at least one team in the org (team-based access)
	inOrg, err := s.orgRepo.UserInOrg(userID, organizationID)
	if err != nil || !inOrg {
		return false, nil
	}

	if s.teamRepo == nil {
		return false, fmt.Errorf("team repository not available")
	}

	// Get all teams user is member of
	teams, err := s.teamRepo.GetTeamsByUserID(userID, organizationID)
	if err != nil {
		return false, err
	}

	// Check if user is in "owners" team (always has full permissions)
	for _, team := range teams {
		if team.Name == "owners" {
			return true, nil
		}

		// Check if team has manage-membership permission
		// GetTeamsByUserID already preloads OrganizationAccess, so use it directly
		if team.OrganizationAccess != nil && team.OrganizationAccess.ManageMembership {
			return true, nil
		}
	}

	return false, nil
}

// CheckOrgManageTeams checks if user can manage teams (create/update/delete teams)
// Team-based: User must be in "owners" team OR have team with manage-teams permission
func (s *Service) CheckOrgManageTeams(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	// Tenant isolation: user must have at least one team in the org (team-based access)
	inOrg, err := s.orgRepo.UserInOrg(userID, organizationID)
	if err != nil || !inOrg {
		return false, nil
	}

	if s.teamRepo == nil {
		return false, fmt.Errorf("team repository not available")
	}

	// Get all teams user is member of
	teams, err := s.teamRepo.GetTeamsByUserID(userID, organizationID)
	if err != nil {
		return false, err
	}

	// Check if user is in "owners" team (always has full permissions)
	for _, team := range teams {
		if team.Name == "owners" {
			return true, nil
		}

		// Check if team has manage-teams permission
		// GetTeamsByUserID already preloads OrganizationAccess, so use it directly
		if team.OrganizationAccess != nil && team.OrganizationAccess.ManageTeams {
			return true, nil
		}
	}

	return false, nil
}

// IsOrgOwner checks if the user is a member of the organization's "owners" team.
// Some operations must be restricted to owners even when the caller holds ManageTeams
// or ManageMembership grants — e.g. managing the owners team's own membership, where
// anything weaker allows privilege escalation to owner (AUD-003).
func (s *Service) IsOrgOwner(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	// Tenant isolation: user must have at least one team in the org (team-based access)
	inOrg, err := s.orgRepo.UserInOrg(userID, organizationID)
	if err != nil || !inOrg {
		return false, nil
	}

	if s.teamRepo == nil {
		return false, fmt.Errorf("team repository not available")
	}

	teams, err := s.teamRepo.GetTeamsByUserID(userID, organizationID)
	if err != nil {
		return false, err
	}

	for _, team := range teams {
		if team.Name == "owners" {
			return true, nil
		}
	}

	return false, nil
}

// CheckOrgManageProjects checks if user can manage projects (create/update/delete projects)
// Team-based: Check if user has manage-projects permission from any team
func (s *Service) CheckOrgManageProjects(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return s.checkOrgPermission(ctx, userID, organizationID, PermissionOrgManageProjects)
}

// CheckOrgManageWorkspaces checks if user can manage workspaces (create/update/delete workspaces)
// Team-based: Check if user has manage-workspaces permission from any team
func (s *Service) CheckOrgManageWorkspaces(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return s.checkOrgPermission(ctx, userID, organizationID, PermissionOrgManageWorkspaces)
}

// CheckOrgManageVCSSettings checks if user can manage VCS settings
func (s *Service) CheckOrgManageVCSSettings(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return s.checkOrgPermission(ctx, userID, organizationID, PermissionOrgManageVCSSettings)
}

// CheckOrgReadProjects checks if user can read projects
func (s *Service) CheckOrgReadProjects(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return s.checkOrgPermission(ctx, userID, organizationID, PermissionOrgReadProjects)
}

// CheckOrgReadWorkspaces checks if user can read workspaces
func (s *Service) CheckOrgReadWorkspaces(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return s.checkOrgPermission(ctx, userID, organizationID, PermissionOrgReadWorkspaces)
}

// CheckOrgManageAgentPools checks if user can manage agent pools (create/update/delete)
func (s *Service) CheckOrgManageAgentPools(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return s.checkOrgPermission(ctx, userID, organizationID, PermissionOrgManageAgentPools)
}

// CheckOrgManageModules checks if user can manage registry modules (publish/delete)
func (s *Service) CheckOrgManageModules(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return s.checkOrgPermission(ctx, userID, organizationID, PermissionOrgManageModules)
}

// CheckOrgManageProviders checks if user can manage the registry provider trust
// plane — provider shells, published binaries, and the org's GPG trust anchors.
func (s *Service) CheckOrgManageProviders(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return s.checkOrgPermission(ctx, userID, organizationID, PermissionOrgManageProviders)
}

// CheckOrgManageAnsible checks if user can manage all Ansible resources (create/update/delete)
func (s *Service) CheckOrgManageAnsible(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return s.checkOrgPermission(ctx, userID, organizationID, PermissionOrgManageAnsible)
}

// CheckOrgReadAnsible checks if user can read Ansible resources
func (s *Service) CheckOrgReadAnsible(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return s.checkOrgPermission(ctx, userID, organizationID, PermissionOrgReadAnsible)
}

// checkOrgPermission is a helper to check organization-level permissions from team memberships
// GetEffectivePermissions returns all effective permissions for a user in an organization.
// This is the union of all permissions from all teams the user is a member of.
// Used by the /effective-permissions endpoint for frontend permission enforcement.
func (s *Service) GetEffectivePermissions(ctx context.Context, userID, organizationID uuid.UUID) (map[Permission]bool, error) {
	inOrg, err := s.orgRepo.UserInOrg(userID, organizationID)
	if err != nil || !inOrg {
		return nil, fmt.Errorf("user not in organization")
	}

	if s.teamRepo == nil {
		return nil, fmt.Errorf("team repository not available")
	}

	teams, err := s.teamRepo.GetTeamsByUserID(userID, organizationID)
	if err != nil {
		return nil, err
	}

	// Owners get all permissions
	for _, team := range teams {
		if team.Name == "owners" {
			return map[Permission]bool{
				PermissionOrgManageAnsible:            true,
				PermissionOrgReadAnsible:              true,
				PermissionOrgManageProjects:           true,
				PermissionOrgReadProjects:             true,
				PermissionOrgManageWorkspaces:         true,
				PermissionOrgReadWorkspaces:           true,
				PermissionOrgManageTeams:              true,
				PermissionOrgManageMembership:         true,
				PermissionOrgManageVCSSettings:        true,
				PermissionOrgManageProviders:          true,
				PermissionOrgManageModules:            true,
				PermissionOrgManagePolicies:           true,
				PermissionOrgManagePolicyOverrides:    true,
				PermissionOrgManageRunTasks:           true,
				PermissionOrgManageAgentPools:         true,
				PermissionOrgAccessSecretTeams:        true,
				PermissionOrgManageOrganizationAccess: true,
				PermissionAnsiblePlaybookRead:         true,
				PermissionAnsiblePlaybookWrite:        true,
				PermissionAnsibleInventoryRead:        true,
				PermissionAnsibleInventoryWrite:       true,
				PermissionAnsibleCredentialRead:       true,
				PermissionAnsibleCredentialWrite:      true,
				PermissionAnsibleJobTemplateRead:      true,
				PermissionAnsibleJobTemplateWrite:     true,
				PermissionAnsibleJobRead:              true,
				PermissionAnsibleJobExecute:           true,
				PermissionAnsibleAdHocExecute:         true,
				PermissionAnsibleScheduleRead:         true,
				PermissionAnsibleScheduleWrite:        true,
			}, nil
		}
	}

	allPermissions := make(map[Permission]bool)
	for _, team := range teams {
		var orgAccess *models.TeamOrganizationAccess
		if team.OrganizationAccess != nil {
			orgAccess = team.OrganizationAccess
		} else {
			orgAccess, err = s.teamRepo.GetOrganizationAccess(team.ID)
			if err != nil {
				continue
			}
		}
		if orgAccess != nil {
			teamPerms := s.getPermissionsFromOrganizationAccess(orgAccess)
			for perm := range teamPerms {
				allPermissions[perm] = true
			}
		}
	}

	return allPermissions, nil
}

func (s *Service) checkOrgPermission(ctx context.Context, userID, organizationID uuid.UUID, permission Permission) (bool, error) {
	// Tenant isolation: user must have at least one team in the org (team-based access)
	inOrg, err := s.orgRepo.UserInOrg(userID, organizationID)
	if err != nil || !inOrg {
		return false, nil
	}

	if s.teamRepo == nil {
		return false, fmt.Errorf("team repository not available")
	}

	// Get all teams user is member of
	teams, err := s.teamRepo.GetTeamsByUserID(userID, organizationID)
	if err != nil {
		return false, err
	}

	// Check if user is in "owners" team (always has full permissions)
	for _, team := range teams {
		if team.Name == "owners" {
			return true, nil
		}
	}

	// Collect all permissions from all teams
	// GetTeamsByUserID already preloads OrganizationAccess, so use it directly
	allPermissions := make(map[Permission]bool)
	for _, team := range teams {
		// Use preloaded OrganizationAccess if available, otherwise fetch it
		var orgAccess *models.TeamOrganizationAccess
		if team.OrganizationAccess != nil {
			orgAccess = team.OrganizationAccess
		} else {
			// Fallback: fetch if not preloaded (shouldn't happen, but be defensive)
			var err error
			orgAccess, err = s.teamRepo.GetOrganizationAccess(team.ID)
			if err != nil {
				continue
			}
		}

		if orgAccess != nil {
			teamPerms := s.getPermissionsFromOrganizationAccess(orgAccess)
			for perm := range teamPerms {
				allPermissions[perm] = true
			}
		}
	}

	return allPermissions[permission], nil
}
