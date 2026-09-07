// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
)

// Typed organization-membership wire shapes (#760).

// OrgMembershipAttributes: Role is always null (roles are deprecated; permissions come from
// team memberships), typed *string to keep the member present.
type OrgMembershipAttributes struct {
	Email     string  `json:"email"`
	Status    string  `json:"status"`
	Role      *string `json:"role"`
	CreatedAt string  `json:"created-at"`
	Username  string  `json:"username"`
	Name      string  `json:"name"`
}

// OrgMembershipRelationships: teams starts empty and is filled by the list/show handlers once
// the user's teams are fetched - the typed equivalent of the map mutation they used to do.
type OrgMembershipRelationships struct {
	Organization jsonapi.Relationship     `json:"organization"`
	User         jsonapi.Relationship     `json:"user"`
	Teams        jsonapi.ManyRelationship `json:"teams"`
}

// OrgMembershipResource has mutable relationships for the teams decoration.
type OrgMembershipResource struct {
	ID            string                      `json:"id"`
	Type          string                      `json:"type"`
	Attributes    OrgMembershipAttributes     `json:"attributes"`
	Relationships *OrgMembershipRelationships `json:"relationships"`
}

// IncludedUserAttributes is the sideloaded user payload; email and name may be empty (admin
// users created before auth) and the frontend renders the fallback.
type IncludedUserAttributes struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

// IncludedTeamAttributes is the sideloaded team payload.
type IncludedTeamAttributes struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Visibility  string `json:"visibility"`
}

// Typed team wire shapes (#760).

// TeamOrganizationAccessAttributes mirrors the TFE organization-access block plus the
// StackWeaver Ansible members; the nil-access default is simply the zero value.
type TeamOrganizationAccessAttributes struct {
	ManagePolicies            bool `json:"manage-policies"`
	ManagePolicyOverrides     bool `json:"manage-policy-overrides"`
	ManageWorkspaces          bool `json:"manage-workspaces"`
	ManageVCSSettings         bool `json:"manage-vcs-settings"`
	ManageProviders           bool `json:"manage-providers"`
	ManageModules             bool `json:"manage-modules"`
	ManageRunTasks            bool `json:"manage-run-tasks"`
	ManageProjects            bool `json:"manage-projects"`
	ReadWorkspaces            bool `json:"read-workspaces"`
	ReadProjects              bool `json:"read-projects"`
	ManageMembership          bool `json:"manage-membership"`
	ManageTeams               bool `json:"manage-teams"`
	ManageOrganizationAccess  bool `json:"manage-organization-access"`
	AccessSecretTeams         bool `json:"access-secret-teams"`
	ManageAgentPools          bool `json:"manage-agent-pools"`
	ManageAnsible             bool `json:"manage-ansible"`
	ReadAnsible               bool `json:"read-ansible"`
	ManageAnsiblePlaybooks    bool `json:"manage-ansible-playbooks"`
	ReadAnsiblePlaybooks      bool `json:"read-ansible-playbooks"`
	ManageAnsibleInventories  bool `json:"manage-ansible-inventories"`
	ReadAnsibleInventories    bool `json:"read-ansible-inventories"`
	ManageAnsibleCredentials  bool `json:"manage-ansible-credentials"`
	ReadAnsibleCredentials    bool `json:"read-ansible-credentials"`
	ManageAnsibleJobTemplates bool `json:"manage-ansible-job-templates"`
	ReadAnsibleJobTemplates   bool `json:"read-ansible-job-templates"`
	ManageAnsibleJobs         bool `json:"manage-ansible-jobs"`
	ReadAnsibleJobs           bool `json:"read-ansible-jobs"`
	ManageAnsibleSchedules    bool `json:"manage-ansible-schedules"`
	ReadAnsibleSchedules      bool `json:"read-ansible-schedules"`
}

// TeamPermissions reflects the CALLER's team-management rights, set by the handler after the
// base builder runs - the typed equivalent of the map overwrite it used to do.
type TeamPermissions struct {
	CanUpdateMembership         bool `json:"can-update-membership"`
	CanDestroy                  bool `json:"can-destroy"`
	CanUpdateOrganizationAccess bool `json:"can-update-organization-access"`
	CanUpdateAPIToken           bool `json:"can-update-api-token"`
	CanUpdateVisibility         bool `json:"can-update-visibility"`
}

// TeamAttributes is the teams attribute block. SSOTeamID is a pointer: present as null.
type TeamAttributes struct {
	Name                       string                           `json:"name"`
	Visibility                 string                           `json:"visibility"`
	UsersCount                 int                              `json:"users-count"`
	AllowMemberTokenManagement bool                             `json:"allow-member-token-management"`
	OrganizationAccess         TeamOrganizationAccessAttributes `json:"organization-access"`
	SSOTeamID                  *string                          `json:"sso-team-id"`
	Permissions                TeamPermissions                  `json:"permissions"`
}

// TeamAuthTokenRelationship is TFE's authentication-token relation: an empty meta object.
type TeamAuthTokenRelationship struct {
	Meta struct{} `json:"meta"`
}

// TeamRelationships: organization-memberships starts empty and is filled by the show handler.
type TeamRelationships struct {
	Users                   jsonapi.ManyRelationship  `json:"users"`
	OrganizationMemberships jsonapi.ManyRelationship  `json:"organization-memberships"`
	AuthenticationToken     TeamAuthTokenRelationship `json:"authentication-token"`
}

// TeamResource has mutable attributes/relationships for the handler decorations.
type TeamResource struct {
	ID            string             `json:"id"`
	Type          string             `json:"type"`
	Attributes    TeamAttributes     `json:"attributes"`
	Relationships *TeamRelationships `json:"relationships"`
	Links         jsonapi.SelfLink   `json:"links"`
}

// AgentPoolAttributes is the TFE agent-pools attribute block.
type AgentPoolAttributes struct {
	Name               string `json:"name"`
	AgentCount         int    `json:"agent-count"`
	OrganizationScoped bool   `json:"organization-scoped"`
	CreatedAt          string `json:"created-at"`
}

// AgentPoolRelationships: the scoping relations appear only when populated.
type AgentPoolRelationships struct {
	Organization       jsonapi.Relationship      `json:"organization"`
	AllowedWorkspaces  *jsonapi.ManyRelationship `json:"allowed-workspaces,omitempty"`
	AllowedProjects    *jsonapi.ManyRelationship `json:"allowed-projects,omitempty"`
	ExcludedWorkspaces *jsonapi.ManyRelationship `json:"excluded-workspaces,omitempty"`
}

// AgentAttributes is the TFE agents shape: id, name, ip-address, status, last-ping-at.
type AgentAttributes struct {
	Name       string     `json:"name"`
	IPAddress  string     `json:"ip-address"`
	Status     string     `json:"status"`
	LastPingAt *time.Time `json:"last-ping-at"`
}

// QueueDepthAttributes is the StackWeaver queue-depths extension.
type QueueDepthAttributes struct {
	PendingTerraformJobs int64 `json:"pending-terraform-jobs"`
	PendingAnsibleJobs   int64 `json:"pending-ansible-jobs"`
	TotalPending         int64 `json:"total-pending"`
	BusyRunners          int64 `json:"busy-runners"`
	TotalRunners         int64 `json:"total-runners"`
	IdleRunners          int64 `json:"idle-runners"`
}

// VCSConnectionAttributes: snake_case members, a StackWeaver-native surface predating the
// hyphenated convention; renaming them is a wire change and not this task.
type VCSConnectionAttributes struct {
	Provider       models.VCSProvider `json:"provider"`
	AccountName    string             `json:"account_name"`
	AccountType    string             `json:"account_type"`
	TokenExpiresAt *time.Time         `json:"token_expires_at"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
}

// vcsConnectionResource builds the shared shape.
func vcsConnectionResource(conn *models.VCSConnection, orgID uuid.UUID) jsonapi.Resource[VCSConnectionAttributes] {
	return jsonapi.Resource[VCSConnectionAttributes]{
		ID:   conn.ID.String(),
		Type: "vcs-connections",
		Attributes: VCSConnectionAttributes{
			Provider:       conn.Provider,
			AccountName:    conn.AccountName,
			AccountType:    conn.AccountType,
			TokenExpiresAt: conn.TokenExpiresAt,
			CreatedAt:      conn.CreatedAt,
			UpdatedAt:      conn.UpdatedAt,
		},
		Relationships: WorkspaceOnlyRelationshipsNamed{Organization: jsonapi.ToOne(orgID.String(), "organizations")},
	}
}

// WorkspaceOnlyRelationshipsNamed is the single organization relationship block.
type WorkspaceOnlyRelationshipsNamed struct {
	Organization jsonapi.Relationship `json:"organization"`
}

// LegacyPageMeta is the {"pagination": {"page", "per_page"}} block the VCS pass-through
// listings emit - no total exists, because the rows come from the upstream provider
// (#756 records these as deliberate exceptions).
type LegacyPageMeta struct {
	Pagination LegacyPage `json:"pagination"`
}

type LegacyPage struct {
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
}

// VCSFileContentResponse is the file-fetch payload.
type VCSFileContentResponse struct {
	Content string `json:"content"`
	Path    string `json:"path"`
	Ref     string `json:"ref"`
}

// ProjectSettingOverwrites mirrors TFE's setting-overwrites block; the provider sets both
// flags together, so they reflect one stored flag.
type ProjectSettingOverwrites struct {
	DefaultExecutionMode bool `json:"default-execution-mode"`
	DefaultAgentPool     bool `json:"default-agent-pool"`
}

// ProjectAttributes is the TFE projects attribute block. The count members are pointers with
// omitempty: the detail (with-counts) variant always sets them, the list variant never does.
type ProjectAttributes struct {
	Name                 string                   `json:"name"`
	Description          string                   `json:"description"`
	IsUnified            bool                     `json:"is-unified"`
	DefaultExecutionMode string                   `json:"default-execution-mode"`
	SettingOverwrites    ProjectSettingOverwrites `json:"setting-overwrites"`
	CreatedAt            string                   `json:"created-at"`
	UpdatedAt            string                   `json:"updated-at"`
	WorkspacesCount      *int                     `json:"workspaces-count,omitempty"`
	InventoriesCount     *int                     `json:"inventories-count,omitempty"`
	PlaybooksCount       *int                     `json:"playbooks-count,omitempty"`
	JobTemplatesCount    *int                     `json:"job-templates-count,omitempty"`
	WorkflowsCount       *int                     `json:"workflows-count,omitempty"`
	CredentialsCount     *int                     `json:"credentials-count,omitempty"`
}

// ProjectRelationships: default-agent-pool is always present, {data: null} when unset (TFE
// contract). The tag-binding relations are decorated post-hoc on ?include requests and stay
// any until tag_bindings.go is typed.
type ProjectRelationships struct {
	Organization         jsonapi.Relationship `json:"organization"`
	DefaultAgentPool     jsonapi.Relationship `json:"default-agent-pool"`
	EffectiveTagBindings any                  `json:"effective-tag-bindings,omitempty"`
	TagBindings          any                  `json:"tag-bindings,omitempty"`
}

// TeamWorkspacePermissions is the custom-permissions block of a team-workspaces resource;
// every member is emitted, with TFE's defaults filled for unset fields.
type TeamWorkspacePermissions struct {
	Runs             string `json:"runs"`
	Variables        string `json:"variables"`
	StateVersions    string `json:"state-versions"`
	SentinelMocks    string `json:"sentinel-mocks"`
	WorkspaceLocking bool   `json:"workspace-locking"`
	RunTasks         bool   `json:"run-tasks"`
}

// TeamWorkspaceAccessAttributes: "custom" + permissions when any custom field is set, the
// fixed level alone otherwise, and {} when neither is stored.
type TeamWorkspaceAccessAttributes struct {
	Access      string                    `json:"access,omitempty"`
	Permissions *TeamWorkspacePermissions `json:"permissions,omitempty"`
}

// TeamAndWorkspaceRelationships is the fixed relation pair of a team-workspaces resource.
type TeamAndWorkspaceRelationships struct {
	Team      jsonapi.Relationship `json:"team"`
	Workspace jsonapi.Relationship `json:"workspace"`
}

// TeamProjectProjectAccess is the project-access block of a team-projects resource.
type TeamProjectProjectAccess struct {
	Settings     string `json:"settings"`
	Teams        string `json:"teams"`
	VariableSets string `json:"variable-sets"`
}

// TeamProjectWorkspaceAccess is the workspace-access block of a team-projects resource.
type TeamProjectWorkspaceAccess struct {
	Runs          string `json:"runs"`
	SentinelMocks string `json:"sentinel-mocks"`
	StateVersions string `json:"state-versions"`
	Variables     string `json:"variables"`
	Create        bool   `json:"create"`
	Locking       bool   `json:"locking"`
	Move          bool   `json:"move"`
	Delete        bool   `json:"delete"`
	RunTasks      bool   `json:"run-tasks"`
}

// TeamProjectAccessAttributes mirrors TeamWorkspaceAccessAttributes for team-projects.
type TeamProjectAccessAttributes struct {
	Access          string                      `json:"access,omitempty"`
	ProjectAccess   *TeamProjectProjectAccess   `json:"project-access,omitempty"`
	WorkspaceAccess *TeamProjectWorkspaceAccess `json:"workspace-access,omitempty"`
}

// TeamAndProjectRelationships is the fixed relation pair of a team-projects resource.
type TeamAndProjectRelationships struct {
	Team    jsonapi.Relationship `json:"team"`
	Project jsonapi.Relationship `json:"project"`
}

// RunnerRecentJob is one row of the runner detail's job history (snake_case members - a
// StackWeaver-native surface).
type RunnerRecentJob struct {
	ID            string                    `json:"id"`
	JobType       models.JobType            `json:"job_type"`
	JobID         string                    `json:"job_id"`
	WorkspaceID   string                    `json:"workspace_id"`
	WorkspaceName string                    `json:"workspace_name"`
	Status        models.JobExecutionStatus `json:"status"`
	StartedAt     *time.Time                `json:"started_at"`
	FinishedAt    *time.Time                `json:"finished_at"`
	DurationMS    int64                     `json:"duration_ms"`
}

// RunnerAttributes is the runners attribute block. RecentJobs is a slice pointer because the
// detail endpoint always emits the member (even empty) while the listing never does.
type RunnerAttributes struct {
	Name                 string                   `json:"name"`
	Description          string                   `json:"description"`
	AgentPoolID          string                   `json:"agent-pool-id"`
	RunnerType           models.RunnerType        `json:"runner-type"`
	Status               models.RunnerStatus      `json:"status"`
	Hostname             string                   `json:"hostname"`
	IPAddress            string                   `json:"ip-address"`
	OSType               string                   `json:"os-type"`
	OSVersion            string                   `json:"os-version"`
	AgentVersion         string                   `json:"agent-version"`
	Labels               models.RunnerLabels      `json:"labels"`
	TofuVersion          string                   `json:"tofu-version"`
	AnsibleVersion       string                   `json:"ansible-version"`
	AvailableCollections models.RunnerCollections `json:"available-collections"`
	MaxConcurrentJobs    int                      `json:"max-concurrent-jobs"`
	CurrentJobs          int                      `json:"current-jobs"`
	LastHeartbeatAt      *string                  `json:"last-heartbeat-at"`
	RegisteredAt         string                   `json:"registered-at"`
	AgentPoolName        string                   `json:"agent-pool-name,omitempty"`
	RecentJobs           *[]RunnerRecentJob       `json:"recent_jobs,omitempty"`
}

// OrgAndAgentPoolRelationships is the fixed relation pair of a runners resource.
type OrgAndAgentPoolRelationships struct {
	Organization jsonapi.Relationship `json:"organization"`
	AgentPool    jsonapi.Relationship `json:"agent-pool"`
}

// RunnerStatsAttributes is the runner-stats counter block.
type RunnerStatsAttributes struct {
	Total   int64 `json:"total"`
	Online  int64 `json:"online"`
	Offline int64 `json:"offline"`
}

// RunnerStatsDocument has no id member on the wire (the old map never set one), so it cannot
// use jsonapi.Resource.
type RunnerStatsDocument struct {
	Type       string                `json:"type"`
	Attributes RunnerStatsAttributes `json:"attributes"`
}

// VCSInstallURLResponse / VCSAuthURLResponse: the app-installation redirect payloads.
type VCSInstallURLResponse struct {
	InstallURL string `json:"install_url"`
}

type VCSAuthURLResponse struct {
	AuthURL string `json:"auth_url"`
}

// VCSConnectionAckAttributes is the slim acknowledgment the OAuth callback paths return;
// the GitHub App path adds account_type, the Azure DevOps path never does.
type VCSConnectionAckAttributes struct {
	Provider    models.VCSProvider `json:"provider"`
	AccountName string             `json:"account_name"`
}

type VCSConnectionAckWithTypeAttributes struct {
	Provider    models.VCSProvider `json:"provider"`
	AccountName string             `json:"account_name"`
	AccountType string             `json:"account_type"`
}

// PublishedModuleAttributes is the StackWeaver registry-modules management surface
// (snake_case members). The VCS members appear only when a connection is wired; the listing
// adds version/published/download tracking the create ack never carries.
type PublishedModuleAttributes struct {
	Name            string  `json:"name"`
	Provider        string  `json:"provider"`
	Description     string  `json:"description"`
	VCSRepository   string  `json:"vcs_repository"`
	AutoPublishTags bool    `json:"auto_publish_tags"`
	VCSProvider     string  `json:"vcs_provider,omitempty"`
	VCSAccountName  string  `json:"vcs_account_name,omitempty"`
	LatestVersion   *string `json:"latest_version,omitempty"`
	PublishedAt     *string `json:"published_at,omitempty"`
	Downloads       *int    `json:"downloads,omitempty"`
}

// PublishedModuleVersionAttributes is one module version in the management listing. The
// parsed-config members forward stored JSONB blobs verbatim (null until parsed).
type PublishedModuleVersionAttributes struct {
	Version      string `json:"version"`
	Source       string `json:"source"`
	Readme       string `json:"readme"`
	PublishedAt  string `json:"published_at"`
	Downloads    int    `json:"downloads"`
	Inputs       any    `json:"inputs"`
	Outputs      any    `json:"outputs"`
	Dependencies any    `json:"dependencies"`
	Resources    any    `json:"resources"`
	Submodules   any    `json:"submodules"`
	TarballSize  int64  `json:"tarball_size"`
}

// PublishedModuleVersionAckAttributes is the slim upload acknowledgment.
type PublishedModuleVersionAckAttributes struct {
	Version     string `json:"version"`
	PublishedAt string `json:"published_at"`
}

// RegistryProviderPermissions is the go-tfe registry-providers permissions block.
type RegistryProviderPermissions struct {
	CanDelete bool `json:"can-delete"`
}

// RegistryProviderAttributes is the go-tfe registry-providers attribute block.
type RegistryProviderAttributes struct {
	Name         string                      `json:"name"`
	Namespace    string                      `json:"namespace"`
	RegistryName string                      `json:"registry-name"`
	CreatedAt    string                      `json:"created-at"`
	UpdatedAt    string                      `json:"updated-at"`
	Permissions  RegistryProviderPermissions `json:"permissions"`
}

// ProviderPlatformAckAttributes acknowledges a platform binary upload.
type ProviderPlatformAckAttributes struct {
	OS                     string `json:"os"`
	Arch                   string `json:"arch"`
	Filename               string `json:"filename"`
	Shasum                 string `json:"shasum"`
	ProviderBinaryUploaded bool   `json:"provider-binary-uploaded"`
}

// GPGKeyAttributes is the TFE gpg-keys attribute block. SourceURL is a pointer emitted as
// null: the provider distinguishes null from empty string.
type GPGKeyAttributes struct {
	ASCIIArmor     string  `json:"ascii-armor"`
	CreatedAt      string  `json:"created-at"`
	UpdatedAt      string  `json:"updated-at"`
	KeyID          string  `json:"key-id"`
	Namespace      string  `json:"namespace"`
	Source         string  `json:"source"`
	SourceURL      *string `json:"source-url"`
	TrustSignature string  `json:"trust-signature"`
}

// The four workload-identity configuration surfaces share a shape - one attribute block per
// cloud, an organization relationship and a self link - but each cloud's attributes are its
// own, so they get one type each rather than a lowest-common-denominator map.

// AWSOIDCConfigAttributes is the aws-oidc-configurations attribute block.
type AWSOIDCConfigAttributes struct {
	RoleARN string `json:"role-arn"`
}

// GCPOIDCConfigAttributes is the gcp-oidc-configurations attribute block.
type GCPOIDCConfigAttributes struct {
	ServiceAccountEmail  string `json:"service-account-email"`
	ProjectNumber        string `json:"project-number"`
	WorkloadProviderName string `json:"workload-provider-name"`
}

// AzureOIDCConfigAttributes is the azure-oidc-configurations attribute block.
type AzureOIDCConfigAttributes struct {
	ClientID       string `json:"client-id"`
	SubscriptionID string `json:"subscription-id"`
	TenantID       string `json:"tenant-id"`
}

// VaultOIDCConfigAttributes is the vault-oidc-configurations attribute block. The member
// names deliberately differ from the model field names (role, auth-path, encoded-cacert).
type VaultOIDCConfigAttributes struct {
	Address       string `json:"address"`
	Role          string `json:"role"`
	Namespace     string `json:"namespace"`
	AuthPath      string `json:"auth-path"`
	EncodedCACert string `json:"encoded-cacert"`
}

// TagBindingAttributes is one key/value tag on a project or workspace.
type TagBindingAttributes struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// DashboardOrgCounts is one organization's row in the dashboard roll-up. The trailing
// members are pointers because the map added them only when the caller is entitled to see
// them: a hard zero would read as "no runners offline" to a member who simply is not
// allowed to know.
type DashboardOrgCounts struct {
	ID                              string `json:"id"`
	Name                            string `json:"name"`
	Description                     string `json:"description"`
	Projects                        int64  `json:"projects"`
	TerraformWorkspaces             int64  `json:"terraform_workspaces"`
	AnsiblePlaybooks                int64  `json:"ansible_playbooks"`
	ActiveTerraformRuns             int64  `json:"active_terraform_runs"`
	PendingTerraformRuns            int64  `json:"pending_terraform_runs"`
	AwaitingApproval                int64  `json:"awaiting_approval"`
	PendingWorkflowApprovals        int64  `json:"pending_workflow_approvals"`
	ErroredWorkspaces               int64  `json:"errored_workspaces"`
	ErroredJobTemplates             int64  `json:"errored_job_templates"`
	FailedInventorySyncs            int64  `json:"failed_inventory_syncs"`
	RecentRunFailures               int64  `json:"recent_run_failures"`
	RecentJobFailures               int64  `json:"recent_job_failures"`
	ActiveAnsibleJobs               int64  `json:"active_ansible_jobs"`
	CompletedTerraformRunsThisMonth int64  `json:"completed_terraform_runs_this_month"`
	CompletedAnsibleJobsThisMonth   int64  `json:"completed_ansible_jobs_this_month"`
	OpenChangeRequests              *int64 `json:"open_change_requests,omitempty"`
	RunnersTotal                    *int64 `json:"runners_total,omitempty"`
	RunnersOffline                  *int64 `json:"runners_offline,omitempty"`
}

// DashboardStatsAttributes is the cross-org roll-up plus the per-org breakdown.
type DashboardStatsAttributes struct {
	Projects                        int64                `json:"projects"`
	TerraformWorkspaces             int64                `json:"terraform_workspaces"`
	AnsiblePlaybooks                int64                `json:"ansible_playbooks"`
	ActiveTerraformRuns             int64                `json:"active_terraform_runs"`
	PendingTerraformRuns            int64                `json:"pending_terraform_runs"`
	AwaitingApproval                int64                `json:"awaiting_approval"`
	PendingWorkflowApprovals        int64                `json:"pending_workflow_approvals"`
	ErroredWorkspaces               int64                `json:"errored_workspaces"`
	ErroredJobTemplates             int64                `json:"errored_job_templates"`
	FailedInventorySyncs            int64                `json:"failed_inventory_syncs"`
	RecentRunFailures               int64                `json:"recent_run_failures"`
	RecentJobFailures               int64                `json:"recent_job_failures"`
	ActiveAnsibleJobs               int64                `json:"active_ansible_jobs"`
	CompletedTerraformRunsThisMonth int64                `json:"completed_terraform_runs_this_month"`
	CompletedAnsibleJobsThisMonth   int64                `json:"completed_ansible_jobs_this_month"`
	RecentFailureWindowDays         int                  `json:"recent_failure_window_days"`
	Organizations                   []DashboardOrgCounts `json:"organizations"`
}

// DashboardStatsDocument and DashboardOperationsDocument have no id member on the wire, so
// they cannot use jsonapi.Resource.
type DashboardStatsDocument struct {
	Type       string                   `json:"type"`
	Attributes DashboardStatsAttributes `json:"attributes"`
}

// DashboardExecution is one live run or job on the operations strip.
type DashboardExecution struct {
	ID               string `json:"id"`
	Platform         string `json:"platform"`
	OrganizationID   string `json:"organization_id"`
	OrganizationName string `json:"organization_name"`
	Name             string `json:"name"`
	Detail           string `json:"detail"`
	Status           string `json:"status"`
	StartedAt        string `json:"started_at"`
}

// DashboardOperationsAttributes carries the live list and whether it was cut short.
type DashboardOperationsAttributes struct {
	Executions []DashboardExecution `json:"executions"`
	// Truncated is true when more work is in flight than the list returns, so the UI can
	// say so rather than implying the list is everything.
	Truncated bool `json:"truncated"`
}

type DashboardOperationsDocument struct {
	Type       string                        `json:"type"`
	Attributes DashboardOperationsAttributes `json:"attributes"`
}

// ActivityAttributes is one audit-log row. The five id members are omitted rather than
// nulled when the event had no such parent, which is what the map did.
type ActivityAttributes struct {
	Action         string              `json:"action"`
	ResourceType   string              `json:"resource_type"`
	Details        models.AuditDetails `json:"details"`
	CreatedAt      string              `json:"created_at"`
	ResourceID     string              `json:"resource_id,omitempty"`
	UserID         string              `json:"user_id,omitempty"`
	OrganizationID string              `json:"organization_id,omitempty"`
	ProjectID      string              `json:"project_id,omitempty"`
	WorkspaceID    string              `json:"workspace_id,omitempty"`
}

// ActivityPageMeta is the activities listing's offset meta block. #756 recorded this route
// as a deliberate exception to the page/per-page contract: the UI drives it by offset.
type ActivityPageMeta struct {
	Pagination ActivityPage `json:"pagination"`
}

type ActivityPage struct {
	Total  int64 `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

// AnsibleConfigAttributes is the ansible-configs attribute block.
type AnsibleConfigAttributes struct {
	Scope         string `json:"scope"`
	ConfigContent string `json:"config-content"`
	CreatedAt     string `json:"created-at"`
	UpdatedAt     string `json:"updated-at"`
}

// AnsibleConfigRelationships expresses the config's scope parent. Exactly one is set, and
// the whole block is omitted when none is (a config always has a scope, but the builder
// never assumed it).
type AnsibleConfigRelationships struct {
	Organization *jsonapi.Relationship `json:"organization,omitempty"`
	Project      *jsonapi.Relationship `json:"project,omitempty"`
	Workspace    *jsonapi.Relationship `json:"workspace,omitempty"`
}

// The token surfaces share the TFE authentication-tokens type but not one attribute block:
// team tokens always report a null description, org tokens carry none at all, and agent
// tokens store theirs as the key name. Each keeps its own type so the difference stays
// visible instead of being flattened into a map.

// TeamTokenAttributes: description is a pointer without omitempty because legacy team tokens
// carry none and the member is emitted as null, which is what a client reads as "unnamed".
type TeamTokenAttributes struct {
	CreatedAt   time.Time  `json:"created-at"`
	LastUsedAt  *time.Time `json:"last-used-at"`
	ExpiredAt   *time.Time `json:"expired-at"`
	Description *string    `json:"description"`
	// Token is the plaintext, present only on create.
	Token string `json:"token,omitempty"`
}

// OrgTokenAttributes has no description member at all.
type OrgTokenAttributes struct {
	CreatedAt  time.Time  `json:"created-at"`
	LastUsedAt *time.Time `json:"last-used-at"`
	ExpiredAt  *time.Time `json:"expired-at"`
	Token      string     `json:"token,omitempty"`
}

// AgentTokenAttributes stores its description as the key name and has no expiry member.
type AgentTokenAttributes struct {
	CreatedAt   time.Time  `json:"created-at"`
	LastUsedAt  *time.Time `json:"last-used-at"`
	Description string     `json:"description"`
	Token       string     `json:"token,omitempty"`
}

// The user-bound /api/v2/tokens surface uses snake_case members rather than the kebab-case
// the team/org/agent token routes use. That split is the shipped contract; renaming is a
// wire change and not this task. Create and list are two shapes, not one with optional
// members: create returns the plaintext and no last_used_at, list returns last_used_at
// (null when the token has never been used) and no plaintext. One struct with omitempty
// would silently drop a null last_used_at from every listing.
type UserTokenCreateAttributes struct {
	Token       string     `json:"token"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

type UserTokenListAttributes struct {
	Description string     `json:"description"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// WebhookEventSimple is the ?format=simple projection of a webhook delivery: a flat
// snake_case row the settings page renders directly, not a JSON:API resource.
type WebhookEventSimple struct {
	ID           string     `json:"id"`
	EventType    string     `json:"event_type"`
	Provider     string     `json:"provider"`
	Repository   string     `json:"repository"`
	Branch       string     `json:"branch"`
	Commit       string     `json:"commit"`
	Status       string     `json:"status"`
	ResponseCode int        `json:"response_code"`
	Message      string     `json:"message"`
	DeliveredAt  time.Time  `json:"delivered_at"`
	ProcessedAt  *time.Time `json:"processed_at"`
}

// WebhookEventSimpleMeta is the simple projection's meta block. #756 recorded this as a
// deliberate exception: the member names are total/page_size/page_number, not the
// standard pagination block.
type WebhookEventSimpleMeta struct {
	Total      int64 `json:"total"`
	PageSize   int   `json:"page_size"`
	PageNumber int   `json:"page_number"`
}

// WebhookEventAttributes is the JSON:API projection of the same delivery.
type WebhookEventAttributes struct {
	EventType    string     `json:"event-type"`
	Provider     string     `json:"provider"`
	Repository   string     `json:"repository"`
	Branch       string     `json:"branch"`
	Commit       string     `json:"commit"`
	Status       string     `json:"status"`
	ResponseCode int        `json:"response-code"`
	Message      string     `json:"message"`
	DeliveredAt  time.Time  `json:"delivered-at"`
	ProcessedAt  *time.Time `json:"processed-at"`
}

// TofuVersionAttributes is the terraform-versions attribute block. deprecated-reason is a
// pointer with omitempty: the provider always sends "" but maps nil to a null on read, so
// emitting "" would produce a "was null, but now cty.StringVal(\"\")" inconsistency.
type TofuVersionAttributes struct {
	Version          string                 `json:"version"`
	URL              string                 `json:"url"`
	Sha              string                 `json:"sha"`
	Deprecated       bool                   `json:"deprecated"`
	Official         bool                   `json:"official"`
	Enabled          bool                   `json:"enabled"`
	Beta             bool                   `json:"beta"`
	Usage            int                    `json:"usage"`
	CreatedAt        string                 `json:"created-at"`
	Archs            []terraformVersionArch `json:"archs"`
	DeprecatedReason string                 `json:"deprecated-reason,omitempty"`
}

// AccountAttributes is the TFE account (current user) attribute block.
type AccountAttributes struct {
	Username         string `json:"username"`
	Email            string `json:"email"`
	IsServiceAccount bool   `json:"is-service-account"`
	AvatarURL        string `json:"avatar-url"`
	V2Only           bool   `json:"v2-only"`
}

// AgentJobVCS tells a self-hosted agent where to clone from when the run has no
// configuration version.
type AgentJobVCS struct {
	RepoURL    string `json:"repo_url"`
	Branch     string `json:"branch"`
	Repository string `json:"repository"`
}

// AgentJobArtifacts is the self-hosted agent's job payload. This is the agent protocol,
// not a public API: every member past the first four is populated only when it applies,
// and older agents ignore members they do not know.
type AgentJobArtifacts struct {
	JobID            string            `json:"job_id"`
	JobType          string            `json:"job_type"`
	TofuVersion      string            `json:"tofu_version"`
	WorkingDirectory string            `json:"working_directory"`
	ConfigTarball    string            `json:"config_tarball,omitempty"`
	VCS              *AgentJobVCS      `json:"vcs,omitempty"`
	Variables        map[string]string `json:"variables,omitempty"`
	// VariablesHCL tells the agent which variables are HCL-typed so it writes them
	// unquoted in tfvars (AUD-022). Separate from Variables so older agents keep working.
	VariablesHCL    []string          `json:"variables_hcl,omitempty"`
	EnvironmentVars map[string]string `json:"environment_vars,omitempty"`
	StateJSON       string            `json:"state_json,omitempty"`
}

// AuthorizeParamsResponse returns the OIDC parameters the login SPA needs. Every member
// past authRequest is passed through only when the original request carried it.
type AuthorizeParamsResponse struct {
	AuthRequest        string `json:"authRequest"`
	LoginHint          string `json:"loginHint,omitempty"`
	Prompt             string `json:"prompt,omitempty"`
	Scope              string `json:"scope,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationID     string `json:"organizationId,omitempty"`
	OrganizationDomain string `json:"organizationDomain,omitempty"`
}
