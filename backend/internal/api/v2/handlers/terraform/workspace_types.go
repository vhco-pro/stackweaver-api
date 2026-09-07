// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
)

// Typed workspace wire shapes (#760). The workspace attribute block is the most
// conditional-heavy in the API: which members appear depends on VCS wiring, locking state,
// agent pools and StackWeaver extensions, and every conditional below reproduces exactly what
// the map-based builder emitted - a pointer/omitempty field per conditional `m["k"] = v`.

// WorkspaceVCSRepo mirrors go-tfe's VCSRepo struct: every member always present, plain types.
type WorkspaceVCSRepo struct {
	Identifier              string `json:"identifier"`
	DisplayIdentifier       string `json:"display-identifier"`
	Branch                  string `json:"branch"`
	IngressSubmodules       bool   `json:"ingress-submodules"`
	ServiceProvider         string `json:"service-provider"`
	TagsRegex               string `json:"tags-regex"`
	RepositoryHTTPURL       string `json:"repository-http-url"`
	WebhookURL              string `json:"webhook-url"`
	Tags                    bool   `json:"tags"`
	GithubAppInstallationID string `json:"github-app-installation-id"`
	OAuthTokenID            string `json:"oauth-token-id"`
}

// WorkspaceActions is the static actions block.
type WorkspaceActions struct {
	IsDestroyable bool `json:"is-destroyable"`
}

// WorkspacePermissions is the static permission surface. can-force-delete is load-bearing:
// terraform-provider-tfe uses its presence to decide whether the backend supports safe-delete,
// and without it `terraform destroy` refuses unless force_delete=true. SafeDeleteByID is real,
// so the capability is advertised.
type WorkspacePermissions struct {
	CanUpdate         bool `json:"can-update"`
	CanDestroy        bool `json:"can-destroy"`
	CanQueueDestroy   bool `json:"can-queue-destroy"`
	CanQueueRun       bool `json:"can-queue-run"`
	CanUpdateVariable bool `json:"can-update-variable"`
	CanLock           bool `json:"can-lock"`
	CanUnlock         bool `json:"can-unlock"`
	CanForceUnlock    bool `json:"can-force-unlock"`
	CanReadSettings   bool `json:"can-read-settings"`
	CanForceDelete    bool `json:"can-force-delete"`
}

// WorkspaceSettingOverwrites reports which settings the workspace defines itself versus
// inheriting from org/project defaults.
type WorkspaceSettingOverwrites struct {
	ExecutionMode bool `json:"execution-mode"`
	AgentPool     bool `json:"agent-pool"`
}

// WorkspaceAttributes is the TFE workspaces attribute block plus the StackWeaver extensions
// the frontend reads (TFE clients ignore unknown members).
//
// Presence rules preserved from the map builder: VCSRepo and LockedReason are always-present
// pointers (JSON null when unset); SourceName, SourceURL, RunTimeout, VCSConnectionID,
// VCSAccountName, AgentPoolName and LockedAt appear only when set.
type WorkspaceAttributes struct {
	Name               string            `json:"name"`
	TerraformVersion   string            `json:"terraform-version"`
	WorkingDirectory   string            `json:"working-directory"`
	AutoApply          bool              `json:"auto-apply"`
	AutoQueueRuns      bool              `json:"auto-queue-runs"`
	QueueAllRuns       bool              `json:"queue-all-runs"`
	SpeculativeEnabled bool              `json:"speculative-enabled"`
	AllowDestroyPlan   bool              `json:"allow-destroy-plan"`
	ExecutionMode      string            `json:"execution-mode"`
	AgentPoolID        *string           `json:"agent-pool-id"`
	Locked             bool              `json:"locked"`
	CreatedAt          string            `json:"created-at"`
	UpdatedAt          string            `json:"updated-at"`
	Description        string            `json:"description"`
	VCSRepo            *WorkspaceVCSRepo `json:"vcs-repo"`

	Actions                    WorkspaceActions `json:"actions"`
	AutoApplyRunTrigger        bool             `json:"auto-apply-run-trigger"`
	AssessmentsEnabled         bool             `json:"assessments-enabled"`
	ForceDelete                bool             `json:"force-delete"`
	Environment                string           `json:"environment"`
	FileTriggersEnabled        bool             `json:"file-triggers-enabled"`
	GlobalRemoteState          bool             `json:"global-remote-state"`
	ResourceCount              int              `json:"resource-count"`
	SourceName                 string           `json:"source-name,omitempty"`
	SourceURL                  string           `json:"source-url,omitempty"`
	Source                     string           `json:"source"`
	StructuredRunOutputEnabled bool             `json:"structured-run-output-enabled"`
	TriggerPrefixes            []string         `json:"trigger-prefixes"`
	TriggerPatterns            []string         `json:"trigger-patterns"`
	TagNames                   []string         `json:"tag-names"`
	LatestChangeAt             string           `json:"latest-change-at"`
	LockedReason               *string          `json:"locked-reason"`
	Operations                 bool             `json:"operations"`

	Permissions       WorkspacePermissions       `json:"permissions"`
	RunTimeout        int                        `json:"run-timeout,omitempty"`
	SettingOverwrites WorkspaceSettingOverwrites `json:"setting-overwrites"`
	VCSConnectionID   string                     `json:"vcs-connection-id,omitempty"`
	VCSAccountName    string                     `json:"vcs-account-name,omitempty"`
	AgentPoolName     string                     `json:"agent-pool-name,omitempty"`
	LockedAt          string                     `json:"locked-at,omitempty"`
}

// WorkspaceRelationships: pointers throughout because the list handler decorates a formatted
// workspace with current-run and effective-tag-bindings after the base builder runs - the
// typed equivalent of the map mutation it used to do. AgentPool is always present ({"data":
// null} when unpooled, per go-tfe / tfe_workspace_settings).
type WorkspaceRelationships struct {
	Organization         *jsonapi.Relationship     `json:"organization,omitempty"`
	Project              *jsonapi.Relationship     `json:"project,omitempty"`
	AgentPool            *jsonapi.Relationship     `json:"agent-pool,omitempty"`
	LockedBy             *jsonapi.Relationship     `json:"locked-by,omitempty"`
	CurrentRun           *jsonapi.Relationship     `json:"current-run,omitempty"`
	TagBindings          *jsonapi.ManyRelationship `json:"tag-bindings,omitempty"`
	EffectiveTagBindings *jsonapi.ManyRelationship `json:"effective-tag-bindings,omitempty"`
}

// WorkspaceResource is a workspace with mutable relationships, so list handlers can decorate.
type WorkspaceResource struct {
	ID            string                  `json:"id"`
	Type          string                  `json:"type"`
	Attributes    WorkspaceAttributes     `json:"attributes"`
	Relationships *WorkspaceRelationships `json:"relationships"`
}

// IncludedRunPermissions is the single-member permission block of a sideloaded run.
type IncludedRunPermissions struct {
	CanApply bool `json:"can-apply"`
}

// IncludedRunAttributes is the lightweight run the workspace list sideloads for its cards.
type IncludedRunAttributes struct {
	Status      string                 `json:"status"`
	Operation   string                 `json:"operation"`
	IsDestroy   bool                   `json:"is-destroy"`
	PlanOnly    bool                   `json:"plan-only"`
	CreatedAt   string                 `json:"created-at"`
	UpdatedAt   string                 `json:"updated-at"`
	HasChanges  bool                   `json:"has-changes"`
	Permissions IncludedRunPermissions `json:"permissions"`
	CompletedAt string                 `json:"completed-at,omitempty"`
}

// IncludedRunRelationships points a sideloaded run at its workspace.
type IncludedRunRelationships struct {
	Workspace jsonapi.Relationship `json:"workspace"`
}

// TagBindingAttributes is the key/value payload of a (effective-)tag-bindings resource.
type TagBindingAttributes struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// tagBindingID reproduces the fallback the map builders used: a binding without an ID is
// identified by its key.
func tagBindingID(b *models.TagBinding) string {
	if b.ID != "" {
		return b.ID
	}
	return b.Key
}

// Typed run wire shapes (#760).

// RunStatusTimestamps: every member conditional, exactly mirroring the branchy map-based
// builder - TFE's CLI reads these to recognise phase completion, and an empty struct
// serialises as {} just as the empty map did.
type RunStatusTimestamps struct {
	PlanQueuedAt string `json:"plan-queued-at,omitempty"`
	PlanningAt   string `json:"planning-at,omitempty"`
	PlannedAt    string `json:"planned-at,omitempty"`
	ApplyingAt   string `json:"applying-at,omitempty"`
	AppliedAt    string `json:"applied-at,omitempty"`
}

// RunActions: is-confirmable mirrors permissions.can-apply; it was once hardcoded false,
// which hung go-tfe clients polling it (tfe_workspace_run).
type RunActions struct {
	IsCancelable      bool `json:"is-cancelable"`
	IsConfirmable     bool `json:"is-confirmable"`
	IsDiscardable     bool `json:"is-discardable"`
	IsForceCancelable bool `json:"is-force-cancelable"`
}

// RunPermissions is the per-run permission block.
type RunPermissions struct {
	CanApply        bool `json:"can-apply"`
	CanCancel       bool `json:"can-cancel"`
	CanDiscard      bool `json:"can-discard"`
	CanForceExecute bool `json:"can-force-execute"`
	CanForceCancel  bool `json:"can-force-cancel"`
}

// RunAttributes is the TFE runs attribute block plus StackWeaver's configuration-version
// context and runner extensions. Presence rules preserved from the map builder: the commit,
// branch, PR, timestamp, error and runner members appear only when set.
type RunAttributes struct {
	Status           string              `json:"status"`
	Operation        string              `json:"operation"`
	IsDestroy        bool                `json:"is-destroy"`
	PlanOnly         bool                `json:"plan-only"`
	Message          string              `json:"message"`
	Source           string              `json:"source"`
	CreatedAt        string              `json:"created-at"`
	UpdatedAt        string              `json:"updated-at"`
	StatusTimestamps RunStatusTimestamps `json:"status-timestamps"`
	HasChanges       bool                `json:"has-changes"`
	Actions          RunActions          `json:"actions"`
	Permissions      RunPermissions      `json:"permissions"`

	ConfigurationVersionSource string `json:"configuration-version-source,omitempty"`
	CommitHash                 string `json:"commit-hash,omitempty"`
	Committer                  string `json:"committer,omitempty"`
	PRNumber                   int    `json:"pr-number,omitempty"`
	SourceBranch               string `json:"source-branch,omitempty"`

	StartedAt    string `json:"started-at,omitempty"`
	CompletedAt  string `json:"completed-at,omitempty"`
	ErrorMessage string `json:"error-message,omitempty"`

	AgentPoolID   string `json:"agent-pool-id,omitempty"`
	AgentPoolName string `json:"agent-pool-name,omitempty"`
	RunnerID      string `json:"runner-id,omitempty"`
	RunnerName    string `json:"runner-name,omitempty"`
}

// RunRelationships: workspace always; the rest appear per operation and phase, preserved from
// the map builder (plan/apply ids equal the run id by design).
type RunRelationships struct {
	Workspace            jsonapi.Relationship  `json:"workspace"`
	ConfigurationVersion *jsonapi.Relationship `json:"configuration-version,omitempty"`
	Plan                 *jsonapi.Relationship `json:"plan,omitempty"`
	Apply                *jsonapi.Relationship `json:"apply,omitempty"`
}

// PhaseStatusTimestamps is the shared status-timestamps block of a plan or apply resource;
// every member conditional per the phase's state machine.
type PhaseStatusTimestamps struct {
	PendingAt  string `json:"pending-at,omitempty"`
	QueuedAt   string `json:"queued-at,omitempty"`
	StartedAt  string `json:"started-at,omitempty"`
	FinishedAt string `json:"finished-at,omitempty"`
}

// ExecutionDetails is the single-member execution mode block of a plan or apply.
type ExecutionDetails struct {
	Mode string `json:"mode"`
}

// PlanAttributes is the TFE plans attribute block. PlanJSON carries the raw plan output for
// the frontend when present (json.RawMessage: stored as JSON, forwarded verbatim).
type PlanAttributes struct {
	ExecutionDetails       ExecutionDetails      `json:"execution-details"`
	GeneratedConfiguration bool                  `json:"generated-configuration"`
	HasChanges             bool                  `json:"has-changes"`
	ResourceAdditions      int                   `json:"resource-additions"`
	ResourceChanges        int                   `json:"resource-changes"`
	ResourceDestructions   int                   `json:"resource-destructions"`
	ResourceImports        int                   `json:"resource-imports"`
	Status                 string                `json:"status"`
	StatusTimestamps       PhaseStatusTimestamps `json:"status-timestamps"`
	PlanJSON               models.PlanOutput     `json:"plan-json,omitempty"`
	LogReadURL             string                `json:"log-read-url"`
}

// ApplyResourceState is one applied resource in the StackWeaver apply-resources extension.
type ApplyResourceState struct {
	Address      string `json:"address"`
	Status       string `json:"status"`
	Action       string `json:"action"`
	ResourceID   string `json:"resource_id,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	Details      string `json:"details,omitempty"`
}

// ApplyAttributes is the TFE applies attribute block plus the apply-resources extension.
type ApplyAttributes struct {
	ExecutionDetails     ExecutionDetails      `json:"execution-details"`
	Status               string                `json:"status"`
	StatusTimestamps     PhaseStatusTimestamps `json:"status-timestamps"`
	ResourceAdditions    int                   `json:"resource-additions"`
	ResourceChanges      int                   `json:"resource-changes"`
	ResourceDestructions int                   `json:"resource-destructions"`
	ResourceImports      int                   `json:"resource-imports"`
	ApplyResources       []ApplyResourceState  `json:"apply-resources,omitempty"`
	LogReadURL           string                `json:"log-read-url"`
}

// PhaseRelationships is the plans/applies relationship block: an always-empty state-versions
// linkage, per the TFE spec (state versions are linked separately).
type PhaseRelationships struct {
	StateVersions jsonapi.ManyRelationship `json:"state-versions"`
}

// PlanLinks carries the plan's absolute self and json-output URLs.
type PlanLinks struct {
	Self       string `json:"self"`
	JSONOutput string `json:"json-output"`
}

// ConfigurationVersionAttributes is the TFE configuration-versions attribute block. UpdatedAt
// is a conditional member: the create response omits it (the row was just born), the read
// paths emit it - preserved from the map builders.
type ConfigurationVersionAttributes struct {
	Status        models.ConfigurationVersionStatus `json:"status"`
	UploadURL     string                            `json:"upload-url"`
	Source        string                            `json:"source"`
	AutoQueueRuns bool                              `json:"auto-queue-runs"`
	Speculative   bool                              `json:"speculative"`
	CreatedAt     string                            `json:"created-at"`
	UpdatedAt     string                            `json:"updated-at"`
}

// WorkspaceOnlyRelationships is the single-relationship block many TFE resources share.
type WorkspaceOnlyRelationships struct {
	Workspace jsonapi.Relationship `json:"workspace"`
}

// UploadLink is the configuration-version links object.
type UploadLink struct {
	Upload string `json:"upload"`
}

// configurationVersionResource assembles the shared shape; updatedAt empty reproduces the
// create response's narrower attribute set.
func configurationVersionResource(id string, attrs ConfigurationVersionAttributes, workspaceID, uploadURL string) jsonapi.Resource[ConfigurationVersionAttributes] {
	return jsonapi.Resource[ConfigurationVersionAttributes]{
		ID:            id,
		Type:          "configuration-versions",
		Attributes:    attrs,
		Relationships: WorkspaceOnlyRelationships{Workspace: jsonapi.ToOne(workspaceID, "workspaces")},
		Links:         UploadLink{Upload: uploadURL},
	}
}

// StateVersionResourceAttributes is one materialized resource row of a state version.
type StateVersionResourceAttributes struct {
	Address       string `json:"address"`
	Mode          string `json:"mode"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Provider      string `json:"provider"`
	Module        string `json:"module"`
	InstanceCount int    `json:"instance-count"`
}

// StateVersionOutputAttributes is one materialized output. Value and Type are decoded JSON
// values (any), because outputs carry whatever shape Terraform produced; Type appears only
// when stored.
type StateVersionOutputAttributes struct {
	Name      string `json:"name"`
	Value     any    `json:"value"`
	Sensitive bool   `json:"sensitive"`
	Type      any    `json:"type,omitempty"`
}

// TaskPhaseTimestamps is the shared status-timestamps of task stages and results.
type TaskPhaseTimestamps struct {
	RunningAt  string `json:"running-at,omitempty"`
	PassedAt   string `json:"passed-at,omitempty"`
	FailedAt   string `json:"failed-at,omitempty"`
	ErroredAt  string `json:"errored-at,omitempty"`
	CanceledAt string `json:"canceled-at,omitempty"`
}

// TaskStagePermissions reflect the CALLER's apply permission; can-override-policy stays false
// (policy evaluations: feature we don't have, documented divergence).
type TaskStagePermissions struct {
	CanOverridePolicy bool `json:"can-override-policy"`
	CanOverrideTasks  bool `json:"can-override-tasks"`
	CanOverride       bool `json:"can-override"`
}

// TaskStageActions reports whether the stage actually awaits an override.
type TaskStageActions struct {
	IsOverridable bool `json:"is-overridable"`
}

// TaskStageAttributes is the task-stages attribute block.
type TaskStageAttributes struct {
	Stage            string               `json:"stage"`
	Status           string               `json:"status"`
	StatusTimestamps TaskPhaseTimestamps  `json:"status-timestamps"`
	CreatedAt        string               `json:"created-at"`
	UpdatedAt        string               `json:"updated-at"`
	Permissions      TaskStagePermissions `json:"permissions"`
	Actions          TaskStageActions     `json:"actions"`
}

// TaskStageRelationships: policy-evaluations is emitted empty on purpose (no subsystem).
type TaskStageRelationships struct {
	Run               jsonapi.Relationship     `json:"run"`
	TaskResults       jsonapi.ManyRelationship `json:"task-results"`
	PolicyEvaluations jsonapi.ManyRelationship `json:"policy-evaluations"`
}

// TaskResultAttributes is the task-results attribute block.
type TaskResultAttributes struct {
	Status                        string              `json:"status"`
	Message                       string              `json:"message"`
	URL                           string              `json:"url"`
	StatusTimestamps              TaskPhaseTimestamps `json:"status-timestamps"`
	TaskID                        string              `json:"task-id"`
	TaskName                      string              `json:"task-name"`
	TaskURL                       string              `json:"task-url"`
	WorkspaceTaskID               string              `json:"workspace-task-id"`
	WorkspaceTaskEnforcementLevel string              `json:"workspace-task-enforcement-level"`
	CreatedAt                     string              `json:"created-at"`
	UpdatedAt                     string              `json:"updated-at"`
}

// TaskResultRelationships carries the stage relation under BOTH spellings: go-tfe v1 decodes
// `task_stage` with an underscore while TFE's v2 OpenAPI spec hyphenates, so both are emitted
// to satisfy either reader - preserved from the map builder.
type TaskResultRelationships struct {
	TaskStageUnderscore jsonapi.Relationship `json:"task_stage"`
	TaskStage           jsonapi.Relationship `json:"task-stage"`
}

// TaskResultOutcomeAttributes: Tags is the service's own label payload, stored and forwarded
// verbatim (models.JSONB) - not ours to type.
type TaskResultOutcomeAttributes struct {
	OutcomeID   string       `json:"outcome-id"`
	Description string       `json:"description"`
	Body        string       `json:"body"`
	URL         string       `json:"url"`
	Tags        models.JSONB `json:"tags"`
	CreatedAt   string       `json:"created-at"`
	UpdatedAt   string       `json:"updated-at"`
}

// TaskResultOutcomeRelationships points an outcome at its result.
type TaskResultOutcomeRelationships struct {
	TaskResult jsonapi.Relationship `json:"task-result"`
}

// WorkspaceTaskAttributes: BOTH stage (deprecated, = stages[0]) and stages are emitted - the
// provider stores both and go-tfe decodes both.
type WorkspaceTaskAttributes struct {
	EnforcementLevel string             `json:"enforcement-level"`
	Stage            string             `json:"stage"`
	Stages           models.StringArray `json:"stages"`
	CreatedAt        string             `json:"created-at"`
	UpdatedAt        string             `json:"updated-at"`
}

// WorkspaceTaskRelationships is the fixed task/workspace pair of a workspace-tasks resource.
type WorkspaceTaskRelationships struct {
	Task      jsonapi.Relationship `json:"task"`
	Workspace jsonapi.Relationship `json:"workspace"`
}

// RunTaskGlobalConfiguration is ALWAYS present with a boolean enabled - go-tfe only parses
// the sub-object when that key is a JSON bool, and
// tfe_organization_run_task_global_settings errors on a task without it.
type RunTaskGlobalConfiguration struct {
	Enabled          bool               `json:"enabled"`
	Stages           models.StringArray `json:"stages"`
	EnforcementLevel string             `json:"enforcement-level"`
}

// RunTaskAttributes is the TFE tasks attribute block (hmac-key is write-only and never here).
type RunTaskAttributes struct {
	Name                string                     `json:"name"`
	URL                 string                     `json:"url"`
	Description         string                     `json:"description"`
	Category            string                     `json:"category"`
	Enabled             bool                       `json:"enabled"`
	GlobalConfiguration RunTaskGlobalConfiguration `json:"global-configuration"`
	CreatedAt           string                     `json:"created-at"`
	UpdatedAt           string                     `json:"updated-at"`
}

// RunTaskRelationships: the organization plus the task's workspace attachments.
type RunTaskRelationships struct {
	Organization   jsonapi.Relationship     `json:"organization"`
	WorkspaceTasks jsonapi.ManyRelationship `json:"workspace-tasks"`
}

// ChangeRequestAttributes: archived-by/archived-at are null while the request is open,
// matching TFE. workspace-name and created-by are Stackweaver extras (TFE exposes neither).
type ChangeRequestAttributes struct {
	Subject       string  `json:"subject"`
	Message       string  `json:"message"`
	ArchivedBy    *string `json:"archived-by"`
	ArchivedAt    *string `json:"archived-at"`
	CreatedBy     string  `json:"created-by"`
	CreatedAt     string  `json:"created-at"`
	UpdatedAt     string  `json:"updated-at"`
	WorkspaceName string  `json:"workspace-name,omitempty"`
}

// WorkspaceOnlyRelationshipsWS is the single workspace relationship block.
type WorkspaceOnlyRelationshipsWS struct {
	Workspace jsonapi.Relationship `json:"workspace"`
}

// BulkActionInputs echoes the subject/message the bulk filing carried.
type BulkActionInputs struct {
	Subject string `json:"subject"`
	Message string `json:"message"`
}

// BulkActionAttributes is the bulk-filing acknowledgment (snake_case, no id on the wire).
type BulkActionAttributes struct {
	OrganizationID string             `json:"organization_id"`
	ActionType     string             `json:"action_type"`
	ActionInputs   BulkActionInputs   `json:"action_inputs"`
	CreatedBy      jsonapi.ResourceID `json:"created_by"`
}

// BulkActionDocument has no id member, so it cannot use jsonapi.Resource.
type BulkActionDocument struct {
	Type       string               `json:"type"`
	Attributes BulkActionAttributes `json:"attributes"`
}

// NotificationConfigAttributes is the TFE notification-configurations attribute block (the
// token is write-only and never here).
type NotificationConfigAttributes struct {
	Name            string   `json:"name"`
	DestinationType string   `json:"destination-type"`
	URL             string   `json:"url"`
	Enabled         bool     `json:"enabled"`
	Triggers        []string `json:"triggers"`
	EmailAddresses  []string `json:"email-addresses"`
	CreatedAt       string   `json:"created-at"`
	UpdatedAt       string   `json:"updated-at"`
}

// NotificationConfigRelationships: subscribable is polymorphic (workspace, project or team)
// and a raw pointer - an unhandled scope emits null rather than being omitted.
type NotificationConfigRelationships struct {
	Subscribable *jsonapi.Relationship `json:"subscribable"`
}
