// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import "github.com/google/uuid"

// resolver adapters — one per resource type. Each wraps an OrgResolver
// method so a route entry can reference it by value.
var (
	rOrgMembership          = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByOrgMembershipID(v) }
	rProject                = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByProjectID(v) }
	rWorkspace              = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByWorkspaceID(v) }
	rRun                    = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByRunID(v) }
	rConfigVersion          = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByConfigVersionID(v) }
	rStateVersion           = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByStateVersionID(v) }
	rVariable               = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByVariableID(v) }
	rVariableSet            = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByVariableSetID(v) }
	rVariableSetVariable    = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByVariableSetVariableID(v) }
	rTeam                   = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByTeamID(v) }
	rTeamWorkspaceAccess    = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByTeamWorkspaceAccessID(v) }
	rTeamProjectAccess      = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByTeamProjectAccessID(v) }
	rAgentPool              = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAgentPoolID(v) }
	rRunner                 = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByRunnerID(v) }
	rVCSConnection          = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByVCSConnectionID(v) }
	rOIDCConfig             = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByOIDCConfigID(v) }
	rRegistryProvider       = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByRegistryProviderID(v) }
	rAnsibleInventory       = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsibleInventoryID(v) }
	rAnsibleHost            = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsibleHostID(v) }
	rAnsibleGroup           = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsibleGroupID(v) }
	rAnsibleInventorySource = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsibleInventorySourceID(v) }
	rAnsibleCredential      = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsibleCredentialID(v) }
	rAnsiblePlaybook        = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsiblePlaybookID(v) }
	rAnsibleJobTemplate     = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsibleJobTemplateID(v) }
	rAnsibleJobTemplateVar  = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsibleJobTemplateVariableID(v) }
	rAnsibleJob             = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsibleJobID(v) }
	rAnsibleSchedule        = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsibleScheduleID(v) }
	rAnsibleWorkflow        = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsibleWorkflowID(v) }
	rAnsibleWorkflowNode    = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsibleWorkflowNodeID(v) }
	rAnsibleWorkflowEdge    = func(r OrgResolver, v string) (uuid.UUID, error) { return r.ByAnsibleWorkflowEdgeID(v) }
)

func orgByName() routeEntry { return routeEntry{orgNameParam: "name"} }
func agnostic() routeEntry  { return routeEntry{agnostic: true} }
func resource(p string, f resolverFunc) routeEntry {
	return routeEntry{param: p, resolve: f}
}

// wallRegistry classifies every authenticated /api/v2 route for the
// org-resolution wall, keyed by its gin c.FullPath() pattern. Any api-key
// request to a route absent from this map is denied (fail-closed), so a new
// route cannot silently bypass tenant isolation.
//
// Routes registered directly on the root router (the token-in-query upload
// endpoint, VCS/Zitadel webhooks, public registry v1/v2, OIDC .well-known)
// are NOT under the v2 group and therefore never reach this wall.
var wallRegistry = map[string]routeEntry{
	// --- ping / global ---
	"/api/v2/ping":                         agnostic(),
	"/api/v2/admin/terraform-versions":     agnostic(),
	"/api/v2/admin/terraform-versions/:id": agnostic(),
	"/api/v2/terraform-versions":           agnostic(),
	"/api/v2/activities":                   agnostic(),
	"/api/v2/activities/recent":            agnostic(),
	"/api/v2/dashboard/stats":              agnostic(),

	// --- own user tokens (user-bound, no target org) ---
	"/api/v2/tokens":     agnostic(),
	"/api/v2/tokens/:id": agnostic(),

	// --- organizations ---
	// List + create carry no single target org (create has no parent).
	"/api/v2/organizations":                                orgListCreate(),
	"/api/v2/organizations/:name":                          orgByName(),
	"/api/v2/organizations/:name/entitlement-set":          orgByName(),
	"/api/v2/organizations/:name/organization-memberships": orgByName(),
	"/api/v2/organizations/:name/effective-permissions":    orgByName(),
	"/api/v2/organization-memberships/:id":                 resource("id", rOrgMembership),

	// --- teams ---
	"/api/v2/organizations/:name/teams":                        orgByName(),
	"/api/v2/organizations/:name/teams/:teamName":              orgByName(),
	"/api/v2/teams/:id":                                        resource("id", rTeam),
	"/api/v2/teams/:id/relationships/organization-memberships": resource("id", rTeam),

	// --- projects ---
	"/api/v2/organizations/:name/projects":                      orgByName(),
	"/api/v2/organizations/:name/projects/:project_name":        orgByName(),
	"/api/v2/projects/:id":                                      resource("id", rProject),
	"/api/v2/projects/:id/ansible-config":                       resource("id", rProject),
	"/api/v2/projects/:id/relationships/team-access":            resource("id", rProject),
	"/api/v2/projects/:id/relationships/team-access/:access_id": resource("access_id", rTeamProjectAccess),

	// --- agent pools ---
	"/api/v2/organizations/:name/agent-pools": orgByName(),
	"/api/v2/agent-pools/:id":                 resource("id", rAgentPool),
	"/api/v2/agent-pools/:id/agents":          resource("id", rAgentPool),

	// --- OIDC configurations ---
	"/api/v2/organizations/:name/oidc-configurations": orgByName(),
	"/api/v2/oidc-configurations/:id":                 resource("id", rOIDCConfig),

	// --- runners (management API) ---
	"/api/v2/organizations/:name/runners":       orgByName(),
	"/api/v2/organizations/:name/runners/stats": orgByName(),
	"/api/v2/runners/:id":                       resource("id", rRunner),

	// --- ansible config (org/project) ---
	"/api/v2/organizations/:name/ansible-config":           orgByName(),
	"/api/v2/organizations/:name/ansible-config/effective": orgByName(),

	// --- webhook events ---
	"/api/v2/organizations/:name/webhook-events": orgByName(),

	// --- workspaces ---
	"/api/v2/organizations/:name/workspaces":                                     orgByName(),
	"/api/v2/organizations/:name/workspaces/:workspace_name":                     orgByName(),
	"/api/v2/organizations/:name/workspaces/:workspace_name/actions/safe-delete": orgByName(),
	"/api/v2/terraform/workspaces/:id":                                           resource("id", rWorkspace),
	"/api/v2/workspaces/:id":                                                     resource("id", rWorkspace),
	"/api/v2/workspaces/:id/actions/lock":                                        resource("id", rWorkspace),
	"/api/v2/workspaces/:id/actions/unlock":                                      resource("id", rWorkspace),
	"/api/v2/workspaces/:id/actions/force-unlock":                                resource("id", rWorkspace),
	"/api/v2/workspaces/:id/actions/safe-delete":                                 resource("id", rWorkspace),
	"/api/v2/workspaces/:id/runs":                                                resource("id", rWorkspace),
	"/api/v2/workspaces/:id/configuration-versions":                              resource("id", rWorkspace),
	"/api/v2/workspaces/:id/state-versions":                                      resource("id", rWorkspace),
	"/api/v2/workspaces/:id/state-versions/remove-resource":                      resource("id", rWorkspace),
	"/api/v2/workspaces/:id/current-state-version":                               resource("id", rWorkspace),
	"/api/v2/workspaces/:id/current-state-version-outputs":                       resource("id", rWorkspace),
	"/api/v2/workspaces/:id/current-state-version-resources":                     resource("id", rWorkspace),
	"/api/v2/workspaces/:id/vars":                                                resource("id", rWorkspace),
	"/api/v2/workspaces/:id/vars/:variable_id":                                   resource("variable_id", rVariable),
	"/api/v2/workspaces/:id/platform-variables":                                  resource("id", rWorkspace),

	// --- team access (workspace) ---
	// Collection routes carry team+workspace in the body and are validated
	// by the handler; the wall treats them as agnostic.
	"/api/v2/team-workspaces":                                     agnostic(),
	"/api/v2/team-workspaces/:id":                                 resource("id", rTeamWorkspaceAccess),
	"/api/v2/workspaces/:id/relationships/team-access":            resource("id", rWorkspace),
	"/api/v2/workspaces/:id/relationships/team-access/:access_id": resource("access_id", rTeamWorkspaceAccess),
	"/api/v2/team-projects":                                       agnostic(),
	"/api/v2/team-projects/:id":                                   resource("id", rTeamProjectAccess),

	// --- runs ---
	// POST /runs carries the workspace in the body; validated by handler.
	"/api/v2/runs":                           agnostic(),
	"/api/v2/runs/:id":                       resource("id", rRun),
	"/api/v2/runs/:id/plan":                  resource("id", rRun),
	"/api/v2/runs/:id/outputs":               resource("id", rRun),
	"/api/v2/runs/:id/logs":                  resource("id", rRun),
	"/api/v2/runs/:id/logs/plan":             resource("id", rRun),
	"/api/v2/runs/:id/logs/apply":            resource("id", rRun),
	"/api/v2/runs/:id/actions/apply":         resource("id", rRun),
	"/api/v2/runs/:id/actions/cancel":        resource("id", rRun),
	"/api/v2/runs/:id/actions/discard":       resource("id", rRun),
	"/api/v2/runs/:id/actions/force-cancel":  resource("id", rRun),
	"/api/v2/runs/:id/actions/force-execute": resource("id", rRun),
	"/api/v2/plans/:id":                      resource("id", rRun),
	"/api/v2/applies/:id":                    resource("id", rRun),
	"/api/v2/organizations/:name/runs":       orgByName(),
	"/api/v2/organizations/:name/runs/queue": orgByName(),

	// --- configuration versions ---
	"/api/v2/configuration-versions/:id": resource("id", rConfigVersion),

	// --- state versions (by id) ---
	"/api/v2/state-versions/:id":          resource("id", rStateVersion),
	"/api/v2/state-versions/:id/download": resource("id", rStateVersion),
	"/api/v2/state-versions/:id/outputs":  resource("id", rStateVersion),

	// --- variable sets ---
	"/api/v2/organizations/:name/varsets":                                     orgByName(),
	"/api/v2/organizations/:name/varsets/:id":                                 orgByName(),
	"/api/v2/organizations/:name/varsets/:id/relationships/workspaces":        orgByName(),
	"/api/v2/organizations/:name/varsets/:id/relationships/projects":          orgByName(),
	"/api/v2/organizations/:name/varsets/:id/relationships/vars":              orgByName(),
	"/api/v2/organizations/:name/varsets/:id/relationships/vars/:variable_id": orgByName(),
	"/api/v2/varsets/:id":                                 resource("id", rVariableSet),
	"/api/v2/varsets/:id/relationships/workspaces":        resource("id", rVariableSet),
	"/api/v2/varsets/:id/relationships/projects":          resource("id", rVariableSet),
	"/api/v2/varsets/:id/relationships/vars":              resource("id", rVariableSet),
	"/api/v2/varsets/:id/relationships/vars/:variable_id": resource("variable_id", rVariableSetVariable),

	// --- VCS connections ---
	"/api/v2/organizations/:name/vcs-connections":                                       orgByName(),
	"/api/v2/organizations/:name/vcs-connections/github/install":                        orgByName(),
	"/api/v2/organizations/:name/vcs-connections/github/installations/:installation_id": orgByName(),
	"/api/v2/organizations/:name/vcs-connections/azure-devops/install":                  orgByName(),
	"/api/v2/vcs-connections/:id":                                                       resource("id", rVCSConnection),
	"/api/v2/vcs-connections/:id/repositories":                                          resource("id", rVCSConnection),
	"/api/v2/vcs-connections/:id/projects":                                              resource("id", rVCSConnection),
	"/api/v2/vcs-connections/:id/repositories/:owner/:repo/branches":                    resource("id", rVCSConnection),
	"/api/v2/vcs-connections/:id/repositories/:owner/:repo/contents/*path":              resource("id", rVCSConnection),
	"/api/v2/vcs-connections/:id/repositories/:owner/:repo/yaml-files":                  resource("id", rVCSConnection),
	"/api/v2/vcs-connections/:id/repositories/:owner/:repo/inventory-files":             resource("id", rVCSConnection),

	// --- registry: modules / providers / gpg keys (all org-in-URL) ---
	"/api/v2/organizations/:name/registry/modules":                                                                        orgByName(),
	"/api/v2/organizations/:name/registry/modules/:module_name/:provider":                                                 orgByName(),
	"/api/v2/organizations/:name/registry/modules/:module_name/:provider/versions":                                        orgByName(),
	"/api/v2/organizations/:name/registry/modules/:module_name/:provider/versions/:version":                               orgByName(),
	"/api/v2/organizations/:name/registry-providers":                                                                      orgByName(),
	"/api/v2/organizations/:name/registry-providers/:registry_name/:namespace/:provider_name":                             orgByName(),
	"/api/v2/organizations/:name/registry-providers/:registry_name/:namespace/:provider_name/versions/:version/platforms": orgByName(),
	"/api/v2/registry-providers/:id":                                                                                      resource("id", rRegistryProvider),
	"/api/v2/organizations/:name/registry/gpg-keys":                                                                       orgByName(),
	"/api/v2/organizations/:name/registry/gpg-keys/:key_id":                                                               orgByName(),

	// --- runner agent control plane (api-key auth from runner agents) ---
	// The runner registers with an org-scoped key, so its own bound org is
	// the only org it can act in. Job routes are validated by the handler
	// against the runner's assignment; org resolution from the job exec id
	// is a future refinement (TODO).
	"/api/v2/runner/register":           agnostic(),
	"/api/v2/runner/heartbeat":          agnostic(),
	"/api/v2/runner/deregister":         agnostic(),
	"/api/v2/runner/jobs/:id/start":     agnostic(),
	"/api/v2/runner/jobs/:id/output":    agnostic(),
	"/api/v2/runner/jobs/:id/complete":  agnostic(),
	"/api/v2/runner/jobs/:id/state":     agnostic(),
	"/api/v2/runner/jobs/:id/artifacts": agnostic(),
	"/api/v2/runner/jobs/:id/status":    agnostic(),

	// --- ansible: inventories ---
	"/api/v2/organizations/:name/ansible/inventories":           orgByName(),
	"/api/v2/ansible/inventories/:id":                           resource("id", rAnsibleInventory),
	"/api/v2/ansible/inventories/:id/actions/sync":              resource("id", rAnsibleInventory),
	"/api/v2/ansible/inventories/:id/ini":                       resource("id", rAnsibleInventory),
	"/api/v2/ansible/inventories/:id/json":                      resource("id", rAnsibleInventory),
	"/api/v2/ansible/inventories/:id/hosts":                     resource("id", rAnsibleInventory),
	"/api/v2/ansible/inventories/:id/groups":                    resource("id", rAnsibleInventory),
	"/api/v2/ansible/inventories/:id/sources":                   resource("id", rAnsibleInventory),
	"/api/v2/ansible/hosts/:id":                                 resource("id", rAnsibleHost),
	"/api/v2/ansible/groups/:id":                                resource("id", rAnsibleGroup),
	"/api/v2/ansible/inventory-sources/:source_id":              resource("source_id", rAnsibleInventorySource),
	"/api/v2/ansible/inventory-sources/:source_id/actions/sync": resource("source_id", rAnsibleInventorySource),

	// --- ansible: credentials ---
	"/api/v2/organizations/:name/ansible/credentials": orgByName(),
	"/api/v2/ansible/credentials/:id":                 resource("id", rAnsibleCredential),

	// --- ansible: playbooks ---
	"/api/v2/organizations/:name/ansible/playbooks": orgByName(),
	"/api/v2/projects/:id/ansible/playbooks":        resource("id", rProject),
	"/api/v2/ansible/playbooks/:id":                 resource("id", rAnsiblePlaybook),
	"/api/v2/ansible/playbooks/:id/actions/sync":    resource("id", rAnsiblePlaybook),

	// --- ansible: job templates ---
	"/api/v2/organizations/:name/ansible/job-templates":   orgByName(),
	"/api/v2/projects/:id/ansible/job-templates":          resource("id", rProject),
	"/api/v2/ansible/job-templates/:id":                   resource("id", rAnsibleJobTemplate),
	"/api/v2/ansible/job-templates/:id/launch":            resource("id", rAnsibleJobTemplate),
	"/api/v2/ansible/job-templates/:id/variable-sets":     resource("id", rAnsibleJobTemplate),
	"/api/v2/ansible/job-templates/:id/vars":              resource("id", rAnsibleJobTemplate),
	"/api/v2/ansible/job-templates/:id/vars/:variable_id": resource("variable_id", rAnsibleJobTemplateVar),

	// --- ansible: jobs ---
	"/api/v2/organizations/:name/ansible/jobs":       orgByName(),
	"/api/v2/organizations/:name/ansible/jobs/queue": orgByName(),
	"/api/v2/projects/:id/ansible/jobs":              resource("id", rProject),
	"/api/v2/ansible/jobs/:id":                       resource("id", rAnsibleJob),
	"/api/v2/ansible/jobs/:id/actions/cancel":        resource("id", rAnsibleJob),
	"/api/v2/ansible/jobs/:id/actions/relaunch":      resource("id", rAnsibleJob),
	"/api/v2/ansible/jobs/:id/events":                resource("id", rAnsibleJob),
	"/api/v2/ansible/jobs/:id/output":                resource("id", rAnsibleJob),
	"/api/v2/ansible/jobs/:id/collections":           resource("id", rAnsibleJob),

	// --- ansible: schedules ---
	"/api/v2/organizations/:name/ansible/schedules":          orgByName(),
	"/api/v2/ansible/schedules/:schedule_id":                 resource("schedule_id", rAnsibleSchedule),
	"/api/v2/ansible/schedules/:schedule_id/actions/enable":  resource("schedule_id", rAnsibleSchedule),
	"/api/v2/ansible/schedules/:schedule_id/actions/disable": resource("schedule_id", rAnsibleSchedule),
	"/api/v2/ansible/schedules/:schedule_id/actions/run-now": resource("schedule_id", rAnsibleSchedule),

	// --- ansible: collections (global) ---
	"/api/v2/ansible/collections/pre-installed": agnostic(),
	"/api/v2/ansible/collections/search":        agnostic(),

	// --- ansible: workflows ---
	"/api/v2/organizations/:name/ansible/workflows": orgByName(),
	"/api/v2/ansible/workflows/:id":                 resource("id", rAnsibleWorkflow),
	"/api/v2/ansible/workflows/:id/nodes":           resource("id", rAnsibleWorkflow),
	"/api/v2/ansible/workflows/:id/edges":           resource("id", rAnsibleWorkflow),
	"/api/v2/ansible/workflow-nodes/:id":            resource("id", rAnsibleWorkflowNode),
	"/api/v2/ansible/workflow-edges/:id":            resource("id", rAnsibleWorkflowEdge),
}

// orgListCreate covers GET/POST /api/v2/organizations. Listing returns only
// the caller's orgs (filtered downstream) and creation is isolation-neutral
// (the creator becomes owner of a brand-new org), so neither has a target
// org for the wall to compare against.
func orgListCreate() routeEntry { return routeEntry{agnostic: true} }
