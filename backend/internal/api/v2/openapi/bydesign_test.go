// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package openapi

// byDesign is the closed list of /api/v2 operations whose bodies a protocol or Terraform
// Enterprise defines, each with that protocol as its reason (#858, D6 and D12). It is the
// public "Endpoints that do not use JSON:API by design" list of docs/api-reference/README.md in
// code, and TestEveryJSONBodyIsADocument skips exactly these. A new exception goes here only
// with a protocol as its reason; a Stackweaver convenience is never one.
// See docs/internal/guidelines/api/json-api-everywhere.md.
var byDesign = map[string]string{
	// Text and file bodies.
	"GET /api/v2/runs/{id}/logs":                                                           "the run log is plain text, as Terraform Enterprise serves it",
	"GET /api/v2/runs/{id}/logs/plan":                                                      "the plan log is plain text, as Terraform Enterprise serves it",
	"GET /api/v2/runs/{id}/logs/apply":                                                     "the apply log is plain text, as Terraform Enterprise serves it",
	"GET /api/v2/ansible/jobs/{id}/output":                                                 "the Ansible job output is plain text, as the run logs are",
	"GET /api/v2/ping":                                                                     "the health check answers the text pong",
	"GET /api/v2/state-versions/{id}/download":                                             "the state file itself, as Terraform Enterprise serves it",
	"GET /api/v2/plans/{id}/json-output":                                                   "the plan's JSON output, whose shape Terraform defines",
	"GET /api/v2/configuration-versions/{id}/download":                                     "the configuration archive itself",
	"GET /api/v2/ansible/inventories/{id}/ini":                                             "the inventory in Ansible's INI format",
	"GET /api/v2/ansible/inventories/{id}/json":                                            "the inventory in Ansible's JSON inventory format",
	"PUT /api/v2/configuration-versions/{id}/upload":                                       "a raw tar.gz body, as Terraform Enterprise accepts it",
	"POST /api/v2/organizations/{name}/registry/modules/{module_name}/{provider}/versions": "a registry upload, multipart form data",
	"POST /api/v2/organizations/{name}/registry-providers/{registry_name}/{namespace}/{provider_name}/versions/{version}/platforms": "a registry upload, multipart form data",

	// Terraform Enterprise's own bodies.
	"POST /api/v2/runs/{id}/actions/apply":           "a run action, 202 Accepted as Terraform Enterprise answers it",
	"POST /api/v2/runs/{id}/actions/cancel":          "a run action, 202 Accepted with no body",
	"POST /api/v2/runs/{id}/actions/discard":         "a run action, 202 Accepted with no body",
	"POST /api/v2/runs/{id}/actions/force-cancel":    "a run action, 202 Accepted with no body",
	"POST /api/v2/runs/{id}/actions/force-execute":   "a run action, 202 Accepted with no body",
	"POST /api/v2/workspaces/{id}/actions/lock":      `Terraform Enterprise's plain {"reason"} body`,
	"POST /api/v2/task-stages/{id}/actions/override": `Terraform Enterprise's plain {"comment"} body`,

	// The runner control plane, spoken by the runner binaries.
	"POST /api/v2/runner/register":                   "the runner control plane",
	"POST /api/v2/runner/deregister":                 "the runner control plane",
	"POST /api/v2/runner/heartbeat":                  "the runner control plane",
	"POST /api/v2/runner/jobs/{id}/start":            "the runner control plane",
	"POST /api/v2/runner/jobs/{id}/complete":         "the runner control plane",
	"POST /api/v2/runner/jobs/{id}/events":           "the runner control plane",
	"POST /api/v2/runner/jobs/{id}/output":           "the runner control plane",
	"POST /api/v2/runner/jobs/{id}/state":            "the runner control plane",
	"GET /api/v2/runner/jobs/{id}/status":            "the runner control plane",
	"GET /api/v2/runner/jobs/{id}/artifacts":         "the runner control plane",
	"GET /api/v2/runner/jobs/{id}/playbook-snapshot": "the runner control plane",

	// Webhook receivers, in the format the sender defines.
	"POST /api/v2/vcs-connections/azure-devops/webhook": "Azure DevOps service hook deliveries",
	"POST /api/v2/zitadel/actions/complement-token":     "the identity provider's action callback",
	"POST /api/v2/zitadel/actions/idp-sync":             "the identity provider's action callback",
	"POST /api/v2/ansible/job-templates/{id}/callback":  "the AWX-compatible provisioning callback",

	// OAuth 2.0.
	"POST /api/v2/oauth/authorize":                       "terraform login, which OAuth 2.0 defines",
	"POST /api/v2/oauth/token":                           "terraform login, which OAuth 2.0 defines",
	"POST /api/v2/vcs-connections/azure-devops/callback": "the Azure DevOps OAuth callback",
}
