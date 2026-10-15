// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package routes_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	terraformHandlers "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers/terraform"
)

// Write cases for the workspace and run routes: workspaces and what hangs off one (variables,
// team access, run triggers, notifications, tags, configuration versions, state), runs and
// their actions, run tasks and change requests.
func init() {
	registerWriteCases(
		writeCase{
			// The workspace arrives in the body, not the path.
			route: "POST /api/v2/runs",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/runs", related(
					document("runs", map[string]any{"message": "Recorded by the golden write harness", "plan-only": true}),
					"workspace", "workspaces", w.id("workspaces")))
			},
		},
		writeCase{
			// Storage-backed, and it needs a write before it: the version being uploaded to.
			route: "PUT /api/v2/configuration-versions/:id/upload",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				created := w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/configuration-versions"),
					document("configuration-versions", map[string]any{"auto-queue-runs": false})))
				// A client uploads to the URL the create hands back, which carries the upload token.
				data, _ := created["data"].(map[string]any)
				attrs, _ := data["attributes"].(map[string]any)
				uploadURL, _ := attrs["upload-url"].(string)
				u, err := url.Parse(uploadURL)
				if err != nil || u.Path == "" {
					t.Fatalf("creating a configuration version returned no usable upload-url: %v", created)
				}
				return w.rawRequest(http.MethodPut, u.RequestURI(), "application/octet-stream", tinyConfigArchive(t))
			},
		},
	)
}

// workspaceIDByName is the identifier of a seeded workspace other than the one w.id resolves to,
// for the writes that name two: a run trigger's source, a second target of a bulk action.
func workspaceIDByName(t *testing.T, w *writeRun, name string) string {
	t.Helper()
	var id string
	if err := w.db.Raw("SELECT id FROM workspaces WHERE name = ?", name).Scan(&id).Error; err != nil || id == "" {
		t.Fatalf("the seed has no workspace named %s: %v", name, err)
	}
	return id
}

// workspaceCreate creates a workspace of the case's own in the seeded organization and returns
// its identifier. A fresh workspace has no applied run, so nothing protects it from deletion.
func workspaceCreate(t *testing.T, w *writeRun, name string) string {
	t.Helper()
	return dataID(t, w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/workspaces"),
		document("workspaces", map[string]any{"name": name}))))
}

// workspaceLock locks the seeded workspace as the caller, for the writes that need it locked.
func workspaceLock(t *testing.T, w *writeRun) {
	t.Helper()
	w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/actions/lock"),
		map[string]any{"reason": "Locked by the golden write harness"}))
}

// Workspaces: create, update, lock and delete.
func init() {
	registerWriteCases(
		writeCase{
			route: "POST /api/v2/organizations/:name/workspaces",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				doc := related(document("workspaces", map[string]any{
					"name":                  "golden-write-workspace",
					"description":           "Recorded by the golden write harness",
					"terraform-version":     "1.10.6",
					"working-directory":     "environments/production",
					"execution-mode":        "remote",
					"auto-apply":            false,
					"queue-all-runs":        false,
					"speculative-enabled":   true,
					"allow-destroy-plan":    false,
					"file-triggers-enabled": true,
					"trigger-patterns":      []string{"modules/**", "environments/production/**"},
					"run-timeout":           3600,
				}), "project", "projects", w.id("projects"))
				// The tfe provider sends a workspace's tags as a relationship whose members carry
				// the key and value inline.
				rels := doc["data"].(map[string]any)["relationships"].(map[string]any)
				rels["tag-bindings"] = map[string]any{"data": []any{
					map[string]any{"type": "tag-bindings", "attributes": map[string]any{"key": "environment", "value": "production"}},
					map[string]any{"type": "tag-bindings", "attributes": map[string]any{"key": "team", "value": "platform"}},
				}}
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/workspaces"), doc)
			},
		},
		writeCase{
			// This handler writes description and working-directory on every request, so a body
			// that leaves them out clears them. The case sends both.
			route: "PATCH /api/v2/organizations/:name/workspaces/:workspace_name",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/organizations/:name/workspaces/:workspace_name"),
					document("workspaces", map[string]any{
						"description":       "Updated by the golden write harness",
						"working-directory": "environments/production",
						"terraform-version": "1.10.6",
						"auto-apply":        true,
						"execution-mode":    "remote",
						"trigger-prefixes":  []string{"modules/network", "modules/compute"},
						"tag-names":         []string{"production", "platform"},
						"run-timeout":       5400,
					}))
			},
		},
		writeCase{
			// The route go-tfe's UpdateByID uses, and the one that also replaces the tags.
			route: "PATCH /api/v2/workspaces/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				doc := document("workspaces", map[string]any{
					"description":           "Updated by the golden write harness",
					"auto-apply":            true,
					"file-triggers-enabled": true,
					"trigger-patterns":      []string{"modules/**"},
					"global-remote-state":   true,
					"assessments-enabled":   true,
					"allow-destroy-plan":    false,
				})
				doc["data"].(map[string]any)["relationships"] = map[string]any{"tag-bindings": map[string]any{"data": []any{
					map[string]any{"type": "tag-bindings", "attributes": map[string]any{"key": "environment", "value": "production"}},
				}}}
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/workspaces/:id"), doc)
			},
		},
		writeCase{
			// The body is optional and is not a JSON:API document: go-tfe sends the reason bare.
			route: "POST /api/v2/workspaces/:id/actions/lock",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/actions/lock"),
					map[string]any{"reason": "Maintenance window: migrating the network module"})
			},
		},
		writeCase{
			// Needs a locked workspace.
			route: "POST /api/v2/workspaces/:id/actions/unlock",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				workspaceLock(t, w)
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/actions/unlock"), nil)
			},
		},
		writeCase{
			// Needs a locked workspace.
			route: "POST /api/v2/workspaces/:id/actions/force-unlock",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				workspaceLock(t, w)
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/actions/force-unlock"), nil)
			},
		},
		writeCase{
			route: "DELETE /api/v2/organizations/:name/workspaces/:workspace_name",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				workspaceCreate(t, w, "golden-write-doomed")
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/organizations/"+w.org()+"/workspaces/golden-write-doomed", nil)
			},
		},
		writeCase{
			// TFE's force delete: it removes a workspace that has applied runs, which the plain
			// delete and both safe-deletes refuse (409), so those three act on a workspace of
			// their own. The seeded workspace w.path resolves to is in no run trigger. One that
			// is, as source or as target, cannot be deleted at all: run_triggers references
			// workspaces twice with no ON DELETE rule and the handler answers 500. That is the
			// defect the organization-delete case works around, tracked on its own.
			route: "DELETE /api/v2/workspaces/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/workspaces/:id"), nil)
			},
		},
		writeCase{
			route: "POST /api/v2/organizations/:name/workspaces/:workspace_name/actions/safe-delete",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				workspaceCreate(t, w, "golden-write-doomed")
				return w.jsonRequest(t, http.MethodPost, "/api/v2/organizations/"+w.org()+"/workspaces/golden-write-doomed/actions/safe-delete", nil)
			},
		},
		writeCase{
			route: "POST /api/v2/workspaces/:id/actions/safe-delete",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/workspaces/"+workspaceCreate(t, w, "golden-write-doomed")+"/actions/safe-delete", nil)
			},
		},
	)
}

// workspaceExec changes the case's database directly, for state only a runner or the
// orchestrator would otherwise bring about.
func workspaceExec(t *testing.T, w *writeRun, sql string, args ...any) {
	t.Helper()
	if err := w.db.Exec(sql, args...).Error; err != nil {
		t.Fatalf("prepare the database (%s): %v", sql, err)
	}
}

// workspaceQueueRun creates a plan-and-apply run on the seeded workspace through the API and
// returns its identifier. No runner is behind the recorder, so the run stays pending.
func workspaceQueueRun(t *testing.T, w *writeRun) string {
	t.Helper()
	return dataID(t, w.mustSend(t, w.jsonRequest(t, http.MethodPost, "/api/v2/runs", related(
		document("runs", nil), "workspace", "workspaces", w.id("workspaces")))))
}

// workspaceRunIn is a run in the status a runner would have brought it to.
func workspaceRunIn(t *testing.T, w *writeRun, status string) string {
	t.Helper()
	runID := workspaceQueueRun(t, w)
	workspaceExec(t, w, "UPDATE runs SET status = ? WHERE id = ?", status, runID)
	return runID
}

// Run actions. None of them reads a body, and each needs a run in a status of its own.
func init() {
	registerWriteCases(
		writeCase{
			// Confirms a plan: the run has to be waiting at planned.
			route: "POST /api/v2/runs/:id/actions/apply",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/runs/"+workspaceRunIn(t, w, "planned")+"/actions/apply", nil)
			},
		},
		writeCase{
			route: "POST /api/v2/runs/:id/actions/cancel",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/runs/"+workspaceRunIn(t, w, "planning")+"/actions/cancel", nil)
			},
		},
		writeCase{
			// Turns down a plan that is waiting for confirmation.
			route: "POST /api/v2/runs/:id/actions/discard",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/runs/"+workspaceRunIn(t, w, "planned")+"/actions/discard", nil)
			},
		},
		writeCase{
			route: "POST /api/v2/runs/:id/actions/force-cancel",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/runs/"+workspaceRunIn(t, w, "applying")+"/actions/force-cancel", nil)
			},
		},
		writeCase{
			// Needs a pending run on a locked workspace. The run comes first: a locked
			// workspace refuses new runs.
			route: "POST /api/v2/runs/:id/actions/force-execute",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				runID := workspaceQueueRun(t, w)
				workspaceLock(t, w)
				return w.jsonRequest(t, http.MethodPost, "/api/v2/runs/"+runID+"/actions/force-execute", nil)
			},
		},
	)
}

// workspaceVariableID is the identifier of one of the seeded workspace's variables, by key.
func workspaceVariableID(t *testing.T, w *writeRun, key string) string {
	t.Helper()
	var id string
	if err := w.db.Raw("SELECT id FROM variables WHERE workspace_id = ? AND key = ?", w.id("workspaces"), key).Scan(&id).Error; err != nil || id == "" {
		t.Fatalf("the seeded workspace has no variable %s: %v", key, err)
	}
	return id
}

// Workspace variables.
func init() {
	registerWriteCases(
		writeCase{
			// A sensitive value is stored encrypted and never returned: the response masks it.
			route: "POST /api/v2/workspaces/:id/vars",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/workspaces/"+w.id("workspaces")+"/vars",
					document("vars", map[string]any{
						"key":         "DATABASE_PASSWORD",
						"value":       "golden-write-not-a-real-password",
						"description": "Recorded by the golden write harness",
						"category":    "env",
						"hcl":         false,
						"sensitive":   true,
					}))
			},
			requestSecrets: []string{"data.attributes.value"},
		},
		writeCase{
			route: "PATCH /api/v2/workspaces/:id/vars/:variable_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				variableID := workspaceVariableID(t, w, "instance_type")
				doc := document("vars", map[string]any{
					"key":         "instance_type",
					"value":       "t3.large",
					"description": "Updated by the golden write harness",
					"category":    "terraform",
					"hcl":         false,
					"sensitive":   false,
				})
				doc["data"].(map[string]any)["id"] = variableID
				return w.jsonRequest(t, http.MethodPatch, "/api/v2/workspaces/"+w.id("workspaces")+"/vars/"+variableID, doc)
			},
		},
		writeCase{
			route: "DELETE /api/v2/workspaces/:id/vars/:variable_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/workspaces/"+w.id("workspaces")+"/vars/"+workspaceVariableID(t, w, "TF_LOG"), nil)
			},
		},
	)
}

// workspaceSeededTeamAccess is the seeded team access row and the workspace it is on, which is
// not the workspace w.id resolves to.
func workspaceSeededTeamAccess(t *testing.T, w *writeRun) (workspaceID, accessID string) {
	t.Helper()
	accessID = w.id("team-workspaces")
	if err := w.db.Raw("SELECT workspace_id FROM team_workspace_accesses WHERE id = ?", accessID).Scan(&workspaceID).Error; err != nil || workspaceID == "" {
		t.Fatalf("the seeded team access %s names no workspace: %v", accessID, err)
	}
	return workspaceID, accessID
}

// Team access to a workspace, on TFE's /team-workspaces routes and on the workspace-scoped ones.
func init() {
	registerWriteCases(
		writeCase{
			// Custom access: every permission is then required, and `access` reads "custom".
			route: "POST /api/v2/team-workspaces",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/team-workspaces", related(related(
					document("team-workspaces", map[string]any{
						"access":            "custom",
						"runs":              "apply",
						"variables":         "write",
						"state-versions":    "read-outputs",
						"sentinel-mocks":    "none",
						"workspace-locking": true,
						"run-tasks":         false,
					}),
					"team", "teams", w.id("teams")),
					"workspace", "workspaces", w.id("workspaces")))
			},
		},
		writeCase{
			// TFE's own address for one access: the path names the access and nothing else. It
			// is how the tfe provider updates a tfe_team_access.
			route: "PATCH /api/v2/team-workspaces/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/team-workspaces/:id"),
					document("team-workspaces", map[string]any{"access": "admin"}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/team-workspaces/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/team-workspaces/:id"), nil)
			},
		},
		writeCase{
			// A fixed access level: the workspace comes from the path, the team from the body.
			route: "POST /api/v2/workspaces/:id/relationships/team-access",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/relationships/team-access"), related(
					document("team-workspaces", map[string]any{"access": "write"}),
					"team", "teams", w.id("teams")))
			},
		},
		writeCase{
			route: "PATCH /api/v2/workspaces/:id/relationships/team-access/:access_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				workspaceID, accessID := workspaceSeededTeamAccess(t, w)
				return w.jsonRequest(t, http.MethodPatch, "/api/v2/workspaces/"+workspaceID+"/relationships/team-access/"+accessID,
					document("team-workspaces", map[string]any{"access": "admin"}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/workspaces/:id/relationships/team-access/:access_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				workspaceID, accessID := workspaceSeededTeamAccess(t, w)
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/workspaces/"+workspaceID+"/relationships/team-access/"+accessID, nil)
			},
		},
	)
}

// Run triggers, notification configurations, configuration versions and tags.
func init() {
	registerWriteCases(
		writeCase{
			// The path names the workspace whose runs are triggered, the body the one whose
			// applies trigger them.
			route: "POST /api/v2/workspaces/:id/run-triggers",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/run-triggers"), related(
					document("run-triggers", nil),
					"sourceable", "workspaces", workspaceIDByName(t, w, "payments-prod")))
			},
		},
		writeCase{
			route: "DELETE /api/v2/run-triggers/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/run-triggers/:id"), nil)
			},
		},
		writeCase{
			// Creating a configuration delivers nothing; the token signs later deliveries and
			// is write-only.
			route: "POST /api/v2/workspaces/:id/notification-configurations",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/notification-configurations"),
					document("notification-configurations", map[string]any{
						"name":             "golden-write-notifications",
						"destination-type": "generic",
						"url":              "https://hooks.example.com/stackweaver/runs",
						"token":            "golden-write-not-a-real-token",
						"enabled":          true,
						"triggers":         []string{"run:created", "run:needs_attention", "run:completed", "run:errored"},
					}))
			},
			requestSecrets: []string{"data.attributes.token"},
		},
		writeCase{
			route: "POST /api/v2/workspaces/:id/configuration-versions",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/configuration-versions"),
					document("configuration-versions", map[string]any{"auto-queue-runs": false, "speculative": true}))
			},
		},
		writeCase{
			// Replaces the workspace's own tags with the list sent.
			route: "PATCH /api/v2/workspaces/:id/tag-bindings",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/workspaces/:id/tag-bindings"), map[string]any{"data": []any{
					map[string]any{"type": "tag-bindings", "attributes": map[string]any{"key": "environment", "value": "production"}},
					map[string]any{"type": "tag-bindings", "attributes": map[string]any{"key": "cost-center", "value": "platform-1042"}},
				}})
			},
		},
	)
}

// workspaceStatePush is the body of a state push. It is not a JSON:API document and not TFE's
// shape either: the state travels as an object, with its serial and lineage beside it. The
// state is the smallest OpenTofu state worth storing: one output and one resource, so there is
// something to materialize and something to remove.
func workspaceStatePush() map[string]any {
	const lineage = "8f2c1d7e-3b4a-4c5d-9e6f-0a1b2c3d4e5f"
	state := map[string]any{
		"version":           4,
		"terraform_version": "1.10.6",
		"serial":            1,
		"lineage":           lineage,
		"outputs": map[string]any{
			"endpoint": map[string]any{"value": "https://warehouse.example.com", "type": "string"},
		},
		"resources": []any{map[string]any{
			"mode":     "managed",
			"type":     "null_resource",
			"name":     "example",
			"provider": `provider["registry.opentofu.org/hashicorp/null"]`,
			"instances": []any{map[string]any{
				"schema_version": 0,
				"attributes":     map[string]any{"id": "5577006791947779410", "triggers": nil},
			}},
		}},
	}
	return map[string]any{"state_data": state, "serial": 1, "lineage": lineage}
}

// State versions. All three are storage-backed: the state itself lives in the bucket, and a
// state a caller pushes is as real to these handlers as one an apply produced.
func init() {
	registerWriteCases(
		writeCase{
			// Refused while the workspace is locked, which is the reverse of TFE.
			route: "POST /api/v2/workspaces/:id/state-versions",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/state-versions"), workspaceStatePush())
			},
		},
		writeCase{
			// The equivalent of `tofu state rm`: it reads the latest state from storage and
			// stores the result as a new version, so a state has to be pushed first.
			route: "POST /api/v2/workspaces/:id/state-versions/remove-resource",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/state-versions"), workspaceStatePush()))
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/state-versions/remove-resource"),
					map[string]any{"address": "null_resource.example"})
			},
		},
		writeCase{
			route: "DELETE /api/v2/state-versions/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				pushed := w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/state-versions"), workspaceStatePush()))
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/state-versions/"+dataID(t, pushed), nil)
			},
		},
	)
}

// workspaceAttachTask attaches the seeded run task to the seeded workspace and returns the
// attachment's identifier. The seed attaches none.
func workspaceAttachTask(t *testing.T, w *writeRun) string {
	t.Helper()
	return dataID(t, w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/tasks"), related(
		document("workspace-tasks", map[string]any{"enforcement-level": "advisory", "stages": []string{"post_plan"}}),
		"task", "tasks", w.id("tasks")))))
}

// workspaceSeededTaskResult puts the seeded task stage, its one result and the run they belong
// to back where they stand while the stage executes: the seed records them as passed, and both
// the callback and the override act only on a stage that is still open. A runner would have
// brought the run to its post-plan stage and the orchestrator would have started the stage; no
// runner output is involved. It returns the result's and the run's identifiers.
func workspaceSeededTaskResult(t *testing.T, w *writeRun, stageStatus, resultStatus string) (resultID, runID string) {
	t.Helper()
	resultID = w.id("task-results")
	var stageID string
	if err := w.db.Raw("SELECT task_stage_id FROM task_results WHERE id = ?", resultID).Scan(&stageID).Error; err != nil || stageID != w.id("task-stages") {
		t.Fatalf("the seeded task result %s is not in the seeded task stage: %q, %v", resultID, stageID, err)
	}
	if err := w.db.Raw("SELECT run_id FROM task_stages WHERE id = ?", stageID).Scan(&runID).Error; err != nil || runID == "" {
		t.Fatalf("the seeded task stage %s names no run: %v", stageID, err)
	}
	workspaceExec(t, w, "UPDATE runs SET status = 'post_plan_running', completed_at = NULL WHERE id = ?", runID)
	workspaceExec(t, w, "UPDATE task_stages SET status = ?, passed_at = NULL, running_at = now() WHERE id = ?", stageStatus, stageID)
	// The task's name and url are copied onto a result when its run is created; the seed
	// leaves them empty.
	workspaceExec(t, w, `UPDATE task_results r SET status = ?, passed_at = NULL, message = '', running_at = now(),
		enforcement_level = 'mandatory', task_name = k.name, task_url = k.url
		FROM run_tasks k WHERE k.id = r.task_id AND r.id = ?`, resultStatus, resultID)
	return resultID, runID
}

// workspaceTaskService stands in for an external run task service, and returns its URL. Creating
// a run task makes the server call the task: it POSTs a verification payload to the task's url
// and stores the task only when that answers 2xx.
//
// The stand-in listens on whatever loopback port is free, which is a different one on every run
// and not an address anyone calling the API would give, so the fixture shows a task service's
// address in its place.
func workspaceTaskService(t *testing.T, w *writeRun) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	w.publishAs(srv.URL, "https://run-tasks.example.com")
	return srv.URL + "/run-tasks/cost-estimate"
}

// Run tasks: the organization's tasks, their attachment to a workspace, and what a run's task
// stage is told by the task service and by a person.
func init() {
	registerWriteCases(
		writeCase{
			// The one write here that calls out: see workspaceTaskService. The hmac-key signs
			// every request the server sends the task, the verification included, and is
			// write-only.
			route: "POST /api/v2/organizations/:name/tasks",
			// The server refuses to call a task on a loopback or private address unless it was
			// started with this, and the stand-in is on loopback.
			env: map[string]string{"STACKWEAVER_RUN_TASKS_ALLOW_PRIVATE": "true"},
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/tasks"),
					document("tasks", map[string]any{
						"name":        "cost-estimate",
						"url":         workspaceTaskService(t, w),
						"description": "Recorded by the golden write harness",
						"category":    "task",
						"hmac-key":    "golden-write-not-a-real-key",
						"enabled":     true,
						"global-configuration": map[string]any{
							"enabled":           true,
							"stages":            []string{"post_plan"},
							"enforcement-level": "advisory",
						},
					}))
			},
			requestSecrets: []string{"data.attributes.hmac-key"},
		},
		writeCase{
			// Changing the url or the hmac-key makes the server verify the task again by
			// calling it, so the case changes neither.
			route: "PATCH /api/v2/tasks/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/tasks/:id"),
					document("tasks", map[string]any{
						"name":        "drift-scanner",
						"description": "Updated by the golden write harness",
						"category":    "task",
						"enabled":     false,
						"global-configuration": map[string]any{
							"enabled":           true,
							"stages":            []string{"post_plan", "pre_apply"},
							"enforcement-level": "advisory",
						},
					}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/tasks/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/tasks/:id"), nil)
			},
		},
		writeCase{
			route: "POST /api/v2/workspaces/:id/tasks",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/tasks"), related(
					document("workspace-tasks", map[string]any{"enforcement-level": "mandatory", "stages": []string{"post_plan", "pre_apply"}}),
					"task", "tasks", w.id("tasks")))
			},
		},
		writeCase{
			route: "PATCH /api/v2/workspaces/:id/tasks/:tid",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, "/api/v2/workspaces/"+w.id("workspaces")+"/tasks/"+workspaceAttachTask(t, w),
					document("workspace-tasks", map[string]any{"enforcement-level": "mandatory", "stages": []string{"pre_plan", "post_plan"}}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/workspaces/:id/tasks/:tid",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/workspaces/"+w.id("workspaces")+"/tasks/"+workspaceAttachTask(t, w), nil)
			},
		},
		writeCase{
			// Called by the task service, not by a user: it authenticates with the access token
			// the server put in the webhook it sent, which is minted here the way the
			// orchestrator mints it. The outcomes travel in `included`, the only place this
			// handler reads them from; TFE documents them under data.relationships.outcomes.
			route: "PATCH /api/v2/task-results/:id/callback",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				resultID, runID := workspaceSeededTaskResult(t, w, "running", "running")
				doc := document("task-results", map[string]any{
					"status":  "passed",
					"message": "No drift detected in 14 resources.",
					"url":     "https://tasks.example.com/drift/results/1042",
				})
				doc["included"] = []any{map[string]any{
					"type": "task-result-outcomes",
					"attributes": map[string]any{
						"outcome-id":  "DRIFT-001",
						"description": "All managed resources match their recorded state.",
						"body":        "## Drift scan\n\n14 resources checked, 0 drifted.",
						"url":         "https://tasks.example.com/drift/results/1042#DRIFT-001",
						"tags": map[string]any{
							"Status":   []any{map[string]any{"label": "Passed", "level": "info"}},
							"Severity": []any{map[string]any{"label": "None"}},
						},
					},
				}}
				req := w.jsonRequest(t, http.MethodPatch, "/api/v2/task-results/"+resultID+"/callback", doc)
				req.Header.Set("Authorization", "Bearer "+terraformHandlers.MintTaskResultToken(resultID, runID))
				return req
			},
		},
		writeCase{
			// A person with apply rights lets a run past a mandatory task that failed: the stage
			// has to be awaiting that override. The body is optional and is not a JSON:API
			// document.
			route: "POST /api/v2/task-stages/:id/actions/override",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				resultID, _ := workspaceSeededTaskResult(t, w, "awaiting_override", "failed")
				workspaceExec(t, w, "UPDATE task_results SET failed_at = now(), message = 'Drift detected in 2 resources.' WHERE id = ?", resultID)
				workspaceExec(t, w, "UPDATE task_stages SET failed_at = now() WHERE id = ?", w.id("task-stages"))
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/task-stages/:id/actions/override"),
					map[string]any{"comment": "Reviewed with the platform team: the reported drift is expected."})
			},
		},
	)
}

// workspaceOpenChangeRequest is a seeded change request nobody has archived yet.
func workspaceOpenChangeRequest(t *testing.T, w *writeRun) string {
	t.Helper()
	var id string
	if err := w.db.Raw("SELECT id FROM change_requests WHERE archived_at IS NULL ORDER BY subject LIMIT 1").Scan(&id).Error; err != nil || id == "" {
		t.Fatalf("the seed has no open change request: %v", err)
	}
	return id
}

// Change requests: Stackweaver files them through TFE's bulk-action endpoint, and the team that
// did the work archives them.
func init() {
	registerWriteCases(
		writeCase{
			// One subject and message, filed against every workspace listed. The attribute
			// names are snake_case here, as TFE documents this one endpoint.
			route: "POST /api/v2/organizations/:name/explorer/bulk-actions",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/explorer/bulk-actions"),
					document("bulk_actions", map[string]any{
						"action_type": "change_requests",
						"action_inputs": map[string]any{
							"subject": "Upgrade the AWS provider to 6.x",
							"message": "The 5.x line stops receiving fixes next quarter. Bump the provider constraint, run a plan and confirm it is clean.",
						},
						"target_ids": []string{w.id("workspaces"), workspaceIDByName(t, w, "payments-prod")},
					}))
			},
		},
		writeCase{
			// Archiving takes no body. TFE's documentation names both PATCH and POST for it,
			// and both are served.
			route: "PATCH /api/v2/workspaces/change-requests/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, "/api/v2/workspaces/change-requests/"+workspaceOpenChangeRequest(t, w), nil)
			},
		},
		writeCase{
			route: "POST /api/v2/workspaces/change-requests/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/workspaces/change-requests/"+workspaceOpenChangeRequest(t, w), nil)
			},
		},
		writeCase{
			route: "DELETE /api/v2/workspaces/change-requests/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/workspaces/change-requests/:id"), nil)
			},
		},
	)
}
