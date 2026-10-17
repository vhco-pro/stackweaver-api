// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package routes_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

// ansibleCreated performs a create a case needs before the write it records and returns the new
// row's identifier.
func ansibleCreated(t *testing.T, w *writeRun, target string, doc map[string]any) string {
	t.Helper()
	return dataID(t, w.mustSend(t, w.jsonRequest(t, http.MethodPost, target, doc)))
}

// ansibleAWSCredential creates the cloud credential an AWS inventory source authenticates with.
// The seeded credential is an SSH one, which a source refuses.
func ansibleAWSCredential(t *testing.T, w *writeRun) string {
	t.Helper()
	return ansibleCreated(t, w, w.path("/api/v2/organizations/:name/ansible/credentials"),
		document("ansible-credentials", map[string]any{
			"name":                  "golden-write-aws",
			"credential-type":       "aws",
			"aws-access-key-id":     "golden-write-access-key-id",
			"aws-secret-access-key": "golden-write-secret-access-key",
		}))
}

// ansibleRelatedMany adds a to-many relationship to a document built by document.
func ansibleRelatedMany(doc map[string]any, name, resourceType string, ids ...string) map[string]any {
	data := doc["data"].(map[string]any)
	rels, _ := data["relationships"].(map[string]any)
	if rels == nil {
		rels = map[string]any{}
		data["relationships"] = rels
	}
	refs := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, map[string]any{"type": resourceType, "id": id})
	}
	rels[name] = map[string]any{"data": refs}
	return doc
}

// ansibleVCSConnection gives the seeded organization a VCS connection and returns its identifier.
//
// The seed has none, because a real one is the result of an OAuth exchange with a provider. The
// routes that use it here only name a connection: they store its identifier and queue the clone
// for a runner. A token-based GitHub connection is the kind whose clone URL is built without
// asking GitHub for anything.
func ansibleVCSConnection(t *testing.T, w *writeRun) string {
	t.Helper()
	var org models.Organization
	if err := w.db.Select("id").Where("name = ?", w.org()).First(&org).Error; err != nil {
		t.Fatalf("read the seeded organization: %v", err)
	}
	conn := models.VCSConnection{
		OrganizationID: org.ID,
		Provider:       models.VCSProviderGitHub,
		AccountName:    "stackweaver-demo",
		AccountType:    "organization",
	}
	if err := w.db.Create(&conn).Error; err != nil {
		t.Fatalf("create a VCS connection: %v", err)
	}
	return conn.ID.String()
}

// Write cases for the Ansible inventories and what hangs off one: hosts, groups, dynamic sources
// and ad hoc commands.
func init() {
	registerWriteCases(
		writeCase{
			route: "POST /api/v2/organizations/:name/ansible/inventories",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/ansible/inventories"), related(
					document("inventories", map[string]any{
						"name":           "golden-write-inventory",
						"description":    "Recorded by the golden write harness",
						"inventory-type": "static",
						"variables":      map[string]any{"ansible_user": "deploy", "ntp_server": "time.example.com"},
					}),
					"project", "projects", w.id("projects")))
			},
		},
		writeCase{
			route: "PATCH /api/v2/ansible/inventories/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/ansible/inventories/:id"),
					document("inventories", map[string]any{
						"description": "Updated by the golden write harness",
						"variables":   map[string]any{"ansible_user": "deploy", "ansible_port": 2222},
					}))
			},
		},
		writeCase{
			// An inventory of the case's own: the seeded one is named by job templates and jobs,
			// and the server refuses to delete an inventory anything still refers to.
			route: "DELETE /api/v2/ansible/inventories/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				id := ansibleCreated(t, w, w.path("/api/v2/organizations/:name/ansible/inventories"),
					document("inventories", map[string]any{"name": "golden-write-doomed"}))
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/ansible/inventories/"+id, nil)
			},
		},
		writeCase{
			// A constructed inventory, which rebuilds from its inputs: the sync is queued and the
			// answer does not wait for it. The other kind that syncs, a VCS inventory, needs a
			// connection to a provider, and the seed has none.
			route: "POST /api/v2/ansible/inventories/:id/actions/sync",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				id := ansibleCreated(t, w, w.path("/api/v2/organizations/:name/ansible/inventories"),
					document("inventories", map[string]any{
						"name":                "golden-write-constructed",
						"inventory-type":      "constructed",
						"input-inventory-ids": []string{w.id("inventories")},
					}))
				return w.jsonRequest(t, http.MethodPost, "/api/v2/ansible/inventories/"+id+"/actions/sync", nil)
			},
		},
		writeCase{
			// Queue-backed like a template launch: the command becomes a job.
			route: "POST /api/v2/ansible/inventories/:id/actions/run-command",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/inventories/:id/actions/run-command"),
					document("ansible-jobs", map[string]any{
						"module":         "shell",
						"module-args":    "uptime",
						"limit":          "webservers",
						"credential-id":  w.id("credentials"),
						"forks":          10,
						"verbosity":      1,
						"become-enabled": true,
					}))
			},
		},
		writeCase{
			route: "POST /api/v2/ansible/inventories/:id/hosts",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/inventories/:id/hosts"),
					document("ansible-hosts", map[string]any{
						"name":        "web-02.demo.internal",
						"description": "Recorded by the golden write harness",
						"hostname":    "10.0.1.12",
						"port":        22,
						"variables":   map[string]any{"ansible_user": "deploy", "http_port": 8080},
						"enabled":     true,
					}))
			},
		},
		writeCase{
			route: "PATCH /api/v2/ansible/hosts/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/ansible/hosts/:id"),
					document("ansible-hosts", map[string]any{
						"description": "Updated by the golden write harness",
						"hostname":    "10.0.1.21",
						"port":        2222,
						"variables":   map[string]any{"ansible_user": "deploy"},
						"enabled":     false,
					}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/hosts/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/ansible/hosts/:id"), nil)
			},
		},
		writeCase{
			// The seeded host and the seeded group are in the same inventory, which is the one
			// thing a membership needs.
			route: "POST /api/v2/ansible/hosts/:id/groups/:group_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/hosts/:id/groups/:group_id"), nil)
			},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/hosts/:id/groups/:group_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				membership := w.path("/api/v2/ansible/hosts/:id/groups/:group_id")
				w.mustSend(t, w.jsonRequest(t, http.MethodPost, membership, nil))
				return w.jsonRequest(t, http.MethodDelete, membership, nil)
			},
		},
		writeCase{
			route: "POST /api/v2/ansible/inventories/:id/groups",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/inventories/:id/groups"), related(
					document("ansible-groups", map[string]any{
						"name":        "webservers-eu",
						"description": "Recorded by the golden write harness",
						"variables":   map[string]any{"region": "eu-west-1"},
					}),
					"parent", "ansible-groups", w.id("groups")))
			},
		},
		writeCase{
			route: "PATCH /api/v2/ansible/groups/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/ansible/groups/:id"),
					document("ansible-groups", map[string]any{
						"description": "Updated by the golden write harness",
						"variables":   map[string]any{"http_port": 8080, "max_clients": 200},
					}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/groups/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/ansible/groups/:id"), nil)
			},
		},
		writeCase{
			route: "POST /api/v2/ansible/inventories/:id/sources",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/inventories/:id/sources"),
					document("inventory-sources", map[string]any{
						"name":                 "aws-eu-central-1",
						"description":          "Recorded by the golden write harness",
						"source-type":          "aws",
						"credential-id":        ansibleAWSCredential(t, w),
						"config":               map[string]any{"regions": []string{"eu-central-1"}},
						"sync-schedule":        "0 */6 * * *",
						"update-on-launch":     true,
						"update-cache-timeout": 300,
						"overwrite":            true,
						"group-by-region":      true,
						"group-by-tag":         "Environment",
						"hostname-var":         "private_ip",
					}))
			},
		},
		writeCase{
			route: "PATCH /api/v2/ansible/inventory-sources/:source_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/ansible/inventory-sources/:source_id"),
					document("inventory-sources", map[string]any{
						"description":                "Updated by the golden write harness",
						"config":                     map[string]any{"regions": []string{"eu-west-1", "eu-central-1"}},
						"sync-schedule":              "30 2 * * *",
						"update-cache-timeout":       600,
						"overwrite-vars":             true,
						"group-by-availability-zone": true,
						"verbosity":                  1,
					}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/inventory-sources/:source_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/ansible/inventory-sources/:source_id"), nil)
			},
		},
		writeCase{
			// Queue-backed: the sync is handed to a runner and the answer does not wait for it,
			// so the cloud account the source names is never reached from here.
			route: "POST /api/v2/ansible/inventory-sources/:source_id/actions/sync",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/inventory-sources/:source_id/actions/sync"), nil)
			},
		},
	)
}

// Write cases for the Ansible credentials. Every secret a credential carries arrives in the
// request body and none is returned: the response says only which ones are set.
func init() {
	registerWriteCases(
		writeCase{
			route: "POST /api/v2/organizations/:name/ansible/credentials",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/ansible/credentials"), related(
					document("ansible-credentials", map[string]any{
						"name":            "golden-write-ssh",
						"description":     "Recorded by the golden write harness",
						"credential-type": "ssh",
						"username":        "deploy",
						"ssh-private-key": "-----BEGIN OPENSSH PRIVATE KEY-----\ngolden-write-key\n-----END OPENSSH PRIVATE KEY-----\n",
						"ssh-passphrase":  "golden-write-passphrase",
						"become-password": "golden-write-become",
						"ssh-port":        2222,
						"ssh-become-user": "root",
					}),
					"project", "projects", w.id("projects")))
			},
			requestSecrets: []string{
				"data.attributes.ssh-private-key",
				"data.attributes.ssh-passphrase",
				"data.attributes.become-password",
			},
		},
		writeCase{
			route: "PATCH /api/v2/ansible/credentials/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/ansible/credentials/:id"),
					document("ansible-credentials", map[string]any{
						"description":     "Updated by the golden write harness",
						"username":        "ansible",
						"password":        "golden-write-password",
						"ssh-port":        2200,
						"ssh-become-user": "admin",
					}))
			},
			requestSecrets: []string{"data.attributes.password"},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/credentials/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/ansible/credentials/:id"), nil)
			},
		},
	)
}

// ansiblePlaybookRepository is the repository the playbook cases name. Nothing clones it: a
// playbook's sync is queued for a runner and the recorder has none.
const ansiblePlaybookRepository = "stackweaver-demo/ansible-playbooks"

// ansiblePlaybookDocument is a playbook kept in a repository behind the given VCS connection.
func ansiblePlaybookDocument(w *writeRun, name, connectionID string) map[string]any {
	return related(related(
		document("ansible-playbooks", map[string]any{
			"name":           name,
			"description":    "Recorded by the golden write harness",
			"vcs-repository": ansiblePlaybookRepository,
			"vcs-branch":     "main",
			"playbook-path":  "playbooks/site.yml",
			"source-mode":    "fresh",
		}),
		"project", "projects", w.id("projects")),
		"vcs-connection", "vcs-connections", connectionID)
}

// Write cases for the Ansible playbooks.
//
// A playbook lives in a repository, so most of these need a VCS connection, and none of them
// needs the provider behind it: registering a playbook and asking for a sync both store a row,
// queue the clone for a runner and answer.
func init() {
	registerWriteCases(
		writeCase{
			route: "POST /api/v2/organizations/:name/ansible/playbooks",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/ansible/playbooks"),
					ansiblePlaybookDocument(w, "golden-write-playbook", ansibleVCSConnection(t, w)))
			},
		},
		writeCase{
			route: "PATCH /api/v2/ansible/playbooks/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/ansible/playbooks/:id"),
					document("ansible-playbooks", map[string]any{
						"description":   "Updated by the golden write harness",
						"vcs-branch":    "release",
						"playbook-path": "playbooks/deploy-app.yml",
						"source-mode":   "cached",
					}))
			},
		},
		writeCase{
			// A playbook of the case's own: every seeded one is named by a job template, and the
			// server refuses to delete a playbook anything still refers to.
			route: "DELETE /api/v2/ansible/playbooks/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				id := ansibleCreated(t, w, w.path("/api/v2/organizations/:name/ansible/playbooks"),
					document("ansible-playbooks", map[string]any{"name": "golden-write-doomed", "playbook-path": "site.yml"}))
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/ansible/playbooks/"+id, nil)
			},
		},
		writeCase{
			// The seeded playbooks have no repository behind them, and a sync refuses one that
			// has none.
			route: "POST /api/v2/ansible/playbooks/:id/actions/sync",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				id := ansibleCreated(t, w, w.path("/api/v2/organizations/:name/ansible/playbooks"),
					ansiblePlaybookDocument(w, "golden-write-synced", ansibleVCSConnection(t, w)))
				return w.jsonRequest(t, http.MethodPost, "/api/v2/ansible/playbooks/"+id+"/actions/sync", nil)
			},
		},
		writeCase{
			route: "POST /api/v2/organizations/:name/ansible/playbooks/actions/bulk-import",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/ansible/playbooks/actions/bulk-import"),
					document("ansible-playbooks", map[string]any{
						"project-id":        w.id("projects"),
						"vcs-connection-id": ansibleVCSConnection(t, w),
						"repository":        ansiblePlaybookRepository,
						"branch":            "main",
						"source-mode":       "cached",
						"playbooks": []map[string]any{
							{"path": "playbooks/webservers.yml", "name": "golden-write-webservers"},
							{"path": "playbooks/databases.yml", "name": "golden-write-databases"},
						},
					}))
			},
		},
		writeCase{
			// Nothing is registered for the path yet, so this records the creating answer, 201.
			// A second call with the same body answers 200 with the same playbook.
			route: "POST /api/v2/organizations/:name/ansible/playbooks/actions/find-or-create",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/ansible/playbooks/actions/find-or-create"),
					document("ansible-playbooks", map[string]any{
						"project-id":        w.id("projects"),
						"vcs-connection-id": ansibleVCSConnection(t, w),
						"repository":        ansiblePlaybookRepository,
						"branch":            "main",
						"path":              "playbooks/hardening.yml",
						"name":              "golden-write-hardening",
						"source-mode":       "fresh",
					}))
			},
		},
	)
}

// ansibleProject is the project the seeded playbooks, templates and jobs live in. It is not the
// project a path resolves to: the seed hangs them off its first workspace's project, and a job
// runs only in the project of its playbook.
func ansibleProject(t *testing.T, w *writeRun) string {
	t.Helper()
	var id string
	if err := w.db.Raw("SELECT project_id::text FROM ansible_playbooks WHERE id = ?", w.id("playbooks")).Scan(&id).Error; err != nil || id == "" {
		t.Fatalf("read the seeded playbook's project: %v", err)
	}
	return id
}

// ansibleLaunched launches the seeded job template and returns the job, which stays pending:
// the recorder has a queue and no runner.
func ansibleLaunched(t *testing.T, w *writeRun) string {
	t.Helper()
	return dataID(t, w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/job-templates/:id/launch"), nil)))
}

// Write cases for the Ansible job templates, their variables and credentials, and jobs.
func init() {
	registerWriteCases(
		writeCase{
			route: "POST /api/v2/organizations/:name/ansible/job-templates",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				doc := document("ansible-job-templates", map[string]any{
					"name":            "golden-write-template",
					"description":     "Recorded by the golden write harness",
					"extra-vars":      map[string]any{"app_version": "1.4.2", "rolling_update": true},
					"limit":           "webservers",
					"tags":            "deploy,config",
					"skip-tags":       "slow",
					"verbosity":       1,
					"forks":           10,
					"become-enabled":  true,
					"diff-mode":       true,
					"timeout-seconds": 3600,
					"retention-days":  30,
					"job-slice-count": 2,
				})
				related(doc, "project", "projects", ansibleProject(t, w))
				related(doc, "playbook", "ansible-playbooks", w.id("playbooks"))
				related(doc, "inventory", "ansible-inventories", w.id("inventories"))
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/ansible/job-templates"),
					ansibleRelatedMany(doc, "credentials", "ansible-credentials", w.id("credentials")))
			},
		},
		writeCase{
			// Switching provisioning callbacks on makes the server generate the template's host
			// config key, which it returns with the template from then on.
			route: "PATCH /api/v2/ansible/job-templates/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/ansible/job-templates/:id"), ansibleRelatedMany(
					document("ansible-job-templates", map[string]any{
						"description":        "Updated by the golden write harness",
						"extra-vars":         map[string]any{"compliance_profile": "cis-level-1"},
						"limit":              "webservers",
						"forks":              20,
						"timeout-seconds":    1800,
						"allow-simultaneous": true,
						"allow-callbacks":    true,
					}),
					"credentials", "ansible-credentials", w.id("credentials")))
			},
			responseSecrets: []string{"data.attributes.host-config-key"},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/job-templates/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/ansible/job-templates/:id"), nil)
			},
		},
		writeCase{
			// Queue-backed: a launch enqueues a job, so this fails without a Redis behind the
			// router. The body is optional; the case sends one so the document shows what a
			// launch may override.
			route: "POST /api/v2/ansible/job-templates/:id/launch",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/job-templates/:id/launch"),
					document("ansible-jobs", map[string]any{"limit": "web", "extra-vars": map[string]any{"release": "1.4.2"}}))
			},
		},
		writeCase{
			// A provisioning callback is not an authenticated call. A host that has just been
			// provisioned sends the template's host config key and is recognised by its address,
			// which has to be a host of the template's inventory: the request comes from the
			// seeded host's address and carries no token.
			route: "POST /api/v2/ansible/job-templates/:id/callback",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				enabled := w.mustSend(t, w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/ansible/job-templates/:id"),
					document("ansible-job-templates", map[string]any{"allow-callbacks": true})))
				data, _ := enabled["data"].(map[string]any)
				attrs, _ := data["attributes"].(map[string]any)
				key, _ := attrs["host-config-key"].(string)
				if key == "" {
					t.Fatalf("enabling callbacks returned no host-config-key: %v", enabled)
				}
				var address string
				if err := w.db.Raw("SELECT hostname FROM ansible_inventory_hosts WHERE id = ?", w.id("hosts")).Scan(&address).Error; err != nil || address == "" {
					t.Fatalf("read the seeded host's address: %v", err)
				}
				req := w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/job-templates/:id/callback"),
					map[string]any{"host_config_key": key})
				req.Header.Del("Authorization")
				req.RemoteAddr = address + ":49152"
				return req
			},
			requestSecrets: []string{"host_config_key"},
		},
		writeCase{
			route: "POST /api/v2/ansible/job-templates/:id/credentials",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/job-templates/:id/credentials"),
					map[string]any{"data": map[string]any{"type": "ansible-credentials", "id": w.id("credentials")}})
			},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/job-templates/:id/credentials/:credential_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/job-templates/:id/credentials"),
					map[string]any{"data": map[string]any{"type": "ansible-credentials", "id": w.id("credentials")}}))
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/ansible/job-templates/:id/credentials/:credential_id"), nil)
			},
		},
		writeCase{
			route: "POST /api/v2/ansible/job-templates/:id/vars",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/job-templates/:id/vars"),
					document("vars", map[string]any{
						"key":         "app_version",
						"value":       "1.4.2",
						"description": "Recorded by the golden write harness",
						"category":    "env",
						"sensitive":   false,
					}))
			},
		},
		writeCase{
			// The seed gives no template a variable, so the case makes the one it changes.
			route: "PATCH /api/v2/ansible/job-templates/:id/vars/:variable_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				vars := w.path("/api/v2/ansible/job-templates/:id/vars")
				id := ansibleCreated(t, w, vars, document("vars", map[string]any{"key": "app_version", "value": "1.4.2"}))
				return w.jsonRequest(t, http.MethodPatch, vars+"/"+id,
					document("vars", map[string]any{
						"key":         "app_version",
						"value":       "1.5.0",
						"description": "Updated by the golden write harness",
					}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/job-templates/:id/vars/:variable_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				vars := w.path("/api/v2/ansible/job-templates/:id/vars")
				id := ansibleCreated(t, w, vars, document("vars", map[string]any{"key": "app_version", "value": "1.4.2"}))
				return w.jsonRequest(t, http.MethodDelete, vars+"/"+id, nil)
			},
		},
		writeCase{
			// A job launched without a template: the playbook, the inventory and the credentials
			// arrive in the body.
			route: "POST /api/v2/organizations/:name/ansible/jobs",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				doc := document("ansible-jobs", map[string]any{
					"name":           "golden-write-job",
					"job-type":       "check",
					"extra-vars":     map[string]any{"release": "1.4.2"},
					"limit":          "webservers",
					"tags":           "deploy",
					"verbosity":      1,
					"forks":          10,
					"become-enabled": true,
					"diff-mode":      true,
				})
				related(doc, "project", "projects", ansibleProject(t, w))
				related(doc, "playbook", "ansible-playbooks", w.id("playbooks"))
				related(doc, "inventory", "ansible-inventories", w.id("inventories"))
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/ansible/jobs"),
					ansibleRelatedMany(doc, "credentials", "ansible-credentials", w.id("credentials")))
			},
		},
		writeCase{
			// A job can be canceled while it is pending or running, and every seeded job the
			// path resolves to has finished: the case cancels one it has just launched.
			route: "POST /api/v2/ansible/jobs/:id/actions/cancel",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/ansible/jobs/"+ansibleLaunched(t, w)+"/actions/cancel", nil)
			},
		},
		writeCase{
			// A relaunch repeats the job's playbook, and the seeded jobs were written straight to
			// the table without one: the case relaunches a job it has launched itself.
			route: "POST /api/v2/ansible/jobs/:id/actions/relaunch",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/ansible/jobs/"+ansibleLaunched(t, w)+"/actions/relaunch", nil)
			},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/jobs/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/ansible/jobs/:id"), nil)
			},
		},
	)
}

// Write cases for the Ansible schedules. The seeded ones are disabled, so that no scheduler ever
// starts a job from a fixture.
func init() {
	registerWriteCases(
		writeCase{
			// One document shape for four kinds of schedule: schedule-type says which of
			// job-template-id, inventory-source-id, playbook-id and workflow-id it needs.
			route: "POST /api/v2/organizations/:name/ansible/schedules",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/ansible/schedules"),
					document("schedules", map[string]any{
						"name":            "golden-write-schedule",
						"description":     "Recorded by the golden write harness",
						"schedule-type":   "job_template",
						"job-template-id": w.id("job-templates"),
						"cron-expression": "30 3 * * 1-5",
						"timezone":        "Europe/Brussels",
						"start-date-time": "2027-01-01T00:00:00Z",
						"end-date-time":   "2027-12-31T23:59:59Z",
						"config":          map[string]any{"extra_vars": map[string]any{"compliance_profile": "cis-level-1"}},
					}))
			},
		},
		writeCase{
			// Like the create, an update is a schedules document; an omitted attribute is left as it is.
			route: "PATCH /api/v2/ansible/schedules/:schedule_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/ansible/schedules/:schedule_id"),
					document("schedules", map[string]any{
						"name":            "nightly-patch-baseline",
						"description":     "Updated by the golden write harness",
						"cron-expression": "15 1 * * *",
						"timezone":        "Europe/Brussels",
						"config":          map[string]any{"extra_vars": map[string]any{"reboot": false}},
					}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/schedules/:schedule_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/ansible/schedules/:schedule_id"), nil)
			},
		},
		writeCase{
			route: "POST /api/v2/ansible/schedules/:schedule_id/actions/enable",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/schedules/:schedule_id/actions/enable"), nil)
			},
		},
		writeCase{
			route: "POST /api/v2/ansible/schedules/:schedule_id/actions/disable",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/schedules/:schedule_id/actions/enable"), nil))
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/schedules/:schedule_id/actions/disable"), nil)
			},
		},
		writeCase{
			// Queue-backed: running a job-template schedule launches its template.
			route: "POST /api/v2/ansible/schedules/:schedule_id/actions/run-now",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/schedules/:schedule_id/actions/run-now"), nil)
			},
		},
	)
}

// ansibleSeededNode is the one node of the seeded workflow. Nodes and edges are not a family a
// path resolves, so the cases look them up or make them.
func ansibleSeededNode(t *testing.T, w *writeRun) string {
	t.Helper()
	var id string
	if err := w.db.Raw("SELECT id::text FROM ansible_workflow_nodes WHERE workflow_id = ? ORDER BY identifier LIMIT 1", w.id("workflows")).Scan(&id).Error; err != nil || id == "" {
		t.Fatalf("read the seeded workflow's node: %v", err)
	}
	return id
}

// ansibleVerifyNode adds a second job-template node to the seeded workflow, for an edge to end at.
func ansibleVerifyNode(t *testing.T, w *writeRun) string {
	t.Helper()
	return ansibleCreated(t, w, w.path("/api/v2/ansible/workflows/:id/nodes"), related(
		document("ansible-workflow-nodes", map[string]any{"node-type": "job_template", "identifier": "verify"}),
		"job-template", "ansible-job-templates", w.id("job-templates")))
}

// ansibleEdgeDocument joins two nodes of a workflow.
func ansibleEdgeDocument(source, target string) map[string]any {
	return related(related(
		document("ansible-workflow-edges", map[string]any{"condition": "on_success"}),
		"source-node", "ansible-workflow-nodes", source),
		"target-node", "ansible-workflow-nodes", target)
}

// ansibleAwaitingApproval builds a workflow whose only node is an approval gate, launches it, and
// returns the node's run, which waits for a decision from the moment the workflow starts.
func ansibleAwaitingApproval(t *testing.T, w *writeRun) string {
	t.Helper()
	workflow := ansibleCreated(t, w, w.path("/api/v2/organizations/:name/ansible/workflows"), related(
		document("ansible-workflows", map[string]any{"name": "golden-write-gated"}),
		"project", "projects", ansibleProject(t, w)))
	ansibleCreated(t, w, "/api/v2/ansible/workflows/"+workflow+"/nodes",
		document("ansible-workflow-nodes", map[string]any{
			"node-type":        "approval",
			"identifier":       "approve-rollout",
			"approval-message": "Approve the production rollout",
		}))
	run := ansibleCreated(t, w, "/api/v2/ansible/workflows/"+workflow+"/launch", document("ansible-workflow-jobs", nil))
	detail := w.mustSend(t, w.jsonRequest(t, http.MethodGet, "/api/v2/ansible/workflow-jobs/"+run, nil))
	included, _ := detail["included"].([]any)
	if len(included) != 1 {
		t.Fatalf("a launched one-node workflow should have one node run: %v", detail)
	}
	nodeRun, _ := included[0].(map[string]any)
	id, _ := nodeRun["id"].(string)
	if id == "" {
		t.Fatalf("the node run has no id: %v", detail)
	}
	return id
}

// Write cases for the Ansible workflows, their nodes and edges, and the approval decisions on a
// running workflow.
func init() {
	registerWriteCases(
		writeCase{
			// extra-vars is a JSON object travelling as a string, here and on a node.
			route: "POST /api/v2/organizations/:name/ansible/workflows",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/ansible/workflows"), related(related(
					document("ansible-workflows", map[string]any{
						"name":                    "golden-write-workflow",
						"description":             "Recorded by the golden write harness",
						"allow-simultaneous":      true,
						"ask-variables-on-launch": true,
						"ask-limit-on-launch":     true,
						"extra-vars":              `{"environment":"staging"}`,
						"limit":                   "webservers",
					}),
					"project", "projects", ansibleProject(t, w)),
					"inventory", "ansible-inventories", w.id("inventories")))
			},
		},
		writeCase{
			route: "PATCH /api/v2/ansible/workflows/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/ansible/workflows/:id"),
					document("ansible-workflows", map[string]any{
						"description":             "Updated by the golden write harness",
						"allow-simultaneous":      true,
						"ask-inventory-on-launch": true,
						"extra-vars":              `{"environment":"production","canary":true}`,
						"limit":                   "webservers",
					}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/workflows/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/ansible/workflows/:id"), nil)
			},
		},
		writeCase{
			// Queue-backed: a launch starts the workflow's root nodes, and the seeded one's is a
			// job template. The body is optional.
			route: "POST /api/v2/ansible/workflows/:id/launch",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/workflows/:id/launch"),
					document("ansible-workflow-jobs", map[string]any{"extra-vars": map[string]any{"release": "1.4.2", "canary": true}}))
			},
		},
		writeCase{
			// node-type decides which relationships mean anything: a job_template node names a
			// job template, an approval node names nothing and carries the approval members.
			route: "POST /api/v2/ansible/workflows/:id/nodes",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/workflows/:id/nodes"), related(related(
					document("ansible-workflow-nodes", map[string]any{
						"node-type":                 "job_template",
						"identifier":                "verify",
						"position-x":                320,
						"position-y":                120,
						"extra-vars":                `{"smoke_tests":true}`,
						"limit":                     "webservers",
						"tags":                      "verify",
						"verbosity":                 1,
						"all-parents-must-converge": true,
					}),
					"job-template", "ansible-job-templates", w.id("job-templates")),
					"inventory", "ansible-inventories", w.id("inventories")))
			},
		},
		writeCase{
			route: "PATCH /api/v2/ansible/workflow-nodes/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, "/api/v2/ansible/workflow-nodes/"+ansibleSeededNode(t, w),
					document("ansible-workflow-nodes", map[string]any{
						"position-x": 80,
						"position-y": 120,
						"extra-vars": `{"reboot":false}`,
						"limit":      "webservers",
						"skip-tags":  "slow",
						"verbosity":  2,
					}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/workflow-nodes/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/ansible/workflow-nodes/"+ansibleSeededNode(t, w), nil)
			},
		},
		writeCase{
			// The seeded workflow has one node, and an edge needs two.
			route: "POST /api/v2/ansible/workflows/:id/edges",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/workflows/:id/edges"),
					ansibleEdgeDocument(ansibleSeededNode(t, w), ansibleVerifyNode(t, w)))
			},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/workflow-edges/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				id := ansibleCreated(t, w, w.path("/api/v2/ansible/workflows/:id/edges"),
					ansibleEdgeDocument(ansibleSeededNode(t, w), ansibleVerifyNode(t, w)))
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/ansible/workflow-edges/"+id, nil)
			},
		},
		writeCase{
			route: "POST /api/v2/ansible/workflow-node-jobs/:id/approve",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/ansible/workflow-node-jobs/"+ansibleAwaitingApproval(t, w)+"/approve", nil)
			},
		},
		writeCase{
			route: "POST /api/v2/ansible/workflow-node-jobs/:id/deny",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/ansible/workflow-node-jobs/"+ansibleAwaitingApproval(t, w)+"/deny", nil)
			},
		},
	)
}

// ansibleWebhookTemplate creates a webhook notification template that delivers to url and
// returns its identifier. The seed has no notification templates.
func ansibleWebhookTemplate(t *testing.T, w *writeRun, url string) string {
	t.Helper()
	return ansibleCreated(t, w, w.path("/api/v2/organizations/:name/ansible/notification-templates"),
		document("ansible-notification-templates", map[string]any{"name": "golden-write-webhook", "notification-type": "webhook", "config": map[string]any{"url": url}}))
}

// Write cases for the Ansible notification templates and their attachments.
func init() {
	registerWriteCases(
		writeCase{
			// notification-type is webhook, email or teams, and config holds that channel's settings. The
			// secret is the channel's password and is never returned. A webhook sends it as HTTP
			// basic auth together with config.username.
			route: "POST /api/v2/organizations/:name/ansible/notification-templates",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/ansible/notification-templates"),
					document("ansible-notification-templates", map[string]any{
						"name":              "golden-write-deploy-hook",
						"description":       "Recorded by the golden write harness",
						"notification-type": "webhook",
						"config": map[string]any{
							"url":      "https://hooks.example.com/stackweaver/deploys",
							"method":   "POST",
							"headers":  map[string]any{"X-Source": "stackweaver"},
							"username": "stackweaver",
						},
						"secret": "golden-write-webhook-password",
					}))
			},
			requestSecrets: []string{"data.attributes.secret"},
		},
		writeCase{
			route: "PATCH /api/v2/ansible/notification-templates/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				id := ansibleWebhookTemplate(t, w, "https://hooks.example.com/stackweaver/deploys")
				return w.jsonRequest(t, http.MethodPatch, "/api/v2/ansible/notification-templates/"+id,
					document("ansible-notification-templates", map[string]any{
						"name":        "golden-write-webhook",
						"description": "Updated by the golden write harness",
						"config": map[string]any{
							"url":             "https://hooks.example.com/stackweaver/releases",
							"method":          "PUT",
							"username":        "stackweaver",
							"skip_tls_verify": false,
						},
						"secret": "golden-write-rotated-password",
					}))
			},
			requestSecrets: []string{"data.attributes.secret"},
		},
		writeCase{
			route: "DELETE /api/v2/ansible/notification-templates/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				id := ansibleWebhookTemplate(t, w, "https://hooks.example.com/stackweaver/deploys")
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/ansible/notification-templates/"+id, nil)
			},
		},
		writeCase{
			// A test send succeeds only when the channel accepted the message, and a webhook
			// channel is whatever URL its template names. This one names a listener the case
			// starts on this machine, so the delivery is real and goes nowhere else.
			route: "POST /api/v2/ansible/notification-templates/:id/test",
			// The server refuses to deliver to a loopback or private address unless it was
			// started with this, and the listener is on loopback.
			env: map[string]string{"STACKWEAVER_ANSIBLE_NOTIFICATIONS_ALLOW_PRIVATE": "true"},
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				receiver := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
					rw.WriteHeader(http.StatusNoContent)
				}))
				t.Cleanup(receiver.Close)
				id := ansibleWebhookTemplate(t, w, receiver.URL)
				return w.jsonRequest(t, http.MethodPost, "/api/v2/ansible/notification-templates/"+id+"/test", nil)
			},
		},
		writeCase{
			// An attachment hangs a template on exactly one of a job template and a workflow:
			// the job-template or the workflow relationship, never both.
			route: "POST /api/v2/organizations/:name/ansible/notification-attachments",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/ansible/notification-attachments"),
					related(related(document("ansible-notification-attachments", map[string]any{
						"on-started": true,
						"on-success": false,
						"on-failure": true,
					}), "notification-template", "ansible-notification-templates", ansibleWebhookTemplate(t, w, "https://hooks.example.com/stackweaver/deploys")),
						"job-template", "ansible-job-templates", w.id("job-templates")))
			},
		},
		writeCase{
			route: "DELETE /api/v2/organizations/:name/ansible/notification-attachments/:attachment_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				attachments := w.path("/api/v2/organizations/:name/ansible/notification-attachments")
				id := ansibleCreated(t, w, attachments, related(related(document("ansible-notification-attachments", nil),
					"notification-template", "ansible-notification-templates", ansibleWebhookTemplate(t, w, "https://hooks.example.com/stackweaver/deploys")),
					"workflow", "ansible-workflows", w.id("workflows")))
				return w.jsonRequest(t, http.MethodDelete, attachments+"/"+id, nil)
			},
		},
	)
}

// ansibleConfigDocument is an ansible.cfg, which is what an Ansible config stores.
func ansibleConfigDocument() map[string]any {
	return document("ansible-configs", map[string]any{
		"config-content": "[defaults]\nforks = 20\nhost_key_checking = False\ntimeout = 30\n\n[ssh_connection]\npipelining = True\n",
	})
}

// Write cases for the ansible.cfg an organization or a project gives its jobs. The seed sets
// none, so a delete first stores the one it removes.
func init() {
	registerWriteCases(
		writeCase{
			route: "PUT /api/v2/organizations/:name/ansible-config",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPut, w.path("/api/v2/organizations/:name/ansible-config"), ansibleConfigDocument())
			},
		},
		writeCase{
			route: "DELETE /api/v2/organizations/:name/ansible-config",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				config := w.path("/api/v2/organizations/:name/ansible-config")
				w.mustSend(t, w.jsonRequest(t, http.MethodPut, config, ansibleConfigDocument()))
				return w.jsonRequest(t, http.MethodDelete, config, nil)
			},
		},
		writeCase{
			route: "PUT /api/v2/projects/:id/ansible-config",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPut, w.path("/api/v2/projects/:id/ansible-config"), ansibleConfigDocument())
			},
		},
		writeCase{
			route: "DELETE /api/v2/projects/:id/ansible-config",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				config := w.path("/api/v2/projects/:id/ansible-config")
				w.mustSend(t, w.jsonRequest(t, http.MethodPut, config, ansibleConfigDocument()))
				return w.jsonRequest(t, http.MethodDelete, config, nil)
			},
		},
	)
}
