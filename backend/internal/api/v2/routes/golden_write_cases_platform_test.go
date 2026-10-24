// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package routes_test

import (
	"net/http"
	"testing"
)

// Write cases for the platform routes: organizations and their memberships, projects, teams and
// who is in them, what a team may do in a project, authentication tokens, and variable sets
// under both of their route trees. One init per group, in that order.

// Seeded people the membership cases act on. The recorder authenticates as the first owner by
// email, avery.diaz, so a case that removes somebody removes one of these instead, and never
// the membership the recorder's own permissions come through.
const (
	// platformTeamMember belongs to application-developers, the seeded team the team routes
	// resolve to: the seeder puts the first three of its four users in it.
	platformTeamMember = "priya.raman@example.com"
	// platformTeamOutsider is the fourth: a member of the organization, and of no team but owners.
	platformTeamOutsider = "lena.fischer@example.com"
)

// platformMembershipID is the organization membership of a seeded user. Memberships have no
// entry in the resolver's family table, so w.path cannot fill one in.
func platformMembershipID(t *testing.T, w *writeRun, email string) string {
	t.Helper()
	var id string
	err := w.db.Raw(`
		SELECT om.id::text FROM organization_members om
		JOIN users u ON u.id = om.user_id
		JOIN organizations o ON o.id = om.organization_id
		WHERE u.email = ? AND o.name = ?`, email, w.org()).Scan(&id).Error
	if err != nil || id == "" {
		t.Fatalf("no seeded organization membership for %s: %v", email, err)
	}
	return id
}

// platformRefs is the body of a to-many relationship write: a list of resource identifiers.
func platformRefs(resourceType string, ids ...string) map[string]any {
	data := make([]any, 0, len(ids))
	for _, id := range ids {
		data = append(data, map[string]any{"type": resourceType, "id": id})
	}
	return map[string]any{"data": data}
}

// Organizations and their memberships.
func init() {
	registerWriteCases(
		writeCase{
			route: "POST /api/v2/organizations",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/organizations",
					document("organizations", map[string]any{
						"name":                          "golden-write-org",
						"email":                         "platform-team@example.com",
						"description":                   "Recorded by the golden write harness",
						"collaborator-auth-policy":      "two_factor_mandatory",
						"cost-estimation-enabled":       true,
						"allow-force-delete-workspaces": true,
						"ansible-job-retention-days":    30,
					}))
			},
		},
		writeCase{
			// Agent execution needs a pool to dispatch to, and the pool is a relationship here,
			// not an attribute, so the case sends both halves of that setting together.
			route: "PATCH /api/v2/organizations/:name",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/organizations/:name"), related(
					document("organizations", map[string]any{
						"email":                               "platform-team@example.com",
						"description":                         "Updated by the golden write harness",
						"collaborator-auth-policy":            "two_factor_mandatory",
						"cost-estimation-enabled":             true,
						"default-execution-mode":              "agent",
						"ansible-job-retention-days":          30,
						"speculative-plan-management-enabled": false,
						"assessments-enforced":                true,
					}),
					"default-agent-pool", "agent-pools", w.id("agent-pools")))
			},
		},
		writeCase{
			// The route the read harness has to exclude, because it destroys what every later
			// fixture reads. Here it runs on its own copy, like any other write.
			route: "DELETE /api/v2/organizations/:name",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				// An organization of the case's own, not the seeded one. The seeded organization
				// cannot be deleted at all: it has a run trigger, and run_triggers.sourceable_id
				// references workspaces with no ON DELETE rule, so the cascade stops there and the
				// handler answers 500. That is a defect in the product, found by this recorder and
				// tracked on its own; a case has to be a write the server accepts.
				w.mustSend(t, w.jsonRequest(t, http.MethodPost, "/api/v2/organizations",
					document("organizations", map[string]any{"name": "golden-write-doomed", "email": "golden-write@example.com"})))
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/organizations/golden-write-doomed", nil)
			},
		},
		writeCase{
			// An address nobody has signed in with yet is an invitation: the handler keeps a
			// placeholder user for it and nothing leaves the machine.
			route: "POST /api/v2/organizations/:name/organization-memberships",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/organization-memberships"),
					document("organization-memberships", map[string]any{"email": "new.hire@example.com"}))
			},
		},
		writeCase{
			// The body has to name the membership it updates, and nothing else in it is read:
			// roles are gone, a member's permissions come from teams.
			route: "PATCH /api/v2/organization-memberships/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				id := platformMembershipID(t, w, platformTeamOutsider)
				doc := document("organization-memberships", nil)
				doc["data"].(map[string]any)["id"] = id
				return w.jsonRequest(t, http.MethodPatch, "/api/v2/organization-memberships/"+id, doc)
			},
		},
		writeCase{
			route: "DELETE /api/v2/organization-memberships/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete,
					"/api/v2/organization-memberships/"+platformMembershipID(t, w, platformTeamOutsider), nil)
			},
		},
	)
}

// platformTagBindings is the tag-bindings relationship of a project document. The key and value
// ride inline in each relationship member's attributes, which is how the tfe provider sends its
// `tags` map; they are not sideloaded.
func platformTagBindings(doc map[string]any, tags ...[2]string) map[string]any {
	members := make([]any, 0, len(tags))
	for _, tag := range tags {
		members = append(members, map[string]any{
			"type":       "tag-bindings",
			"attributes": map[string]any{"key": tag[0], "value": tag[1]},
		})
	}
	data := doc["data"].(map[string]any)
	data["relationships"] = map[string]any{"tag-bindings": map[string]any{"data": members}}
	return doc
}

// Projects, their tags and their notification configurations.
func init() {
	registerWriteCases(
		writeCase{
			route: "POST /api/v2/organizations/:name/projects",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/projects"), platformTagBindings(
					document("projects", map[string]any{"name": "golden-write-project", "description": "Recorded by the golden write harness"}),
					[2]string{"environment", "staging"}, [2]string{"cost-center", "platform-1042"}))
			},
		},
		writeCase{
			// The settings half of a project: workspaces that do not choose their own execution
			// mode run on the project's pool.
			route: "PATCH /api/v2/organizations/:name/projects/:project_name",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/organizations/:name/projects/:project_name"),
					document("projects", map[string]any{
						"description":            "Updated by the golden write harness",
						"default-execution-mode": "agent",
						"default-agent-pool-id":  w.id("agent-pools"),
					}))
			},
		},
		writeCase{
			route: "PATCH /api/v2/projects/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/projects/:id"), platformTagBindings(
					document("projects", map[string]any{"name": "golden-write-renamed", "description": "Updated by the golden write harness"}),
					[2]string{"environment", "production"}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/organizations/:name/projects/:project_name",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/organizations/:name/projects/:project_name"), nil)
			},
		},
		writeCase{
			route: "DELETE /api/v2/projects/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/projects/:id"), nil)
			},
		},
		writeCase{
			// A replace, not a merge: the list sent is the list the project ends up with.
			route: "PATCH /api/v2/projects/:id/tag-bindings",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/projects/:id/tag-bindings"), map[string]any{
					"data": []any{
						map[string]any{"type": "tag-bindings", "attributes": map[string]any{"key": "environment", "value": "production"}},
						map[string]any{"type": "tag-bindings", "attributes": map[string]any{"key": "owner", "value": "platform-engineering"}},
					},
				})
			},
		},
		writeCase{
			// Creating a configuration delivers nothing; only the verify action and a run do. The
			// token is the secret a generic webhook's payload is signed with, and is never read back.
			route: "POST /api/v2/projects/:id/notification-configurations",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/projects/:id/notification-configurations"),
					document("notification-configurations", map[string]any{
						"name":             "golden-write-run-events",
						"destination-type": "generic",
						"url":              "https://hooks.example.com/stackweaver/runs",
						"token":            "golden-write-signing-secret",
						"enabled":          true,
						"triggers":         []string{"run:needs_attention", "run:completed", "run:errored"},
					}))
			},
			requestSecrets: []string{"data.attributes.token"},
		},
	)
}

// Teams, who is in them, and what a team is told about.
func init() {
	registerWriteCases(
		writeCase{
			route: "POST /api/v2/organizations/:name/teams",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/teams"),
					document("teams", map[string]any{
						"name":                          "golden-write-team",
						"description":                   "Recorded by the golden write harness",
						"visibility":                    "organization",
						"allow-member-token-management": false,
						"organization-access": map[string]any{
							"manage-workspaces": true,
							"manage-modules":    true,
							"read-projects":     true,
							"read-ansible":      true,
						},
					}))
			},
		},
		writeCase{
			route: "PATCH /api/v2/organizations/:name/teams/:teamName",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/organizations/:name/teams/:teamName"),
					document("teams", map[string]any{
						"description": "Updated by the golden write harness",
						"visibility":  "organization",
						"organization-access": map[string]any{
							"manage-workspaces": false,
							"read-workspaces":   true,
							"manage-run-tasks":  true,
						},
					}))
			},
		},
		writeCase{
			route: "PATCH /api/v2/teams/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/teams/:id"),
					document("teams", map[string]any{
						"name":                          "golden-write-renamed",
						"description":                   "Updated by the golden write harness",
						"visibility":                    "secret",
						"allow-member-token-management": false,
						"sso-team-id":                   "golden-write-idp-group",
					}))
			},
		},
		writeCase{
			// The seeded team the family resolves to is an ordinary one. The two the server
			// creates itself, owners and viewers, are refused.
			route: "DELETE /api/v2/organizations/:name/teams/:teamName",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/organizations/:name/teams/:teamName"), nil)
			},
		},
		writeCase{
			route: "DELETE /api/v2/teams/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/teams/:id"), nil)
			},
		},
		writeCase{
			route: "POST /api/v2/teams/:id/relationships/organization-memberships",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/teams/:id/relationships/organization-memberships"),
					platformRefs("organization-memberships", platformMembershipID(t, w, platformTeamOutsider)))
			},
		},
		writeCase{
			route: "DELETE /api/v2/teams/:id/relationships/organization-memberships",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/teams/:id/relationships/organization-memberships"),
					platformRefs("organization-memberships", platformMembershipID(t, w, platformTeamMember)))
			},
		},
		writeCase{
			// go-tfe puts a username in the identifier of a users resource. Stackweaver has no
			// usernames of its own and reads that identifier as an email address.
			route: "POST /api/v2/teams/:id/relationships/users",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/teams/:id/relationships/users"),
					platformRefs("users", platformTeamOutsider))
			},
		},
		writeCase{
			route: "DELETE /api/v2/teams/:id/relationships/users",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/teams/:id/relationships/users"),
					platformRefs("users", platformTeamMember))
			},
		},
		writeCase{
			// A team is told about one thing, a change request that names it. An email
			// destination is stored and not delivered, so it carries addresses and no URL.
			route: "POST /api/v2/teams/:id/notification-configurations",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/teams/:id/notification-configurations"),
					document("notification-configurations", map[string]any{
						"name":             "golden-write-change-requests",
						"destination-type": "email",
						"email-addresses":  []string{"platform-team@example.com", "on-call@example.com"},
						"enabled":          true,
						"triggers":         []string{"change_request:created"},
					}))
			},
		},
	)
}

// platformCreateTeam makes a team no project knows yet. The principal belongs to every seeded
// team and the harness grants each of those every project, so a seeded team already has access
// to a seeded project and granting it again is a conflict.
func platformCreateTeam(t *testing.T, w *writeRun) string {
	t.Helper()
	return dataID(t, w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/teams"),
		document("teams", map[string]any{"name": "golden-write-contractors", "visibility": "organization"}))))
}

// What a team may do in a project, under the TFE route and the project-scoped one.
func init() {
	registerWriteCases(
		writeCase{
			// Custom access, the fuller of the two shapes: `access` says "custom" and both blocks
			// say what that means. A fixed level sends `access` alone, as the project-scoped
			// create does.
			route: "POST /api/v2/team-projects",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				doc := document("team-projects", map[string]any{
					"access": "custom",
					"project-access": map[string]any{
						"settings":      "read",
						"teams":         "none",
						"variable-sets": "read",
					},
					"workspace-access": map[string]any{
						"runs":           "apply",
						"sentinel-mocks": "none",
						"state-versions": "read-outputs",
						"variables":      "write",
						"create":         true,
						"locking":        true,
						"move":           false,
						"delete":         false,
						"run-tasks":      false,
					},
				})
				related(doc, "team", "teams", platformCreateTeam(t, w))
				return w.jsonRequest(t, http.MethodPost, "/api/v2/team-projects", related(doc, "project", "projects", w.id("projects")))
			},
		},
		writeCase{
			route: "PATCH /api/v2/team-projects/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/team-projects/:id"),
					document("team-projects", map[string]any{"access": "maintain"}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/team-projects/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/team-projects/:id"), nil)
			},
		},
		writeCase{
			// The project comes from the path here, so the body names only the team.
			route: "POST /api/v2/projects/:id/relationships/team-access",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/projects/:id/relationships/team-access"), related(
					document("team-projects", map[string]any{"access": "read"}),
					"team", "teams", platformCreateTeam(t, w)))
			},
		},
		writeCase{
			// The same access under its project: the path names both, and they have to belong
			// together.
			route: "PATCH /api/v2/projects/:id/relationships/team-access/:access_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				projectID, accessID := platformSeededProjectAccess(t, w)
				return w.jsonRequest(t, http.MethodPatch, "/api/v2/projects/"+projectID+"/relationships/team-access/"+accessID,
					document("team-projects", map[string]any{"access": "write"}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/projects/:id/relationships/team-access/:access_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				projectID, accessID := platformSeededProjectAccess(t, w)
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/projects/"+projectID+"/relationships/team-access/"+accessID, nil)
			},
		},
	)
}

// platformSeededProjectAccess is the seeded team access to a project and the project it is on,
// which is not necessarily the project w.id resolves to.
func platformSeededProjectAccess(t *testing.T, w *writeRun) (projectID, accessID string) {
	t.Helper()
	accessID = w.id("team-projects")
	if err := w.db.Raw("SELECT project_id FROM team_project_accesses WHERE id = ?", accessID).Scan(&projectID).Error; err != nil || projectID == "" {
		t.Fatalf("the seeded team access %s names no project: %v", accessID, err)
	}
	return projectID, accessID
}

// Variable sets. A set is created under its organization and then addressed two ways, by its
// own identifier as TFE does and under the organization as the application does.
func init() {
	registerWriteCases(
		writeCase{
			// One request makes the set, its variables and its assignments, or none of them. A
			// variable rides inline in the vars relationship, attributes and all.
			route: "POST /api/v2/organizations/:name/varsets",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				doc := document("varsets", map[string]any{
					"name":        "golden-write-varset",
					"description": "Recorded by the golden write harness",
					"global":      false,
					"priority":    true,
				})
				doc["data"].(map[string]any)["relationships"] = map[string]any{
					"workspaces": platformRefs("workspaces", w.id("workspaces")),
					"projects":   platformRefs("projects", w.id("projects")),
					"vars": map[string]any{"data": []any{
						map[string]any{"type": "vars", "attributes": map[string]any{
							"key": "region", "value": "eu-west-1", "category": "terraform", "description": "Region every workspace deploys to.",
						}},
						map[string]any{"type": "vars", "attributes": map[string]any{
							"key": "DEPLOY_TOKEN", "value": "golden-write-deploy-token", "category": "env", "sensitive": true,
						}},
					}},
				}
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/varsets"), doc)
			},
			requestSecrets: []string{"data.relationships.vars.data.1.attributes.value"},
		},
	)
	registerWriteCases(platformVarsetCases("/api/v2/varsets")...)
	registerWriteCases(platformVarsetCases("/api/v2/organizations/:name/varsets")...)
}

// platformVarsetCases is the cases for the routes both variable-set trees register, under one
// of them. The handlers are shared and the routes are not, so each tree is recorded.
func platformVarsetCases(tree string) []writeCase {
	// An assignment has to exist before it can be removed, and the seeded set has none.
	unassign := func(route, resourceType, family string) writeCase {
		return writeCase{
			route: "DELETE " + route,
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				body := platformRefs(resourceType, w.id(family))
				w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path(route), body))
				return w.jsonRequest(t, http.MethodDelete, w.path(route), body)
			},
		}
	}
	return []writeCase{
		{
			route: "PATCH " + tree + "/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path(tree+"/:id"),
					document("varsets", map[string]any{
						"name":        "golden-write-renamed",
						"description": "Updated by the golden write harness",
						"global":      false,
						"priority":    true,
					}))
			},
		},
		{
			route: "DELETE " + tree + "/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path(tree+"/:id"), nil)
			},
		},
		{
			route: "POST " + tree + "/:id/relationships/workspaces",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path(tree+"/:id/relationships/workspaces"),
					platformRefs("workspaces", w.id("workspaces")))
			},
		},
		unassign(tree+"/:id/relationships/workspaces", "workspaces", "workspaces"),
		{
			route: "POST " + tree + "/:id/relationships/projects",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path(tree+"/:id/relationships/projects"),
					platformRefs("projects", w.id("projects")))
			},
		},
		unassign(tree+"/:id/relationships/projects", "projects", "projects"),
		{
			// A sensitive value is write-only: it goes in here and is never read back.
			route: "POST " + tree + "/:id/relationships/vars",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path(tree+"/:id/relationships/vars"),
					document("vars", map[string]any{
						"key":         "AWS_SESSION_TOKEN",
						"value":       "golden-write-session-token",
						"description": "Recorded by the golden write harness",
						"category":    "env",
						"hcl":         false,
						"sensitive":   true,
					}))
			},
			requestSecrets: []string{"data.attributes.value"},
		},
		{
			// The seeded variable is a region stored as sensitive. The case makes it an ordinary
			// one, so the value it sends is not a secret and the response may show it.
			route: "PATCH " + tree + "/:id/relationships/vars/:variable_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path(tree+"/:id/relationships/vars/:variable_id"),
					document("vars", map[string]any{
						"key":         "AWS_DEFAULT_REGION",
						"value":       "eu-central-1",
						"description": "Updated by the golden write harness",
						"category":    "env",
						"sensitive":   false,
					}))
			},
		},
		{
			route: "DELETE " + tree + "/:id/relationships/vars/:variable_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path(tree+"/:id/relationships/vars/:variable_id"), nil)
			},
		},
	}
}

// platformAgentToken mints an agent token to act on. The /authentication-tokens/:id routes serve
// agent tokens only, and the resolver hands them whichever API key sorts first by name, of any
// kind; the seed has no agent token to find.
func platformAgentToken(t *testing.T, w *writeRun) string {
	t.Helper()
	return dataID(t, w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/agent-pools/:id/authentication-tokens"),
		document("authentication-tokens", map[string]any{"description": "golden-write-agent"}))))
}

// Tokens. Every create returns the generated secret exactly once.
func init() {
	registerWriteCases(
		writeCase{
			// The body is optional; without one the token never expires.
			route: "POST /api/v2/organizations/:name/authentication-token",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/authentication-token"),
					document("authentication-tokens", map[string]any{"expired-at": "2030-01-01T00:00:00Z"}))
			},
			responseSecrets: []string{"data.attributes.token"},
		},
		writeCase{
			route: "DELETE /api/v2/organizations/:name/authentication-token",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				target := w.path("/api/v2/organizations/:name/authentication-token")
				w.mustSend(t, w.jsonRequest(t, http.MethodPost, target, nil))
				return w.jsonRequest(t, http.MethodDelete, target, nil)
			},
		},
		writeCase{
			route: "DELETE /api/v2/teams/:id/authentication-token",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				target := w.path("/api/v2/teams/:id/authentication-token")
				w.mustSend(t, w.jsonRequest(t, http.MethodPost, target, nil))
				return w.jsonRequest(t, http.MethodDelete, target, nil)
			},
		},
		writeCase{
			route: "DELETE /api/v2/authentication-tokens/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/authentication-tokens/"+platformAgentToken(t, w), nil)
			},
		},
		writeCase{
			// A new token for the same pool, returned once, while the old one keeps working for
			// the grace period so running agents can be switched over. The body is optional.
			route: "POST /api/v2/authentication-tokens/:id/actions/rotate",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/authentication-tokens/"+platformAgentToken(t, w)+"/actions/rotate",
					document("authentication-tokens", map[string]any{"grace-period-hours": 48}))
			},
			responseSecrets: []string{"data.attributes.token"},
		},
		writeCase{
			// The server generates the token and returns it exactly once, here. Like the
			// organization's, the body is optional and says only when the token stops working.
			route: "POST /api/v2/teams/:id/authentication-token",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/teams/:id/authentication-token"),
					document("authentication-tokens", map[string]any{"expired-at": "2030-01-01T00:00:00Z"}))
			},
			responseSecrets: []string{"data.attributes.token"},
		},
	)
}

// platformNonAdminUser is a seeded user who is not a platform administrator, the target the
// grant and revoke cases act on.
func platformNonAdminUser(t *testing.T, w *writeRun) string {
	t.Helper()
	var id string
	if err := w.db.Raw(`SELECT id::text FROM users WHERE NOT platform_admin AND email <> '' ORDER BY email LIMIT 1`).Scan(&id).Error; err != nil || id == "" {
		t.Fatalf("no seeded user who is not a platform administrator: %v", err)
	}
	return id
}

// Platform administration (#132): the TFE admin users actions. The recorder's token is a
// platform administrator's platform:admin token.
func init() {
	registerWriteCases(
		writeCase{
			route: "POST /api/v2/admin/users/:id/actions/grant_admin",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/admin/users/"+platformNonAdminUser(t, w)+"/actions/grant_admin", nil)
			},
		},
		writeCase{
			route: "POST /api/v2/admin/users/:id/actions/revoke_admin",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				target := platformNonAdminUser(t, w)
				w.mustSend(t, w.jsonRequest(t, http.MethodPost, "/api/v2/admin/users/"+target+"/actions/grant_admin", nil))
				return w.jsonRequest(t, http.MethodPost, "/api/v2/admin/users/"+target+"/actions/revoke_admin", nil)
			},
		},
	)
}
