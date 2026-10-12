// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a workflow or a workflow node refuses on create and on PATCH (#899): `extra-vars` that
// does not decode to a JSON object, an empty name, and a relationship identifier that does not
// parse. Each is a mistake in the request and is answered with a 400 in the JSON:API errors
// document, before the row is touched.
//
// The defect this test was written against: the handlers wrapped `extra-vars` in a jsonb value as
// sent and discarded the error of uuid.Parse on the inventory, job-template and credential
// relationships. Text that is not JSON was refused by the column and answered with a 500, a
// malformed identifier became the zero UUID and failed at the foreign key with a 500, a JSON list
// was stored and then silently ignored by the engine, and nothing looked at the name at all.
//
// Every rejection is paired with the nearest request that is still valid, so that the rule is
// shown to refuse the mistake and nothing beside it.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run 'TestWorkflow(Node)?(Create|Update)_'

//go:build integration

package ansible

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// workflowDocument is a JSON:API request document for a workflow or a workflow node. A
// relationship is given as its identifier.
func workflowDocument(t *testing.T, resourceType string, attrs map[string]any, relationships map[string]string) string {
	t.Helper()
	data := map[string]any{"type": resourceType, "attributes": attrs}
	if len(relationships) > 0 {
		rels := make(map[string]any, len(relationships))
		for name, id := range relationships {
			rels[name] = map[string]any{"data": map[string]any{"id": id}}
		}
		data["relationships"] = rels
	}
	raw, err := json.Marshal(map[string]any{"data": data})
	if err != nil {
		t.Fatalf("marshalling the request document: %v", err)
	}
	return string(raw)
}

// assertBadRequest checks that a response is a 400 in the JSON:API errors document with the
// given detail, and that no flat `error` key travels with it.
func assertBadRequest(t *testing.T, code int, body []byte, wantDetail string) {
	t.Helper()
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (%s)", code, body)
		return
	}
	var doc struct {
		Errors []struct {
			Status string `json:"status"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
		Error any `json:"error"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decoding the error document: %v\n%s", err, body)
	}
	if doc.Error != nil {
		t.Errorf("the response carries a top-level `error` key: %s", body)
	}
	if len(doc.Errors) != 1 {
		t.Fatalf("the response holds %d errors, want 1: %s", len(doc.Errors), body)
	}
	if got := doc.Errors[0]; got.Status != "400" || got.Title != "Bad Request" || got.Detail != wantDetail {
		t.Errorf("error = {status %q, title %q, detail %q}, want {status \"400\", title \"Bad Request\", detail %q}",
			got.Status, got.Title, got.Detail, wantDetail)
	}
}

// notJSONObjects are `extra-vars` strings the handlers must refuse: text that is not JSON, and
// JSON of every kind but an object.
var notJSONObjects = []struct{ name, value string }{
	{"text that is not JSON", "region: eu"},
	{"a truncated object", `{"region":`},
	{"a list", `["eu","us"]`},
	{"a string", `"eu"`},
	{"a number", `42`},
	{"null", `null`},
	{"only spaces", "   "},
	{"an object followed by more", `{"region":"eu"} {"zone":"a"}`},
}

const extraVarsDetail = "extra-vars must be a JSON object"

// createdResource decodes the resource of a 201 response.
func createdResource(t *testing.T, code int, body []byte) storedAsSentResource {
	t.Helper()
	if code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%s)", code, body)
	}
	var doc struct {
		Data storedAsSentResource `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decoding the created resource: %v\n%s", err, body)
	}
	if _, err := uuid.Parse(doc.Data.ID); err != nil {
		t.Fatalf("the created resource has no usable id: %s", body)
	}
	return doc.Data
}

// decodedExtraVars reads a resource's `extra-vars` attribute, a JSON object travelling as a
// string, as the value it encodes.
func decodedExtraVars(t *testing.T, r storedAsSentResource) any {
	t.Helper()
	text, _ := r.Attributes["extra-vars"].(string)
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		t.Fatalf("extra-vars %q is not JSON: %v", text, err)
	}
	return decoded
}

func TestWorkflowCreate_RefusesWhatItCannotStore(t *testing.T) {
	f := setupWorkflowUpdate(t)
	path := "/api/v2/organizations/" + f.orgName + "/ansible/workflows"
	project := map[string]string{"project": f.projectID}

	// countWorkflows is how a rejection is shown to have written nothing.
	countWorkflows := func(t *testing.T) int64 {
		t.Helper()
		var n int64
		if err := f.db.Model(&models.AnsibleWorkflow{}).Where("project_id = ?", f.projectID).Count(&n).Error; err != nil {
			t.Fatalf("counting the project's workflows: %v", err)
		}
		return n
	}
	before := countWorkflows(t)
	post := func(t *testing.T, attrs map[string]any, relationships map[string]string) (int, []byte) {
		t.Helper()
		return storedAsSentCall(t, f.router, http.MethodPost, path, f.owner,
			workflowDocument(t, "ansible-workflows", attrs, relationships))
	}
	// create posts a document that must be accepted and deletes the row it made afterwards.
	create := func(t *testing.T, attrs map[string]any, relationships map[string]string) storedAsSentResource {
		t.Helper()
		code, body := post(t, attrs, relationships)
		created := createdResource(t, code, body)
		t.Cleanup(func() { f.db.Where("id = ?", created.ID).Delete(&models.AnsibleWorkflow{}) })
		return created
	}

	for _, tc := range notJSONObjects {
		t.Run("extra-vars: "+tc.name, func(t *testing.T) {
			code, body := post(t, map[string]any{"name": "wfval-" + uuid.NewString()[:8], "extra-vars": tc.value}, project)
			assertBadRequest(t, code, body, extraVarsDetail)
		})
	}
	for name, attrs := range map[string]map[string]any{
		"no name":             {"description": "nameless"},
		"an empty name":       {"name": ""},
		"a name of spaces":    {"name": "   "},
		"a name that is null": {"name": nil},
	} {
		t.Run(name, func(t *testing.T) {
			code, body := post(t, attrs, project)
			assertBadRequest(t, code, body, "name is required")
		})
	}
	t.Run("an inventory identifier that does not parse", func(t *testing.T) {
		code, body := post(t, map[string]any{"name": "wfval-" + uuid.NewString()[:8]},
			map[string]string{"project": f.projectID, "inventory": "not-a-uuid"})
		assertBadRequest(t, code, body, "Invalid inventory ID")
	})
	t.Run("an empty inventory identifier", func(t *testing.T) {
		code, body := post(t, map[string]any{"name": "wfval-" + uuid.NewString()[:8]},
			map[string]string{"project": f.projectID, "inventory": ""})
		assertBadRequest(t, code, body, "Invalid inventory ID")
	})
	if after := countWorkflows(t); after != before {
		t.Errorf("the rejected requests left %d workflow(s) behind", after-before)
	}

	t.Run("a name alone is enough, and the extra vars are the empty object", func(t *testing.T) {
		name := "wfval-" + uuid.NewString()[:8]
		created := create(t, map[string]any{"name": name}, project)
		if created.Attributes["name"] != name {
			t.Errorf("name = %v, want %q", created.Attributes["name"], name)
		}
		// The create response echoes the row as built, before the column default is read back,
		// so the stored value is what is checked.
		var row models.AnsibleWorkflow
		if err := f.db.First(&row, "id = ?", created.ID).Error; err != nil {
			t.Fatalf("loading the created workflow: %v", err)
		}
		if string(row.ExtraVars) != "{}" {
			t.Errorf("stored extra vars = %s, want {}", row.ExtraVars)
		}
	})
	t.Run("an empty extra-vars string is no extra vars", func(t *testing.T) {
		created := create(t, map[string]any{"name": "wfval-" + uuid.NewString()[:8], "extra-vars": ""}, project)
		var row models.AnsibleWorkflow
		if err := f.db.First(&row, "id = ?", created.ID).Error; err != nil {
			t.Fatalf("loading the created workflow: %v", err)
		}
		if string(row.ExtraVars) != "{}" {
			t.Errorf("stored extra vars = %s, want {}", row.ExtraVars)
		}
	})
	t.Run("an object and a real inventory are stored", func(t *testing.T) {
		created := create(t,
			map[string]any{"name": "wfval-" + uuid.NewString()[:8], "extra-vars": `{"region":"eu","hosts":["a","b"]}`},
			map[string]string{"project": f.projectID, "inventory": f.inventoryID})
		want := map[string]any{"region": "eu", "hosts": []any{"a", "b"}}
		if diff := attributeDiff(map[string]any{"extra-vars": want}, map[string]any{"extra-vars": decodedExtraVars(t, created)}); diff != "" {
			t.Errorf("the workflow does not hold the extra vars it was sent:\n%s", diff)
		}
		var row models.AnsibleWorkflow
		if err := f.db.First(&row, "id = ?", created.ID).Error; err != nil {
			t.Fatalf("loading the created workflow: %v", err)
		}
		if row.InventoryID == nil || row.InventoryID.String() != f.inventoryID {
			t.Errorf("stored inventory = %v, want %s", row.InventoryID, f.inventoryID)
		}
	})
	t.Run("the empty object is an object", func(t *testing.T) {
		created := create(t, map[string]any{"name": "wfval-" + uuid.NewString()[:8], "extra-vars": `{}`}, project)
		if got := decodedExtraVars(t, created); len(got.(map[string]any)) != 0 {
			t.Errorf("extra vars = %v, want the empty object", got)
		}
	})
}

func TestWorkflowUpdate_RefusesWhatItCannotStore(t *testing.T) {
	f := setupWorkflowUpdate(t)
	path := "/api/v2/ansible/workflows/" + f.workflowID.String()

	var seeded models.AnsibleWorkflow
	if err := f.db.First(&seeded, "id = ?", f.workflowID).Error; err != nil {
		t.Fatalf("loading the seeded workflow: %v", err)
	}
	if err := f.db.Model(&models.AnsibleWorkflow{}).Where("id = ?", f.workflowID).
		Update("extra_vars", `{"region":"eu"}`).Error; err != nil {
		t.Fatalf("seeding the workflow's extra vars: %v", err)
	}
	// unchanged fails the test when a rejected PATCH wrote anything it carried.
	unchanged := func(t *testing.T) {
		t.Helper()
		var row models.AnsibleWorkflow
		if err := f.db.First(&row, "id = ?", f.workflowID).Error; err != nil {
			t.Fatalf("loading the workflow: %v", err)
		}
		var vars map[string]any
		if err := json.Unmarshal(row.ExtraVars, &vars); err != nil {
			t.Fatalf("stored extra vars %s are not a JSON object: %v", row.ExtraVars, err)
		}
		if row.Name != seeded.Name || row.Description != "" || len(vars) != 1 || vars["region"] != "eu" {
			t.Errorf("the rejected PATCH changed the row: name %q, description %q, extra vars %s",
				row.Name, row.Description, row.ExtraVars)
		}
	}
	patch := func(t *testing.T, attrs map[string]any) (int, []byte) {
		t.Helper()
		return storedAsSentCall(t, f.router, http.MethodPatch, path, f.owner,
			workflowDocument(t, "ansible-workflows", attrs, nil))
	}

	for _, tc := range notJSONObjects {
		t.Run("extra-vars: "+tc.name, func(t *testing.T) {
			// The description travels with it to show that nothing of a refused document is kept.
			code, body := patch(t, map[string]any{"extra-vars": tc.value, "description": "must not be stored"})
			assertBadRequest(t, code, body, extraVarsDetail)
			unchanged(t)
		})
	}
	for name, value := range map[string]string{"an empty name": "", "a name of spaces": "  "} {
		t.Run(name, func(t *testing.T) {
			code, body := patch(t, map[string]any{"name": value, "description": "must not be stored"})
			assertBadRequest(t, code, body, "name must not be empty")
			unchanged(t)
		})
	}

	t.Run("a name that is null is a name that was not sent", func(t *testing.T) {
		if code, body := patch(t, map[string]any{"name": nil}); code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", code, body)
		}
		unchanged(t)
	})
	t.Run("an object replaces the extra vars", func(t *testing.T) {
		if code, body := patch(t, map[string]any{"extra-vars": `{"region":"us"}`}); code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", code, body)
		}
		var row models.AnsibleWorkflow
		if err := f.db.First(&row, "id = ?", f.workflowID).Error; err != nil {
			t.Fatalf("loading the workflow: %v", err)
		}
		var vars map[string]any
		if err := json.Unmarshal(row.ExtraVars, &vars); err != nil || vars["region"] != "us" {
			t.Errorf("stored extra vars = %s (%v), want {\"region\":\"us\"}", row.ExtraVars, err)
		}
	})
	// The empty string still clears, as #891 established: it is the one value that is not an
	// object and is accepted, because it is how a caller says "no extra vars".
	t.Run("the empty string still clears the extra vars", func(t *testing.T) {
		if code, body := patch(t, map[string]any{"extra-vars": ""}); code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", code, body)
		}
		var row models.AnsibleWorkflow
		if err := f.db.First(&row, "id = ?", f.workflowID).Error; err != nil {
			t.Fatalf("loading the workflow: %v", err)
		}
		if string(row.ExtraVars) != "{}" {
			t.Errorf("stored extra vars = %s, want {}", row.ExtraVars)
		}
	})
}

func TestWorkflowNodeCreate_RefusesWhatItCannotStore(t *testing.T) {
	f := setupWorkflowUpdate(t)
	path := "/api/v2/ansible/workflows/" + f.workflowID.String() + "/nodes"

	// A credential of the workflow's organization, for the one relationship the shared fixture
	// has no row for.
	var workflow models.AnsibleWorkflow
	if err := f.db.First(&workflow, "id = ?", f.workflowID).Error; err != nil {
		t.Fatalf("loading the seeded workflow: %v", err)
	}
	if err := f.db.AutoMigrate(&models.AnsibleCredential{}); err != nil {
		t.Fatalf("migrating the credential table: %v", err)
	}
	credential := &models.AnsibleCredential{
		ID: uuid.New(), OrganizationID: workflow.OrganizationID,
		Name: "wfval-cred-" + uuid.NewString()[:8], Type: models.CredentialTypeSSH,
	}
	if err := f.db.Create(credential).Error; err != nil {
		t.Fatalf("seeding the credential: %v", err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", credential.ID).Delete(&models.AnsibleCredential{}) })

	countNodes := func(t *testing.T) int64 {
		t.Helper()
		var n int64
		if err := f.db.Model(&models.AnsibleWorkflowNode{}).Where("workflow_id = ?", f.workflowID).Count(&n).Error; err != nil {
			t.Fatalf("counting the workflow's nodes: %v", err)
		}
		return n
	}
	before := countNodes(t)
	post := func(t *testing.T, attrs map[string]any, relationships map[string]string) (int, []byte) {
		t.Helper()
		return storedAsSentCall(t, f.router, http.MethodPost, path, f.owner,
			workflowDocument(t, "ansible-workflow-nodes", attrs, relationships))
	}
	jobNode := func(extra map[string]any) map[string]any {
		attrs := map[string]any{"node-type": "job_template", "identifier": "step-" + uuid.NewString()[:8]}
		for name, value := range extra {
			attrs[name] = value
		}
		return attrs
	}

	for _, tc := range notJSONObjects {
		t.Run("extra-vars: "+tc.name, func(t *testing.T) {
			code, body := post(t, jobNode(map[string]any{"extra-vars": tc.value}), map[string]string{"job-template": f.templateID})
			assertBadRequest(t, code, body, extraVarsDetail)
		})
	}
	for _, tc := range []struct{ relationship, detail string }{
		{"job-template", "Invalid job template ID"},
		{"inventory", "Invalid inventory ID"},
		{"credential", "Invalid credential ID"},
	} {
		t.Run("a "+tc.relationship+" identifier that does not parse", func(t *testing.T) {
			code, body := post(t, jobNode(nil), map[string]string{tc.relationship: "not-a-uuid"})
			assertBadRequest(t, code, body, tc.detail)
		})
		t.Run("an empty "+tc.relationship+" identifier", func(t *testing.T) {
			code, body := post(t, jobNode(nil), map[string]string{tc.relationship: ""})
			assertBadRequest(t, code, body, tc.detail)
		})
	}
	if after := countNodes(t); after != before {
		t.Errorf("the rejected requests left %d node(s) behind", after-before)
	}

	t.Run("an object and three real relationships are stored", func(t *testing.T) {
		code, body := post(t, jobNode(map[string]any{"extra-vars": `{"batch":"one"}`}), map[string]string{
			"job-template": f.templateID, "inventory": f.inventoryID, "credential": credential.ID.String(),
		})
		created := createdResource(t, code, body)
		t.Cleanup(func() { f.db.Where("id = ?", created.ID).Delete(&models.AnsibleWorkflowNode{}) })

		var row models.AnsibleWorkflowNode
		if err := f.db.First(&row, "id = ?", created.ID).Error; err != nil {
			t.Fatalf("loading the created node: %v", err)
		}
		var vars map[string]any
		if err := json.Unmarshal(row.ExtraVars, &vars); err != nil || len(vars) != 1 || vars["batch"] != "one" {
			t.Errorf("stored extra vars = %s (%v), want {\"batch\":\"one\"}", row.ExtraVars, err)
		}
		for name, pair := range map[string]struct {
			got  *uuid.UUID
			want string
		}{
			"job template": {row.JobTemplateID, f.templateID},
			"inventory":    {row.InventoryID, f.inventoryID},
			"credential":   {row.CredentialID, credential.ID.String()},
		} {
			if pair.got == nil || pair.got.String() != pair.want {
				t.Errorf("stored %s = %v, want %s", name, pair.got, pair.want)
			}
		}
	})
	t.Run("a node with no extra vars and no relationships is stored", func(t *testing.T) {
		code, body := post(t, map[string]any{"node-type": "approval", "identifier": "gate-" + uuid.NewString()[:8], "extra-vars": ""}, nil)
		created := createdResource(t, code, body)
		t.Cleanup(func() { f.db.Where("id = ?", created.ID).Delete(&models.AnsibleWorkflowNode{}) })

		var row models.AnsibleWorkflowNode
		if err := f.db.First(&row, "id = ?", created.ID).Error; err != nil {
			t.Fatalf("loading the created node: %v", err)
		}
		if string(row.ExtraVars) != "{}" || row.JobTemplateID != nil || row.InventoryID != nil || row.CredentialID != nil {
			t.Errorf("stored node = extra vars %s, job template %v, inventory %v, credential %v; want {} and no relationships",
				row.ExtraVars, row.JobTemplateID, row.InventoryID, row.CredentialID)
		}
	})
}

func TestWorkflowNodeUpdate_RefusesWhatItCannotStore(t *testing.T) {
	f := setupWorkflowUpdate(t)
	path := "/api/v2/ansible/workflow-nodes/" + f.nodeID.String()

	if err := f.db.Model(&models.AnsibleWorkflowNode{}).Where("id = ?", f.nodeID).
		Updates(map[string]any{"extra_vars": `{"batch":"one"}`, "limit": "db"}).Error; err != nil {
		t.Fatalf("seeding the node: %v", err)
	}
	patch := func(t *testing.T, attrs map[string]any) (int, []byte) {
		t.Helper()
		return storedAsSentCall(t, f.router, http.MethodPatch, path, f.owner,
			workflowDocument(t, "ansible-workflow-nodes", attrs, nil))
	}
	stored := func(t *testing.T) (map[string]any, string) {
		t.Helper()
		var row models.AnsibleWorkflowNode
		if err := f.db.First(&row, "id = ?", f.nodeID).Error; err != nil {
			t.Fatalf("loading the node: %v", err)
		}
		var vars map[string]any
		if err := json.Unmarshal(row.ExtraVars, &vars); err != nil {
			t.Fatalf("stored extra vars %s are not a JSON object: %v", row.ExtraVars, err)
		}
		return vars, row.Limit
	}

	for _, tc := range notJSONObjects {
		t.Run("extra-vars: "+tc.name, func(t *testing.T) {
			// The limit travels with it to show that nothing of a refused document is kept.
			code, body := patch(t, map[string]any{"extra-vars": tc.value, "limit": "must-not-be-stored"})
			assertBadRequest(t, code, body, extraVarsDetail)
			if vars, limit := stored(t); len(vars) != 1 || vars["batch"] != "one" || limit != "db" {
				t.Errorf("the rejected PATCH changed the row: extra vars %v, limit %q", vars, limit)
			}
		})
	}

	t.Run("an object replaces the extra vars", func(t *testing.T) {
		if code, body := patch(t, map[string]any{"extra-vars": `{"batch":"two"}`}); code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", code, body)
		}
		if vars, _ := stored(t); len(vars) != 1 || vars["batch"] != "two" {
			t.Errorf("stored extra vars = %v, want {\"batch\":\"two\"}", vars)
		}
	})
	t.Run("the empty string still clears the extra vars", func(t *testing.T) {
		if code, body := patch(t, map[string]any{"extra-vars": ""}); code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", code, body)
		}
		if vars, _ := stored(t); len(vars) != 0 {
			t.Errorf("stored extra vars = %v, want the empty object", vars)
		}
	})
}
