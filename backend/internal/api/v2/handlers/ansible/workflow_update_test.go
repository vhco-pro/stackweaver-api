// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A PATCH on a workflow or on a workflow node changes the attributes the document carries and
// leaves every other one as it is. An attribute sent with its zero value (an empty string, false,
// 0) is a value like any other and is stored.
//
// The defect this test was written against (#891): both handlers bound the create request, whose
// fields are not pointers, and assigned every field. An attribute the caller left out arrived as
// its zero value and was written, so renaming a workflow also cleared its description, its limit
// and its four flags, and sending a node's new position alone cleared its limit, tags and verbosity.
// `extra-vars` had the opposite fault: it was assigned only when non-empty, so it could not be
// cleared at all.
//
// Each case below starts from a row with every attribute set, sends one attribute, and reads the
// row back through the API: the one attribute holds what was sent, the rest hold what they held.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run 'TestWorkflow(Node)?Update'

//go:build integration

package ansible

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type workflowUpdateFixture struct {
	router     *gin.Engine
	db         *gorm.DB
	owner      uuid.UUID
	workflowID uuid.UUID
	nodeID     uuid.UUID

	// What a create document can name: the organization the workflow lives in, and a project, an
	// inventory and a job template of that organization.
	orgName     string
	projectID   string
	inventoryID string
	templateID  string
}

// setupWorkflowUpdate seeds one workflow with one approval node in org A of the shared Ansible
// fixture and mounts the workflow handlers the way a JWT caller reaches them.
func setupWorkflowUpdate(t *testing.T) *workflowUpdateFixture {
	t.Helper()
	f := setupAnsibleSubResourceAuthz(t) // org A with an owner who administers its project
	db := f.db
	if err := db.AutoMigrate(&models.AnsibleWorkflow{}, &models.AnsibleWorkflowNode{}, &models.AnsibleWorkflowEdge{}); err != nil {
		t.Fatalf("migrating the workflow tables: %v", err)
	}

	var template models.AnsibleJobTemplate
	if err := db.First(&template, "id = ?", f.templateID).Error; err != nil {
		t.Fatalf("loading the fixture's job template: %v", err)
	}
	var project models.Project
	if err := db.First(&project, "id = ?", template.ProjectID).Error; err != nil {
		t.Fatalf("loading the fixture's project: %v", err)
	}

	workflow := &models.AnsibleWorkflow{
		ID: uuid.New(), OrganizationID: project.OrganizationID, ProjectID: project.ID,
		Name: "wfupd-" + uuid.NewString()[:8],
	}
	if err := db.Create(workflow).Error; err != nil {
		t.Fatalf("seeding the workflow: %v", err)
	}
	// An approval node needs no job template, so nothing else has to exist for it.
	node := &models.AnsibleWorkflowNode{
		ID: uuid.New(), WorkflowID: workflow.ID, NodeType: models.WorkflowNodeTypeApproval, Identifier: "gate",
	}
	if err := db.Create(node).Error; err != nil {
		t.Fatalf("seeding the workflow node: %v", err)
	}
	// Registered after the shared fixture's cleanup, so it runs before it.
	t.Cleanup(func() {
		db.Where("id = ?", node.ID).Delete(&models.AnsibleWorkflowNode{})
		db.Where("id = ?", workflow.ID).Delete(&models.AnsibleWorkflow{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	workflowRepo := repository.NewAnsibleWorkflowRepository(db)
	h := NewWorkflowHandler(
		workflowRepo, orgRepo, projectRepo,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), projectRepo),
		// The engine checks what a create names; nothing here launches, so it needs no services.
		ansiblesvc.NewWorkflowEngineService(workflowRepo, nil, nil, nil),
	)
	router := storedAsSentRouter()
	router.POST("/api/v2/organizations/:name/ansible/workflows", h.Create)
	router.GET("/api/v2/ansible/workflows/:id", h.Get)
	router.PATCH("/api/v2/ansible/workflows/:id", h.Update)
	router.POST("/api/v2/ansible/workflows/:id/nodes", h.CreateNode)
	router.GET("/api/v2/ansible/workflows/:id/nodes", h.ListNodes)
	router.PATCH("/api/v2/ansible/workflow-nodes/:id", h.UpdateNode)

	var org models.Organization
	if err := db.First(&org, "id = ?", project.OrganizationID).Error; err != nil {
		t.Fatalf("loading the fixture's organization: %v", err)
	}

	return &workflowUpdateFixture{
		router: router, db: db, owner: f.owner.ID, workflowID: workflow.ID, nodeID: node.ID,
		orgName: org.Name, projectID: project.ID.String(), inventoryID: f.inventoryID, templateID: f.templateID,
	}
}

// patch sends one PATCH document carrying attrs and fails the test unless it answers 200.
func (f *workflowUpdateFixture) patch(t *testing.T, path, resourceType string, attrs map[string]any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"data": map[string]any{"type": resourceType, "attributes": attrs}})
	if err != nil {
		t.Fatalf("marshalling the PATCH document: %v", err)
	}
	if code, body := storedAsSentCall(t, f.router, http.MethodPatch, path, f.owner, string(raw)); code != http.StatusOK {
		t.Fatalf("PATCH %s = %d, want 200 (%s)", path, code, body)
	}
}

// pickAttributes reduces a resource's attributes to the named ones. `extra-vars` travels as a
// JSON string whose spacing the database is free to change, so it is compared decoded.
func pickAttributes(t *testing.T, attrs map[string]any, names []string) map[string]any {
	t.Helper()
	out := make(map[string]any, len(names))
	for _, name := range names {
		value, present := attrs[name]
		if !present {
			t.Errorf("the resource has no %q attribute", name)
			continue
		}
		if name == "extra-vars" {
			text, _ := value.(string)
			var decoded any
			if err := json.Unmarshal([]byte(text), &decoded); err != nil {
				t.Errorf("extra-vars %q is not JSON: %v", text, err)
			}
			value = decoded
		}
		out[name] = value
	}
	return out
}

// attributeDiff names every attribute whose value in got is not the one in want, one per line
// and in a stable order. It is empty when the two agree.
func attributeDiff(want, got map[string]any) string {
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(want)) {
		if !reflect.DeepEqual(got[name], want[name]) {
			fmt.Fprintf(&b, "  %s: got %#v, want %#v\n", name, got[name], want[name])
		}
	}
	return b.String()
}

// attributeCase is one PATCH that carries a single attribute.
type attributeCase struct {
	attr string
	sent any // the value in the document
	want any // what the attribute reads as afterwards
	// rejected marks a value the handler refuses with a 400, leaving the row as it was.
	rejected bool
}

func TestWorkflowUpdate_OmittedAttributesAreLeftAlone(t *testing.T) {
	f := setupWorkflowUpdate(t)
	path := "/api/v2/ansible/workflows/" + f.workflowID.String()

	// Every attribute set to something other than its zero value.
	stored := map[string]any{
		"name":                    "nightly-rollout",
		"description":             "rolls the fleet every night",
		"allow-simultaneous":      true,
		"ask-variables-on-launch": true,
		"ask-inventory-on-launch": true,
		"ask-limit-on-launch":     true,
		"extra-vars":              map[string]any{"region": "eu"},
		"limit":                   "web",
		"survey-enabled":          true,
	}
	names := make([]string, 0, len(stored))
	for name := range stored {
		names = append(names, name)
	}
	reset := func(t *testing.T) {
		t.Helper()
		if err := f.db.Model(&models.AnsibleWorkflow{}).Where("id = ?", f.workflowID).Updates(map[string]any{
			"name":                    "nightly-rollout",
			"description":             "rolls the fleet every night",
			"allow_simultaneous":      true,
			"ask_variables_on_launch": true,
			"ask_inventory_on_launch": true,
			"ask_limit_on_launch":     true,
			"extra_vars":              datatypes.JSON(`{"region":"eu"}`),
			"limit":                   "web",
			"survey_enabled":          true,
		}).Error; err != nil {
			t.Fatalf("resetting the workflow: %v", err)
		}
	}
	read := func(t *testing.T) map[string]any {
		t.Helper()
		code, body := storedAsSentCall(t, f.router, http.MethodGet, path, f.owner, "")
		if code != http.StatusOK {
			t.Fatalf("reading the workflow = %d, want 200 (%s)", code, body)
		}
		var doc struct {
			Data storedAsSentResource `json:"data"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("decoding the workflow: %v\n%s", err, body)
		}
		return pickAttributes(t, doc.Data.Attributes, names)
	}

	t.Run("a document with no attributes changes nothing", func(t *testing.T) {
		reset(t)
		f.patch(t, path, "ansible-workflows", map[string]any{})
		if diff := attributeDiff(stored, read(t)); diff != "" {
			t.Errorf("the workflow changed:\n%s", diff)
		}
	})

	// One attribute per case, sent with its zero value: the hardest value to tell from absent.
	// Cleared extra vars read as the empty object, the value a workflow created without any has.
	//
	// The name is the one attribute whose zero value is not stored. This case used to expect the
	// empty string to be written, because it recorded what the handler did so that the #891 fix
	// could be shown to change nothing else; it was never a statement that a nameless workflow
	// is wanted. Since #899 a PATCH that carries an empty name is a 400 and the name stays.
	zeroes := []attributeCase{
		{attr: "name", sent: "", want: "nightly-rollout", rejected: true},
		{attr: "description", sent: "", want: ""},
		{attr: "allow-simultaneous", sent: false, want: false},
		{attr: "ask-variables-on-launch", sent: false, want: false},
		{attr: "ask-inventory-on-launch", sent: false, want: false},
		{attr: "ask-limit-on-launch", sent: false, want: false},
		{attr: "extra-vars", sent: "", want: map[string]any{}},
		{attr: "limit", sent: "", want: ""},
		{attr: "survey-enabled", sent: false, want: false},
	}
	for _, tc := range zeroes {
		t.Run(tc.attr+" alone, sent as its zero value", func(t *testing.T) {
			reset(t)
			if tc.rejected {
				code, body := storedAsSentCall(t, f.router, http.MethodPatch, path, f.owner,
					workflowDocument(t, "ansible-workflows", map[string]any{tc.attr: tc.sent}, nil))
				assertBadRequest(t, code, body, "name must not be empty")
			} else {
				f.patch(t, path, "ansible-workflows", map[string]any{tc.attr: tc.sent})
			}

			want := make(map[string]any, len(stored))
			for name, value := range stored {
				want[name] = value
			}
			want[tc.attr] = tc.want
			if diff := attributeDiff(want, read(t)); diff != "" {
				t.Errorf("only %s should have changed:\n%s", tc.attr, diff)
			}
		})
	}

	t.Run("every attribute sent with a new value is stored", func(t *testing.T) {
		reset(t)
		f.patch(t, path, "ansible-workflows", map[string]any{
			"name":                    "weekly-rollout",
			"description":             "rolls the fleet every week",
			"allow-simultaneous":      false,
			"ask-variables-on-launch": false,
			"ask-inventory-on-launch": false,
			"ask-limit-on-launch":     false,
			"extra-vars":              `{"region":"us"}`,
			"limit":                   "db",
			"survey-enabled":          false,
		})
		want := map[string]any{
			"name":                    "weekly-rollout",
			"description":             "rolls the fleet every week",
			"allow-simultaneous":      false,
			"ask-variables-on-launch": false,
			"ask-inventory-on-launch": false,
			"ask-limit-on-launch":     false,
			"extra-vars":              map[string]any{"region": "us"},
			"limit":                   "db",
			"survey-enabled":          false,
		}
		if diff := attributeDiff(want, read(t)); diff != "" {
			t.Errorf("the workflow does not hold what was sent:\n%s", diff)
		}
	})
}

func TestWorkflowNodeUpdate_OmittedAttributesAreLeftAlone(t *testing.T) {
	f := setupWorkflowUpdate(t)
	path := "/api/v2/ansible/workflow-nodes/" + f.nodeID.String()

	// Every attribute set to something other than its zero value. The last four are not
	// writable through PATCH; they are listed so that the test sees them survive one.
	stored := map[string]any{
		"position-x":                120.5,
		"position-y":                80.25,
		"extra-vars":                map[string]any{"batch": "one"},
		"limit":                     "db",
		"tags":                      "deploy",
		"skip-tags":                 "slow",
		"verbosity":                 float64(3),
		"all-parents-must-converge": true,
		"node-type":                 "approval",
		"identifier":                "gate",
		"approval-timeout":          float64(600),
		"approval-message":          "ship it?",
	}
	names := make([]string, 0, len(stored))
	for name := range stored {
		names = append(names, name)
	}
	reset := func(t *testing.T) {
		t.Helper()
		if err := f.db.Model(&models.AnsibleWorkflowNode{}).Where("id = ?", f.nodeID).Updates(map[string]any{
			"position_x":                120.5,
			"position_y":                80.25,
			"extra_vars":                datatypes.JSON(`{"batch":"one"}`),
			"limit":                     "db",
			"tags":                      "deploy",
			"skip_tags":                 "slow",
			"verbosity":                 3,
			"all_parents_must_converge": true,
			"approval_timeout":          600,
			"approval_message":          "ship it?",
		}).Error; err != nil {
			t.Fatalf("resetting the node: %v", err)
		}
	}
	read := func(t *testing.T) map[string]any {
		t.Helper()
		code, body := storedAsSentCall(t, f.router, http.MethodGet,
			"/api/v2/ansible/workflows/"+f.workflowID.String()+"/nodes", f.owner, "")
		if code != http.StatusOK {
			t.Fatalf("listing the workflow's nodes = %d, want 200 (%s)", code, body)
		}
		var doc struct {
			Data []storedAsSentResource `json:"data"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("decoding the nodes: %v\n%s", err, body)
		}
		for _, node := range doc.Data {
			if node.ID == f.nodeID.String() {
				return pickAttributes(t, node.Attributes, names)
			}
		}
		t.Fatalf("the node is not in its workflow's node list: %s", body)
		return nil
	}

	t.Run("a document with no attributes changes nothing", func(t *testing.T) {
		reset(t)
		f.patch(t, path, "ansible-workflow-nodes", map[string]any{})
		if diff := attributeDiff(stored, read(t)); diff != "" {
			t.Errorf("the node changed:\n%s", diff)
		}
	})

	zeroes := []attributeCase{
		{attr: "position-x", sent: 0, want: float64(0)},
		{attr: "position-y", sent: 0, want: float64(0)},
		{attr: "extra-vars", sent: "", want: map[string]any{}},
		{attr: "limit", sent: "", want: ""},
		{attr: "tags", sent: "", want: ""},
		{attr: "skip-tags", sent: "", want: ""},
		{attr: "verbosity", sent: 0, want: float64(0)},
		{attr: "all-parents-must-converge", sent: false, want: false},
	}
	for _, tc := range zeroes {
		t.Run(tc.attr+" alone, sent as its zero value", func(t *testing.T) {
			reset(t)
			f.patch(t, path, "ansible-workflow-nodes", map[string]any{tc.attr: tc.sent})

			want := make(map[string]any, len(stored))
			for name, value := range stored {
				want[name] = value
			}
			want[tc.attr] = tc.want
			if diff := attributeDiff(want, read(t)); diff != "" {
				t.Errorf("only %s should have changed:\n%s", tc.attr, diff)
			}
		})
	}

	// The smallest real update: a caller that moves a node sends its two coordinates only.
	t.Run("a move sends the position only", func(t *testing.T) {
		reset(t)
		f.patch(t, path, "ansible-workflow-nodes", map[string]any{"position-x": 300, "position-y": 40})

		want := make(map[string]any, len(stored))
		for name, value := range stored {
			want[name] = value
		}
		want["position-x"], want["position-y"] = float64(300), float64(40)
		if diff := attributeDiff(want, read(t)); diff != "" {
			t.Errorf("only the position should have changed:\n%s", diff)
		}
	})

	t.Run("every writable attribute sent with a new value is stored", func(t *testing.T) {
		reset(t)
		f.patch(t, path, "ansible-workflow-nodes", map[string]any{
			"position-x":                10,
			"position-y":                20,
			"extra-vars":                `{"batch":"two"}`,
			"limit":                     "web",
			"tags":                      "config",
			"skip-tags":                 "backup",
			"verbosity":                 1,
			"all-parents-must-converge": false,
		})
		want := make(map[string]any, len(stored))
		for name, value := range stored {
			want[name] = value
		}
		for name, value := range map[string]any{
			"position-x":                float64(10),
			"position-y":                float64(20),
			"extra-vars":                map[string]any{"batch": "two"},
			"limit":                     "web",
			"tags":                      "config",
			"skip-tags":                 "backup",
			"verbosity":                 float64(1),
			"all-parents-must-converge": false,
		} {
			want[name] = value
		}
		if diff := attributeDiff(want, read(t)); diff != "" {
			t.Errorf("the node does not hold what was sent:\n%s", diff)
		}
	})
}
