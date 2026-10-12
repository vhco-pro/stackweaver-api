// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The body of a workflow launch is optional: no body, or an object without `extra_vars`, starts
// a run with the workflow's own variables, and `extra_vars` is merged over them. A body that is
// there and cannot be read is a 400 and starts nothing.
//
// The defect this test was written against (#890): the handler threw the bind error away, so a
// body cut short in transit, or one whose `extra_vars` was not an object, started a run without
// the variables its sender asked for and answered 201.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestLaunchWorkflow

//go:build integration

package ansible

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/datatypes"
)

func TestLaunchWorkflow_UnreadableBodyIsRefused(t *testing.T) {
	f := setupAnsibleSubResourceAuthz(t) // org A with an owner who administers its project
	db := f.db
	if err := db.AutoMigrate(
		&models.AnsibleWorkflow{}, &models.AnsibleWorkflowNode{}, &models.AnsibleWorkflowEdge{},
		&models.AnsibleWorkflowJob{}, &models.AnsibleWorkflowNodeJob{}, &models.AnsibleJob{},
	); err != nil {
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

	// Simultaneous runs are allowed so that each case can start its own. The one node is an
	// approval gate: a run reaches it and waits, so no job is ever dispatched.
	workflow := &models.AnsibleWorkflow{
		ID: uuid.New(), OrganizationID: project.OrganizationID, ProjectID: project.ID,
		Name: "wflaunch-" + uuid.NewString()[:8], AllowSimultaneous: true,
		ExtraVars: datatypes.JSON(`{"from_workflow":"yes","shared":"workflow"}`),
	}
	if err := db.Create(workflow).Error; err != nil {
		t.Fatalf("seeding the workflow: %v", err)
	}
	node := &models.AnsibleWorkflowNode{
		ID: uuid.New(), WorkflowID: workflow.ID, NodeType: models.WorkflowNodeTypeApproval, Identifier: "gate",
	}
	if err := db.Create(node).Error; err != nil {
		t.Fatalf("seeding the workflow node: %v", err)
	}
	// Registered after the shared fixture's cleanup, so it runs before it. Children first.
	t.Cleanup(func() {
		db.Where("node_id = ?", node.ID).Delete(&models.AnsibleWorkflowNodeJob{})
		db.Where("workflow_id = ?", workflow.ID).Delete(&models.AnsibleWorkflowJob{})
		db.Where("id = ?", node.ID).Delete(&models.AnsibleWorkflowNode{})
		db.Where("id = ?", workflow.ID).Delete(&models.AnsibleWorkflow{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	workflowRepo := repository.NewAnsibleWorkflowRepository(db)
	jobRepo := repository.NewAnsibleJobRepository(db)
	// No queue: nothing here may dispatch a job.
	jobService := ansiblesvc.NewJobService(
		jobRepo, repository.NewAnsiblePlaybookRepository(db), f.inventoryRepo,
		repository.NewAnsibleJobTemplateRepository(db), projectRepo, nil,
	)
	h := NewWorkflowHandler(
		workflowRepo, orgRepo, projectRepo,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), projectRepo),
		ansiblesvc.NewWorkflowEngineService(workflowRepo, jobRepo, jobService, nil),
	)
	router := storedAsSentRouter()
	router.POST("/api/v2/ansible/workflows/:id/launch", h.LaunchWorkflow)

	launchPath := "/api/v2/ansible/workflows/" + workflow.ID.String() + "/launch"
	runCount := func(t *testing.T) int64 {
		t.Helper()
		var n int64
		if err := db.Model(&models.AnsibleWorkflowJob{}).Where("workflow_id = ?", workflow.ID).Count(&n).Error; err != nil {
			t.Fatalf("counting the workflow's runs: %v", err)
		}
		return n
	}
	workflowVars := map[string]any{"from_workflow": "yes", "shared": "workflow"}

	accepted := []struct {
		name     string
		body     string
		wantVars map[string]any // the run's extra vars as stored
	}{
		{"no body", "", workflowVars},
		{"a body of whitespace", " \n", workflowVars},
		{"an empty object", "{}", workflowVars},
		{
			"extra_vars are merged over the workflow's",
			`{"extra_vars":{"shared":"launch","from_launch":"yes"}}`,
			map[string]any{"from_workflow": "yes", "shared": "launch", "from_launch": "yes"},
		},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			code, body := storedAsSentCall(t, router, http.MethodPost, launchPath, f.owner.ID, tc.body)
			if code != http.StatusCreated {
				t.Fatalf("launch = %d, want 201 (%s)", code, body)
			}
			var created struct {
				Data storedAsSentResource `json:"data"`
			}
			if err := json.Unmarshal(body, &created); err != nil {
				t.Fatalf("decoding the launch response: %v\n%s", err, body)
			}
			var run models.AnsibleWorkflowJob
			if err := db.First(&run, "id = ?", created.Data.ID).Error; err != nil {
				t.Fatalf("reading the run back: %v", err)
			}
			var gotVars map[string]any
			if err := json.Unmarshal(run.ExtraVars, &gotVars); err != nil {
				t.Fatalf("the run's extra vars are not a JSON object: %v (%s)", err, run.ExtraVars)
			}
			if !reflect.DeepEqual(gotVars, tc.wantVars) {
				t.Errorf("the run does not carry the variables the launch asked for\n got: %v\nwant: %v", gotVars, tc.wantVars)
			}
		})
	}

	refused := []struct {
		name string
		body string
	}{
		{"a body that is not JSON", `{"extra_vars":`},
		{"a body that is not an object", `[]`},
		{"extra_vars that is not an object", `{"extra_vars":"region=eu"}`},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			before := runCount(t)
			code, body := storedAsSentCall(t, router, http.MethodPost, launchPath, f.owner.ID, tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("launch = %d, want 400 (%s)", code, body)
			}
			var doc struct {
				Errors []struct {
					Status string `json:"status"`
					Title  string `json:"title"`
					Detail string `json:"detail"`
				} `json:"errors"`
			}
			if err := json.Unmarshal(body, &doc); err != nil || len(doc.Errors) != 1 {
				t.Fatalf("the response is not a JSON:API errors document with one error: %v\n%s", err, body)
			}
			if got := doc.Errors[0]; got.Status != "400" || got.Title != "Bad Request" || got.Detail == "" {
				t.Errorf("error = %+v, want status 400, title Bad Request and a detail", got)
			}
			if after := runCount(t); after != before {
				t.Errorf("a refused launch started %d run(s)", after-before)
			}
		})
	}
}
