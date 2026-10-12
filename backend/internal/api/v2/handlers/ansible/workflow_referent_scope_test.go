// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a workflow, a workflow node and a workflow edge may name (#905): a project, an inventory,
// a job template and a credential of the workflow's own organization, and nodes of the workflow
// itself. Anything else is a 400 in the JSON:API errors document, and a row that exists in
// another organization gets the very same bytes as an identifier that names nothing, so the
// answer never confirms that the row is there.
//
// The defect this test was written against: the handlers stored the identifiers as sent. The
// permission check they make is about the workflow, and nothing asked which organization the
// named row belongs to, so a workflow of one organization could name a job template of another
// and a launch ran it there. An identifier that parsed and named no row failed at the foreign
// key and was answered with a 500; an edge discarded the parse error on its two node
// identifiers; `node-type` and `condition` were stored whatever they held.
//
// The refusals are driven by a caller who administers both organizations, so that only the
// organization boundary can be what refuses them. The last test is the same boundary seen by a
// member of one organization only.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestWorkflowReferents

//go:build integration

package ansible

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/datatypes"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// referentScopeFixture is two organizations that each own one of everything a workflow can
// name, a workflow with two nodes in each, and two callers.
type referentScopeFixture struct {
	router *gin.Engine
	db     *gorm.DB

	admin  uuid.UUID // owner of both organizations
	member uuid.UUID // owner of the first organization, no part in the second

	orgName  string
	orgID    uuid.UUID
	workflow uuid.UUID // of the first organization
	nodeA    string    // two approval nodes of that workflow
	nodeB    string

	// What the first organization owns.
	project, inventory, template, credential string
	siblingNode                              string // a node of another workflow of the first organization

	// What the second organization owns.
	otherProjectID                                         uuid.UUID
	otherProject, otherInventory, otherTemplate, otherCred string
	otherNode                                              string // a node of the second organization's workflow
}

func setupReferentScope(t *testing.T) *referentScopeFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connecting to the test database: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.OrganizationMember{},
		&models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{}, &models.TeamProjectAccess{},
		&models.Project{}, &models.AnsibleInventory{}, &models.AnsibleCredential{},
		&models.AnsiblePlaybook{}, &models.AnsibleJobTemplate{}, &models.AnsibleJob{},
		&models.AnsibleWorkflow{}, &models.AnsibleWorkflowNode{}, &models.AnsibleWorkflowEdge{},
		&models.AnsibleWorkflowJob{}, &models.AnsibleWorkflowNodeJob{},
	); err != nil {
		t.Fatalf("migrating the tables: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "wfref-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "wfref-b-" + sfx}
	admin := &models.User{ID: uuid.New(), ZitadelSubject: "wfref-adm-" + sfx, Email: "wfref-adm-" + sfx + "@test.local"}
	member := &models.User{ID: uuid.New(), ZitadelSubject: "wfref-mem-" + sfx, Email: "wfref-mem-" + sfx + "@test.local"}
	teamA := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	teamB := &models.Team{ID: uuid.New(), OrganizationID: orgB.ID, Name: "owners"}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "wfref-proj-" + sfx}
	projB := &models.Project{ID: uuid.New(), OrganizationID: orgB.ID, Name: "wfref-proj-" + sfx}

	invA := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: orgA.ID, Name: "wfref-inv-" + sfx, Type: models.InventoryTypeStatic}
	invB := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: orgB.ID, Name: "wfref-inv-" + sfx, Type: models.InventoryTypeStatic}
	credA := &models.AnsibleCredential{ID: uuid.New(), OrganizationID: orgA.ID, Name: "wfref-cred-" + sfx, Type: models.CredentialTypeSSH}
	credB := &models.AnsibleCredential{ID: uuid.New(), OrganizationID: orgB.ID, Name: "wfref-cred-" + sfx, Type: models.CredentialTypeSSH}
	pbA := &models.AnsiblePlaybook{ID: uuid.New(), ProjectID: projA.ID, Name: "wfref-pb-" + sfx, PlaybookPath: "site.yml", SourceMode: "cached"}
	pbB := &models.AnsiblePlaybook{ID: uuid.New(), ProjectID: projB.ID, Name: "wfref-pb-" + sfx, PlaybookPath: "site.yml", SourceMode: "cached"}
	tmplA := &models.AnsibleJobTemplate{ID: uuid.New(), ProjectID: projA.ID, PlaybookID: pbA.ID, InventoryID: invA.ID, Name: "wfref-tmpl-" + sfx}
	tmplB := &models.AnsibleJobTemplate{ID: uuid.New(), ProjectID: projB.ID, PlaybookID: pbB.ID, InventoryID: invB.ID, Name: "wfref-tmpl-b-" + sfx}

	// Simultaneous runs are allowed so that a test can launch the workflow more than once.
	wfA := &models.AnsibleWorkflow{
		ID: uuid.New(), OrganizationID: orgA.ID, ProjectID: projA.ID, Name: "wfref-wf-" + sfx,
		AllowSimultaneous: true, ExtraVars: datatypes.JSON(`{"set_by":"the first organization"}`),
	}
	wfSibling := &models.AnsibleWorkflow{ID: uuid.New(), OrganizationID: orgA.ID, ProjectID: projA.ID, Name: "wfref-wf-sibling-" + sfx}
	wfB := &models.AnsibleWorkflow{ID: uuid.New(), OrganizationID: orgB.ID, ProjectID: projB.ID, Name: "wfref-wf-b-" + sfx}
	approval := func(workflowID uuid.UUID, identifier string) *models.AnsibleWorkflowNode {
		return &models.AnsibleWorkflowNode{ID: uuid.New(), WorkflowID: workflowID, NodeType: models.WorkflowNodeTypeApproval, Identifier: identifier}
	}
	nodeA, nodeB := approval(wfA.ID, "gate-a"), approval(wfA.ID, "gate-b")
	siblingNode, otherNode := approval(wfSibling.ID, "gate"), approval(wfB.ID, "gate")

	adminAccess := "admin"
	for _, row := range []any{
		orgA, orgB, admin, member, teamA, teamB, projA, projB,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: admin.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: admin.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: member.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: teamA.ID, UserID: admin.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: teamB.ID, UserID: admin.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: teamA.ID, UserID: member.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: teamA.ID, ProjectID: projA.ID, Access: &adminAccess},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: teamB.ID, ProjectID: projB.ID, Access: &adminAccess},
		invA, invB, credA, credB, pbA, pbB, tmplA, tmplB,
		wfA, wfSibling, wfB, nodeA, nodeB, siblingNode, otherNode,
	} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}

	orgIDs := []uuid.UUID{orgA.ID, orgB.ID}
	projectIDs := []uuid.UUID{projA.ID, projB.ID}
	teamIDs := []uuid.UUID{teamA.ID, teamB.ID}
	t.Cleanup(func() {
		// Children before parents (foreign-key order), every statement scoped to this run's rows.
		// A workflow the API was wrongly allowed to create in one organization with the other's
		// project still carries one of the two organization ids, so it is found here too.
		workflowIDs := db.Model(&models.AnsibleWorkflow{}).Select("id").Where("organization_id IN ?", orgIDs)
		db.Where("workflow_job_id IN (?)", db.Model(&models.AnsibleWorkflowJob{}).Select("id").Where("workflow_id IN (?)", workflowIDs)).
			Delete(&models.AnsibleWorkflowNodeJob{})
		db.Where("workflow_id IN (?)", workflowIDs).Delete(&models.AnsibleWorkflowJob{})
		db.Where("project_id IN ?", projectIDs).Delete(&models.AnsibleJob{})
		db.Where("workflow_id IN (?)", workflowIDs).Delete(&models.AnsibleWorkflowEdge{})
		db.Where("workflow_id IN (?)", workflowIDs).Delete(&models.AnsibleWorkflowNode{})
		db.Where("organization_id IN ?", orgIDs).Delete(&models.AnsibleWorkflow{})
		db.Where("id IN ?", []uuid.UUID{tmplA.ID, tmplB.ID}).Delete(&models.AnsibleJobTemplate{})
		db.Where("id IN ?", []uuid.UUID{pbA.ID, pbB.ID}).Delete(&models.AnsiblePlaybook{})
		db.Where("id IN ?", []uuid.UUID{credA.ID, credB.ID}).Delete(&models.AnsibleCredential{})
		db.Where("id IN ?", []uuid.UUID{invA.ID, invB.ID}).Delete(&models.AnsibleInventory{})
		db.Where("team_id IN ?", teamIDs).Delete(&models.TeamProjectAccess{})
		db.Where("team_id IN ?", teamIDs).Delete(&models.TeamMember{})
		db.Where("id IN ?", teamIDs).Delete(&models.Team{})
		db.Where("id IN ?", projectIDs).Delete(&models.Project{})
		db.Where("organization_id IN ?", orgIDs).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", orgIDs).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{admin.ID, member.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	workflowRepo := repository.NewAnsibleWorkflowRepository(db)
	jobRepo := repository.NewAnsibleJobRepository(db)
	// No queue: a job a launch creates is never dispatched.
	jobService := ansiblesvc.NewJobService(
		jobRepo, repository.NewAnsiblePlaybookRepository(db), repository.NewAnsibleInventoryRepository(db),
		repository.NewAnsibleJobTemplateRepository(db), projectRepo, nil,
	)
	h := NewWorkflowHandler(
		workflowRepo, orgRepo, projectRepo,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), projectRepo),
		ansiblesvc.NewWorkflowEngineService(workflowRepo, jobRepo, jobService, nil),
	)
	router := storedAsSentRouter()
	router.POST("/api/v2/organizations/:name/ansible/workflows", h.Create)
	router.PATCH("/api/v2/ansible/workflows/:id", h.Update)
	router.POST("/api/v2/ansible/workflows/:id/nodes", h.CreateNode)
	router.PATCH("/api/v2/ansible/workflow-nodes/:id", h.UpdateNode)
	router.POST("/api/v2/ansible/workflows/:id/edges", h.CreateEdge)
	router.POST("/api/v2/ansible/workflows/:id/launch", h.LaunchWorkflow)

	return &referentScopeFixture{
		router: router, db: db, admin: admin.ID, member: member.ID,
		orgName: orgA.Name, orgID: orgA.ID, workflow: wfA.ID,
		nodeA: nodeA.ID.String(), nodeB: nodeB.ID.String(),
		project: projA.ID.String(), inventory: invA.ID.String(), template: tmplA.ID.String(), credential: credA.ID.String(),
		siblingNode:    siblingNode.ID.String(),
		otherProjectID: projB.ID,
		otherProject:   projB.ID.String(), otherInventory: invB.ID.String(), otherTemplate: tmplB.ID.String(), otherCred: credB.ID.String(),
		otherNode: otherNode.ID.String(),
	}
}

// count is how a refusal is shown to have written nothing.
func (f *referentScopeFixture) count(t *testing.T, model any, where string, arg any) int64 {
	t.Helper()
	var n int64
	if err := f.db.Model(model).Where(where, arg).Count(&n).Error; err != nil {
		t.Fatalf("counting %T rows: %v", model, err)
	}
	return n
}

// referentWrite is one of the three writes that store a reference: where it goes, the document
// around the relationship under test, and the rows it would add to.
type referentWrite struct {
	path          string
	resourceType  string
	attrs         func() map[string]any
	relationships map[string]string // the valid relationships the document needs beside the one under test
	rows          func(t *testing.T) int64
}

func (f *referentScopeFixture) writes() (workflow, node, edge referentWrite) {
	workflow = referentWrite{
		path:         "/api/v2/organizations/" + f.orgName + "/ansible/workflows",
		resourceType: "ansible-workflows",
		attrs:        func() map[string]any { return map[string]any{"name": "wfref-" + uuid.NewString()[:8]} },
		// The fixture's organization has no project named "default" to fall back on.
		relationships: map[string]string{"project": f.project},
		rows: func(t *testing.T) int64 {
			return f.count(t, &models.AnsibleWorkflow{}, "organization_id = ?", f.orgID)
		},
	}
	node = referentWrite{
		path:         "/api/v2/ansible/workflows/" + f.workflow.String() + "/nodes",
		resourceType: "ansible-workflow-nodes",
		attrs: func() map[string]any {
			return map[string]any{"node-type": "job_template", "identifier": "step-" + uuid.NewString()[:8]}
		},
		rows: func(t *testing.T) int64 {
			return f.count(t, &models.AnsibleWorkflowNode{}, "workflow_id = ?", f.workflow)
		},
	}
	edge = referentWrite{
		path:         "/api/v2/ansible/workflows/" + f.workflow.String() + "/edges",
		resourceType: "ansible-workflow-edges",
		attrs:        func() map[string]any { return map[string]any{"condition": "on_success"} },
		rows: func(t *testing.T) int64 {
			return f.count(t, &models.AnsibleWorkflowEdge{}, "workflow_id = ?", f.workflow)
		},
	}
	return workflow, node, edge
}

// send posts the write's document with one relationship set to id, beside the valid ones.
func (f *referentScopeFixture) send(t *testing.T, w referentWrite, relationship, id string) (int, []byte) {
	t.Helper()
	relationships := map[string]string{relationship: id}
	for name, valid := range w.relationships {
		if name != relationship {
			relationships[name] = valid
		}
	}
	return storedAsSentCall(t, f.router, http.MethodPost, w.path, f.admin,
		workflowDocument(t, w.resourceType, w.attrs(), relationships))
}

func TestWorkflowReferents_AnotherOrganizationReadsAsNotFound(t *testing.T) {
	f := setupReferentScope(t)
	workflow, node, edge := f.writes()
	edge.relationships = map[string]string{"source-node": f.nodeA, "target-node": f.nodeB}

	cases := []struct {
		name         string
		write        referentWrite
		relationship string
		foreign      string // a real row the workflow may not name
		detail       string
	}{
		{"a workflow naming an inventory of another organization", workflow, "inventory", f.otherInventory, "inventory not found"},
		{"a workflow naming a project of another organization", workflow, "project", f.otherProject, "project not found"},
		{"a node naming a job template of another organization", node, "job-template", f.otherTemplate, "job template not found"},
		{"a node naming an inventory of another organization", node, "inventory", f.otherInventory, "inventory not found"},
		{"a node naming a credential of another organization", node, "credential", f.otherCred, "credential not found"},
		{"an edge from a node of another organization", edge, "source-node", f.otherNode, "source node not found"},
		{"an edge to a node of another organization", edge, "target-node", f.otherNode, "target node not found"},
		// The two ends of an edge belong to the workflow in the URL, not merely to its organization.
		{"an edge from a node of another workflow", edge, "source-node", f.siblingNode, "source node not found"},
		{"an edge to a node of another workflow", edge, "target-node", f.siblingNode, "target node not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.write.rows(t)

			code, body := f.send(t, tc.write, tc.relationship, tc.foreign)
			assertBadRequest(t, code, body, tc.detail)

			// The same request naming nothing at all: the two answers must not differ by a byte,
			// or the difference tells the caller that the first identifier is a real row.
			missingCode, missingBody := f.send(t, tc.write, tc.relationship, uuid.NewString())
			assertBadRequest(t, missingCode, missingBody, tc.detail)
			if code != missingCode || !bytes.Equal(body, missingBody) {
				t.Errorf("a row of another organization and a row that does not exist are answered differently:\n  other organization: %d %s\n  does not exist:     %d %s",
					code, body, missingCode, missingBody)
			}

			if after := tc.write.rows(t); after != before {
				t.Errorf("the refused requests left %d row(s) behind", after-before)
			}
		})
	}
}

func TestWorkflowReferents_OwnOrganizationIsAccepted(t *testing.T) {
	f := setupReferentScope(t)
	workflow, node, edge := f.writes()

	t.Run("a workflow naming its organization's project and inventory", func(t *testing.T) {
		code, body := storedAsSentCall(t, f.router, http.MethodPost, workflow.path, f.admin,
			workflowDocument(t, workflow.resourceType, workflow.attrs(), map[string]string{"project": f.project, "inventory": f.inventory}))
		created := createdResource(t, code, body)
		var row models.AnsibleWorkflow
		if err := f.db.First(&row, "id = ?", created.ID).Error; err != nil {
			t.Fatalf("loading the created workflow: %v", err)
		}
		if row.ProjectID.String() != f.project || row.InventoryID == nil || row.InventoryID.String() != f.inventory {
			t.Errorf("stored project %s and inventory %v, want %s and %s", row.ProjectID, row.InventoryID, f.project, f.inventory)
		}
	})
	t.Run("a node naming its organization's job template, inventory and credential", func(t *testing.T) {
		code, body := storedAsSentCall(t, f.router, http.MethodPost, node.path, f.admin,
			workflowDocument(t, node.resourceType, node.attrs(), map[string]string{
				"job-template": f.template, "inventory": f.inventory, "credential": f.credential,
			}))
		created := createdResource(t, code, body)
		var row models.AnsibleWorkflowNode
		if err := f.db.First(&row, "id = ?", created.ID).Error; err != nil {
			t.Fatalf("loading the created node: %v", err)
		}
		for name, pair := range map[string]struct {
			got  *uuid.UUID
			want string
		}{
			"job template": {row.JobTemplateID, f.template},
			"inventory":    {row.InventoryID, f.inventory},
			"credential":   {row.CredentialID, f.credential},
		} {
			if pair.got == nil || pair.got.String() != pair.want {
				t.Errorf("stored %s = %v, want %s", name, pair.got, pair.want)
			}
		}
	})
	t.Run("an edge between two nodes of the workflow", func(t *testing.T) {
		code, body := storedAsSentCall(t, f.router, http.MethodPost, edge.path, f.admin,
			workflowDocument(t, edge.resourceType, edge.attrs(), map[string]string{"source-node": f.nodeA, "target-node": f.nodeB}))
		created := createdResource(t, code, body)
		var row models.AnsibleWorkflowEdge
		if err := f.db.First(&row, "id = ?", created.ID).Error; err != nil {
			t.Fatalf("loading the created edge: %v", err)
		}
		if row.SourceNodeID.String() != f.nodeA || row.TargetNodeID.String() != f.nodeB || row.Condition != models.WorkflowEdgeOnSuccess {
			t.Errorf("stored edge %s -> %s (%s), want %s -> %s (on_success)", row.SourceNodeID, row.TargetNodeID, row.Condition, f.nodeA, f.nodeB)
		}
	})
}

func TestWorkflowReferents_EdgeAndNodeInputIsValidated(t *testing.T) {
	f := setupReferentScope(t)
	_, node, edge := f.writes()
	ends := map[string]string{"source-node": f.nodeA, "target-node": f.nodeB}
	postEdge := func(t *testing.T, attrs map[string]any, relationships map[string]string) (int, []byte) {
		t.Helper()
		return storedAsSentCall(t, f.router, http.MethodPost, edge.path, f.admin,
			workflowDocument(t, edge.resourceType, attrs, relationships))
	}
	postNode := func(t *testing.T, attrs map[string]any) (int, []byte) {
		t.Helper()
		return storedAsSentCall(t, f.router, http.MethodPost, node.path, f.admin,
			workflowDocument(t, node.resourceType, attrs, nil))
	}
	edgesBefore, nodesBefore := edge.rows(t), node.rows(t)

	for _, tc := range []struct {
		name          string
		relationships map[string]string
		detail        string
	}{
		{"a source node identifier that does not parse", map[string]string{"source-node": "not-a-uuid", "target-node": f.nodeB}, "Invalid source node ID"},
		{"a target node identifier that does not parse", map[string]string{"source-node": f.nodeA, "target-node": "not-a-uuid"}, "Invalid target node ID"},
		{"an empty source node identifier", map[string]string{"source-node": "", "target-node": f.nodeB}, "Invalid source node ID"},
		{"no source node", map[string]string{"target-node": f.nodeB}, "Invalid source node ID"},
		{"no target node", map[string]string{"source-node": f.nodeA}, "Invalid target node ID"},
	} {
		t.Run("an edge with "+tc.name, func(t *testing.T) {
			code, body := postEdge(t, map[string]any{"condition": "on_success"}, tc.relationships)
			assertBadRequest(t, code, body, tc.detail)
		})
	}
	const conditionDetail = "condition must be one of on_success, on_failure, always"
	for name, condition := range map[string]any{"an unknown condition": "sometimes", "a condition in another case": "On_Success", "a condition of spaces": "  "} {
		t.Run("an edge with "+name, func(t *testing.T) {
			code, body := postEdge(t, map[string]any{"condition": condition}, ends)
			assertBadRequest(t, code, body, conditionDetail)
		})
	}
	const nodeTypeDetail = "node-type must be one of job_template, workflow, inventory_sync, approval"
	for name, nodeType := range map[string]any{"an unknown node type": "banana", "a node type in another case": "Approval", "a node type of spaces": "  "} {
		t.Run("a node with "+name, func(t *testing.T) {
			code, body := postNode(t, map[string]any{"node-type": nodeType, "identifier": "step-" + uuid.NewString()[:8]})
			assertBadRequest(t, code, body, nodeTypeDetail)
		})
	}
	if after := edge.rows(t); after != edgesBefore {
		t.Errorf("the refused requests left %d edge(s) behind", after-edgesBefore)
	}
	if after := node.rows(t); after != nodesBefore {
		t.Errorf("the refused requests left %d node(s) behind", after-nodesBefore)
	}

	for _, condition := range []models.WorkflowEdgeCondition{models.WorkflowEdgeOnSuccess, models.WorkflowEdgeOnFailure, models.WorkflowEdgeAlways} {
		t.Run("an edge with condition "+string(condition), func(t *testing.T) {
			code, body := postEdge(t, map[string]any{"condition": string(condition)}, ends)
			created := createdResource(t, code, body)
			if got := created.Attributes["condition"]; got != string(condition) {
				t.Errorf("condition = %v, want %s", got, condition)
			}
		})
	}
	// A document that leaves the attribute out gets the column's default, as it always has.
	t.Run("an edge with no condition follows on success", func(t *testing.T) {
		code, body := postEdge(t, map[string]any{}, ends)
		created := createdResource(t, code, body)
		var row models.AnsibleWorkflowEdge
		if err := f.db.First(&row, "id = ?", created.ID).Error; err != nil {
			t.Fatalf("loading the created edge: %v", err)
		}
		if row.Condition != models.WorkflowEdgeOnSuccess {
			t.Errorf("stored condition = %q, want on_success", row.Condition)
		}
	})
	for _, nodeType := range []models.WorkflowNodeType{
		models.WorkflowNodeTypeJobTemplate, models.WorkflowNodeTypeWorkflow,
		models.WorkflowNodeTypeInventorySync, models.WorkflowNodeTypeApproval,
	} {
		t.Run("a node of type "+string(nodeType), func(t *testing.T) {
			code, body := postNode(t, map[string]any{"node-type": string(nodeType), "identifier": "step-" + uuid.NewString()[:8]})
			created := createdResource(t, code, body)
			if got := created.Attributes["node-type"]; got != string(nodeType) {
				t.Errorf("node-type = %v, want %s", got, nodeType)
			}
		})
	}
	t.Run("a node with no node type is a job template node", func(t *testing.T) {
		code, body := postNode(t, map[string]any{"identifier": "step-" + uuid.NewString()[:8]})
		created := createdResource(t, code, body)
		var row models.AnsibleWorkflowNode
		if err := f.db.First(&row, "id = ?", created.ID).Error; err != nil {
			t.Fatalf("loading the created node: %v", err)
		}
		if row.NodeType != models.WorkflowNodeTypeJobTemplate {
			t.Errorf("stored node type = %q, want job_template", row.NodeType)
		}
	})
}

// A PATCH changes attributes only: neither update document has a relationship the handler reads,
// so there is nothing for it to check. This pins that. If a PATCH ever learns to move a workflow
// to another inventory or a node to another job template, this test fails, and the change that
// made it fail owes the same check the create path has.
func TestWorkflowReferents_PatchDoesNotChangeWhatIsNamed(t *testing.T) {
	f := setupReferentScope(t)
	nodeA := uuid.MustParse(f.nodeA)
	inventory, template := uuid.MustParse(f.inventory), uuid.MustParse(f.template)
	if err := f.db.Model(&models.AnsibleWorkflow{}).Where("id = ?", f.workflow).Update("inventory_id", inventory).Error; err != nil {
		t.Fatalf("giving the workflow an inventory: %v", err)
	}
	if err := f.db.Model(&models.AnsibleWorkflowNode{}).Where("id = ?", nodeA).Update("job_template_id", template).Error; err != nil {
		t.Fatalf("giving the node a job template: %v", err)
	}

	for name, foreign := range map[string]map[string]string{
		"rows of another organization": {"project": f.otherProject, "inventory": f.otherInventory},
		"rows that do not exist":       {"project": uuid.NewString(), "inventory": uuid.NewString()},
	} {
		t.Run("a workflow PATCH naming "+name, func(t *testing.T) {
			code, body := storedAsSentCall(t, f.router, http.MethodPatch, "/api/v2/ansible/workflows/"+f.workflow.String(), f.admin,
				workflowDocument(t, "ansible-workflows", map[string]any{"description": "patched"}, foreign))
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (%s)", code, body)
			}
			var row models.AnsibleWorkflow
			if err := f.db.First(&row, "id = ?", f.workflow).Error; err != nil {
				t.Fatalf("loading the workflow: %v", err)
			}
			if row.ProjectID.String() != f.project || row.InventoryID == nil || *row.InventoryID != inventory {
				t.Errorf("the PATCH moved the workflow to project %s and inventory %v", row.ProjectID, row.InventoryID)
			}
		})
	}
	for name, foreign := range map[string]map[string]string{
		"rows of another organization": {"job-template": f.otherTemplate, "inventory": f.otherInventory, "credential": f.otherCred},
		"rows that do not exist":       {"job-template": uuid.NewString(), "inventory": uuid.NewString(), "credential": uuid.NewString()},
	} {
		t.Run("a node PATCH naming "+name, func(t *testing.T) {
			code, body := storedAsSentCall(t, f.router, http.MethodPatch, "/api/v2/ansible/workflow-nodes/"+f.nodeA, f.admin,
				workflowDocument(t, "ansible-workflow-nodes", map[string]any{"limit": "web"}, foreign))
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (%s)", code, body)
			}
			var row models.AnsibleWorkflowNode
			if err := f.db.First(&row, "id = ?", nodeA).Error; err != nil {
				t.Fatalf("loading the node: %v", err)
			}
			if row.JobTemplateID == nil || *row.JobTemplateID != template || row.InventoryID != nil || row.CredentialID != nil {
				t.Errorf("the PATCH changed what the node names: job template %v, inventory %v, credential %v",
					row.JobTemplateID, row.InventoryID, row.CredentialID)
			}
		})
	}
}

// TestWorkflowReferents_MemberOfOneOrganizationCannotRunAnothersTemplate is the boundary as the
// caller it exists for meets it: someone who owns the first organization and has no part in the
// second. The write is refused, and a node row that names the other organization's job template
// anyway (inserted directly, as one stored before the write was checked would be) starts nothing
// there when the workflow is launched.
func TestWorkflowReferents_MemberOfOneOrganizationCannotRunAnothersTemplate(t *testing.T) {
	f := setupReferentScope(t)
	nodesPath := "/api/v2/ansible/workflows/" + f.workflow.String() + "/nodes"
	jobsInOtherProject := func(t *testing.T) int64 {
		t.Helper()
		return f.count(t, &models.AnsibleJob{}, "project_id = ?", f.otherProjectID)
	}
	before := jobsInOtherProject(t)

	code, body := storedAsSentCall(t, f.router, http.MethodPost, nodesPath, f.member,
		workflowDocument(t, "ansible-workflow-nodes",
			map[string]any{"node-type": "job_template", "identifier": "borrowed"},
			map[string]string{"job-template": f.otherTemplate}))
	assertBadRequest(t, code, body, "job template not found")

	otherTemplate := uuid.MustParse(f.otherTemplate)
	stored := &models.AnsibleWorkflowNode{
		ID: uuid.New(), WorkflowID: f.workflow, NodeType: models.WorkflowNodeTypeJobTemplate,
		Identifier: "stored-earlier", JobTemplateID: &otherTemplate,
	}
	if err := f.db.Create(stored).Error; err != nil {
		t.Fatalf("inserting the node row: %v", err)
	}

	code, body = storedAsSentCall(t, f.router, http.MethodPost,
		"/api/v2/ansible/workflows/"+f.workflow.String()+"/launch", f.member, "")
	if code != http.StatusCreated {
		t.Fatalf("launch = %d, want 201 (%s)", code, body)
	}
	var launched struct {
		Data storedAsSentResource `json:"data"`
	}
	if err := json.Unmarshal(body, &launched); err != nil {
		t.Fatalf("decoding the launch response: %v\n%s", err, body)
	}

	if got := jobsInOtherProject(t) - before; got != 0 {
		var job models.AnsibleJob
		f.db.Where("project_id = ?", f.otherProjectID).Order("created_at DESC").First(&job)
		t.Errorf("the launch started %d job(s) in the other organization's project (inventory %s, extra vars %v), want 0",
			got, job.InventoryID, job.ExtraVars)
	}
	var nodeJob models.AnsibleWorkflowNodeJob
	if err := f.db.First(&nodeJob, "workflow_job_id = ? AND node_id = ?", launched.Data.ID, stored.ID).Error; err != nil {
		t.Fatalf("reading the node's run: %v", err)
	}
	if nodeJob.Status != models.WorkflowNodeJobFailed || nodeJob.AnsibleJobID != nil {
		t.Errorf("the node is %q with job %v, want failed with no job", nodeJob.Status, nodeJob.AnsibleJobID)
	}
}
