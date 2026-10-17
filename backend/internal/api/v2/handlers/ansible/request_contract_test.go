// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The request and response contract of the Ansible endpoints #858 converted onto JSON:API (D5,
// AC1). The golden corpus pins the accepted write of each; this pins what the corpus cannot
// see: the 400 a flat body gets, the 400 a wrong data.type or relationship type gets, and the
// documents the conversions answer with, including the unseeded playbook file listing through
// a fake VCS provider.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestAnsibleRequestContract

//go:build integration
// +build integration

package ansible

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// contractQueue accepts every job, so a launch and a run-now complete without a Redis.
type contractQueue struct {
	mu   sync.Mutex
	jobs int
}

func (q *contractQueue) Enqueue(context.Context, string, interface{}) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.jobs++
	return nil
}

func (q *contractQueue) Dequeue(context.Context, string, time.Duration) ([]byte, error) {
	return nil, nil
}
func (q *contractQueue) Close() error { return nil }

// contractProvider is a VCS provider that lists a fixed set of files. Every other method is
// the embedded nil interface and is never called by the handlers under test.
type contractProvider struct {
	vcs.ProviderService
	files []string
}

func (p contractProvider) ListFiles(context.Context, *models.VCSConnection, string, string, string, []string) ([]string, error) {
	return p.files, nil
}

type contractProviders struct{ provider vcs.ProviderService }

func (p contractProviders) GetProvider(*models.VCSConnection) (vcs.ProviderService, error) {
	return p.provider, nil
}

type requestContractFixture struct {
	router       *gin.Engine
	owner        uuid.UUID
	orgName      string
	projectID    string
	scheduleID   string
	templateID   string
	credentialID string
	workflowID   string
	channelID    string
	connectionID string
	jobID        string
}

func setupRequestContract(t *testing.T) *requestContractFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connecting to the test database: %v", err)
	}
	if _, err := models.ReconcileFKDeleteRules(db); err != nil {
		t.Fatalf("reconciling the foreign key delete rules: %v", err)
	}
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "reqc-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "reqc-own-" + sfx, Email: "reqc-own-" + sfx + "@test.local"}
	team := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "reqc-proj-" + sfx}
	admin := "admin"
	inventory := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: org.ID, ProjectID: &project.ID, Name: "reqc-inv-" + sfx, Type: models.InventoryTypeStatic}
	credential := &models.AnsibleCredential{ID: uuid.New(), OrganizationID: org.ID, Name: "reqc-cred-" + sfx, Type: models.CredentialTypeSSH}
	playbook := &models.AnsiblePlaybook{ID: uuid.New(), ProjectID: project.ID, Name: "reqc-pb-" + sfx, PlaybookPath: "site.yml", SourceMode: "cached"}
	template := &models.AnsibleJobTemplate{ID: uuid.New(), ProjectID: project.ID, PlaybookID: playbook.ID, InventoryID: inventory.ID, Name: "reqc-tmpl-" + sfx}
	workflow := &models.AnsibleWorkflow{ID: uuid.New(), OrganizationID: org.ID, ProjectID: project.ID, Name: "reqc-wf-" + sfx, AllowSimultaneous: true}
	gate := &models.AnsibleWorkflowNode{ID: uuid.New(), WorkflowID: workflow.ID, NodeType: models.WorkflowNodeTypeApproval, Identifier: "gate"}
	channel := &models.AnsibleNotificationTemplate{ID: uuid.New(), OrganizationID: org.ID, Name: "reqc-chan-" + sfx, Type: models.NotificationTypeWebhook, Config: datatypes.JSON(`{"url":"https://example.test/hook"}`)}
	connection := &models.VCSConnection{ID: uuid.New(), OrganizationID: org.ID, Provider: models.VCSProviderGitHub, AccountName: "reqc-" + sfx, AccountType: "organization", InstallationID: "1"}
	job := &models.AnsibleJob{ID: uuid.New(), ProjectID: project.ID, PlaybookID: &playbook.ID, InventoryID: inventory.ID, Status: models.AnsibleJobStatusSuccessful}
	for _, row := range []any{
		org, owner, team, project,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: owner.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: team.ID, ProjectID: project.ID, Access: &admin},
		inventory, credential, playbook, template, workflow, gate, channel, connection, job,
		&models.AnsibleJobEvent{ID: uuid.New(), JobID: job.ID, Counter: 1, Event: "runner_on_ok", Stdout: "PLAY [all]\n"},
		&models.AnsibleJobEvent{ID: uuid.New(), JobID: job.ID, Counter: 2, Event: "playbook_on_stats", Stdout: "ok=1 changed=0\n"},
	} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}

	t.Cleanup(func() {
		// Children before parents, every statement scoped to this run's ids.
		db.Where("organization_id = ?", org.ID).Delete(&models.AnsibleSchedule{})
		db.Where("notification_template_id = ?", channel.ID).Delete(&models.AnsibleNotificationAttachment{})
		db.Where("organization_id = ?", org.ID).Delete(&models.AnsibleNotificationTemplate{})
		db.Exec("DELETE FROM ansible_workflow_node_jobs WHERE node_id = ?", gate.ID)
		db.Where("workflow_id = ?", workflow.ID).Delete(&models.AnsibleWorkflowJob{})
		db.Where("id = ?", gate.ID).Delete(&models.AnsibleWorkflowNode{})
		db.Where("id = ?", workflow.ID).Delete(&models.AnsibleWorkflow{})
		db.Exec("DELETE FROM ansible_job_template_credentials WHERE ansible_job_template_id = ?", template.ID)
		db.Exec("DELETE FROM ansible_job_events WHERE job_id IN (SELECT id FROM ansible_jobs WHERE project_id = ?)", project.ID)
		db.Where("project_id = ?", project.ID).Delete(&models.AnsibleJob{})
		db.Where("project_id = ?", project.ID).Delete(&models.AnsibleJobTemplate{})
		db.Where("project_id = ?", project.ID).Delete(&models.AnsiblePlaybook{})
		db.Where("id = ?", connection.ID).Delete(&models.VCSConnection{})
		db.Where("id = ?", credential.ID).Delete(&models.AnsibleCredential{})
		db.Where("id = ?", inventory.ID).Delete(&models.AnsibleInventory{})
		db.Where("team_id = ?", team.ID).Delete(&models.TeamProjectAccess{})
		db.Where("team_id = ?", team.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", team.ID).Delete(&models.Team{})
		db.Where("id = ?", project.ID).Delete(&models.Project{})
		db.Where("organization_id = ?", org.ID).Delete(&models.OrganizationMember{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
		db.Where("id = ?", owner.ID).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	inventoryRepo := repository.NewAnsibleInventoryRepository(db)
	credentialRepo := repository.NewAnsibleCredentialRepository(db)
	templateRepo := repository.NewAnsibleJobTemplateRepository(db)
	playbookRepo := repository.NewAnsiblePlaybookRepository(db)
	jobRepo := repository.NewAnsibleJobRepository(db)
	scheduleRepo := repository.NewAnsibleScheduleRepository(db)
	workflowRepo := repository.NewAnsibleWorkflowRepository(db)
	sourceRepo := repository.NewAnsibleInventorySourceRepository(db)

	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo)
	q := &contractQueue{}
	sourceService := ansiblesvc.NewInventorySourceService(sourceRepo, inventoryRepo, credentialRepo, nil)
	jobService := ansiblesvc.NewJobService(jobRepo, playbookRepo, inventoryRepo, templateRepo, projectRepo, q)
	jobService.SetOrganizationRepo(orgRepo)
	schedulerService := ansiblesvc.NewSchedulerService(scheduleRepo, jobRepo, templateRepo, playbookRepo, sourceService, jobService, orgRepo)
	engine := ansiblesvc.NewWorkflowEngineService(workflowRepo, jobRepo, jobService, sourceService)
	schedulerService.SetWorkflowEngine(engine)

	schedule, err := schedulerService.CreateSchedule(
		org.ID, "reqc-sched-"+sfx, "", models.ScheduleTypeJobTemplate, "0 2 * * *", "UTC",
		&template.ID, nil, nil, nil, models.ScheduleConfig{}, &owner.ID, nil, nil,
	)
	if err != nil {
		t.Fatalf("creating the schedule: %v", err)
	}

	scheduleHandler := NewScheduleHandler(schedulerService, orgRepo, authService, rbacService)
	notificationHandler := NewNotificationHandler(
		repository.NewAnsibleNotificationRepository(db), templateRepo, workflowRepo, orgRepo, authService, rbacService, nil, nil,
	)
	playbookHandler := NewPlaybookHandler(
		playbookRepo, templateRepo, jobRepo, scheduleRepo, projectRepo, orgRepo, authService, rbacService, q,
		nil, repository.NewVCSConnectionRepository(db), jobService,
	)
	playbookHandler.SetCredentialRepo(credentialRepo)
	playbookHandler.providers = contractProviders{provider: contractProvider{files: []string{"site.yml", "deploy.yml", "group_vars/all.yml"}}}
	workflowHandler := NewWorkflowHandler(workflowRepo, orgRepo, projectRepo, authService, rbacService, engine)
	jobHandler := NewJobHandler(jobService, projectRepo, orgRepo, templateRepo, authService, rbacService)
	varsHandler := NewJobTemplateVariableHandlerV2(repository.NewAnsibleJobTemplateVariableRepository(db), templateRepo, authService, rbacService, nil)
	varsHandler.SetRepositories(orgRepo, projectRepo)

	router := storedAsSentRouter()
	// The paths and parameter names of ansible_routes.go.
	router.PATCH("/ansible/schedules/:schedule_id", scheduleHandler.Update)
	router.POST("/ansible/schedules/:schedule_id/actions/enable", scheduleHandler.Enable)
	router.POST("/ansible/schedules/:schedule_id/actions/disable", scheduleHandler.Disable)
	router.POST("/ansible/schedules/:schedule_id/actions/run-now", scheduleHandler.RunNow)
	router.POST("/organizations/:name/ansible/notification-templates", notificationHandler.Create)
	router.PATCH("/ansible/notification-templates/:id", notificationHandler.Update)
	router.POST("/organizations/:name/ansible/notification-attachments", notificationHandler.Attach)
	router.POST("/ansible/job-templates/:id/credentials", playbookHandler.AttachTemplateCredential)
	router.POST("/ansible/workflows/:id/launch", workflowHandler.LaunchWorkflow)
	router.POST("/organizations/:name/ansible/playbooks/actions/bulk-import", playbookHandler.BulkImportPlaybooks)
	router.POST("/organizations/:name/ansible/playbooks/actions/find-or-create", playbookHandler.FindOrCreatePlaybook)
	router.GET("/organizations/:name/ansible/vcs-playbook-files", playbookHandler.ListPlaybookFiles)
	router.GET("/ansible/jobs/:id/output", jobHandler.GetOutput)
	router.POST("/ansible/job-templates/:id/vars", varsHandler.Create)

	return &requestContractFixture{
		router:       router,
		owner:        owner.ID,
		orgName:      org.Name,
		projectID:    project.ID.String(),
		scheduleID:   schedule.ID.String(),
		templateID:   template.ID.String(),
		credentialID: credential.ID.String(),
		workflowID:   workflow.ID.String(),
		channelID:    channel.ID.String(),
		connectionID: connection.ID.String(),
		jobID:        job.ID.String(),
	}
}

// contractDoc is the parts of a response document the cases read.
type contractDoc struct {
	Data   json.RawMessage `json:"data"`
	Meta   map[string]any  `json:"meta"`
	Errors []struct {
		Detail string `json:"detail"`
	} `json:"errors"`
}

type contractResource struct {
	Type          string                     `json:"type"`
	ID            string                     `json:"id"`
	Attributes    map[string]any             `json:"attributes"`
	Relationships map[string]json.RawMessage `json:"relationships"`
}

func (f *requestContractFixture) call(t *testing.T, method, path, body string) (int, http.Header, []byte) {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Test-User", f.owner.String())
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	return rec.Code, rec.Header(), rec.Body.Bytes()
}

// refused asserts a 400 whose only error detail is want.
func (f *requestContractFixture) refused(t *testing.T, method, path, body, want string) {
	t.Helper()
	code, _, raw := f.call(t, method, path, body)
	var doc contractDoc
	_ = json.Unmarshal(raw, &doc)
	if code != http.StatusBadRequest || len(doc.Errors) != 1 || doc.Errors[0].Detail != want {
		t.Errorf("%s %s with %s: got %d %s\n want 400 with detail %q", method, path, body, code, raw, want)
	}
}

// accepted asserts the status and returns the document.
func (f *requestContractFixture) accepted(t *testing.T, method, path, body string, want int) contractDoc {
	t.Helper()
	code, _, raw := f.call(t, method, path, body)
	if code != want {
		t.Fatalf("%s %s with %s: got %d %s, want %d", method, path, body, code, raw, want)
	}
	var doc contractDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s %s: the answer is not JSON: %v (%s)", method, path, err, raw)
	}
	if _, isArray := doc.Meta["results"]; isArray {
		t.Errorf("%s %s: meta carries results; a bulk outcome is resources under data", method, path)
	}
	return doc
}

func one(t *testing.T, doc contractDoc, wantType string) contractResource {
	t.Helper()
	var res contractResource
	if err := json.Unmarshal(doc.Data, &res); err != nil || res.Type != wantType || res.ID == "" {
		t.Fatalf("data is not one %s resource: %s", wantType, doc.Data)
	}
	return res
}

func many(t *testing.T, doc contractDoc, wantType string) []contractResource {
	t.Helper()
	var rows []contractResource
	if err := json.Unmarshal(doc.Data, &rows); err != nil {
		t.Fatalf("data is not an array of resources: %s", doc.Data)
	}
	for _, r := range rows {
		if r.Type != wantType || r.ID == "" {
			t.Fatalf("data holds %+v, want %s resources with an id", r, wantType)
		}
	}
	return rows
}

func documentRequired(resourceType string) string {
	return `request body must be a JSON:API document: {"data": {"type": "` + resourceType + `", "attributes": {...}}}`
}

func wrongType(path, want, got string) string {
	return path + `.type must be "` + want + `" (got "` + got + `")`
}

func TestAnsibleRequestContract(t *testing.T) {
	f := setupRequestContract(t)

	t.Run("schedule update takes a schedules document", func(t *testing.T) {
		path := "/ansible/schedules/" + f.scheduleID
		f.refused(t, http.MethodPatch, path, `{"cron_expression":"0 3 * * *"}`, documentRequired("schedules"))
		f.refused(t, http.MethodPatch, path, `{"data":{"type":"jobs","attributes":{}}}`, wrongType("data", "schedules", "jobs"))
		doc := f.accepted(t, http.MethodPatch, path, `{"data":{"type":"schedules","attributes":{"cron-expression":"0 3 * * *","name":"reqc-renamed"}}}`, http.StatusOK)
		res := one(t, doc, "schedules")
		if res.Attributes["cron-expression"] != "0 3 * * *" || res.Attributes["name"] != "reqc-renamed" {
			t.Errorf("the update did not apply: %v", res.Attributes)
		}
		// An omitted attribute is untouched.
		doc = f.accepted(t, http.MethodPatch, path, `{"data":{"type":"schedules","attributes":{"description":"kept"}}}`, http.StatusOK)
		if res := one(t, doc, "schedules"); res.Attributes["cron-expression"] != "0 3 * * *" {
			t.Errorf("an omitted cron-expression changed: %v", res.Attributes)
		}
	})

	t.Run("schedule actions answer the schedule", func(t *testing.T) {
		base := "/ansible/schedules/" + f.scheduleID + "/actions/"
		if res := one(t, f.accepted(t, http.MethodPost, base+"disable", "", http.StatusOK), "schedules"); res.Attributes["status"] != "disabled" {
			t.Errorf("disable answered status %v", res.Attributes["status"])
		}
		if res := one(t, f.accepted(t, http.MethodPost, base+"enable", "", http.StatusOK), "schedules"); res.Attributes["status"] != "enabled" {
			t.Errorf("enable answered status %v", res.Attributes["status"])
		}
		if res := one(t, f.accepted(t, http.MethodPost, base+"run-now", "", http.StatusOK), "schedules"); res.ID != f.scheduleID {
			t.Errorf("run-now answered schedule %s, want %s", res.ID, f.scheduleID)
		}
	})

	t.Run("notification templates take a document", func(t *testing.T) {
		create := "/organizations/" + f.orgName + "/ansible/notification-templates"
		f.refused(t, http.MethodPost, create, `{"name":"x","type":"webhook"}`, documentRequired("ansible-notification-templates"))
		f.refused(t, http.MethodPost, create, `{"data":{"type":"notification-templates","attributes":{"name":"x"}}}`,
			wrongType("data", "ansible-notification-templates", "notification-templates"))
		doc := f.accepted(t, http.MethodPost, create,
			`{"data":{"type":"ansible-notification-templates","attributes":{"name":"reqc-new-channel","notification-type":"webhook","config":{"url":"https://example.test/new"},"secret":"s3cret"}}}`,
			http.StatusCreated)
		res := one(t, doc, "ansible-notification-templates")
		if res.Attributes["notification-type"] != "webhook" || res.Attributes["name"] != "reqc-new-channel" {
			t.Errorf("created %v", res.Attributes)
		}

		update := "/ansible/notification-templates/" + res.ID
		f.refused(t, http.MethodPatch, update, `{"name":"y"}`, documentRequired("ansible-notification-templates"))
		doc = f.accepted(t, http.MethodPatch, update, `{"data":{"type":"ansible-notification-templates","attributes":{"name":"reqc-renamed-channel"}}}`, http.StatusOK)
		if got := one(t, doc, "ansible-notification-templates"); got.Attributes["name"] != "reqc-renamed-channel" {
			t.Errorf("updated %v", got.Attributes)
		}
	})

	t.Run("notification attachment takes a document with typed relationships", func(t *testing.T) {
		attach := "/organizations/" + f.orgName + "/ansible/notification-attachments"
		f.refused(t, http.MethodPost, attach, `{"notification_template_id":"`+f.channelID+`","job_template_id":"`+f.templateID+`"}`,
			documentRequired("ansible-notification-attachments"))
		rels := func(channelType string) string {
			return `"relationships":{"notification-template":{"data":{"type":"` + channelType + `","id":"` + f.channelID + `"}},` +
				`"job-template":{"data":{"type":"ansible-job-templates","id":"` + f.templateID + `"}}}`
		}
		f.refused(t, http.MethodPost, attach, `{"data":{"type":"ansible-notification-attachments","attributes":{},`+rels("ansible-job-templates")+`}}`,
			wrongType("data.relationships.notification-template.data", "ansible-notification-templates", "ansible-job-templates"))
		doc := f.accepted(t, http.MethodPost, attach,
			`{"data":{"type":"ansible-notification-attachments","attributes":{"on-started":true},`+rels("ansible-notification-templates")+`}}`,
			http.StatusCreated)
		res := one(t, doc, "ansible-notification-attachments")
		assertStoredBool(t, "attach", res.Attributes, "on-started", true)
		assertStoredBool(t, "attach", res.Attributes, "on-success", true)
		assertStoredBool(t, "attach", res.Attributes, "on-failure", true)
	})

	t.Run("credential attach takes a resource identifier", func(t *testing.T) {
		path := "/ansible/job-templates/" + f.templateID + "/credentials"
		f.refused(t, http.MethodPost, path, `{"credential_id":"`+f.credentialID+`"}`,
			`request body must be a JSON:API resource identifier: {"data": {"type": "ansible-credentials", "id": "..."}}`)
		f.refused(t, http.MethodPost, path, `{"data":{"type":"ansible-inventories","id":"`+f.credentialID+`"}}`,
			wrongType("data", "ansible-credentials", "ansible-inventories"))
		doc := f.accepted(t, http.MethodPost, path, `{"data":{"type":"ansible-credentials","id":"`+f.credentialID+`"}}`, http.StatusCreated)
		if res := one(t, doc, "ansible-credentials"); res.ID != f.credentialID {
			t.Errorf("attached %s, want %s", res.ID, f.credentialID)
		}
	})

	t.Run("workflow launch takes an optional document", func(t *testing.T) {
		path := "/ansible/workflows/" + f.workflowID + "/launch"
		one(t, f.accepted(t, http.MethodPost, path, "", http.StatusCreated), "ansible-workflow-jobs")
		f.refused(t, http.MethodPost, path, `{"extra_vars":{"a":"b"}}`, documentRequired("ansible-workflow-jobs"))
		f.refused(t, http.MethodPost, path, `{}`, documentRequired("ansible-workflow-jobs"))
		f.refused(t, http.MethodPost, path, `{"data":{"type":"ansible-jobs","attributes":{}}}`, wrongType("data", "ansible-workflow-jobs", "ansible-jobs"))
		one(t, f.accepted(t, http.MethodPost, path, `{"data":{"type":"ansible-workflow-jobs","attributes":{"extra-vars":{"a":"b"}}}}`, http.StatusCreated), "ansible-workflow-jobs")
	})

	t.Run("playbook bulk import and find-or-create take ansible-playbooks documents", func(t *testing.T) {
		bulk := "/organizations/" + f.orgName + "/ansible/playbooks/actions/bulk-import"
		attrs := `"project-id":"` + f.projectID + `","vcs-connection-id":"` + f.connectionID + `","repository":"acme/infra","branch":"main","source-mode":"cached"`
		f.refused(t, http.MethodPost, bulk, `{"project_id":"`+f.projectID+`","playbooks":[{"path":"site.yml"}]}`, documentRequired("ansible-playbooks"))
		f.refused(t, http.MethodPost, bulk, `{"data":{"type":"playbooks","attributes":{}}}`, wrongType("data", "ansible-playbooks", "playbooks"))

		body := `{"data":{"type":"ansible-playbooks","attributes":{` + attrs + `,"playbooks":[{"path":"site.yml"},{"path":"deploy.yml"}]}}}`
		doc := f.accepted(t, http.MethodPost, bulk, body, http.StatusOK)
		if rows := many(t, doc, "ansible-playbooks"); len(rows) != 2 {
			t.Errorf("first import answered %d playbooks, want 2", len(rows))
		}
		if doc.Meta["created"] != float64(2) || doc.Meta["skipped"] != float64(0) || doc.Meta["failed"] != float64(0) {
			t.Errorf("first import meta: %v", doc.Meta)
		}
		if rows, ok := doc.Meta["failed-rows"].([]any); !ok || len(rows) != 0 {
			t.Errorf("first import failed-rows: %v", doc.Meta["failed-rows"])
		}
		doc = f.accepted(t, http.MethodPost, bulk, body, http.StatusOK)
		if rows := many(t, doc, "ansible-playbooks"); len(rows) != 2 || doc.Meta["skipped"] != float64(2) || doc.Meta["created"] != float64(0) {
			t.Errorf("second import: %d rows, meta %v; want the two playbooks, both skipped", len(rows), doc.Meta)
		}

		find := "/organizations/" + f.orgName + "/ansible/playbooks/actions/find-or-create"
		f.refused(t, http.MethodPost, find, `{"repository":"acme/infra","branch":"main","path":"site.yml"}`, documentRequired("ansible-playbooks"))
		doc = f.accepted(t, http.MethodPost, find, `{"data":{"type":"ansible-playbooks","attributes":{`+attrs+`,"path":"site.yml"}}}`, http.StatusOK)
		one(t, doc, "ansible-playbooks")
		if doc.Meta["created"] != false {
			t.Errorf("find-or-create of an imported path: meta %v, want created false", doc.Meta)
		}
	})

	t.Run("playbook files are ansible-playbook-files resources", func(t *testing.T) {
		path := "/organizations/" + f.orgName + "/ansible/vcs-playbook-files?vcs_connection_id=" + f.connectionID + "&repository=acme/infra&branch=main"
		doc := f.accepted(t, http.MethodGet, path, "", http.StatusOK)
		rows := many(t, doc, "ansible-playbook-files")
		byID := map[string]contractResource{}
		for _, r := range rows {
			byID[r.ID] = r
		}
		site, ok := byID["site.yml"]
		if !ok {
			t.Fatalf("site.yml is not listed: %s", doc.Data)
		}
		if site.Attributes["registered"] != true || site.Attributes["name"] != "site.yml" {
			t.Errorf("site.yml attributes: %v", site.Attributes)
		}
		var rel struct {
			Data *struct{ Type, ID string } `json:"data"`
		}
		if err := json.Unmarshal(site.Relationships["playbook"], &rel); err != nil || rel.Data == nil || rel.Data.Type != "ansible-playbooks" {
			t.Errorf("a registered file carries no playbook relationship: %s", site.Relationships["playbook"])
		}
		if _, leaked := site.Attributes["playbook_id"]; leaked {
			t.Errorf("playbook_id is still an attribute: %v", site.Attributes)
		}
		pagination, _ := doc.Meta["pagination"].(map[string]any)
		for _, member := range []string{"current-page", "page-size", "prev-page", "next-page", "total-pages", "total-count"} {
			if _, present := pagination[member]; !present {
				t.Errorf("meta.pagination lacks %s: %v", member, doc.Meta)
			}
		}
		if pagination["total-count"] != nil || pagination["total-pages"] != nil || pagination["next-page"] != nil {
			t.Errorf("a provider listing states totals or a next page it cannot know: %v", pagination)
		}
	})

	t.Run("job output is text", func(t *testing.T) {
		code, header, body := f.call(t, http.MethodGet, "/ansible/jobs/"+f.jobID+"/output", "")
		if code != http.StatusOK || !strings.HasPrefix(header.Get("Content-Type"), "text/plain") {
			t.Fatalf("output: %d %s (%s)", code, header.Get("Content-Type"), body)
		}
		if string(body) != "PLAY [all]\nok=1 changed=0\n" {
			t.Errorf("output body %q", body)
		}
	})

	t.Run("a job template variable names the vars type the one way", func(t *testing.T) {
		f.refused(t, http.MethodPost, "/ansible/job-templates/"+f.templateID+"/vars",
			`{"data":{"type":"variables","attributes":{"key":"k","value":"v"}}}`, wrongType("data", "vars", "variables"))
	})
}
