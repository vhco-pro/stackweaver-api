// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Error envelope of the schedule, inventory source, ad hoc command and inventory sync handlers
// (#857). These four answered errors with a flat {"error": "..."} body long after the rest of
// the API converged on the JSON:API errors document, and the golden error harness never saw it:
// its API-key identity is stopped by the org wall before any of these handlers runs. This test
// mounts the handlers directly, the way a JWT caller reaches them, and drives one site per class
// per handler: an invalid identifier, a missing row, a bind failure, caller-input validation
// that the service performs, the disabled-template conflict, and the 500s that can be provoked
// on real Postgres. Each case asserts the status, errors[0].status, title and detail, and that
// no top-level `error` key is left.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. The schema is expected to
// be migrated already. Cleanup is strictly row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestAnsibleErrorEnvelope

//go:build integration
// +build integration

package ansible

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type errorEnvelopeFixture struct {
	router *gin.Engine
	owner  *models.User

	orgName         string
	inventoryID     string
	otherProjectID  string // a project of a second organization the owner also administers
	sourceID        string // enabled
	disabledSource  string
	sshCredentialID string

	scheduleID               string // job_template schedule, enabled template
	disabledTemplateSchedule string
	orphanSchedule           string // its job template was deleted after the schedule was created
	disabledSourceSchedule   string
	brokenCronSchedule       string // cron_expression corrupted in the row
}

func setupErrorEnvelope(t *testing.T) *errorEnvelopeFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connecting to the test database: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "errenv-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "errenv-b-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "errenv-own-" + sfx, Email: "errenv-own-" + sfx + "@test.local"}
	teamA := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	teamB := &models.Team{ID: uuid.New(), OrganizationID: orgB.ID, Name: "owners"}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "errenv-proj-" + sfx}
	projB := &models.Project{ID: uuid.New(), OrganizationID: orgB.ID, Name: "errenv-proj-" + sfx}

	adminAccess := "admin"
	seed := []any{
		orgA, orgB, owner, teamA, teamB, projA, projB,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: teamA.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: teamB.ID, UserID: owner.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: teamA.ID, ProjectID: projA.ID, Access: &adminAccess},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: teamB.ID, ProjectID: projB.ID, Access: &adminAccess},
	}
	for _, row := range seed {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	inventoryRepo := repository.NewAnsibleInventoryRepository(db)
	sourceRepo := repository.NewAnsibleInventorySourceRepository(db)
	syncRepo := repository.NewAnsibleInventorySyncRepository(db)
	credentialRepo := repository.NewAnsibleCredentialRepository(db)
	templateRepo := repository.NewAnsibleJobTemplateRepository(db)
	playbookRepo := repository.NewAnsiblePlaybookRepository(db)
	jobRepo := repository.NewAnsibleJobRepository(db)
	scheduleRepo := repository.NewAnsibleScheduleRepository(db)
	agentPoolRepo := repository.NewAgentPoolRepository(db)

	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo)
	inventoryService := ansiblesvc.NewInventoryService(inventoryRepo, orgRepo)
	sourceService := ansiblesvc.NewInventorySourceService(sourceRepo, inventoryRepo, credentialRepo, nil)
	// No queue: none of the cases below may dispatch a job, and a nil queue is what makes the
	// "Sync queue not available" 500 reachable.
	jobService := ansiblesvc.NewJobService(jobRepo, playbookRepo, inventoryRepo, templateRepo, projectRepo, nil)
	jobService.SetOrganizationRepo(orgRepo)
	schedulerService := ansiblesvc.NewSchedulerService(scheduleRepo, jobRepo, templateRepo, playbookRepo, sourceService, jobService, orgRepo)

	inventory, err := inventoryService.CreateInventory(
		orgA.ID, &projA.ID, "errenv-inv-"+sfx, "", models.InventoryTypeStatic, "", models.InventoryVariables{}, nil, "", "", "",
	)
	if err != nil {
		t.Fatalf("creating the inventory: %v", err)
	}
	source, err := sourceService.CreateInventorySource(inventory.ID, "errenv-src-"+sfx, "", models.InventorySourceTypeCustom, nil, models.InventorySourceConfig{})
	if err != nil {
		t.Fatalf("creating the enabled source: %v", err)
	}
	disabledSource, err := sourceService.CreateInventorySource(inventory.ID, "errenv-src-off-"+sfx, "", models.InventorySourceTypeCustom, nil, models.InventorySourceConfig{})
	if err != nil {
		t.Fatalf("creating the disabled source: %v", err)
	}
	off := false
	if _, err := sourceService.UpdateInventorySource(disabledSource.ID, ansiblesvc.UpdateInventorySourceOptions{Enabled: &off}); err != nil {
		t.Fatalf("disabling the source: %v", err)
	}
	sshCredential := &models.AnsibleCredential{ID: uuid.New(), OrganizationID: orgA.ID, Name: "errenv-cred-" + sfx, Type: models.CredentialTypeSSH}
	playbook := &models.AnsiblePlaybook{ID: uuid.New(), ProjectID: projA.ID, Name: "errenv-pb-" + sfx, PlaybookPath: "site.yml", SourceMode: "cached"}
	template := &models.AnsibleJobTemplate{ID: uuid.New(), ProjectID: projA.ID, PlaybookID: playbook.ID, InventoryID: inventory.ID, Name: "errenv-tmpl-" + sfx}
	disabledTemplate := &models.AnsibleJobTemplate{ID: uuid.New(), ProjectID: projA.ID, PlaybookID: playbook.ID, InventoryID: inventory.ID, Name: "errenv-tmpl-off-" + sfx, Disabled: true}
	doomedTemplate := &models.AnsibleJobTemplate{ID: uuid.New(), ProjectID: projA.ID, PlaybookID: playbook.ID, InventoryID: inventory.ID, Name: "errenv-tmpl-gone-" + sfx}
	for _, row := range []any{sshCredential, playbook, template, disabledTemplate, doomedTemplate} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}

	t.Cleanup(func() {
		// Children before parents (foreign-key order), every statement scoped to this run's ids.
		db.Where("organization_id = ?", orgA.ID).Delete(&models.AnsibleSchedule{})
		db.Where("project_id = ?", projA.ID).Delete(&models.AnsibleJob{})
		db.Where("project_id = ?", projA.ID).Delete(&models.AnsibleJobTemplate{})
		db.Where("id = ?", playbook.ID).Delete(&models.AnsiblePlaybook{})
		db.Where("inventory_id = ?", inventory.ID).Delete(&models.AnsibleInventorySync{})
		db.Where("inventory_id = ?", inventory.ID).Delete(&models.AnsibleInventorySource{})
		db.Where("id = ?", sshCredential.ID).Delete(&models.AnsibleCredential{})
		db.Where("id = ?", inventory.ID).Delete(&models.AnsibleInventory{})
		db.Where("team_id IN ?", []uuid.UUID{teamA.ID, teamB.ID}).Delete(&models.TeamProjectAccess{})
		db.Where("team_id IN ?", []uuid.UUID{teamA.ID, teamB.ID}).Delete(&models.TeamMember{})
		db.Where("id IN ?", []uuid.UUID{teamA.ID, teamB.ID}).Delete(&models.Team{})
		db.Where("id IN ?", []uuid.UUID{projA.ID, projB.ID}).Delete(&models.Project{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id = ?", owner.ID).Delete(&models.User{})
	})

	newSchedule := func(name string, scheduleType models.ScheduleType, templateID, sourceID *uuid.UUID) *models.AnsibleSchedule {
		t.Helper()
		s, err := schedulerService.CreateSchedule(
			orgA.ID, name+"-"+sfx, "", scheduleType, "0 2 * * *", "UTC",
			templateID, sourceID, nil, nil, models.ScheduleConfig{}, &owner.ID, nil, nil,
		)
		if err != nil {
			t.Fatalf("creating schedule %s: %v", name, err)
		}
		return s
	}
	schedule := newSchedule("errenv-sched", models.ScheduleTypeJobTemplate, &template.ID, nil)
	disabledTemplateSchedule := newSchedule("errenv-sched-off", models.ScheduleTypeJobTemplate, &disabledTemplate.ID, nil)
	orphanSchedule := newSchedule("errenv-sched-orphan", models.ScheduleTypeJobTemplate, &doomedTemplate.ID, nil)
	disabledSourceSchedule := newSchedule("errenv-sched-src", models.ScheduleTypeInventorySource, nil, &disabledSource.ID)
	brokenCronSchedule := newSchedule("errenv-sched-cron", models.ScheduleTypeJobTemplate, &template.ID, nil)

	// The schedule's foreign key is ON DELETE SET NULL (core/models/fk_delete_rules.go), so
	// deleting the template leaves a schedule with no target, which run-now cannot execute.
	if err := db.Where("id = ?", doomedTemplate.ID).Delete(&models.AnsibleJobTemplate{}).Error; err != nil {
		t.Fatalf("deleting the job template under the orphan schedule: %v", err)
	}
	// A cron expression the parser rejects, written past the service's validation, so that
	// enabling the schedule fails server-side for a reason the caller did not send.
	if err := db.Model(&models.AnsibleSchedule{}).Where("id = ?", brokenCronSchedule.ID).
		Update("cron_expression", "not a cron").Error; err != nil {
		t.Fatalf("corrupting the cron expression: %v", err)
	}

	scheduleHandler := NewScheduleHandler(schedulerService, orgRepo, authService, rbacService)
	sourceHandler := NewInventorySourceHandler(sourceService, inventoryService, authService, rbacService, nil)
	adHocHandler := NewAdHocHandler(inventoryRepo, orgRepo, credentialRepo, projectRepo, agentPoolRepo, jobService, authService, rbacService)
	syncHandler := NewInventorySyncHandler(syncRepo, inventoryRepo, authService, rbacService)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if v := c.GetHeader("X-Test-User"); v != "" {
			if id, err := uuid.Parse(v); err == nil {
				c.Set("user_id", id)
			}
		}
		c.Next()
	})
	// The paths and parameter names of ansible_routes.go.
	router.GET("/organizations/:name/ansible/schedules", scheduleHandler.ListByOrganization)
	router.POST("/organizations/:name/ansible/schedules", scheduleHandler.Create)
	router.GET("/ansible/schedules/:schedule_id", scheduleHandler.Get)
	router.PATCH("/ansible/schedules/:schedule_id", scheduleHandler.Update)
	router.DELETE("/ansible/schedules/:schedule_id", scheduleHandler.Delete)
	router.POST("/ansible/schedules/:schedule_id/actions/enable", scheduleHandler.Enable)
	router.POST("/ansible/schedules/:schedule_id/actions/disable", scheduleHandler.Disable)
	router.POST("/ansible/schedules/:schedule_id/actions/run-now", scheduleHandler.RunNow)
	router.GET("/ansible/inventories/:id/sources", sourceHandler.List)
	router.POST("/ansible/inventories/:id/sources", sourceHandler.Create)
	router.GET("/ansible/inventory-sources/:source_id", sourceHandler.Get)
	router.PATCH("/ansible/inventory-sources/:source_id", sourceHandler.Update)
	router.DELETE("/ansible/inventory-sources/:source_id", sourceHandler.Delete)
	router.POST("/ansible/inventory-sources/:source_id/actions/sync", sourceHandler.Sync)
	router.POST("/ansible/inventories/:id/actions/run-command", adHocHandler.RunCommand)
	router.GET("/organizations/:name/ansible/adhoc-modules", adHocHandler.ListModules)
	router.GET("/ansible/inventories/:id/syncs", syncHandler.List)
	router.GET("/ansible/inventory-syncs/:sync_id", syncHandler.Get)

	return &errorEnvelopeFixture{
		router:                   router,
		owner:                    owner,
		orgName:                  orgA.Name,
		inventoryID:              inventory.ID.String(),
		otherProjectID:           projB.ID.String(),
		sourceID:                 source.ID.String(),
		disabledSource:           disabledSource.ID.String(),
		sshCredentialID:          sshCredential.ID.String(),
		scheduleID:               schedule.ID.String(),
		disabledTemplateSchedule: disabledTemplateSchedule.ID.String(),
		orphanSchedule:           orphanSchedule.ID.String(),
		disabledSourceSchedule:   disabledSourceSchedule.ID.String(),
		brokenCronSchedule:       brokenCronSchedule.ID.String(),
	}
}

// scheduleBody is a well-formed schedule create document with the given attributes merged over
// a valid job_template schedule, so each case varies exactly one thing.
func scheduleBody(t *testing.T, overrides map[string]any) string {
	t.Helper()
	attrs := map[string]any{
		"name":            "errenv-created-" + uuid.NewString()[:8],
		"schedule-type":   "job_template",
		"cron-expression": "0 2 * * *",
		"timezone":        "UTC",
	}
	for k, v := range overrides {
		attrs[k] = v
	}
	b, err := json.Marshal(map[string]any{"data": map[string]any{"type": "schedules", "attributes": attrs}})
	if err != nil {
		t.Fatalf("encoding the schedule body: %v", err)
	}
	return string(b)
}

func TestAnsibleErrorEnvelope(t *testing.T) {
	f := setupErrorEnvelope(t)
	missing := uuid.NewString()

	const (
		badRequest = "Bad Request"
		notFound   = "Not Found"
		conflict   = "Conflict"
		internal   = "Internal Server Error"
	)

	cases := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
		wantTitle  string
		wantDetail string
	}{
		// --- schedules ---
		{"schedule: invalid id", http.MethodGet, "/ansible/schedules/not-a-uuid", "", 400, badRequest, "Invalid schedule ID"},
		{"schedule: missing row", http.MethodGet, "/ansible/schedules/" + missing, "", 404, notFound, "Schedule not found"},
		{"schedule: delete with an invalid id", http.MethodDelete, "/ansible/schedules/not-a-uuid", "", 400, badRequest, "Invalid schedule ID"},
		{"schedule: disable a missing row", http.MethodPost, "/ansible/schedules/" + missing + "/actions/disable", "", 404, notFound, "Schedule not found"},
		{"schedule: list in a missing organization", http.MethodGet, "/organizations/errenv-no-such-org/ansible/schedules", "", 404, notFound, "Organization not found"},
		{
			"schedule: create bind failure", http.MethodPost, "/organizations/" + f.orgName + "/ansible/schedules", `{}`, 400, badRequest,
			"Key: 'CreateScheduleRequest.Data.Type' Error:Field validation for 'Type' failed on the 'required' tag\n" +
				"Key: 'CreateScheduleRequest.Data.Attributes.Name' Error:Field validation for 'Name' failed on the 'required' tag\n" +
				"Key: 'CreateScheduleRequest.Data.Attributes.ScheduleType' Error:Field validation for 'ScheduleType' failed on the 'required' tag\n" +
				"Key: 'CreateScheduleRequest.Data.Attributes.CronExpression' Error:Field validation for 'CronExpression' failed on the 'required' tag\n" +
				"Key: 'CreateScheduleRequest.Data.Attributes.Timezone' Error:Field validation for 'Timezone' failed on the 'required' tag",
		},
		{
			"schedule: create with the wrong data.type", http.MethodPost, "/organizations/" + f.orgName + "/ansible/schedules",
			strings.Replace(scheduleBody(t, nil), `"type":"schedules"`, `"type":"widgets"`, 1), 400, badRequest, "data.type must be 'schedules'",
		},
		{
			"schedule: create without the target id", http.MethodPost, "/organizations/" + f.orgName + "/ansible/schedules",
			scheduleBody(t, nil), 400, badRequest, "job-template-id is required for job_template schedules",
		},
		{
			"schedule: update bind failure", http.MethodPatch, "/ansible/schedules/" + f.scheduleID, `[]`, 400, badRequest,
			"json: cannot unmarshal array into Go value of type ansible.UpdateScheduleRequest",
		},
		// Caller-input validation the service performs: a 500 with the same sentence before #857.
		{
			"schedule: create with an invalid cron expression", http.MethodPost, "/organizations/" + f.orgName + "/ansible/schedules",
			scheduleBody(t, map[string]any{"job-template-id": missing, "cron-expression": "* * * *"}), 400, badRequest,
			"invalid cron expression: expected exactly 5 fields, found 4: [* * * *]",
		},
		{
			"schedule: create with an unknown timezone", http.MethodPost, "/organizations/" + f.orgName + "/ansible/schedules",
			scheduleBody(t, map[string]any{"job-template-id": missing, "timezone": "Mars/Olympus_Mons"}), 400, badRequest,
			"invalid timezone: unknown time zone Mars/Olympus_Mons",
		},
		{
			"schedule: create naming a job template that does not exist", http.MethodPost, "/organizations/" + f.orgName + "/ansible/schedules",
			scheduleBody(t, map[string]any{"job-template-id": missing}), 400, badRequest, "job template not found",
		},
		{
			"schedule: update with an invalid cron expression", http.MethodPatch, "/ansible/schedules/" + f.scheduleID,
			`{"cron_expression":"* * * *"}`, 400, badRequest, "invalid cron expression: expected exactly 5 fields, found 4: [* * * *]",
		},
		{
			"schedule: update with an unknown timezone", http.MethodPatch, "/ansible/schedules/" + f.scheduleID,
			`{"timezone":"Mars/Olympus_Mons"}`, 400, badRequest, "invalid timezone: unknown time zone Mars/Olympus_Mons",
		},
		// The sentinel the sibling launch handlers answer with 409.
		{
			"schedule: run-now with a disabled job template", http.MethodPost, "/ansible/schedules/" + f.disabledTemplateSchedule + "/actions/run-now", "",
			409, conflict, "Job template is disabled",
		},
		// 500s that real Postgres can be made to produce. The detail is the operator-authored
		// sentence; the cause (which names internals) goes to the log only.
		{
			"schedule: run-now after its job template was deleted", http.MethodPost, "/ansible/schedules/" + f.orphanSchedule + "/actions/run-now", "",
			500, internal, "Failed to run schedule now",
		},
		{
			"schedule: run-now with a disabled inventory source", http.MethodPost, "/ansible/schedules/" + f.disabledSourceSchedule + "/actions/run-now", "",
			500, internal, "Failed to run schedule now",
		},
		{
			"schedule: enable with a stored cron expression that no longer parses", http.MethodPost, "/ansible/schedules/" + f.brokenCronSchedule + "/actions/enable", "",
			500, internal, "Failed to enable schedule",
		},

		// --- inventory sources ---
		{"source: invalid id", http.MethodGet, "/ansible/inventory-sources/not-a-uuid", "", 400, badRequest, "Invalid inventory source ID"},
		{"source: missing row", http.MethodGet, "/ansible/inventory-sources/" + missing, "", 404, notFound, "Inventory source not found"},
		{"source: list with an invalid inventory id", http.MethodGet, "/ansible/inventories/not-a-uuid/sources", "", 400, badRequest, "Invalid inventory_id"},
		{"source: list in a missing inventory", http.MethodGet, "/ansible/inventories/" + missing + "/sources", "", 404, notFound, "Inventory not found"},
		{
			"source: create bind failure", http.MethodPost, "/ansible/inventories/" + f.inventoryID + "/sources", `{}`, 400, badRequest,
			"Key: 'CreateInventorySourceRequest.Data.Attributes.Name' Error:Field validation for 'Name' failed on the 'required' tag\n" +
				"Key: 'CreateInventorySourceRequest.Data.Attributes.SourceType' Error:Field validation for 'SourceType' failed on the 'required' tag",
		},
		{
			"source: create with a malformed credential id", http.MethodPost, "/ansible/inventories/" + f.inventoryID + "/sources",
			`{"data":{"attributes":{"name":"errenv-x","source-type":"aws","credential-id":"not-a-uuid"}}}`, 400, badRequest, "Invalid credential_id",
		},
		{
			"source: update bind failure", http.MethodPatch, "/ansible/inventory-sources/" + f.sourceID, `[]`, 400, badRequest,
			"json: cannot unmarshal array into Go value of type ansible.UpdateInventorySourceRequest",
		},
		{"source: sync a disabled source", http.MethodPost, "/ansible/inventory-sources/" + f.disabledSource + "/actions/sync", "", 400, badRequest, "Inventory source is disabled"},
		{"source: sync without a queue", http.MethodPost, "/ansible/inventory-sources/" + f.sourceID + "/actions/sync", "", 500, internal, "Sync queue not available"},
		{
			"source: create with a credential of the wrong type", http.MethodPost, "/ansible/inventories/" + f.inventoryID + "/sources",
			`{"data":{"attributes":{"name":"errenv-x","source-type":"aws","credential-id":"` + f.sshCredentialID + `"}}}`, 400, badRequest,
			"credential type ssh is not valid for source type aws",
		},
		{
			"source: create naming a credential that does not exist", http.MethodPost, "/ansible/inventories/" + f.inventoryID + "/sources",
			`{"data":{"attributes":{"name":"errenv-x","source-type":"aws","credential-id":"` + missing + `"}}}`, 400, badRequest, "credential not found",
		},
		{
			"source: create with an unknown Azure auth method", http.MethodPost, "/ansible/inventories/" + f.inventoryID + "/sources",
			`{"data":{"attributes":{"name":"errenv-x","source-type":"azure","config":{"auth_method":"carrier_pigeon"}}}}`, 400, badRequest,
			`invalid auth_method "carrier_pigeon" (want managed_identity|credential|oidc|workload_identity)`,
		},

		// --- ad hoc commands ---
		{"ad hoc: invalid inventory id", http.MethodPost, "/ansible/inventories/not-a-uuid/actions/run-command", `{}`, 400, badRequest, "Invalid inventory ID"},
		{
			"ad hoc: bind failure", http.MethodPost, "/ansible/inventories/" + f.inventoryID + "/actions/run-command", `{}`, 400, badRequest,
			"Key: 'Data.Attributes.Module' Error:Field validation for 'Module' failed on the 'required' tag",
		},
		{
			"ad hoc: missing inventory", http.MethodPost, "/ansible/inventories/" + missing + "/actions/run-command",
			`{"data":{"attributes":{"module":"ping"}}}`, 404, notFound, "Inventory not found",
		},
		{
			"ad hoc: malformed project id", http.MethodPost, "/ansible/inventories/" + f.inventoryID + "/actions/run-command",
			`{"data":{"attributes":{"module":"ping","project-id":"not-a-uuid"}}}`, 400, badRequest, "Invalid project-id",
		},
		{
			"ad hoc: module outside the allowlist", http.MethodPost, "/ansible/inventories/" + f.inventoryID + "/actions/run-command",
			`{"data":{"attributes":{"module":"errenv_forbidden"}}}`, 400, badRequest,
			"Module errenv_forbidden is not in the organization's ad hoc module allowlist",
		},
		{
			"ad hoc: project of another organization", http.MethodPost, "/ansible/inventories/" + f.inventoryID + "/actions/run-command",
			`{"data":{"attributes":{"module":"ping","project-id":"` + f.otherProjectID + `"}}}`, 400, badRequest,
			"inventory does not belong to this organization",
		},
		{"ad hoc: modules of a missing organization", http.MethodGet, "/organizations/errenv-no-such-org/ansible/adhoc-modules", "", 404, notFound, "Organization not found"},

		// --- inventory syncs ---
		{"sync: invalid inventory id", http.MethodGet, "/ansible/inventories/not-a-uuid/syncs", "", 400, badRequest, "Invalid inventory_id"},
		{"sync: list in a missing inventory", http.MethodGet, "/ansible/inventories/" + missing + "/syncs", "", 404, notFound, "Inventory not found"},
		{"sync: invalid id", http.MethodGet, "/ansible/inventory-syncs/not-a-uuid", "", 400, badRequest, "Invalid inventory sync ID"},
		{"sync: missing row", http.MethodGet, "/ansible/inventory-syncs/" + missing, "", 404, notFound, "Inventory sync not found"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("X-Test-User", f.owner.ID.String())
			rec := httptest.NewRecorder()
			f.router.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}

			var top map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &top); err != nil {
				t.Fatalf("body is not a JSON object: %v; body: %s", err, rec.Body.String())
			}
			if _, flat := top["error"]; flat {
				t.Errorf("body carries a top-level `error` key: %s", rec.Body.String())
			}
			var doc struct {
				Errors []struct {
					Status string  `json:"status"`
					Title  string  `json:"title"`
					Detail *string `json:"detail"`
				} `json:"errors"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				t.Fatalf("decoding the errors document: %v; body: %s", err, rec.Body.String())
			}
			if len(doc.Errors) != 1 {
				t.Fatalf("errors has %d entries, want 1; body: %s", len(doc.Errors), rec.Body.String())
			}
			got := doc.Errors[0]
			if want := http.StatusText(tc.wantStatus); tc.wantTitle != want {
				t.Fatalf("test table: title %q does not match status %d (%q)", tc.wantTitle, tc.wantStatus, want)
			}
			if want := strconv.Itoa(tc.wantStatus); got.Status != want {
				t.Errorf("errors[0].status = %q, want %q", got.Status, want)
			}
			if got.Title != tc.wantTitle {
				t.Errorf("errors[0].title = %q, want %q", got.Title, tc.wantTitle)
			}
			if got.Detail == nil {
				t.Fatalf("errors[0].detail is absent, want %q", tc.wantDetail)
			}
			if *got.Detail != tc.wantDetail {
				t.Errorf("errors[0].detail = %q, want %q", *got.Detail, tc.wantDetail)
			}
		})
	}
}
