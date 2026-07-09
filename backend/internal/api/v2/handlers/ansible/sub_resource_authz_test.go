// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-100 ansible inventory sub-resource authorization matrix. The hosts, groups,
// inventory-sources and job-template-variable handlers performed NO real
// authorization — HostHandler/GroupHandler held an authService they never called,
// InventorySourceHandler held neither authService nor rbacService, and the
// job-template-variable handler was constructed with a nil rbacService and only
// checked `c.Get("user_id")`. Any authenticated JWT identity (which bypasses the
// org wall) could read/create/modify/delete any tenant's hosts, groups and dynamic
// inventory sources by UUID — including plaintext connection secrets in host/group
// variables — and mutate any tenant's job-template extra-vars. These tests drive
// the real handlers + real rbac.Service + real Postgres and assert cross-tenant and
// unauthenticated callers are denied while a legitimate org member is allowed.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is
// strictly row-scoped (the DB may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestAnsibleSubResourceAuthz

//go:build integration
// +build integration

package ansible

import (
	"net/http"
	"net/http/httptest"
	"os"
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

type ansibleAuthzFixture struct {
	router      *gin.Engine
	owner       *models.User // org A, owners team, project admin
	outsider    *models.User // org B only
	inventoryID string
	hostID      string
	groupID     string
	sourceID    string
	templateID  string
}

func setupAnsibleSubResourceAuthz(t *testing.T) *ansibleAuthzFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.OrganizationMember{},
		&models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{}, &models.TeamProjectAccess{},
		&models.Project{}, &models.AnsibleInventory{}, &models.AnsibleInventoryHost{},
		&models.AnsibleInventoryGroup{}, &models.AnsibleInventorySource{},
		&models.AnsiblePlaybook{}, &models.AnsibleJobTemplate{}, &models.AnsibleJobTemplateVariable{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "ansauthz-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "ansauthz-b-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "ans-own-" + sfx, Email: "ans-own-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "ans-out-" + sfx, Email: "ans-out-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "projA-" + sfx}

	adminAccess := "admin" // cascades ansible read+write to the project's resources
	seed := []interface{}{
		orgA, orgB, owner, outsider, ownersTeam, projA,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: ownersTeam.ID, ProjectID: projA.ID, Access: &adminAccess},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}

	// Repos + services
	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	inventoryRepo := repository.NewAnsibleInventoryRepository(db)
	sourceRepo := repository.NewAnsibleInventorySourceRepository(db)
	credentialRepo := repository.NewAnsibleCredentialRepository(db)
	templateRepo := repository.NewAnsibleJobTemplateRepository(db)
	templateVariableRepo := repository.NewAnsibleJobTemplateVariableRepository(db)

	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo)
	inventoryService := ansiblesvc.NewInventoryService(inventoryRepo, orgRepo)
	sourceService := ansiblesvc.NewInventorySourceService(sourceRepo, inventoryRepo, credentialRepo, nil)

	// Project-scoped inventory with a host, group and dynamic source in org A.
	inventory, err := inventoryService.CreateInventory(
		orgA.ID, &projA.ID, "inv-"+sfx, "", models.InventoryTypeStatic, "", models.InventoryVariables{}, nil, "", "", "",
	)
	if err != nil {
		t.Fatalf("create inventory: %v", err)
	}
	host, err := inventoryService.CreateHost(inventory.ID, "host-"+sfx, "", "10.0.0.1", 22, models.InventoryVariables{"ansible_password": "s3cret"}, true)
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	group, err := inventoryService.CreateGroup(inventory.ID, "group-"+sfx, "", models.InventoryVariables{}, nil)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	source, err := sourceService.CreateInventorySource(inventory.ID, "src-"+sfx, "", models.InventorySourceTypeCustom, nil, models.InventorySourceConfig{})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}

	// Job template (+ one variable) in project A for the vars endpoints.
	playbook := &models.AnsiblePlaybook{ID: uuid.New(), ProjectID: projA.ID, Name: "pb-" + sfx, PlaybookPath: "site.yml", SourceMode: "cached"}
	if err := db.Create(playbook).Error; err != nil {
		t.Fatalf("seed playbook: %v", err)
	}
	template := &models.AnsibleJobTemplate{ID: uuid.New(), ProjectID: projA.ID, PlaybookID: playbook.ID, InventoryID: inventory.ID, Name: "tmpl-" + sfx}
	if err := db.Create(template).Error; err != nil {
		t.Fatalf("seed job template: %v", err)
	}
	tvar := &models.AnsibleJobTemplateVariable{ID: "var-" + sfx + "00000000", JobTemplateID: template.ID, Key: "k", Value: "v", Category: "env"}
	if err := db.Create(tvar).Error; err != nil {
		t.Fatalf("seed template var: %v", err)
	}

	t.Cleanup(func() {
		// Children before parents (FK order).
		db.Where("job_template_id = ?", template.ID).Delete(&models.AnsibleJobTemplateVariable{})
		db.Where("id = ?", template.ID).Delete(&models.AnsibleJobTemplate{})
		db.Where("id = ?", playbook.ID).Delete(&models.AnsiblePlaybook{})
		db.Where("inventory_id = ?", inventory.ID).Delete(&models.AnsibleInventorySource{})
		db.Where("inventory_id = ?", inventory.ID).Delete(&models.AnsibleInventoryHost{})
		db.Where("inventory_id = ?", inventory.ID).Delete(&models.AnsibleInventoryGroup{})
		db.Where("id = ?", inventory.ID).Delete(&models.AnsibleInventory{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamProjectAccess{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", ownersTeam.ID).Delete(&models.Team{})
		db.Where("id = ?", projA.ID).Delete(&models.Project{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{owner.ID, outsider.ID}).Delete(&models.User{})
	})

	hostHandler := NewHostHandler(inventoryService, inventoryRepo, authService, rbacService)
	groupHandler := NewGroupHandler(inventoryService, inventoryRepo, authService, rbacService)
	sourceHandler := NewInventorySourceHandler(sourceService, inventoryService, authService, rbacService, nil)
	tvarHandler := NewJobTemplateVariableHandlerV2(templateVariableRepo, templateRepo, authService, rbacService, nil)
	tvarHandler.SetRepositories(orgRepo, projectRepo)

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
	router.GET("/ansible/inventories/:id/hosts", hostHandler.List)
	router.GET("/ansible/hosts/:id", hostHandler.Get)
	router.DELETE("/ansible/hosts/:id", hostHandler.Delete)
	router.GET("/ansible/groups/:id", groupHandler.Get)
	router.GET("/ansible/inventory-sources/:source_id", sourceHandler.Get)
	router.POST("/ansible/inventory-sources/:source_id/sync", sourceHandler.Sync)
	router.GET("/ansible/job-templates/:id/vars", tvarHandler.ListByJobTemplate)

	return &ansibleAuthzFixture{
		router:      router,
		owner:       owner,
		outsider:    outsider,
		inventoryID: inventory.ID.String(),
		hostID:      host.ID.String(),
		groupID:     group.ID.String(),
		sourceID:    source.ID.String(),
		templateID:  template.ID.String(),
	}
}

func ansAuthzReq(t *testing.T, f *ansibleAuthzFixture, method, path string, asUser uuid.UUID) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if asUser != uuid.Nil {
		req.Header.Set("X-Test-User", asUser.String())
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec.Code
}

// TestAnsibleSubResourceAuthz_CrossTenantDenied is the core AUD-100 assertion: an
// org-B outsider must not reach any org-A sub-resource endpoint, and anonymous
// callers get 401.
func TestAnsibleSubResourceAuthz_CrossTenantDenied(t *testing.T) {
	f := setupAnsibleSubResourceAuthz(t)

	cases := []struct{ m, p string }{
		{http.MethodGet, "/ansible/inventories/" + f.inventoryID + "/hosts"},
		{http.MethodGet, "/ansible/hosts/" + f.hostID},
		{http.MethodDelete, "/ansible/hosts/" + f.hostID},
		{http.MethodGet, "/ansible/groups/" + f.groupID},
		{http.MethodGet, "/ansible/inventory-sources/" + f.sourceID},
		{http.MethodPost, "/ansible/inventory-sources/" + f.sourceID + "/sync"},
		{http.MethodGet, "/ansible/job-templates/" + f.templateID + "/vars"},
	}
	for _, e := range cases {
		t.Run("outsider "+e.m+" "+e.p, func(t *testing.T) {
			if code := ansAuthzReq(t, f, e.m, e.p, f.outsider.ID); code != http.StatusForbidden {
				t.Fatalf("outsider %s %s = %d, want 403", e.m, e.p, code)
			}
		})
		t.Run("anon "+e.m+" "+e.p, func(t *testing.T) {
			if code := ansAuthzReq(t, f, e.m, e.p, uuid.Nil); code != http.StatusUnauthorized {
				t.Fatalf("anon %s %s = %d, want 401", e.m, e.p, code)
			}
		})
	}
}

// TestAnsibleSubResourceAuthz_OwnerAllowed confirms a legitimate org member (owners
// team, admin project access) can still read their own sub-resources — the gates
// must not break the happy path.
func TestAnsibleSubResourceAuthz_OwnerAllowed(t *testing.T) {
	f := setupAnsibleSubResourceAuthz(t)
	reads := []string{
		"/ansible/hosts/" + f.hostID,
		"/ansible/groups/" + f.groupID,
		"/ansible/inventory-sources/" + f.sourceID,
		"/ansible/job-templates/" + f.templateID + "/vars",
	}
	for _, p := range reads {
		if code := ansAuthzReq(t, f, http.MethodGet, p, f.owner.ID); code != http.StatusOK {
			t.Fatalf("owner GET %s = %d, want 200", p, code)
		}
	}
}
