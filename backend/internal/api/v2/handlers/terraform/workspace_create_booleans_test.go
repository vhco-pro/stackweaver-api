// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The five workspace booleans whose default is true (allow-destroy-plan, queue-all-runs,
// speculative-enabled, file-triggers-enabled, structured-run-output-enabled) must store the value
// a caller sends, false included, on create and on both update routes, and must default to true
// when the attribute is absent. That is what Terraform Enterprise does and what the tfe provider
// relies on: it sends all five on every create and reads them back into state, so a server that
// stored true for a sent false plans a diff on every run.
//
// The defect these tests were written against: the model carried `gorm:"default:true"` on the five
// fields, and GORM substitutes a literal default for a zero value in the INSERT (and writes it back
// into the struct), so a false sent on create was stored as true. The application default lives in
// WorkspaceHandlerV2.Create instead.
//
// These drive the real handler, the real rbac.Service and real Postgres. Gated behind
// `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly row-scoped (the
// database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run 'TestWorkspace(Create|Update)_Boolean'

//go:build integration

package terraform

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// workspaceBooleanAttrs are the JSON:API names of the five booleans, as go-tfe spells them.
var workspaceBooleanAttrs = []string{
	"allow-destroy-plan",
	"queue-all-runs",
	"speculative-enabled",
	"file-triggers-enabled",
	"structured-run-output-enabled",
}

type workspaceBooleansFixture struct {
	router    *gin.Engine
	db        *gorm.DB
	orgName   string
	projectID uuid.UUID
}

// setupWorkspaceBooleans seeds one organization, one project and one owner, and mounts the create,
// read and update routes under the paths the real router uses.
func setupWorkspaceBooleans(t *testing.T) *workspaceBooleansFixture {
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
		&models.Project{}, &models.Workspace{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "wsbool-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "wsbool-" + sfx, Email: "wsbool-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "wsbool-proj-" + sfx}

	seed := []any{
		org, owner, ownersTeam, project,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		// Row-scoped only: TEST_DATABASE_URL may point at a live database. The project is this
		// test's own, so its workspaces are exactly the ones the cases below created.
		db.Where("project_id = ?", project.ID).Delete(&models.Workspace{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", ownersTeam.ID).Delete(&models.Team{})
		db.Where("id = ?", project.ID).Delete(&models.Project{})
		db.Where("organization_id = ?", org.ID).Delete(&models.OrganizationMember{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
		db.Where("id = ?", owner.ID).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	h := NewWorkspaceHandlerV2(
		repository.NewWorkspaceRepository(db),
		projectRepo,
		orgRepo,
		repository.NewVCSConnectionRepository(db),
		teamRepo,
		nil, // poolRepo - only reached for execution-mode "agent"
		nil, // runRepo - unused on these paths
		auth.NewService(repository.NewUserRepository(db)),
		nil, // activityService - logging is skipped when nil
		rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo),
		nil, // vcsRegistry - maybeRegisterADOWebhook is nil-safe
		db,
	)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", owner.ID)
		c.Next()
	})
	router.POST("/api/v2/organizations/:name/workspaces", h.Create)
	router.GET("/api/v2/organizations/:name/workspaces/:workspace_name", h.GetByOrganizationAndName)
	router.PATCH("/api/v2/organizations/:name/workspaces/:workspace_name", h.Update)
	router.GET("/api/v2/workspaces/:id", h.GetByID)
	router.PATCH("/api/v2/workspaces/:id", h.UpdateByID)

	return &workspaceBooleansFixture{router: router, db: db, orgName: org.Name, projectID: project.ID}
}

// do sends one JSON:API request and returns the status with the response's data.id and
// data.attributes.
func (f *workspaceBooleansFixture) do(t *testing.T, method, path string, attrs map[string]any) (int, string, map[string]any) {
	t.Helper()
	body := ""
	if attrs != nil {
		raw, err := json.Marshal(map[string]any{"data": map[string]any{"type": "workspaces", "attributes": attrs}})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		body = string(raw)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	var doc struct {
		Data struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("%s %s: decode response (%d): %v\n%s", method, path, rec.Code, err, rec.Body.String())
	}
	return rec.Code, doc.Data.ID, doc.Data.Attributes
}

// create posts a workspace into the fixture's project with the given extra attributes.
func (f *workspaceBooleansFixture) create(t *testing.T, extra map[string]any) (id, name string, attrs map[string]any) {
	t.Helper()
	name = "wsbool-" + uuid.NewString()[:8]
	body := map[string]any{"name": name, "project-id": f.projectID.String()}
	for k, v := range extra {
		body[k] = v
	}
	code, id, attrs := f.do(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/workspaces", body)
	if code != http.StatusCreated {
		t.Fatalf("create workspace = %d, want 201 (%v)", code, attrs)
	}
	if id == "" {
		t.Fatalf("create workspace returned no id")
	}
	return id, name, attrs
}

// assertBooleans checks the five attributes of one response against want.
func assertBooleans(t *testing.T, where string, got map[string]any, want map[string]bool) {
	t.Helper()
	for _, attr := range workspaceBooleanAttrs {
		v, ok := got[attr].(bool)
		if !ok {
			t.Errorf("%s: %s is %v (%T), want a boolean", where, attr, got[attr], got[attr])
			continue
		}
		if v != want[attr] {
			t.Errorf("%s: %s = %t, want %t", where, attr, v, want[attr])
		}
	}
}

// assertStored reads the workspace back by id and by name and checks the five attributes on both.
func (f *workspaceBooleansFixture) assertStored(t *testing.T, when, id, name string, want map[string]bool) {
	t.Helper()
	for _, read := range []struct{ label, path string }{
		{"GET by id", "/api/v2/workspaces/" + id},
		{"GET by name", "/api/v2/organizations/" + f.orgName + "/workspaces/" + name},
	} {
		code, _, attrs := f.do(t, http.MethodGet, read.path, nil)
		if code != http.StatusOK {
			t.Fatalf("%s, %s = %d, want 200", when, read.label, code)
		}
		assertBooleans(t, when+", "+read.label, attrs, want)
	}
}

// allBooleans returns a want map with every attribute set to v.
func allBooleans(v bool) map[string]bool {
	want := make(map[string]bool, len(workspaceBooleanAttrs))
	for _, attr := range workspaceBooleanAttrs {
		want[attr] = v
	}
	return want
}

// TestWorkspaceCreate_BooleanFalseIsStored: a false sent on create is the value stored and
// returned, for each attribute on its own (the others absent, so they default to true) and for
// all five together.
func TestWorkspaceCreate_BooleanFalseIsStored(t *testing.T) {
	f := setupWorkspaceBooleans(t)

	type tc struct {
		name string
		off  []string
	}
	cases := make([]tc, 0, len(workspaceBooleanAttrs)+1)
	for _, attr := range workspaceBooleanAttrs {
		cases = append(cases, tc{name: attr, off: []string{attr}})
	}
	cases = append(cases, tc{name: "all five", off: workspaceBooleanAttrs})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sent := map[string]any{}
			want := allBooleans(true)
			for _, attr := range c.off {
				sent[attr] = false
				want[attr] = false
			}

			id, name, attrs := f.create(t, sent)
			assertBooleans(t, "201 body", attrs, want)
			f.assertStored(t, "after create", id, name, want)
		})
	}
}

// TestWorkspaceCreate_BooleanDefaults pins the handler's defaults: with the five attributes absent
// the workspace is created with every one of them true.
func TestWorkspaceCreate_BooleanDefaults(t *testing.T) {
	f := setupWorkspaceBooleans(t)

	id, name, attrs := f.create(t, nil)
	assertBooleans(t, "201 body", attrs, allBooleans(true))
	f.assertStored(t, "after create", id, name, allBooleans(true))
}

// TestWorkspaceUpdate_BooleansRoundTrip: both update routes store false then true for each
// attribute, and a PATCH that does not mention the attributes leaves them as they were. The web
// UI uses the route by organization and name, the tfe provider the route by id.
func TestWorkspaceUpdate_BooleansRoundTrip(t *testing.T) {
	f := setupWorkspaceBooleans(t)

	handlers := []struct {
		name string
		path func(id, name string) string
	}{
		{"Update by organization and name", func(_, name string) string {
			return "/api/v2/organizations/" + f.orgName + "/workspaces/" + name
		}},
		{"UpdateByID", func(id, _ string) string { return "/api/v2/workspaces/" + id }},
	}

	for _, h := range handlers {
		t.Run(h.name, func(t *testing.T) {
			id, name, _ := f.create(t, nil)
			path := h.path(id, name)
			want := allBooleans(true)

			patch := func(when string, attrs map[string]any) {
				t.Helper()
				code, _, got := f.do(t, http.MethodPatch, path, attrs)
				if code != http.StatusOK {
					t.Fatalf("%s: PATCH = %d, want 200 (%v)", when, code, got)
				}
				assertBooleans(t, when+", PATCH body", got, want)
				f.assertStored(t, when, id, name, want)
			}

			for _, attr := range workspaceBooleanAttrs {
				want[attr] = false
				patch(attr+" set false", map[string]any{attr: false})
				patch(attr+" omitted while false", map[string]any{"description": "untouched " + attr})

				want[attr] = true
				patch(attr+" set true", map[string]any{attr: true})
				patch(attr+" omitted while true", map[string]any{"description": "untouched again " + attr})

				// Leave it false so the next attribute's cases run against a mixed row, where a
				// handler that wrote one column from another would show.
				want[attr] = false
				patch(attr+" left false", map[string]any{attr: false})
			}
		})
	}
}
