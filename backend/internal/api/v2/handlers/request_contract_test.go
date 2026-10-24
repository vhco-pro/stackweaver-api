// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The request and response contract of the platform endpoints #858 converted onto JSON:API (D6,
// AC2). The golden corpus pins the accepted write of each; this pins what the corpus cannot
// see: the 400 a flat body gets on the routes the error harness cannot reach (the JWT-only token
// create), the 400 a wrong data.type gets, the installation_id refusal inside a document, and
// the VCS listings, which the corpus records as 404 because no connection is seeded, through a
// fake provider. The GitHub App installation steps are pinned beside their flow in
// vcs_github_installation_access_test.go, whose fixture already mints the signed states.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestPlatformRequestContract

//go:build integration

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/activity"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"github.com/michielvha/stackweaver/core/storage/storagetest"
)

// contractProvider is a VCS provider that pages a fixed set of repositories, projects and
// branches and lists a fixed file tree. Every other method is the embedded nil interface and is
// never called by the handlers under test.
type contractProvider struct {
	vcs.ProviderService
	repos    []vcs.Repository
	projects []vcs.Project
	branches []vcs.Branch
	files    []string
}

func pageOf[T any](rows []T, page, perPage int) []T {
	start := (page - 1) * perPage
	if start >= len(rows) {
		return nil
	}
	return rows[start:min(start+perPage, len(rows))]
}

func (p contractProvider) ListRepositories(_ context.Context, _ *models.VCSConnection, page, perPage int) ([]vcs.Repository, error) {
	return pageOf(p.repos, page, perPage), nil
}

func (p contractProvider) ListProjects(_ context.Context, _ *models.VCSConnection, page, perPage int) ([]vcs.Project, error) {
	return pageOf(p.projects, page, perPage), nil
}

func (p contractProvider) ListBranches(_ context.Context, _ *models.VCSConnection, _, _ string, page, perPage int) ([]vcs.Branch, error) {
	return pageOf(p.branches, page, perPage), nil
}

func (p contractProvider) ListFiles(context.Context, *models.VCSConnection, string, string, string, []string) ([]string, error) {
	return p.files, nil
}

func (p contractProvider) GetFileContent(_ context.Context, _ *models.VCSConnection, _, _, path, _ string) (string, error) {
	return "contents of " + path, nil
}

type contractProviders struct{ provider vcs.ProviderService }

func (p contractProviders) GetProvider(*models.VCSConnection) (vcs.ProviderService, error) {
	return p.provider, nil
}

type platformContractFixture struct {
	router  *gin.Engine
	owner   uuid.UUID
	orgName string
	orgID   uuid.UUID
	connID  string
	modules func() int64
}

func setupPlatformContract(t *testing.T) *platformContractFixture {
	t.Helper()
	db := setupTestDB(t)
	if err := db.AutoMigrate(&models.VCSConnection{}, &models.APIKey{}, &models.AuditLog{}, &models.Project{}, &models.TeamProjectAccess{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	org := setupTestOrg(t, db)
	owner := createRegistryTestUser(t, db)
	if err := db.Create(&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: owner.ID}).Error; err != nil {
		t.Fatalf("seed organization member: %v", err)
	}
	makeUserOrgOwner(t, db, org, owner)
	conn := &models.VCSConnection{ID: uuid.New(), OrganizationID: org.ID, Provider: models.VCSProviderGitHub, AccountName: "contract-" + uuid.NewString()[:8], AccountType: "organization"}
	orgID := org.ID
	audits := make([]*models.AuditLog, 0, 3)
	for range 3 {
		audits = append(audits, &models.AuditLog{ID: uuid.New(), OrganizationID: &orgID, Action: "create", ResourceType: "workspace"})
	}
	for _, row := range []any{conn, audits[0], audits[1], audits[2]} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	t.Cleanup(func() {
		// Registered after setupTestOrg, so it runs first.
		db.Where("organization_id = ?", org.ID).Delete(&models.AuditLog{})
		db.Where("user_id = ?", owner.ID).Delete(&models.APIKey{})
		db.Exec("DELETE FROM module_versions WHERE module_id IN (SELECT id FROM modules WHERE organization_id = ?)", org.ID)
		db.Where("organization_id = ?", org.ID).Delete(&models.Module{})
		db.Where("organization_id = ?", org.ID).Delete(&models.VCSConnection{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := newProviderRBAC(db)
	connRepo := repository.NewVCSConnectionRepository(db)
	moduleRepo := repository.NewModuleRepository(db)
	moduleVersionRepo := repository.NewModuleVersionRepository(db)

	tokens := NewTokenHandlerV2(apikey.NewService(repository.NewAPIKeyRepository(db), orgRepo, projectRepo, teamRepo), authService)
	vcsHandler := NewVCSConnectionHandlerV2(connRepo, orgRepo, authService, nil, rbacService)
	repos := make([]vcs.Repository, 0, 35)
	for i := range 35 {
		repos = append(repos, vcs.Repository{ID: int64(1000 + i), Name: "repo-" + strconv.Itoa(i), FullName: "acme/repo-" + strconv.Itoa(i), DefaultBranch: "main"})
	}
	vcsHandler.providers = contractProviders{provider: contractProvider{
		repos:    repos,
		projects: []vcs.Project{{ID: "p1", Name: "Platform"}, {ID: "p2", Name: "Apps"}},
		branches: []vcs.Branch{{Name: "main", Protected: true}, {Name: "develop"}},
		files:    []string{"inventories/prod.ini", "site.yml"},
	}}
	modules := NewRegistryPublishingHandler(moduleRepo, moduleVersionRepo, orgRepo, connRepo, authService, rbacService, nil,
		registry.NewModulePublisher(moduleRepo, moduleVersionRepo, orgRepo, connRepo, storagetest.NewMemory()))
	activities := NewActivityHandlerV2(activity.NewService(repository.NewAuditLogRepository(db)), authService, orgRepo,
		repository.NewWorkspaceRepository(db), projectRepo, nil, rbacService)

	router := storedAsSentRouter()
	router.POST("/tokens", tokens.Create)
	router.POST("/organizations/:name/vcs-connections", vcsHandler.Create)
	router.GET("/vcs-connections/:id/repositories", vcsHandler.ListRepositories)
	router.GET("/vcs-connections/:id/projects", vcsHandler.ListProjects)
	router.GET("/vcs-connections/:id/repositories/:owner/:repo/branches", vcsHandler.ListBranches)
	router.GET("/vcs-connections/:id/repositories/:owner/:repo/contents/*path", vcsHandler.GetFileContent)
	router.GET("/vcs-connections/:id/repositories/:owner/:repo/yaml-files", vcsHandler.ListYamlFiles)
	router.GET("/vcs-connections/:id/repositories/:owner/:repo/inventory-files", vcsHandler.ListInventoryFiles)
	router.POST("/organizations/:name/registry/modules", modules.CreateModule)
	router.DELETE("/organizations/:name/registry/modules", modules.DeleteAllModules)
	router.GET("/activities", activities.ListActivities)

	return &platformContractFixture{
		router:  router,
		owner:   owner.ID,
		orgName: org.Name,
		orgID:   org.ID,
		connID:  conn.ID.String(),
		modules: func() int64 {
			var n int64
			db.Model(&models.Module{}).Where("organization_id = ?", org.ID).Count(&n)
			return n
		},
	}
}

type platformDoc struct {
	Data   json.RawMessage `json:"data"`
	Meta   map[string]any  `json:"meta"`
	Errors []struct {
		Detail string `json:"detail"`
	} `json:"errors"`
}

type platformResource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes"`
}

func (f *platformContractFixture) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/vnd.api+json")
	r.Header.Set("X-Test-User", f.owner.String())
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	return rec.Code, rec.Body.Bytes()
}

func (f *platformContractFixture) refused(t *testing.T, method, path, body, want string) {
	t.Helper()
	code, raw := f.call(t, method, path, body)
	var doc platformDoc
	_ = json.Unmarshal(raw, &doc)
	if code != http.StatusBadRequest || len(doc.Errors) != 1 || doc.Errors[0].Detail != want {
		t.Errorf("%s %s with %s: got %d %s\n want 400 with detail %q", method, path, body, code, raw, want)
	}
}

func (f *platformContractFixture) accepted(t *testing.T, method, path, body string, want int) platformDoc {
	t.Helper()
	code, raw := f.call(t, method, path, body)
	if code != want {
		t.Fatalf("%s %s with %s: got %d %s, want %d", method, path, body, code, raw, want)
	}
	var doc platformDoc
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s %s: the answer is not JSON: %v (%s)", method, path, err, raw)
		}
	}
	return doc
}

func platformRows(t *testing.T, doc platformDoc, wantType string) []platformResource {
	t.Helper()
	var rows []platformResource
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

func platformDocRequired(resourceType string) string {
	return `request body must be a JSON:API document: {"data": {"type": "` + resourceType + `", "attributes": {...}}}`
}

// pageBlock returns meta.pagination with each member as JSON-decoded, null kept as nil.
func pageBlock(t *testing.T, doc platformDoc) map[string]any {
	t.Helper()
	p, ok := doc.Meta["pagination"].(map[string]any)
	if !ok {
		t.Fatalf("no meta.pagination: %v", doc.Meta)
	}
	for _, member := range []string{"current-page", "page-size", "prev-page", "next-page", "total-pages", "total-count"} {
		if _, present := p[member]; !present {
			t.Errorf("meta.pagination lacks %s: %v", member, p)
		}
	}
	return p
}

func TestPlatformRequestContract(t *testing.T) {
	f := setupPlatformContract(t)

	t.Run("a token is minted from a tokens document", func(t *testing.T) {
		f.refused(t, http.MethodPost, "/tokens", `{"description":"laptop"}`, platformDocRequired("tokens"))
		f.refused(t, http.MethodPost, "/tokens", `{}`, platformDocRequired("tokens"))
		f.refused(t, http.MethodPost, "/tokens", `{"data":{"type":"authentication-tokens","attributes":{}}}`, `data.type must be "tokens" (got "authentication-tokens")`)
		doc := f.accepted(t, http.MethodPost, "/tokens", `{"data":{"type":"tokens","attributes":{"description":"contract laptop"}}}`, http.StatusCreated)
		var res platformResource
		if err := json.Unmarshal(doc.Data, &res); err != nil || res.Type != "tokens" || res.Attributes["token"] == "" || res.Attributes["description"] != "contract laptop" {
			t.Errorf("minted %s", doc.Data)
		}
	})

	t.Run("a VCS connection is created from a vcs-connections document", func(t *testing.T) {
		path := "/organizations/" + f.orgName + "/vcs-connections"
		// Azure DevOps, because the fixture already holds the organization's one GitHub connection
		// and GitLab is refused until it is implemented (#114).
		attrs := `"provider":"azure_devops","access_token":"ado-contract","account_name":"contract","account_type":"organization"`
		f.refused(t, http.MethodPost, path, `{`+attrs+`}`, platformDocRequired("vcs-connections"))
		// A flat body naming an installation is simply not a document.
		f.refused(t, http.MethodPost, path, `{`+attrs+`,"installation_id":"42"}`, platformDocRequired("vcs-connections"))
		f.refused(t, http.MethodPost, path, `{"data":{"type":"vcs-connections","attributes":{`+attrs+`,"installation_id":"42"}}}`, installationIDRefusal)
		f.refused(t, http.MethodPost, path, `{"data":{"type":"oauth-clients","attributes":{`+attrs+`}}}`, `data.type must be "vcs-connections" (got "oauth-clients")`)
		for _, unimplemented := range []string{"gitlab", "bitbucket"} {
			f.refused(t, http.MethodPost, path, `{"data":{"type":"vcs-connections","attributes":{"provider":"`+unimplemented+`","access_token":"t","account_name":"contract","account_type":"organization"}}}`, "Invalid provider. Must be 'github' or 'azure_devops'")
		}
		doc := f.accepted(t, http.MethodPost, path, `{"data":{"type":"vcs-connections","attributes":{`+attrs+`}}}`, http.StatusCreated)
		var res platformResource
		if err := json.Unmarshal(doc.Data, &res); err != nil || res.Type != "vcs-connections" {
			t.Errorf("created %s", doc.Data)
		}
	})

	base := "/vcs-connections/" + f.connID
	t.Run("repositories are vcs-repositories resources with the provider block", func(t *testing.T) {
		full := f.accepted(t, http.MethodGet, base+"/repositories?page=1&per_page=30", "", http.StatusOK)
		rows := platformRows(t, full, "vcs-repositories")
		if len(rows) != 30 || rows[0].ID != "1000" || rows[0].Attributes["full-name"] != "acme/repo-0" || rows[0].Attributes["default-branch"] != "main" {
			t.Errorf("first page: %d rows, first %+v", len(rows), rows[0])
		}
		p := pageBlock(t, full)
		if p["next-page"] != float64(2) || p["total-count"] != nil || p["total-pages"] != nil {
			t.Errorf("a full page: %v, want next-page 2 and null totals", p)
		}
		short := f.accepted(t, http.MethodGet, base+"/repositories?page=2&per_page=30", "", http.StatusOK)
		if rows := platformRows(t, short, "vcs-repositories"); len(rows) != 5 {
			t.Errorf("second page holds %d rows, want 5", len(rows))
		}
		if p := pageBlock(t, short); p["next-page"] != nil || p["prev-page"] != float64(1) {
			t.Errorf("a short page: %v, want no next page", p)
		}
	})

	t.Run("projects and branches are resources with the provider block", func(t *testing.T) {
		projects := f.accepted(t, http.MethodGet, base+"/projects", "", http.StatusOK)
		if rows := platformRows(t, projects, "vcs-projects"); len(rows) != 2 || rows[0].ID != "p1" || rows[0].Attributes["name"] != "Platform" {
			t.Errorf("projects: %s", projects.Data)
		}
		pageBlock(t, projects)
		branches := f.accepted(t, http.MethodGet, base+"/repositories/acme/infra/branches", "", http.StatusOK)
		rows := platformRows(t, branches, "vcs-branches")
		if len(rows) != 2 || rows[0].ID != "main" || rows[0].Attributes["protected"] != true {
			t.Errorf("branches: %s", branches.Data)
		}
		pageBlock(t, branches)
	})

	t.Run("files are vcs-files resources keyed by path", func(t *testing.T) {
		content := f.accepted(t, http.MethodGet, base+"/repositories/acme/infra/contents/site.yml?ref=main", "", http.StatusOK)
		var file platformResource
		if err := json.Unmarshal(content.Data, &file); err != nil || file.Type != "vcs-files" || file.ID != "site.yml" ||
			file.Attributes["content"] != "contents of site.yml" || file.Attributes["ref"] != "main" {
			t.Errorf("file content: %s", content.Data)
		}
		for _, listing := range []string{"yaml-files", "inventory-files"} {
			doc := f.accepted(t, http.MethodGet, base+"/repositories/acme/infra/"+listing, "", http.StatusOK)
			if rows := platformRows(t, doc, "vcs-files"); len(rows) == 0 {
				t.Errorf("%s listed nothing: %s", listing, doc.Data)
			}
			if p := pageBlock(t, doc); p["next-page"] != nil || p["total-count"] != nil {
				t.Errorf("%s: an unpaged provider listing states a next page or a total: %v", listing, p)
			}
		}
	})

	t.Run("a registry module is created from a document and delete-all answers 204", func(t *testing.T) {
		path := "/organizations/" + f.orgName + "/registry/modules"
		f.refused(t, http.MethodPost, path, `{"name":"vpc","provider":"aws"}`, platformDocRequired("registry-modules"))
		f.refused(t, http.MethodPost, path, `{"data":{"type":"modules","attributes":{"name":"vpc","provider":"aws"}}}`, `data.type must be "registry-modules" (got "modules")`)
		doc := f.accepted(t, http.MethodPost, path, `{"data":{"type":"registry-modules","attributes":{"name":"vpc","provider":"aws","description":"contract"}}}`, http.StatusCreated)
		var res platformResource
		if err := json.Unmarshal(doc.Data, &res); err != nil || res.Type != "registry-modules" {
			t.Errorf("created %s", doc.Data)
		}
		code, raw := f.call(t, http.MethodDelete, path, "")
		if code != http.StatusNoContent || len(raw) != 0 {
			t.Errorf("delete-all: %d %s, want 204 with no body", code, raw)
		}
		if n := f.modules(); n != 0 {
			t.Errorf("%d module(s) left after delete-all", n)
		}
	})

	t.Run("activities page by number with the standard block", func(t *testing.T) {
		doc := f.accepted(t, http.MethodGet, "/activities?organization_id="+f.orgID.String()+"&page%5Bnumber%5D=1&page%5Bsize%5D=2", "", http.StatusOK)
		if rows := platformRows(t, doc, "activity"); len(rows) != 2 {
			t.Errorf("first page holds %d activities, want 2", len(rows))
		}
		p := pageBlock(t, doc)
		if p["total-count"] != float64(3) || p["next-page"] != float64(2) || p["page-size"] != float64(2) {
			t.Errorf("activities pagination: %v, want total-count 3, next-page 2, page-size 2", p)
		}
		second := f.accepted(t, http.MethodGet, "/activities?organization_id="+f.orgID.String()+"&page%5Bnumber%5D=2&page%5Bsize%5D=2", "", http.StatusOK)
		if rows := platformRows(t, second, "activity"); len(rows) != 1 {
			t.Errorf("second page holds %d activities, want 1", len(rows))
		}
	})
}

// The account surface carries the profile (#858, D8): GET /account/details answers the users
// resource with the profile attributes, and PATCH /account/update takes a users document whose
// omitted attributes are left as they are. InteractiveOnly is the route's concern and is proven
// by the routes package; the handler is mounted here for shape.
func TestAccountContract(t *testing.T) {
	db := setupTestDB(t)
	user := createRegistryTestUser(t, db)
	if err := db.Model(user).Updates(map[string]any{"name": "Ada Lovelace", "username": "ada", "bio": "Analyst", "company": "Engines", "location": "London"}).Error; err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	h := NewAccountHandlerV2(auth.NewService(repository.NewUserRepository(db)), repository.NewUserRepository(db), nil)
	router := storedAsSentRouter()
	router.GET("/account/details", h.Details)
	router.PATCH("/account/update", h.Update)
	f := &platformContractFixture{router: router, owner: user.ID}

	details := func(t *testing.T) platformResource {
		t.Helper()
		doc := f.accepted(t, http.MethodGet, "/account/details", "", http.StatusOK)
		var res platformResource
		if err := json.Unmarshal(doc.Data, &res); err != nil || res.Type != "users" || res.ID != user.ID.String() {
			t.Fatalf("details: %s", doc.Data)
		}
		return res
	}

	t.Run("details carry the profile", func(t *testing.T) {
		attrs := details(t).Attributes
		for name, want := range map[string]any{"username": "ada", "name": "Ada Lovelace", "bio": "Analyst", "company": "Engines", "location": "London"} {
			if attrs[name] != want {
				t.Errorf("%s = %v, want %v", name, attrs[name], want)
			}
		}
		for _, name := range []string{"created-at", "updated-at", "avatar-url", "email"} {
			if _, present := attrs[name]; !present {
				t.Errorf("details lack %s: %v", name, attrs)
			}
		}
	})

	t.Run("update takes a users document", func(t *testing.T) {
		f.refused(t, http.MethodPatch, "/account/update", `{}`, platformDocRequired("users"))
		f.refused(t, http.MethodPatch, "/account/update", `{"bio":"x"}`, platformDocRequired("users"))
		f.refused(t, http.MethodPatch, "/account/update", `{"data":{"type":"accounts","attributes":{"bio":"x"}}}`, `data.type must be "users" (got "accounts")`)
		doc := f.accepted(t, http.MethodPatch, "/account/update", `{"data":{"type":"users","attributes":{"bio":"Poet","location":""}}}`, http.StatusOK)
		var res platformResource
		if err := json.Unmarshal(doc.Data, &res); err != nil || res.Type != "users" || res.Attributes["bio"] != "Poet" || res.Attributes["location"] != "" {
			t.Errorf("update answered %s", doc.Data)
		}
		attrs := details(t).Attributes
		if attrs["bio"] != "Poet" || attrs["location"] != "" || attrs["company"] != "Engines" || attrs["name"] != "Ada Lovelace" {
			t.Errorf("after the update: %v; the sent attributes change and the omitted ones stay", attrs)
		}
	})
}
