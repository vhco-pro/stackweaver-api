// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the organization request contract (#844, AC1 and AC2): the create and
// update endpoints accept the JSON:API document go-tfe sends and nothing else.
//
// They drive the real handlers against real Postgres because the interesting half is what does
// NOT happen: a flat body must not create an organization named "" or silently no-op an update.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the dev DB has no backup): every row is found through the IDs or the unique names
// this test generated. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestOrganizationRequestContract

//go:build integration

package handlers

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
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// orgContractErrors is the JSON:API error envelope the contract tests read.
type orgContractErrors struct {
	Errors []struct {
		Status string `json:"status"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	} `json:"errors"`
}

const orgDocumentRequiredDetail = `request body must be a JSON:API document: {"data": {"type": "organizations", "attributes": {...}}}`

func TestOrganizationRequestContract(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.ReservedOrganizationName{},
		&models.OrganizationMember{}, &models.Team{}, &models.TeamMember{},
		&models.TeamOrganizationAccess{}, &models.Project{}, &models.TeamProjectAccess{},
		&models.AgentPool{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	creator := &models.User{ID: uuid.New(), ZitadelSubject: "orgc-own-" + sfx, Email: "orgc-own-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "orgc-out-" + sfx, Email: "orgc-out-" + sfx + "@test.local"}
	for _, u := range []*models.User{creator, outsider} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}

	// Every organization name this test may create, successfully or by a regression. Cleanup
	// walks this list, so a body that wrongly creates an organization is still removed.
	createdName := "orgc-ok-" + sfx
	flatName := "orgc-flat-" + sfx
	wrongTypeName := "orgc-type-" + sfx
	names := []string{createdName, flatName, wrongTypeName}

	t.Cleanup(func() {
		var orgIDs []uuid.UUID
		db.Model(&models.Organization{}).Where("name IN ?", names).Pluck("id", &orgIDs)
		if len(orgIDs) > 0 {
			var teamIDs []uuid.UUID
			db.Model(&models.Team{}).Where("organization_id IN ?", orgIDs).Pluck("id", &teamIDs)
			if len(teamIDs) > 0 {
				db.Where("team_id IN ?", teamIDs).Delete(&models.TeamMember{})
				db.Where("team_id IN ?", teamIDs).Delete(&models.TeamOrganizationAccess{})
				db.Where("team_id IN ?", teamIDs).Delete(&models.TeamProjectAccess{})
			}
			db.Model(&models.Organization{}).Where("id IN ?", orgIDs).Update("default_agent_pool_id", nil)
			db.Where("organization_id IN ?", orgIDs).Delete(&models.AgentPool{})
			db.Where("organization_id IN ?", orgIDs).Delete(&models.Team{})
			db.Where("organization_id IN ?", orgIDs).Delete(&models.OrganizationMember{})
			db.Where("organization_id IN ?", orgIDs).Delete(&models.Project{})
			db.Where("id IN ?", orgIDs).Delete(&models.Organization{})
		}
		db.Where("name IN ?", names).Delete(&models.ReservedOrganizationName{})
		db.Where("id IN ?", []uuid.UUID{creator.ID, outsider.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	agentPoolRepo := repository.NewAgentPoolRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo)
	orgH := NewOrganizationHandlerV2(orgRepo, teamRepo, projectRepo, agentPoolRepo, authService, nil, rbacService, db)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if id, err := uuid.Parse(c.GetHeader("X-Test-User")); err == nil {
			c.Set("user_id", id)
		}
		c.Next()
	})
	router.POST("/organizations", orgH.Create)
	router.PATCH("/organizations/:name", orgH.Update)

	call := func(t *testing.T, method, path string, asUser uuid.UUID, body string) (int, []byte) {
		t.Helper()
		r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
		// go-tfe's content type; the frontend sends application/json and both are accepted.
		r.Header.Set("Content-Type", "application/vnd.api+json")
		r.Header.Set("X-Test-User", asUser.String())
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, r)
		return rec.Code, rec.Body.Bytes()
	}

	wantBadRequest := func(t *testing.T, code int, body []byte, wantDetail string) {
		t.Helper()
		if code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", code, body)
		}
		var doc orgContractErrors
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("response is not a JSON:API error document: %v (%s)", err, body)
		}
		if len(doc.Errors) != 1 {
			t.Fatalf("errors has %d entries, want 1 (%s)", len(doc.Errors), body)
		}
		got := doc.Errors[0]
		if got.Status != "400" || got.Title != "Bad Request" || got.Detail != wantDetail {
			t.Errorf("error = %+v, want status 400, title Bad Request, detail %q", got, wantDetail)
		}
	}

	orgExists := func(t *testing.T, name string) bool {
		t.Helper()
		var n int64
		if err := db.Model(&models.Organization{}).Where("name = ?", name).Count(&n).Error; err != nil {
			t.Fatalf("counting organizations named %q: %v", name, err)
		}
		return n > 0
	}

	t.Run("create rejects a body that is not a JSON:API document", func(t *testing.T) {
		tests := []struct {
			name       string
			body       string
			wantDetail string
		}{
			{"flat body", `{"name":"` + flatName + `"}`, orgDocumentRequiredDetail},
			{"flat body with email", `{"name":"` + flatName + `","email":"x@test.local"}`, orgDocumentRequiredDetail},
			{"empty object", `{}`, orgDocumentRequiredDetail},
			{"null data", `{"data":null}`, orgDocumentRequiredDetail},
			{
				"wrong data.type",
				`{"data":{"type":"workspaces","attributes":{"name":"` + wrongTypeName + `"}}}`,
				`data.type must be "organizations" (got "workspaces")`,
			},
			{
				"missing data.type",
				`{"data":{"attributes":{"name":"` + wrongTypeName + `"}}}`,
				`data.type must be "organizations" (got "")`,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				code, body := call(t, http.MethodPost, "/organizations", creator.ID, tt.body)
				wantBadRequest(t, code, body, tt.wantDetail)
			})
		}
		for _, name := range []string{flatName, wrongTypeName} {
			if orgExists(t, name) {
				t.Errorf("a rejected body created organization %q", name)
			}
		}
	})

	t.Run("create takes name, email and description from data.attributes", func(t *testing.T) {
		// The document go-tfe marshals for OrganizationCreateOptions{Name, Email}, plus the
		// description extension the Stackweaver UI sends.
		doc := `{"data":{"type":"organizations","attributes":{"name":"` + createdName +
			`","email":"ops-` + sfx + `@test.local","description":"Platform team"}}}`
		code, body := call(t, http.MethodPost, "/organizations", creator.ID, doc)
		if code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body %s)", code, body)
		}
		var resp struct {
			Data struct {
				ID         string `json:"id"`
				Type       string `json:"type"`
				Attributes struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("response is not JSON: %v (%s)", err, body)
		}
		if resp.Data.Type != "organizations" || resp.Data.ID != createdName {
			t.Errorf("resource = %s/%s, want organizations/%s", resp.Data.Type, resp.Data.ID, createdName)
		}
		if resp.Data.Attributes.Email != "ops-"+sfx+"@test.local" {
			t.Errorf("response email = %q", resp.Data.Attributes.Email)
		}

		var org models.Organization
		if err := db.Where("name = ?", createdName).First(&org).Error; err != nil {
			t.Fatalf("loading created organization: %v", err)
		}
		if org.Email != "ops-"+sfx+"@test.local" {
			t.Errorf("persisted email = %q, want the attribute value", org.Email)
		}
		if org.Description != "Platform team" {
			t.Errorf("persisted description = %q, want the attribute value", org.Description)
		}
	})

	if !orgExists(t, createdName) {
		t.Fatal("the organization the update tests need was not created")
	}
	orgPath := "/organizations/" + createdName

	t.Run("update rejects a body that is not a JSON:API document", func(t *testing.T) {
		tests := []struct {
			name       string
			body       string
			wantDetail string
		}{
			// A 200 no-op until the flat fields went: an empty object updated nothing and said so.
			{"empty object", `{}`, orgDocumentRequiredDetail},
			{"flat description", `{"description":"changed by a flat body"}`, orgDocumentRequiredDetail},
			{"flat name", `{"name":"` + flatName + `"}`, orgDocumentRequiredDetail},
			{
				"wrong data.type",
				`{"data":{"type":"workspaces","attributes":{"description":"changed by a mistyped document"}}}`,
				`data.type must be "organizations" (got "workspaces")`,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				code, body := call(t, http.MethodPatch, orgPath, creator.ID, tt.body)
				wantBadRequest(t, code, body, tt.wantDetail)
			})
		}
		var org models.Organization
		if err := db.Where("name = ?", createdName).First(&org).Error; err != nil {
			t.Fatalf("a rejected update renamed or removed the organization: %v", err)
		}
		if org.Description != "Platform team" {
			t.Errorf("a rejected update changed the description to %q", org.Description)
		}
	})

	t.Run("update answers 403 before it reads the body", func(t *testing.T) {
		for _, body := range []string{`{}`, `{"name":"x"}`, `{"data":{"type":"workspaces"}}`} {
			if code, resp := call(t, http.MethodPatch, orgPath, outsider.ID, body); code != http.StatusForbidden {
				t.Errorf("outsider with body %s: status = %d, want 403 (%s)", body, code, resp)
			}
		}
	})

	t.Run("update applies attributes and the default-agent-pool relationship", func(t *testing.T) {
		var org models.Organization
		if err := db.Where("name = ?", createdName).First(&org).Error; err != nil {
			t.Fatalf("loading organization: %v", err)
		}
		pool := &models.AgentPool{ID: uuid.New(), OrganizationID: org.ID, Name: "orgc-pool-" + sfx, OrganizationScoped: true}
		if err := db.Create(pool).Error; err != nil {
			t.Fatalf("seed agent pool: %v", err)
		}

		// The document go-tfe marshals for OrganizationUpdateOptions{Email, DefaultExecutionMode,
		// DefaultAgentPool}: default-agent-pool is a relationship, not an attribute.
		doc := `{"data":{"type":"organizations","attributes":{"email":"new-` + sfx +
			`@test.local","description":"Renamed team","default-execution-mode":"agent"},` +
			`"relationships":{"default-agent-pool":{"data":{"type":"agent-pools","id":"` + pool.ID.String() + `"}}}}}`
		code, body := call(t, http.MethodPatch, orgPath, creator.ID, doc)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", code, body)
		}

		if err := db.Where("name = ?", createdName).First(&org).Error; err != nil {
			t.Fatalf("reloading organization: %v", err)
		}
		if org.Email != "new-"+sfx+"@test.local" {
			t.Errorf("email = %q, want the updated attribute", org.Email)
		}
		if org.Description != "Renamed team" {
			t.Errorf("description = %q, want the updated attribute", org.Description)
		}
		if org.DefaultExecutionMode != "agent" {
			t.Errorf("default execution mode = %q, want agent", org.DefaultExecutionMode)
		}
		if org.DefaultAgentPoolID == nil || *org.DefaultAgentPoolID != pool.ID {
			t.Errorf("default agent pool = %v, want %s", org.DefaultAgentPoolID, pool.ID)
		}
	})
}
