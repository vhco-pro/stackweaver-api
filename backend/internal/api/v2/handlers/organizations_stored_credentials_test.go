// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The organization setting that lets stored VCS credentials reach agent pools (#1113, D2, owner
// decision Q13; AC-27): false unless an owner turns it on, read and written as the native attribute
// allow-stored-vcs-credentials-on-agent-pools of GET and PATCH /api/v2/organizations/:name, which
// only those who may manage the organization change.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestOrganizationStoredCredentials

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestOrganizationStoredCredentials(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	t.Cleanup(func() {
		f.db.Model(&models.Organization{}).Where("id = ?", f.orgA.ID).Update("allow_stored_vcs_credentials_on_agent_pools", false)
	})
	orgRepo := repository.NewOrganizationRepository(f.db)
	teamRepo := repository.NewTeamRepository(f.db)
	projectRepo := repository.NewProjectRepository(f.db)
	h := NewOrganizationHandlerV2(orgRepo, teamRepo, projectRepo, repository.NewAgentPoolRepository(f.db), f.authSvc, nil, rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo), f.db)
	r := platformAdminRouter()
	r.GET("/api/v2/organizations/:name", h.Get)
	r.PATCH("/api/v2/organizations/:name", h.Update)
	path := "/api/v2/organizations/" + f.orgA.Name

	read := func(as identity) any {
		t.Helper()
		rec := platformAdminCall(t, r, http.MethodGet, path, as, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET = %d %s", rec.Code, rec.Body.String())
		}
		var doc struct {
			Data struct {
				Attributes map[string]any `json:"attributes"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Data.Attributes["allow-stored-vcs-credentials-on-agent-pools"]
	}
	patch := func(as identity, value bool) int {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"data": map[string]any{
			"type": "organizations", "attributes": map[string]any{"allow-stored-vcs-credentials-on-agent-pools": value},
		}})
		return platformAdminCall(t, r, http.MethodPatch, path, as, string(body)).Code
	}
	stored := func() bool {
		t.Helper()
		var org models.Organization
		if err := f.db.First(&org, "id = ?", f.orgA.ID).Error; err != nil {
			t.Fatal(err)
		}
		return org.AllowStoredVCSCredentialsOnAgentPools
	}

	if got := read(browserAs(f.owner)); got != false {
		t.Errorf("a new organization reads %v, want false", got)
	}
	if code := patch(browserAs(f.member), true); code != http.StatusForbidden || stored() {
		t.Errorf("a member who may not manage the organization: PATCH = %d, stored %v; want 403 and false", code, stored())
	}
	if code := patch(browserAs(f.owner), true); code != http.StatusOK || !stored() {
		t.Fatalf("an owner's PATCH = %d, stored %v; want 200 and true", code, stored())
	}
	if got := read(browserAs(f.owner)); got != true {
		t.Errorf("GET after setting it = %v, want true", got)
	}
	// An organization API token of an owner reads and writes it too.
	token := identity{user: f.owner.ID, method: "api_key", tokenKind: models.APIKeyKindOrg}
	if code := patch(token, false); code != http.StatusOK || stored() {
		t.Errorf("an organization token's PATCH = %d, stored %v; want 200 and false", code, stored())
	}
	if got := read(token); got != false {
		t.Errorf("an organization token reads %v, want false", got)
	}
}

// An organization row written without the setting's column, as every organization that existed
// before the column did, reads false; an organization token reaches GET and PATCH through the
// production authentication and org wall chain, and a token of another organization is refused
// with 403 by the wall (AC-27).
func TestOrganizationStoredCredentials_ThroughTheOrgWall(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	// Inserted with the column left out, so the database's default supplies its value.
	legacy := &models.Organization{ID: uuid.New(), Name: "platadm-legacy-" + f.sfx, Email: "platadm-legacy-" + f.sfx + "@test.local"}
	if err := f.db.Omit("allow_stored_vcs_credentials_on_agent_pools").Create(legacy).Error; err != nil {
		t.Fatalf("inserting an organization without the setting's column: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("organization_id = ?", legacy.ID).Delete(&models.APIKey{})
		f.db.Where("id = ?", legacy.ID).Delete(&models.Organization{})
	})
	t.Cleanup(func() {
		f.db.Model(&models.Organization{}).Where("id = ?", f.orgA.ID).Update("allow_stored_vcs_credentials_on_agent_pools", false)
	})

	orgRepo := repository.NewOrganizationRepository(f.db)
	teamRepo := repository.NewTeamRepository(f.db)
	projectRepo := repository.NewProjectRepository(f.db)
	keys := apikey.NewService(repository.NewAPIKeyRepository(f.db), orgRepo, projectRepo, teamRepo)
	authService := auth.NewService(f.users)
	authService.SetAPIKeyService(keys)
	h := NewOrganizationHandlerV2(orgRepo, teamRepo, projectRepo, repository.NewAgentPoolRepository(f.db), authService, nil, rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo), f.db)

	// The chain routes.go puts in front of every /api/v2 route.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(middleware.AuthMiddleware(authService), middleware.OrgResolutionWall(middleware.NewDBOrgResolver(f.db)))
	v2.GET("/organizations/:name", h.Get)
	v2.PATCH("/organizations/:name", h.Update)

	token := func(org *models.Organization) string {
		t.Helper()
		_, plain, err := keys.CreateOrganizationToken(f.owner.ID, org.ID, nil)
		if err != nil {
			t.Fatalf("minting the token of %s: %v", org.Name, err)
		}
		return plain
	}
	call := func(method, name, bearer, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), method, "/api/v2/organizations/"+name, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+bearer)
		if body != "" {
			req.Header.Set("Content-Type", "application/vnd.api+json")
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	read := func(name, bearer string) any {
		t.Helper()
		rec := call(http.MethodGet, name, bearer, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d %s", name, rec.Code, rec.Body.String())
		}
		var doc struct {
			Data struct {
				Attributes map[string]any `json:"attributes"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Data.Attributes["allow-stored-vcs-credentials-on-agent-pools"]
	}
	patchBody := func(value bool) string {
		raw, err := json.Marshal(map[string]any{"data": map[string]any{
			"type": "organizations", "attributes": map[string]any{"allow-stored-vcs-credentials-on-agent-pools": value},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	stored := func() bool {
		t.Helper()
		var org models.Organization
		if err := f.db.First(&org, "id = ?", f.orgA.ID).Error; err != nil {
			t.Fatal(err)
		}
		return org.AllowStoredVCSCredentialsOnAgentPools
	}

	if got := read(legacy.Name, token(legacy)); got != false {
		t.Errorf("an organization written without the column reads %v, want false", got)
	}

	tokenA, tokenB := token(f.orgA), token(f.orgB)
	if rec := call(http.MethodPatch, f.orgA.Name, tokenA, patchBody(true)); rec.Code != http.StatusOK || !stored() {
		t.Fatalf("the organization's token: PATCH = %d, stored %v; want 200 and true (%s)", rec.Code, stored(), rec.Body.String())
	}
	if got := read(f.orgA.Name, tokenA); got != true {
		t.Errorf("the organization's token reads %v after setting it, want true", got)
	}

	// The owner may manage both organizations, so only the wall's binding of the token to its
	// organization refuses these; its reason says so.
	const wallDenial = "this token is scoped to a different organization"
	if rec := call(http.MethodGet, f.orgA.Name, tokenB, ""); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), wallDenial) {
		t.Errorf("another organization's token: GET = %d %s, want 403 %q", rec.Code, rec.Body.String(), wallDenial)
	}
	if rec := call(http.MethodPatch, f.orgA.Name, tokenB, patchBody(false)); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), wallDenial) || !stored() {
		t.Errorf("another organization's token: PATCH = %d %s, stored %v; want 403 %q and true kept", rec.Code, rec.Body.String(), stored(), wallDenial)
	}

	if rec := call(http.MethodPatch, f.orgA.Name, tokenA, patchBody(false)); rec.Code != http.StatusOK || stored() {
		t.Errorf("the organization's token clearing it: PATCH = %d, stored %v; want 200 and false (%s)", rec.Code, stored(), rec.Body.String())
	}
}
