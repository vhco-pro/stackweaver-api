// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// fakeResolver implements OrgResolver for the wall tests without a database.
// Every By* method returns org/err; UserInOrg returns member/memberErr.
type fakeResolver struct {
	org       uuid.UUID
	err       error
	member    bool
	memberErr error
}

func (f *fakeResolver) resolve() (uuid.UUID, error) { return f.org, f.err }

func (f *fakeResolver) ByOrgName(string) (uuid.UUID, error)                  { return f.resolve() }
func (f *fakeResolver) ByOrgMembershipID(string) (uuid.UUID, error)          { return f.resolve() }
func (f *fakeResolver) ByProjectID(string) (uuid.UUID, error)                { return f.resolve() }
func (f *fakeResolver) ByWorkspaceID(string) (uuid.UUID, error)              { return f.resolve() }
func (f *fakeResolver) ByRunID(string) (uuid.UUID, error)                    { return f.resolve() }
func (f *fakeResolver) ByRunTriggerID(string) (uuid.UUID, error)             { return f.resolve() }
func (f *fakeResolver) ByNotificationConfigID(string) (uuid.UUID, error)     { return f.resolve() }
func (f *fakeResolver) ByChangeRequestID(string) (uuid.UUID, error)          { return f.resolve() }
func (f *fakeResolver) ByRunTaskID(string) (uuid.UUID, error)                { return f.resolve() }
func (f *fakeResolver) ByTaskStageID(string) (uuid.UUID, error)              { return f.resolve() }
func (f *fakeResolver) ByTaskResultID(string) (uuid.UUID, error)             { return f.resolve() }
func (f *fakeResolver) ByTaskResultOutcomeID(string) (uuid.UUID, error)      { return f.resolve() }
func (f *fakeResolver) ByConfigVersionID(string) (uuid.UUID, error)          { return f.resolve() }
func (f *fakeResolver) ByStateVersionID(string) (uuid.UUID, error)           { return f.resolve() }
func (f *fakeResolver) ByVariableID(string) (uuid.UUID, error)               { return f.resolve() }
func (f *fakeResolver) ByVariableSetID(string) (uuid.UUID, error)            { return f.resolve() }
func (f *fakeResolver) ByVariableSetVariableID(string) (uuid.UUID, error)    { return f.resolve() }
func (f *fakeResolver) ByTeamID(string) (uuid.UUID, error)                   { return f.resolve() }
func (f *fakeResolver) ByTeamWorkspaceAccessID(string) (uuid.UUID, error)    { return f.resolve() }
func (f *fakeResolver) ByTeamProjectAccessID(string) (uuid.UUID, error)      { return f.resolve() }
func (f *fakeResolver) ByAgentPoolID(string) (uuid.UUID, error)              { return f.resolve() }
func (f *fakeResolver) ByRunnerID(string) (uuid.UUID, error)                 { return f.resolve() }
func (f *fakeResolver) ByVCSConnectionID(string) (uuid.UUID, error)          { return f.resolve() }
func (f *fakeResolver) ByOIDCConfigID(string) (uuid.UUID, error)             { return f.resolve() }
func (f *fakeResolver) ByGPGKeyID(string) (uuid.UUID, error)                 { return f.resolve() }
func (f *fakeResolver) ByRegistryProviderID(string) (uuid.UUID, error)       { return f.resolve() }
func (f *fakeResolver) ByAnsibleInventoryID(string) (uuid.UUID, error)       { return f.resolve() }
func (f *fakeResolver) ByAnsibleHostID(string) (uuid.UUID, error)            { return f.resolve() }
func (f *fakeResolver) ByAnsibleGroupID(string) (uuid.UUID, error)           { return f.resolve() }
func (f *fakeResolver) ByAnsibleInventorySourceID(string) (uuid.UUID, error) { return f.resolve() }
func (f *fakeResolver) ByAnsibleCredentialID(string) (uuid.UUID, error)      { return f.resolve() }
func (f *fakeResolver) ByAnsiblePlaybookID(string) (uuid.UUID, error)        { return f.resolve() }
func (f *fakeResolver) ByAnsibleJobTemplateID(string) (uuid.UUID, error)     { return f.resolve() }
func (f *fakeResolver) ByAnsibleJobTemplateVariableID(string) (uuid.UUID, error) {
	return f.resolve()
}
func (f *fakeResolver) ByAnsibleJobID(string) (uuid.UUID, error)          { return f.resolve() }
func (f *fakeResolver) ByAnsibleScheduleID(string) (uuid.UUID, error)     { return f.resolve() }
func (f *fakeResolver) ByAnsibleWorkflowID(string) (uuid.UUID, error)     { return f.resolve() }
func (f *fakeResolver) ByAnsibleWorkflowNodeID(string) (uuid.UUID, error) { return f.resolve() }
func (f *fakeResolver) ByAnsibleWorkflowEdgeID(string) (uuid.UUID, error) { return f.resolve() }
func (f *fakeResolver) UserInOrg(uuid.UUID, uuid.UUID) (bool, error) {
	return f.member, f.memberErr
}

// wallTestCase configures one request through the wall.
type wallTestCase struct {
	// route registered on the engine (must match a wallRegistry key, except
	// for the unclassified case).
	route string
	// reqPath is the concrete request path that matches route.
	reqPath string
	// method defaults to GET when empty.
	method string
	// preset values placed in context before the wall runs.
	tokenKind  string // empty => no token_kind (JWT/session)
	tokenOrgID *uuid.UUID
	userID     *uuid.UUID
	apiKey     *models.APIKey
	resolver   *fakeResolver
	wantStatus int
}

func runWall(t *testing.T, tc wallTestCase) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	// Seed context the way AuthMiddleware would, then run the wall.
	engine.Use(func(c *gin.Context) {
		if tc.tokenKind != "" {
			c.Set("token_kind", tc.tokenKind)
		}
		if tc.tokenOrgID != nil {
			c.Set("token_org_id", *tc.tokenOrgID)
		}
		if tc.userID != nil {
			c.Set("user_id", *tc.userID)
		}
		if tc.apiKey != nil {
			c.Set("api_key", tc.apiKey)
		}
		c.Next()
	})
	engine.Use(OrgResolutionWall(tc.resolver))
	handler := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
	method := tc.method
	if method == "" {
		method = http.MethodGet
	}
	engine.Handle(method, tc.route, handler)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), method, tc.reqPath, nil)
	engine.ServeHTTP(w, req)
	return w.Code
}

func TestOrgWall_JWTPassesThrough(t *testing.T) {
	// No token_kind => JWT/session identity; the wall must not interfere
	// even on an unclassified route.
	code := runWall(t, wallTestCase{
		route:      "/api/v2/anything",
		reqPath:    "/api/v2/anything",
		resolver:   &fakeResolver{},
		wantStatus: http.StatusOK,
	})
	if code != http.StatusOK {
		t.Fatalf("JWT request: got %d, want 200", code)
	}
}

func TestOrgWall_UnclassifiedRouteDeniesToken(t *testing.T) {
	code := runWall(t, wallTestCase{
		route:      "/api/v2/unclassified",
		reqPath:    "/api/v2/unclassified",
		tokenKind:  models.APIKeyKindOrg,
		resolver:   &fakeResolver{},
		wantStatus: http.StatusForbidden,
	})
	if code != http.StatusForbidden {
		t.Fatalf("unclassified route: got %d, want 403", code)
	}
}

func TestOrgWall_AgnosticRoutePasses(t *testing.T) {
	code := runWall(t, wallTestCase{
		route:      "/api/v2/ping",
		reqPath:    "/api/v2/ping",
		tokenKind:  models.APIKeyKindOrg,
		resolver:   &fakeResolver{},
		wantStatus: http.StatusOK,
	})
	if code != http.StatusOK {
		t.Fatalf("agnostic route: got %d, want 200", code)
	}
}

func TestOrgWall_OrgBoundSameOrgAllows(t *testing.T) {
	org := uuid.New()
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-123",
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &org,
		resolver:   &fakeResolver{org: org},
		wantStatus: http.StatusOK,
	})
	if code != http.StatusOK {
		t.Fatalf("org-bound same org: got %d, want 200", code)
	}
}

func TestOrgWall_OrgBoundCrossOrgDenied(t *testing.T) {
	boundOrg := uuid.New()
	targetOrg := uuid.New()
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-123",
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &boundOrg,
		resolver:   &fakeResolver{org: targetOrg},
		wantStatus: http.StatusForbidden,
	})
	if code != http.StatusForbidden {
		t.Fatalf("org-bound cross org: got %d, want 403", code)
	}
}

func TestOrgWall_ResolveNotFoundReturns404(t *testing.T) {
	boundOrg := uuid.New()
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/missing",
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &boundOrg,
		resolver:   &fakeResolver{err: errors.New("record not found")},
		wantStatus: http.StatusNotFound,
	})
	if code != http.StatusNotFound {
		t.Fatalf("unresolvable resource: got %d, want 404", code)
	}
}

func TestOrgWall_UserBoundMemberAllows(t *testing.T) {
	user := uuid.New()
	org := uuid.New()
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-123",
		tokenKind:  models.APIKeyKindUser,
		userID:     &user,
		resolver:   &fakeResolver{org: org, member: true},
		wantStatus: http.StatusOK,
	})
	if code != http.StatusOK {
		t.Fatalf("user-bound member: got %d, want 200", code)
	}
}

func TestOrgWall_UserBoundNonMemberDenied(t *testing.T) {
	user := uuid.New()
	org := uuid.New()
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-123",
		tokenKind:  models.APIKeyKindUser,
		userID:     &user,
		resolver:   &fakeResolver{org: org, member: false},
		wantStatus: http.StatusForbidden,
	})
	if code != http.StatusForbidden {
		t.Fatalf("user-bound non-member: got %d, want 403", code)
	}
}

func TestOrgWall_OrgBoundByNameRoute(t *testing.T) {
	org := uuid.New()
	code := runWall(t, wallTestCase{
		route:      "/api/v2/organizations/:name",
		reqPath:    "/api/v2/organizations/acme",
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &org,
		resolver:   &fakeResolver{org: org},
		wantStatus: http.StatusOK,
	})
	if code != http.StatusOK {
		t.Fatalf("org-bound by-name same org: got %d, want 200", code)
	}
}

func orgKey(org uuid.UUID, level string) *models.APIKey {
	return &models.APIKey{
		Kind:           models.APIKeyKindOrg,
		Scopes:         models.StringArray{"org:" + org.String() + ":" + level},
		OrganizationID: &org,
	}
}

func TestOrgWall_ReadTokenAllowedToRead(t *testing.T) {
	org := uuid.New()
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-1",
		method:     http.MethodGet,
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &org,
		apiKey:     orgKey(org, "read"),
		resolver:   &fakeResolver{org: org},
		wantStatus: http.StatusOK,
	})
	if code != http.StatusOK {
		t.Fatalf("read token GET: got %d, want 200", code)
	}
}

func TestOrgWall_ReadTokenDeniedWrite(t *testing.T) {
	org := uuid.New()
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-1",
		method:     http.MethodPatch,
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &org,
		apiKey:     orgKey(org, "read"),
		resolver:   &fakeResolver{org: org},
		wantStatus: http.StatusForbidden,
	})
	if code != http.StatusForbidden {
		t.Fatalf("read token PATCH: got %d, want 403", code)
	}
}

func TestOrgWall_WriteTokenAllowedWrite(t *testing.T) {
	org := uuid.New()
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-1",
		method:     http.MethodDelete,
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &org,
		apiKey:     orgKey(org, "write"),
		resolver:   &fakeResolver{org: org},
		wantStatus: http.StatusOK,
	})
	if code != http.StatusOK {
		t.Fatalf("write token DELETE: got %d, want 200", code)
	}
}

func TestOrgWall_AdminTokenSatisfiesWrite(t *testing.T) {
	org := uuid.New()
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-1",
		method:     http.MethodPost,
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &org,
		apiKey:     orgKey(org, "admin"),
		resolver:   &fakeResolver{org: org},
		wantStatus: http.StatusOK,
	})
	if code != http.StatusOK {
		t.Fatalf("admin token POST: got %d, want 200", code)
	}
}

func TestOrgWall_ProjectScopedTokenDefersToHandler(t *testing.T) {
	// A token scoped only to a project (no org-level scope) cannot be
	// evaluated at org granularity; the wall must allow it through to the
	// handler rather than deny a mutating request.
	org := uuid.New()
	project := uuid.New()
	key := &models.APIKey{
		Kind:           models.APIKeyKindOrg,
		Scopes:         models.StringArray{"project:" + project.String() + ":read"},
		OrganizationID: &org,
	}
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-1",
		method:     http.MethodPost,
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &org,
		apiKey:     key,
		resolver:   &fakeResolver{org: org},
		wantStatus: http.StatusOK,
	})
	if code != http.StatusOK {
		t.Fatalf("project-scoped token POST: got %d, want 200 (deferred)", code)
	}
}

// AUD-042: a token bound to the target org whose scopes are malformed cannot be
// authorized — it must fail closed for mutating methods (previously it failed
// open and was allowed to write).
func TestOrgWall_MalformedScopeDeniedWrite(t *testing.T) {
	org := uuid.New()
	key := &models.APIKey{
		Kind:           models.APIKeyKindOrg,
		Scopes:         models.StringArray{"org:not-a-uuid:write"}, // unparseable resource id
		OrganizationID: &org,
	}
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-1",
		method:     http.MethodPost,
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &org,
		apiKey:     key,
		resolver:   &fakeResolver{org: org},
		wantStatus: http.StatusForbidden,
	})
	if code != http.StatusForbidden {
		t.Fatalf("malformed-scope token POST: got %d, want 403", code)
	}
}

// A malformed-scope token may still perform reads (the token is bound to this org
// and reads are lower risk) — only mutations fail closed.
func TestOrgWall_MalformedScopeAllowedRead(t *testing.T) {
	org := uuid.New()
	key := &models.APIKey{
		Kind:           models.APIKeyKindOrg,
		Scopes:         models.StringArray{"org:not-a-uuid:write"},
		OrganizationID: &org,
	}
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-1",
		method:     http.MethodGet,
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &org,
		apiKey:     key,
		resolver:   &fakeResolver{org: org},
		wantStatus: http.StatusOK,
	})
	if code != http.StatusOK {
		t.Fatalf("malformed-scope token GET: got %d, want 200", code)
	}
}

// AUD-042: a token bound to the target org but carrying no scope applicable to it
// (no org-level scope for this org, no project/team scope) has no basis to mutate
// — it must fail closed for mutating methods rather than defer to a handler.
func TestOrgWall_NoApplicableScopeDeniedWrite(t *testing.T) {
	org := uuid.New()
	otherOrg := uuid.New()
	key := &models.APIKey{
		Kind:           models.APIKeyKindOrg,
		Scopes:         models.StringArray{"org:" + otherOrg.String() + ":write"}, // scope for a different org
		OrganizationID: &org,
	}
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-1",
		method:     http.MethodDelete,
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &org,
		apiKey:     key,
		resolver:   &fakeResolver{org: org},
		wantStatus: http.StatusForbidden,
	})
	if code != http.StatusForbidden {
		t.Fatalf("no-applicable-scope token DELETE: got %d, want 403", code)
	}
}

// An unrestricted (empty-scopes) org-bound token retains full access — the
// backward-compatible default must not be tightened by AUD-042.
func TestOrgWall_UnrestrictedTokenAllowedWrite(t *testing.T) {
	org := uuid.New()
	key := &models.APIKey{
		Kind:           models.APIKeyKindOrg,
		Scopes:         models.StringArray{}, // empty = unrestricted
		OrganizationID: &org,
	}
	code := runWall(t, wallTestCase{
		route:      "/api/v2/workspaces/:id",
		reqPath:    "/api/v2/workspaces/ws-1",
		method:     http.MethodPost,
		tokenKind:  models.APIKeyKindOrg,
		tokenOrgID: &org,
		apiKey:     key,
		resolver:   &fakeResolver{org: org},
		wantStatus: http.StatusOK,
	})
	if code != http.StatusOK {
		t.Fatalf("unrestricted token POST: got %d, want 200", code)
	}
}
