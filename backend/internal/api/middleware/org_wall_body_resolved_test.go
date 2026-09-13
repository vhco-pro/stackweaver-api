// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// #806: routes classified agnostic() because their target org arrives in the request
// body carried NO token-side authorization at all. The wall's agnostic branch calls
// c.Next() immediately, so neither the org-binding comparison nor scopeAllowsMethod ran,
// and the handlers behind those routes authorize through the KEY OWNER's RBAC - which
// answers "may this user do this?", never "may this token do this?". An org-A-bound
// token therefore reached every org its human owner belonged to.
//
// AuthorizeBodyResolvedOrg is the check those handlers now owe. These tests pin its
// behaviour per token kind; the handler-level wiring is covered by the integration
// suites, which can reach a real database.

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

type bodyResolvedCase struct {
	name string
	// identity, seeded the way AuthMiddleware would
	tokenKind  string
	tokenOrgID *uuid.UUID
	userID     *uuid.UUID
	apiKey     *models.APIKey
	method     string
	// the org the handler resolved from the body, and the resolver backing it
	targetOrg   uuid.UUID
	resolveErr  error
	resolver    *fakeResolver
	nilResolver bool

	wantStatus    int
	wantHandlerOK bool
}

// runBodyResolved drives AuthorizeBodyResolvedOrg through a real gin chain and reports
// the status plus whether the protected handler body actually executed. The second
// signal matters: a guard that denies but still falls through to the handler would
// leave the escalation open while looking fixed.
func runBodyResolved(t *testing.T, tc bodyResolvedCase) (int, bool) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()

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

	method := tc.method
	if method == "" {
		method = http.MethodPost
	}

	reached := false
	var resolver OrgResolver
	if !tc.nilResolver {
		resolver = tc.resolver
	}
	engine.Handle(method, "/api/v2/runs", func(c *gin.Context) {
		ok := AuthorizeBodyResolvedOrg(c, resolver, func(OrgResolver) (uuid.UUID, error) {
			if tc.resolveErr != nil {
				return uuid.Nil, tc.resolveErr
			}
			return tc.targetOrg, nil
		})
		if !ok {
			return
		}
		reached = true
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), method, "/api/v2/runs", nil)
	engine.ServeHTTP(w, req)
	return w.Code, reached
}

func TestAuthorizeBodyResolvedOrg(t *testing.T) {
	orgA := uuid.New()
	orgB := uuid.New()
	user := uuid.New()

	cases := []bodyResolvedCase{
		{
			// The reported vulnerability. The owner's RBAC would have allowed this;
			// the token's binding must not.
			name:          "org-bound token denied against another org",
			tokenKind:     models.APIKeyKindOrg,
			tokenOrgID:    &orgA,
			targetOrg:     orgB,
			resolver:      &fakeResolver{},
			wantStatus:    http.StatusForbidden,
			wantHandlerOK: false,
		},
		{
			name:          "org-bound token allowed within its own org",
			tokenKind:     models.APIKeyKindOrg,
			tokenOrgID:    &orgA,
			targetOrg:     orgA,
			resolver:      &fakeResolver{},
			wantStatus:    http.StatusOK,
			wantHandlerOK: true,
		},
		{
			// The agnostic branch skipped scopeAllowsMethod too, so a read-only key
			// could mutate even inside its own org.
			name:       "read-only scoped token denied a mutation in its own org",
			tokenKind:  models.APIKeyKindOrg,
			tokenOrgID: &orgA,
			targetOrg:  orgA,
			apiKey: &models.APIKey{
				Kind:   models.APIKeyKindOrg,
				Scopes: models.StringArray{"org:" + orgA.String() + ":read"},
			},
			resolver:      &fakeResolver{},
			wantStatus:    http.StatusForbidden,
			wantHandlerOK: false,
		},
		{
			name:       "write scoped token allowed a mutation in its own org",
			tokenKind:  models.APIKeyKindOrg,
			tokenOrgID: &orgA,
			targetOrg:  orgA,
			apiKey: &models.APIKey{
				Kind:   models.APIKeyKindOrg,
				Scopes: models.StringArray{"org:" + orgA.String() + ":write"},
			},
			resolver:      &fakeResolver{},
			wantStatus:    http.StatusOK,
			wantHandlerOK: true,
		},
		{
			name:          "org-bound token with no binding in context is denied",
			tokenKind:     models.APIKeyKindOrg,
			targetOrg:     orgA,
			resolver:      &fakeResolver{},
			wantStatus:    http.StatusForbidden,
			wantHandlerOK: false,
		},
		{
			name:          "user-bound token allowed in an org the user belongs to",
			tokenKind:     models.APIKeyKindUser,
			userID:        &user,
			targetOrg:     orgA,
			resolver:      &fakeResolver{member: true},
			wantStatus:    http.StatusOK,
			wantHandlerOK: true,
		},
		{
			name:          "user-bound token denied in an org the user is not a member of",
			tokenKind:     models.APIKeyKindUser,
			userID:        &user,
			targetOrg:     orgA,
			resolver:      &fakeResolver{member: false},
			wantStatus:    http.StatusForbidden,
			wantHandlerOK: false,
		},
		{
			// user_tokens_enabled=false is enforced at the wall for every resource
			// route; an agnostic route must not be a way around it.
			name:          "user-bound token denied when the org disables user tokens",
			tokenKind:     models.APIKeyKindUser,
			userID:        &user,
			targetOrg:     orgA,
			resolver:      &fakeResolver{member: true, userTokensOff: true},
			wantStatus:    http.StatusForbidden,
			wantHandlerOK: false,
		},
		{
			name:          "org owner keeps the anti-lockout carve-out",
			tokenKind:     models.APIKeyKindUser,
			userID:        &user,
			targetOrg:     orgA,
			resolver:      &fakeResolver{member: true, userTokensOff: true, orgOwner: true},
			wantStatus:    http.StatusOK,
			wantHandlerOK: true,
		},
		{
			// JWT and session identities are out of scope for the wall, and this
			// helper must not start governing them - the handler's RBAC is their gate.
			name:          "JWT identity passes through untouched",
			targetOrg:     orgB,
			resolver:      &fakeResolver{},
			wantStatus:    http.StatusOK,
			wantHandlerOK: true,
		},
		{
			// 404, not 403: the response must not disclose that the resource exists
			// in another tenant. Matches the wall's own posture.
			name:          "unresolvable target is a 404, not a 403",
			tokenKind:     models.APIKeyKindOrg,
			tokenOrgID:    &orgA,
			resolveErr:    errors.New("not found"),
			resolver:      &fakeResolver{},
			wantStatus:    http.StatusNotFound,
			wantHandlerOK: false,
		},
		{
			name:          "unrecognized token kind is denied",
			tokenKind:     "banana",
			targetOrg:     orgA,
			resolver:      &fakeResolver{},
			wantStatus:    http.StatusForbidden,
			wantHandlerOK: false,
		},
		{
			// Fail closed: a handler wired without a resolver must not admit tokens.
			name:          "missing resolver fails closed for tokens",
			tokenKind:     models.APIKeyKindOrg,
			tokenOrgID:    &orgA,
			targetOrg:     orgA,
			nilResolver:   true,
			wantStatus:    http.StatusForbidden,
			wantHandlerOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, reached := runBodyResolved(t, tc)
			if code != tc.wantStatus {
				t.Errorf("status = %d, want %d", code, tc.wantStatus)
			}
			if reached != tc.wantHandlerOK {
				t.Errorf("handler reached = %v, want %v (a denial that still runs the handler is not a fix)", reached, tc.wantHandlerOK)
			}
		})
	}
}

// The org wall caches the resolved org for downstream handlers; the body-resolved path
// must do the same so a handler can trust resolved_org_id regardless of how it got there.
func TestAuthorizeBodyResolvedOrg_CachesResolvedOrg(t *testing.T) {
	gin.SetMode(gin.TestMode)
	org := uuid.New()
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		c.Set("token_kind", models.APIKeyKindOrg)
		c.Set("token_org_id", org)
		c.Next()
	})

	var cached any
	var found bool
	engine.POST("/api/v2/runs", func(c *gin.Context) {
		if !AuthorizeBodyResolvedOrg(c, &fakeResolver{}, func(OrgResolver) (uuid.UUID, error) {
			return org, nil
		}) {
			return
		}
		cached, found = c.Get("resolved_org_id")
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v2/runs", nil))

	if !found {
		t.Fatal("resolved_org_id was not cached in context")
	}
	if got, _ := cached.(uuid.UUID); got != org {
		t.Fatalf("resolved_org_id = %v, want %v", got, org)
	}
}
