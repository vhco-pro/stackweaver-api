// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// The settings routes are exercised end to end, with real keys, by
// TestSettings_TokenIdentitiesAreRefused in v2/routes. That test cannot mint a Zitadel-signed
// JWT, so the half it leaves open is pinned here: an interactive caller passes untouched, and
// the decision rests on how the caller authenticated rather than on who they are.
func TestInteractiveOnly(t *testing.T) {
	const denied = `{"errors":[{"status":"403","title":"Forbidden","detail":"this endpoint requires an interactive sign-in and cannot be used with an API token"}]}`

	orgID := uuid.New()
	tests := []struct {
		name string
		// identity seeds the context the way AuthMiddleware does for this kind of caller.
		identity func(c *gin.Context)
		wantCode int
	}{
		{
			name: "interactive JWT passes",
			identity: func(c *gin.Context) {
				c.Set("auth_method", "jwt")
				c.Set("user_subject", "zitadel-subject")
			},
			wantCode: http.StatusOK,
		},
		{
			name: "org-bound API key is refused",
			identity: func(c *gin.Context) {
				c.Set("auth_method", "api_key")
				c.Set("token_kind", models.APIKeyKindOrg)
				c.Set("token_org_id", orgID)
				c.Set("api_key_scopes", []string{"org:" + orgID.String() + ":admin"})
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "user-bound token is refused",
			identity: func(c *gin.Context) {
				c.Set("auth_method", "api_key")
				c.Set("token_kind", models.APIKeyKindUser)
			},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "query token is refused",
			identity: func(c *gin.Context) { c.Set("auth_method", "query_token") },
			wantCode: http.StatusForbidden,
		},
		{
			// AuthMiddleware lets a log-read request through with no identity at all. It cannot
			// reach these routes today, and it must not be admitted if that ever changes.
			name:     "no recorded method is refused",
			identity: func(*gin.Context) {},
			wantCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("user_id", uuid.New())
				tt.identity(c)
				c.Next()
			})
			r.Use(InteractiveOnly())
			r.POST("/x", func(c *gin.Context) {
				reached = true
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", nil))

			if w.Code != tt.wantCode {
				t.Fatalf("got %d, want %d.\nbody: %s", w.Code, tt.wantCode, w.Body.String())
			}
			if wantReached := tt.wantCode == http.StatusOK; reached != wantReached {
				t.Fatalf("handler reached = %v, want %v", reached, wantReached)
			}
			if tt.wantCode == http.StatusForbidden {
				if got := strings.TrimSpace(w.Body.String()); got != denied {
					t.Fatalf("403 body:\n got %s\nwant %s", got, denied)
				}
			}
		})
	}
}
