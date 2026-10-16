// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// AuthorizeTokenOrgWrite asks write scope of an api-key caller whatever the method, and never
// lets the key owner's permissions stand in for a scope the key does not carry.
func TestAuthorizeTokenOrgWrite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	org := uuid.New()
	elsewhere := uuid.New()
	orgKey := func(bound uuid.UUID, scopes ...string) func(*gin.Context) {
		return func(c *gin.Context) {
			c.Set("token_kind", models.APIKeyKindOrg)
			c.Set("token_org_id", bound)
			c.Set("api_key", &models.APIKey{Kind: models.APIKeyKindOrg, OrganizationID: &bound, Scopes: scopes})
		}
	}

	cases := []struct {
		name     string
		identity func(*gin.Context)
		want     bool
	}{
		{"a session", func(*gin.Context) {}, true},
		{"a user-bound token, which acts as its owner", func(c *gin.Context) {
			c.Set("token_kind", models.APIKeyKindUser)
			c.Set("api_key", &models.APIKey{Kind: models.APIKeyKindUser})
		}, true},
		{"a write-scoped key", orgKey(org, "org:"+org.String()+":write"), true},
		{"an admin-scoped key", orgKey(org, "org:"+org.String()+":admin"), true},
		{"an unrestricted key", orgKey(org), true},
		{"a read-only key", orgKey(org, "org:"+org.String()+":read"), false},
		{"a key scoped only to a team", orgKey(org, "team:"+uuid.NewString()+":admin"), false},
		{"a key scoped only to a project", orgKey(org, "project:"+uuid.NewString()+":write"), false},
		{"a key bound to another organization", orgKey(elsewhere, "org:"+elsewhere.String()+":admin"), false},
		{"a key with a malformed scope", orgKey(org, "org:not-a-uuid:write"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			tc.identity(c)
			if got := AuthorizeTokenOrgWrite(c, org); got != tc.want {
				t.Fatalf("AuthorizeTokenOrgWrite = %v, want %v", got, tc.want)
			}
			if !tc.want && (rec.Code != http.StatusForbidden || !c.IsAborted()) {
				t.Errorf("a refusal answered %d (aborted %v), want an aborted 403", rec.Code, c.IsAborted())
			}
		})
	}
}
