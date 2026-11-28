// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// The routes the central Azure workload identity feature adds are classified in the org wall, so
// an API-key caller scoped to the organization reaches them and one scoped to another does not
// (#1113, D1, D3).
func TestOrgWallClassifiesTheIdentityRoutes(t *testing.T) {
	for route, want := range map[string]string{
		"/api/v2/ansible/inventories/:id/effective-settings": "resource:id",
		"/api/v2/organizations/:name/identity-bindings":      "org-by-name",
	} {
		if got := WallClass(route); got != want {
			t.Errorf("WallClass(%s) = %q, want %q", route, got, want)
		}
	}
}

// The organization's binding list answers an API key scoped to that organization and refuses one
// scoped to another (#1113, D3, AC-08).
func TestOrgWall_OrganizationIdentityBindingsByScope(t *testing.T) {
	org, other := uuid.New(), uuid.New()
	for _, c := range []struct {
		name  string
		token uuid.UUID
		want  int
	}{
		{"same organization", org, http.StatusOK},
		{"another organization", other, http.StatusForbidden},
	} {
		code := runWall(t, wallTestCase{
			route:      "/api/v2/organizations/:name/identity-bindings",
			reqPath:    "/api/v2/organizations/acme/identity-bindings",
			tokenKind:  models.APIKeyKindOrg,
			tokenOrgID: &c.token,
			apiKey:     orgKey(c.token, "read"),
			resolver:   &fakeResolver{org: org},
		})
		if code != c.want {
			t.Errorf("%s: got %d, want %d", c.name, code, c.want)
		}
	}
}
