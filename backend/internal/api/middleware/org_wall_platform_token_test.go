// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// AC13 (#132): inside an organization a platform:admin user token is a plain user token. The wall
// holds it to its owner's membership and to the organization's user_tokens_enabled policy,
// exactly as it holds a token with no scopes, for reads and writes alike.
func TestOrgWall_PlatformAdminTokenIsAPlainUserTokenInsideOrganizations(t *testing.T) {
	user, org := uuid.New(), uuid.New()
	for _, method := range []string{http.MethodGet, http.MethodPatch} {
		for _, rs := range []struct {
			name     string
			resolver fakeResolver
		}{
			{"member", fakeResolver{org: org, member: true}},
			{"non-member", fakeResolver{org: org, member: false}},
			{"member, user tokens off", fakeResolver{org: org, member: true, userTokensOff: true}},
			{"owner, user tokens off", fakeResolver{org: org, member: true, userTokensOff: true, orgOwner: true}},
		} {
			results := map[string]int{}
			for name, scopes := range map[string]models.StringArray{"plain": {}, "platform": {"platform:admin"}} {
				resolver := rs.resolver
				results[name] = runWall(t, wallTestCase{
					route:     "/api/v2/workspaces/:id",
					reqPath:   "/api/v2/workspaces/ws-123",
					method:    method,
					tokenKind: models.APIKeyKindUser,
					userID:    &user,
					apiKey:    &models.APIKey{ID: uuid.New(), UserID: user, Kind: models.APIKeyKindUser, Scopes: scopes},
					resolver:  &resolver,
				})
			}
			if results["plain"] != results["platform"] {
				t.Errorf("%s %s: plain user token %d, platform:admin token %d; want the same", method, rs.name, results["plain"], results["platform"])
			}
			wantDenied := rs.name == "non-member" || rs.name == "member, user tokens off"
			if (results["platform"] == http.StatusForbidden) != wantDenied {
				t.Errorf("%s %s: platform:admin token got %d", method, rs.name, results["platform"])
			}
		}
	}
}
