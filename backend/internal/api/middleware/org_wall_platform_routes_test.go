// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import "testing"

// AC21 (#132): every platform administration route is classified, and as agnostic: none has an
// organization to resolve, so the handler's platformadmin check is the whole authorization and
// the wall must not add a membership check that would fall back to the key owner.
func TestPlatformAdminRoutesAreClassifiedAgnostic(t *testing.T) {
	for _, path := range []string{
		"/api/v2/admin/terraform-versions",
		"/api/v2/admin/terraform-versions/:id",
		"/api/v2/admin/users",
		"/api/v2/admin/users/:id/actions/grant_admin",
		"/api/v2/admin/users/:id/actions/revoke_admin",
		"/api/v2/admin/organizations",
		"/api/v2/admin/organizations/:name",
		"/api/v2/platform/settings",
		"/api/v2/account/details",
		"/api/v2/tokens",
	} {
		if !WallClassified(path) {
			t.Errorf("%s is not classified in the org wall", path)
			continue
		}
		if e := wallRegistry[path]; !e.agnostic || e.userBoundMutations {
			t.Errorf("%s is classified %+v, want agnostic()", path, e)
		}
	}
	if e := wallRegistry["/api/v2/organizations"]; !e.agnostic || !e.userBoundMutations {
		t.Errorf("/api/v2/organizations is classified %+v, want orgListCreate()", e)
	}
}
