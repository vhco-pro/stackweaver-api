// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package apikey

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// AC15 (#132, D5): platform:<permission> is a two-part scope with no resource; every other
// two-part type except user still errors, and a platform scope never carries a resource id.
func TestParseScope_Platform(t *testing.T) {
	s, err := ParseScope("platform:admin")
	if err != nil || s.Type != "platform" || s.ResourceID != nil || s.Permission != "admin" {
		t.Fatalf("ParseScope(platform:admin) = %+v, %v", s, err)
	}
	for _, bad := range []string{
		"platform:" + uuid.NewString() + ":admin",
		"org:admin",
		"project:read",
		"team:write",
		"runner:heartbeat",
		"site:admin",
	} {
		if _, err := ParseScope(bad); err == nil {
			t.Errorf("ParseScope(%q) succeeded, want an error", bad)
		}
	}
	if s, err := ParseScope("user:read"); err != nil || s.Type != "user" {
		t.Errorf("user:read = %+v, %v", s, err)
	}
}

// AC13 (#132, D5): a platform scope is invisible to every organization-level evaluation. A user
// token whose only scope is platform:admin is judged exactly as a plain user token (empty
// scopes): unrestricted, full access by HasPermission, no organization, project, team or runner
// scope. HasPlatformAdmin is the one place the scope is read.
func TestScopeChecker_PlatformScopesAreSeparate(t *testing.T) {
	plain, err := NewScopeChecker(nil)
	if err != nil {
		t.Fatal(err)
	}
	platform, err := NewScopeChecker([]string{"platform:admin"})
	if err != nil {
		t.Fatal(err)
	}
	orgID, projectID := uuid.New(), uuid.New()
	for name, check := range map[string]func(*ScopeChecker) bool{
		"IsUnrestricted":       (*ScopeChecker).IsUnrestricted,
		"HasOrgPermission":     func(sc *ScopeChecker) bool { return sc.HasOrgPermission(orgID, "admin") },
		"HasProjectPermission": func(sc *ScopeChecker) bool { return sc.HasProjectPermission(projectID, "write") },
		"HasUserPermission":    func(sc *ScopeChecker) bool { return sc.HasUserPermission("read") },
		"HasRunnerRegister":    func(sc *ScopeChecker) bool { return sc.HasRunnerRegisterPermission(orgID) },
		"GrantsScopedLevel":    func(sc *ScopeChecker) bool { return sc.GrantsScopedLevel("read") },
		"GrantsOrgLevel":       func(sc *ScopeChecker) bool { g, has := sc.GrantsOrgLevel(orgID, "read"); return g || has },
		"no scoped resources": func(sc *ScopeChecker) bool {
			return len(sc.GetScopedOrganizations())+len(sc.GetScopedProjects())+len(sc.GetScopedTeams())+len(sc.GetScopedRunners()) == 0
		},
	} {
		if check(plain) != check(platform) {
			t.Errorf("%s: plain user token %v, platform:admin token %v; want the same", name, check(plain), check(platform))
		}
	}
	if plain.HasPlatformAdmin() {
		t.Error("an empty scope list must not carry platform:admin")
	}
	if !platform.HasPlatformAdmin() {
		t.Error("platform:admin not reported")
	}

	// Mixed with an organization scope, the organization scope is evaluated as it would be alone.
	mixed, err := NewScopeChecker([]string{"org:" + orgID.String() + ":read", "platform:admin"})
	if err != nil {
		t.Fatal(err)
	}
	if mixed.IsUnrestricted() || !mixed.HasOrgPermission(orgID, "read") || mixed.HasOrgPermission(uuid.New(), "read") || !mixed.HasPlatformAdmin() {
		t.Error("platform scope changed the evaluation of an organization scope")
	}
	// Only platform:admin itself carries the right.
	other, err := NewScopeChecker([]string{"platform:read"})
	if err != nil {
		t.Fatal(err)
	}
	if other.HasPlatformAdmin() {
		t.Error("platform:read reported as platform:admin")
	}
}

// AC15: organization-bound keys never carry a platform scope, and the wildcard stays rejected,
// in any position.
func TestCreateAPIKey_RejectsPlatformScopes(t *testing.T) {
	svc := NewService(nil, nil, nil, nil)
	org := "org:" + uuid.NewString() + ":read"
	for _, scopes := range [][]string{
		{"platform:admin"},
		{org, "platform:admin"},
		{"platform:admin", org},
		{org, "*"},
		{"*", org},
	} {
		_, _, err := svc.CreateAPIKey(uuid.New(), "k", scopes, nil)
		if err == nil {
			t.Errorf("CreateAPIKey(%v) succeeded", scopes)
			continue
		}
		hasPlatform := slices.ContainsFunc(scopes, func(s string) bool { return strings.HasPrefix(s, "platform:") })
		if hasPlatform && !slices.Contains(scopes, "*") && !strings.Contains(err.Error(), "platform scopes are only valid on user tokens") {
			t.Errorf("CreateAPIKey(%v) error %q, want the platform-scope refusal", scopes, err)
		}
	}
}

// D5: a user token can carry platform scopes only, so an organization scope never reaches a user
// token through this door.
func TestCreateUserTokenWithScopes_AcceptsPlatformScopesOnly(t *testing.T) {
	svc := NewService(nil, nil, nil, nil)
	for _, scopes := range [][]string{
		{"org:" + uuid.NewString() + ":admin"},
		{"user:read"},
		{"read"},
		{"*"},
		{"platform:admin", "project:" + uuid.NewString() + ":read"},
		{"platform:" + uuid.NewString() + ":admin"},
	} {
		if _, _, err := svc.CreateUserTokenWithScopes(uuid.New(), "t", nil, scopes); err == nil {
			t.Errorf("CreateUserTokenWithScopes(%v) succeeded", scopes)
		}
	}
}
