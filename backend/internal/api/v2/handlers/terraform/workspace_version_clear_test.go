// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// How a workspace that stores an OpenTofu version goes back to inheriting (#1069, Q4, D2, AC22): on
// both workspace PATCH routes a JSON null for terraform-version clears the stored version, and the
// next read renders the effective version from the deployment level; an omitted attribute or ""
// keeps the stored version; a version stores it. The TFE provider never sends null (go-tfe marks
// the option omitempty), so it cannot clear a pin by accident.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestWorkspaceVersionClear

//go:build integration

package terraform

import (
	"net/http"
	"testing"

	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/settings"
	"github.com/michielvha/stackweaver/core/tofu"
)

// effectiveLevel is the level the workspace's version resolves from, through the shared rule.
func (f *workspaceBooleansFixture) effectiveLevel(t *testing.T, id string) settings.Level {
	t.Helper()
	ws, err := repository.NewWorkspaceRepository(f.db).GetByID(id)
	if err != nil {
		t.Fatal(err)
	}
	return settings.EffectiveTofuVersion(ws, repository.InstallationTofuVersion(f.db)).Level
}

func TestWorkspaceVersionClear_NullClearsOmittedAndEmptyKeep(t *testing.T) {
	t.Setenv(settings.EnvTofuDefaultVersion, "")
	f := setupWorkspaceBooleans(t)
	pin := catalogueVersion(t, f.db)
	other := catalogueVersion(t, f.db)

	routes := map[string]func(id, name string) string{
		"PATCH /api/v2/workspaces/:id": func(id, _ string) string { return "/api/v2/workspaces/" + id },
		"PATCH /api/v2/organizations/:org/workspaces/:name": func(_, name string) string {
			return "/api/v2/organizations/" + f.orgName + "/workspaces/" + name
		},
	}
	for route, path := range routes {
		for _, tc := range []struct {
			name       string
			attrs      map[string]any
			wantStored string
			wantRead   string
			wantLevel  settings.Level
		}{
			{"null clears", map[string]any{"terraform-version": nil}, "", tofu.BundledVersion, settings.LevelDeployment},
			{"omitted keeps", map[string]any{"description": "unrelated"}, pin, pin, settings.LevelWorkspace},
			{"empty keeps", map[string]any{"terraform-version": ""}, pin, pin, settings.LevelWorkspace},
			{"a version stores it", map[string]any{"terraform-version": other}, other, other, settings.LevelWorkspace},
		} {
			t.Run(route+": "+tc.name, func(t *testing.T) {
				id, name, _ := f.create(t, map[string]any{"terraform-version": pin})
				code, _, attrs := f.do(t, http.MethodPatch, path(id, name), tc.attrs)
				if code != http.StatusOK {
					t.Fatalf("PATCH = %d (%v)", code, attrs)
				}
				if attrs["terraform-version"] != tc.wantRead {
					t.Errorf("the PATCH response reads terraform-version %v, want %s", attrs["terraform-version"], tc.wantRead)
				}
				if got := storedVersion(t, f.db, id); got != tc.wantStored {
					t.Errorf("stored version = %q, want %q", got, tc.wantStored)
				}
				if got := f.readVersion(t, id, name); got != tc.wantRead {
					t.Errorf("the next GET reads terraform-version %q, want %s", got, tc.wantRead)
				}
				if got := f.effectiveLevel(t, id); got != tc.wantLevel {
					t.Errorf("the version resolves from %s, want %s", got, tc.wantLevel)
				}
			})
		}
	}
}

// A workspace pinned to a version other than the installation default, cleared with null, reads
// the installation default and follows a later change of it with no further write to the
// workspace (#1069, AC24).
func TestWorkspaceVersionClear_ClearedPinFollowsTheInstallation(t *testing.T) {
	t.Setenv(settings.EnvTofuDefaultVersion, "")
	f := setupWorkspaceBooleans(t)
	pin := catalogueVersion(t, f.db)
	id, name, _ := f.create(t, map[string]any{"terraform-version": pin})

	if code, _, attrs := f.do(t, http.MethodPatch, "/api/v2/workspaces/"+id, map[string]any{"terraform-version": nil}); code != http.StatusOK {
		t.Fatalf("PATCH null = %d (%v)", code, attrs)
	}
	if got := f.readVersion(t, id, name); got != tofu.BundledVersion {
		t.Fatalf("a cleared workspace reads %q, want the installation default %s", got, tofu.BundledVersion)
	}
	t.Setenv(settings.EnvTofuDefaultVersion, "1.12.0")
	if got := f.readVersion(t, id, name); got != "1.12.0" {
		t.Errorf("after the installation default changed, the cleared workspace reads %q, want 1.12.0", got)
	}
	if got := f.effectiveLevel(t, id); got != settings.LevelDeployment {
		t.Errorf("the cleared workspace resolves from %s, want deployment", got)
	}
}
