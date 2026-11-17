// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A workspace PATCH that leaves working-directory or description out keeps the stored value, and
// an explicit "" clears it (#1089), on both workspace PATCH routes. This is TFE's behaviour, and
// go-tfe sends both attributes as optional pointers: omitted unless the caller sets them, and ""
// when the provider clears one. Before the fix an omitted working-directory bound as "" and
// cleared the stored value, so the next run planned at the repository root.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestWorkspaceUpdate_OmittedAttributes

//go:build integration

package terraform

import (
	"net/http"
	"testing"

	"github.com/michielvha/stackweaver/core/repository"
)

func TestWorkspaceUpdate_OmittedAttributesKeepAndEmptyClears(t *testing.T) {
	f := setupWorkspaceBooleans(t)

	routes := map[string]func(id, name string) string{
		"PATCH /api/v2/workspaces/:id": func(id, _ string) string { return "/api/v2/workspaces/" + id },
		"PATCH /api/v2/organizations/:org/workspaces/:name": func(_, name string) string {
			return "/api/v2/organizations/" + f.orgName + "/workspaces/" + name
		},
	}
	const dir, desc = "envs/prod", "the production workspace"
	for route, path := range routes {
		for _, tc := range []struct {
			name             string
			attrs            map[string]any
			wantDir, wantDsc string
		}{
			{"omitted keeps both", map[string]any{"auto-apply": true}, dir, desc},
			{"empty working-directory clears it", map[string]any{"working-directory": ""}, "", desc},
			{"empty description clears it", map[string]any{"description": ""}, dir, ""},
			{"values replace both", map[string]any{"working-directory": "envs/dev", "description": "dev"}, "envs/dev", "dev"},
		} {
			t.Run(route+": "+tc.name, func(t *testing.T) {
				id, name, _ := f.create(t, map[string]any{"working-directory": dir, "description": desc})
				code, _, attrs := f.do(t, http.MethodPatch, path(id, name), tc.attrs)
				if code != http.StatusOK {
					t.Fatalf("PATCH = %d (%v)", code, attrs)
				}
				if attrs["working-directory"] != tc.wantDir {
					t.Errorf("the PATCH response reads working-directory %v, want %q", attrs["working-directory"], tc.wantDir)
				}
				ws, err := repository.NewWorkspaceRepository(f.db).GetByID(id)
				if err != nil {
					t.Fatalf("reading the workspace back: %v", err)
				}
				if ws.WorkingDirectory != tc.wantDir {
					t.Errorf("stored working directory = %q, want %q", ws.WorkingDirectory, tc.wantDir)
				}
				if ws.Description != tc.wantDsc {
					t.Errorf("stored description = %q, want %q", ws.Description, tc.wantDsc)
				}
			})
		}
	}
}
