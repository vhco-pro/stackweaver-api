// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A workspace's run timeout is zero (inherit) or a number of seconds up to
// settings.MaxRunTimeoutSeconds, through every route that writes a workspace: a negative value or one
// above the bound answers 422 rather than being dropped or stored.
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run 'TestWorkspaceRunTimeout'

//go:build integration

package terraform

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/settings"
)

func TestWorkspaceRunTimeout_IsBounded(t *testing.T) {
	f := setupWorkspacePools(t)
	name := "wstimeout-" + uuid.NewString()[:8]
	create := "/api/v2/organizations/" + f.orgName + "/workspaces"
	for _, bad := range []int{-10, settings.MaxRunTimeoutSeconds + 1} {
		if rec := f.send(t, http.MethodPost, create, map[string]any{"name": name, "run-timeout": bad}); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("create with run-timeout %d = %d, want 422 (%s)", bad, rec.Code, rec.Body.String())
		}
	}
	if rec := f.send(t, http.MethodPost, create, map[string]any{"name": name, "run-timeout": 3600}); rec.Code != http.StatusCreated {
		t.Fatalf("create with run-timeout 3600 = %d (%s)", rec.Code, rec.Body.String())
	}
	var ws models.Workspace
	if err := f.db.First(&ws, "project_id = ? AND name = ?", f.projectID, name).Error; err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v2/organizations/" + f.orgName + "/workspaces/" + name, "/api/v2/workspaces/" + ws.ID} {
		for _, bad := range []int{-10, settings.MaxRunTimeoutSeconds + 1} {
			if rec := f.send(t, http.MethodPatch, path, map[string]any{"run-timeout": bad}); rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("PATCH %s run-timeout %d = %d, want 422 (%s)", path, bad, rec.Code, rec.Body.String())
			}
		}
	}
	if err := f.db.First(&ws, "id = ?", ws.ID).Error; err != nil {
		t.Fatal(err)
	}
	if ws.RunTimeout != 3600 {
		t.Errorf("the refused updates left run-timeout %d, want 3600", ws.RunTimeout)
	}
}
