// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A workspace response's permissions block tells the caller what it may do, so each flag must say
// what the matching action would allow this caller, using the action's own check:
//
//	can-queue-run        run create: the runs permission and write access
//	can-queue-destroy    the same, and the workspace allows destroy plans
//	can-update-variable  variable writes: the variables permission and write access
//	can-read-settings    workspace read: membership of the organization
//	can-update/destroy   workspace update and delete: "Manage workspaces", or write access
//	can-lock/unlock      the lock permission
//	can-force-unlock     force-unlock's admin check
//
// can-force-delete is the one flag left constant (see formatWorkspaceResponse). A list answers
// every workspace from one load of the caller's grants, so its query count does not grow with the
// number of workspaces.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration
// +build integration

package terraform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"gorm.io/gorm"
)

var permissionFlags = []string{
	"can-queue-run", "can-queue-destroy", "can-update-variable", "can-read-settings",
	"can-update", "can-destroy", "can-lock", "can-unlock", "can-force-unlock", "can-force-delete",
}

type workspaceDoc struct {
	ID         string `json:"id"`
	Attributes struct {
		Permissions map[string]bool `json:"permissions"`
	} `json:"attributes"`
}

func (f *forceUnlockFixture) get(t *testing.T, path string, asUser uuid.UUID, out any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Test-User", asUser.String())
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d.\nbody: %s", path, rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func (f *forceUnlockFixture) permissions(t *testing.T, workspaceID string, asUser uuid.UUID) map[string]bool {
	t.Helper()
	var doc struct {
		Data workspaceDoc `json:"data"`
	}
	f.get(t, "/api/v2/workspaces/"+workspaceID, asUser, &doc)
	return doc.Data.Attributes.Permissions
}

// actionChecks answers every flag the way the matching action decides, one call per check.
func (f *forceUnlockFixture) actionChecks(t *testing.T, userID uuid.UUID, ws *models.Workspace) map[string]bool {
	t.Helper()
	ctx := context.Background()
	must := func(ok bool, err error) bool {
		t.Helper()
		if err != nil {
			t.Fatalf("permission check: %v", err)
		}
		return ok
	}
	resource := func(p rbac.Permission) bool {
		return must(f.rbac.CheckResourcePermission(ctx, userID, rbac.ResourceTypeTerraformWorkspace, ws.ID, p, &ws.ProjectID))
	}
	queueRun := resource(rbac.PermissionRuns) && resource(rbac.PermissionWorkspaceWrite)
	write := must(f.rbac.CheckOrgManageWorkspaces(ctx, userID, f.org.ID)) ||
		must(f.rbac.CheckWorkspacePermission(ctx, userID, ws.ID, rbac.PermissionWorkspaceWrite, ws.ProjectID))
	lock := must(f.rbac.CheckWorkspaceLockingPermission(ctx, userID, ws.ID, ws.ProjectID))
	return map[string]bool{
		"can-queue-run":       queueRun,
		"can-queue-destroy":   queueRun && ws.AllowDestroyPlan,
		"can-update-variable": must(f.rbac.CheckVariablePermission(ctx, userID, ws.ID, ws.ProjectID, "write")),
		"can-read-settings":   must(f.orgRepo.UserInOrg(userID, f.org.ID)),
		"can-update":          write,
		"can-destroy":         write,
		"can-lock":            lock,
		"can-unlock":          lock,
		"can-force-unlock":    must(f.rbac.CheckWorkspaceAdminPermission(ctx, userID, ws.ID, ws.ProjectID)),
		"can-force-delete":    true,
	}
}

func assertFlags(t *testing.T, label string, got, want map[string]bool) {
	t.Helper()
	for _, flag := range permissionFlags {
		v, present := got[flag]
		if !present {
			t.Errorf("%s: %s is missing; the TFE response shape always carries it", label, flag)
			continue
		}
		if v != want[flag] {
			t.Errorf("%s: %s = %t, want %t", label, flag, v, want[flag])
		}
	}
}

func TestWorkspacePermissions_ReflectTheCaller(t *testing.T) {
	f := setupForceUnlockFixture(t)
	var ws models.Workspace
	if err := f.db.Where("id = ?", f.workspaceID).First(&ws).Error; err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	if err := f.db.Model(&ws).Update("allow_destroy_plan", false).Error; err != nil {
		t.Fatalf("disallow destroy plans: %v", err)
	}
	ws.AllowDestroyPlan = false

	all := func(v bool) map[string]bool {
		m := map[string]bool{}
		for _, flag := range permissionFlags {
			m[flag] = v
		}
		m["can-force-delete"] = true
		return m
	}
	// Explicit expectations for the roles whose answer is plain; the destroy flag is false for
	// everyone because this workspace does not allow destroy plans.
	full := all(true)
	full["can-queue-destroy"] = false
	writer := all(true)
	writer["can-queue-destroy"], writer["can-force-unlock"] = false, false
	reader := all(false)
	reader["can-read-settings"] = true
	explicit := map[string]map[string]bool{
		"owner": full, "manage-all": full, "workspace-admin": full, "project-admin": full,
		"workspace-write": writer, "project-write": writer, "project-read": reader,
	}

	for _, caller := range []string{"owner", "manage-all", "project-admin", "project-maintain", "workspace-admin", "workspace-write", "project-write", "project-read"} {
		t.Run(caller, func(t *testing.T) {
			got := f.permissions(t, ws.ID, f.users[caller])
			assertFlags(t, caller+" against the action checks", got, f.actionChecks(t, f.users[caller], &ws))
			if want, ok := explicit[caller]; ok {
				assertFlags(t, caller, got, want)
			}
		})
	}
}

// One caller whose access differs per workspace: admin on the first, write through the second's
// project, nothing on the third beyond reading the organization's workspaces.
func TestWorkspacePermissions_ListWithMixedAccess(t *testing.T) {
	f := setupForceUnlockFixture(t)
	db := f.db
	sfx := uuid.NewString()[:8]

	writeProject := &models.Project{ID: uuid.New(), OrganizationID: f.org.ID, Name: "perm-w-" + sfx}
	bareProject := &models.Project{ID: uuid.New(), OrganizationID: f.org.ID, Name: "perm-b-" + sfx}
	writeWS := &models.Workspace{ID: "ws-pw" + sfx + "00000", ProjectID: writeProject.ID, Name: "perm-w-" + sfx, AllowDestroyPlan: true}
	bareWS := &models.Workspace{ID: "ws-pb" + sfx + "00000", ProjectID: bareProject.ID, Name: "perm-b-" + sfx, AllowDestroyPlan: true}
	user := &models.User{ID: uuid.New(), ZitadelSubject: "perm-mixed-" + sfx, Email: "perm-mixed-" + sfx + "@test.local"}
	team := &models.Team{ID: uuid.New(), OrganizationID: f.org.ID, Name: "perm-mixed-" + sfx}
	admin, write := "admin", "write"
	rows := []any{
		writeProject, bareProject, writeWS, bareWS, user, team,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.org.ID, UserID: user.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: user.ID},
		&models.TeamOrganizationAccess{ID: uuid.New(), TeamID: team.ID, ReadWorkspaces: true},
		&models.TeamWorkspaceAccess{ID: uuid.New(), TeamID: team.ID, WorkspaceID: f.workspaceID, Access: &admin},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: team.ID, ProjectID: writeProject.ID, Access: &write},
	}
	var extraWS []string
	t.Cleanup(func() {
		db.Where("team_id = ?", team.ID).Delete(&models.TeamWorkspaceAccess{})
		db.Where("team_id = ?", team.ID).Delete(&models.TeamProjectAccess{})
		db.Where("team_id = ?", team.ID).Delete(&models.TeamOrganizationAccess{})
		db.Where("team_id = ?", team.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", team.ID).Delete(&models.Team{})
		db.Where("id IN ?", append([]string{writeWS.ID, bareWS.ID}, extraWS...)).Delete(&models.Workspace{})
		db.Where("id IN ?", []uuid.UUID{writeProject.ID, bareProject.ID}).Delete(&models.Project{})
		db.Where("user_id = ?", user.ID).Delete(&models.OrganizationMember{})
		db.Where("id = ?", user.ID).Delete(&models.User{})
	})
	for _, row := range rows {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	list := func() map[string]map[string]bool {
		var doc struct {
			Data []workspaceDoc `json:"data"`
		}
		f.get(t, "/api/v2/organizations/"+f.org.Name+"/workspaces?page[size]=100", user.ID, &doc)
		out := map[string]map[string]bool{}
		for _, d := range doc.Data {
			out[d.ID] = d.Attributes.Permissions
		}
		return out
	}
	listed := list()

	var all []models.Workspace
	if err := db.Where("id IN ?", []string{f.workspaceID, writeWS.ID, bareWS.ID}).Find(&all).Error; err != nil {
		t.Fatalf("load workspaces: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("loaded %d workspaces, want 3", len(all))
	}
	for i := range all {
		ws := &all[i]
		got, ok := listed[ws.ID]
		if !ok {
			t.Fatalf("the list does not contain %s", ws.ID)
		}
		want := f.actionChecks(t, user.ID, ws)
		assertFlags(t, "listed "+ws.Name, got, want)
		assertFlags(t, "read "+ws.Name, f.permissions(t, ws.ID, user.ID), want)
	}
	// The three differ, so the list cannot be answering one verdict for all of them.
	if listed[f.workspaceID]["can-force-unlock"] != true || listed[writeWS.ID]["can-force-unlock"] != false ||
		listed[writeWS.ID]["can-queue-run"] != true || listed[bareWS.ID]["can-queue-run"] != false {
		t.Errorf("the list does not tell the three workspaces apart: %v", listed)
	}

	// The query count of a list does not grow with the number of workspaces it answers.
	var queries atomic.Int64
	count := func(*gorm.DB) { queries.Add(1) }
	name := "perm-count-" + sfx
	if err := db.Callback().Query().After("gorm:query").Register(name, count); err != nil {
		t.Fatalf("register query counter: %v", err)
	}
	if err := db.Callback().Row().After("gorm:row").Register(name, count); err != nil {
		t.Fatalf("register row counter: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Callback().Query().Remove(name)
		_ = db.Callback().Row().Remove(name)
	})
	queries.Store(0)
	list()
	small := queries.Load()

	for i := range 5 {
		extra := &models.Workspace{ID: "ws-px" + sfx + string(rune('a'+i)) + "0000", ProjectID: bareProject.ID, Name: "perm-x-" + sfx + string(rune('a'+i)), AllowDestroyPlan: true}
		if err := db.Create(extra).Error; err != nil {
			t.Fatalf("seed extra workspace: %v", err)
		}
		extraWS = append(extraWS, extra.ID)
	}
	queries.Store(0)
	if n := len(list()); n < 8 {
		t.Fatalf("the list has %d workspaces, want at least 8", n)
	}
	if large := queries.Load(); large > small {
		t.Errorf("listing 5 more workspaces ran %d queries instead of %d", large, small)
	}
}
