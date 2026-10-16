// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A member of an organization's owners team holds every permission in it. The organization-level
// checks and the resource-level checks must judge that membership the same way, so an owner is
// never refused a workspace action the organization-level checks would allow. The owners team
// here has no organization access row, which is what makes the two disagree when only one of
// them recognises the team.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration
// +build integration

package rbac

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestOwnersTeamIsJudgedTheSameAtEveryLevel(t *testing.T) {
	db := setupRBACDB(t)
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "rbacown-org-" + sfx}
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "rbacown-proj-" + sfx}
	workspace := &models.Workspace{ID: "ws-own" + sfx + "00000", ProjectID: project.ID, Name: "rbacown-ws-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "rbacown-" + sfx, Email: "rbacown-" + sfx + "@test.local"}
	owners := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}

	t.Cleanup(func() {
		db.Where("team_id = ?", owners.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", owners.ID).Delete(&models.Team{})
		db.Where("id = ?", workspace.ID).Delete(&models.Workspace{})
		db.Where("id = ?", project.ID).Delete(&models.Project{})
		db.Where("organization_id = ?", org.ID).Delete(&models.OrganizationMember{})
		db.Where("name = ?", org.Name).Delete(&models.ReservedOrganizationName{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
		db.Where("id = ?", owner.ID).Delete(&models.User{})
	})
	for _, obj := range []any{
		org, project, workspace, owner, owners,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: owners.ID, UserID: owner.ID},
	} {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}

	orgRepo := repository.NewOrganizationRepository(db)
	s := NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	ctx := context.Background()

	if ok, err := s.CheckOrgManageWorkspaces(ctx, owner.ID, org.ID); err != nil || !ok {
		t.Fatalf("an owner manages the organization's workspaces: got %t, %v", ok, err)
	}
	for _, perm := range []Permission{
		PermissionWorkspaceRead, PermissionWorkspaceWrite, PermissionWorkspaceLocking,
		PermissionRuns, PermissionVariables, PermissionStateVersions, PermissionRunTasks,
	} {
		ok, err := s.CheckWorkspacePermission(ctx, owner.ID, workspace.ID, perm, project.ID)
		if err != nil || !ok {
			t.Errorf("an owner holds %s on the organization's workspace: got %t, %v", perm, ok, err)
		}
	}
}
