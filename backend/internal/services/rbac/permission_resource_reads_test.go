// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package rbac

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

func TestPermissionResourceReadErrors(t *testing.T) {
	db := openPermissionReadDB(t)
	suffix := uuid.NewString()
	org := &models.Organization{ID: uuid.New(), Name: "permission-resources-" + suffix}
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "permission-" + suffix}
	user := &models.User{ID: uuid.New(), ZitadelSubject: "permission-resources-" + suffix, Email: suffix + "@test.local"}
	team := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "members"}
	member := &models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: user.ID}
	teamMember := &models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: user.ID}
	t.Cleanup(func() {
		for _, row := range []any{teamMember, member, team, project, org, user} {
			if err := db.Delete(row).Error; err != nil {
				t.Error(err)
			}
		}
		if err := db.Where("name = ?", org.Name).Delete(&models.ReservedOrganizationName{}).Error; err != nil {
			t.Error(err)
		}
	})
	for _, row := range []any{org, project, user, team, member, teamMember} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	service := NewServiceWithTeams(repository.NewOrganizationRepository(db), repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	const workspace = "ws-permission-read"
	workspaceCheck := func(ctx context.Context) (bool, error) {
		return service.CheckWorkspacePermission(ctx, user.ID, workspace, PermissionWorkspaceRead, project.ID)
	}
	workspaceAdmin := func(ctx context.Context) (bool, error) {
		return service.CheckWorkspaceAdminPermission(ctx, user.ID, workspace, project.ID)
	}
	readable := func(ctx context.Context) (bool, error) {
		items, err := service.ReadableWorkspaces(ctx, user.ID, org.ID, []models.Workspace{
			{ID: workspace, ProjectID: project.ID},
		}, PermissionWorkspaceRead)
		return len(items) > 0, err
	}
	workspaceGrants := func(ctx context.Context) (bool, error) {
		grants, err := service.LoadWorkspaceGrants(ctx, user.ID, org.ID)
		return grants != nil && grants.Has(project.ID, workspace, PermissionWorkspaceRead), err
	}
	effective := func(ctx context.Context) (bool, error) {
		permissions, err := service.GetEffectivePermissions(ctx, user.ID, org.ID)
		return permissions[PermissionOrgManageAgentPools], err
	}
	for _, check := range []struct {
		name  string
		table string
		read  func(context.Context) (bool, error)
	}{
		{"resource project", "projects", workspaceCheck},
		{"resource membership", "organization_members", workspaceCheck},
		{"resource project grant", "team_project_accesses", workspaceCheck},
		{"resource workspace grant", "team_workspace_accesses", workspaceCheck},
		{"workspace admin project", "projects", workspaceAdmin},
		{"workspace admin project grant", "team_project_accesses", workspaceAdmin},
		{"workspace admin workspace grant", "team_workspace_accesses", workspaceAdmin},
		{"readable membership", "organization_members", readable},
		{"workspace grants membership", "organization_members", workspaceGrants},
		{"workspace grants project rows", "team_project_accesses", workspaceGrants},
		{"workspace grants workspace rows", "team_workspace_accesses", workspaceGrants},
		{"effective membership", "organization_members", effective},
		{"manage membership", "organization_members", func(ctx context.Context) (bool, error) {
			return service.CheckOrgManageMembership(ctx, user.ID, org.ID)
		}},
		{"manage teams membership", "organization_members", func(ctx context.Context) (bool, error) {
			return service.CheckOrgManageTeams(ctx, user.ID, org.ID)
		}},
		{"owner membership", "organization_members", func(ctx context.Context) (bool, error) {
			return service.IsOrgOwner(ctx, user.ID, org.ID)
		}},
	} {
		t.Run(check.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), permissionRequestKey{}, true))
			defer cancel()
			var injected error
			var canceled bool
			var observed bool
			var scoped bool
			const observer = "permission_resource_reads:observe"
			if err := db.Callback().Query().Before("gorm:query").Register(observer, func(tx *gorm.DB) {
				if tx.Statement.Table != check.table || observed {
					return
				}
				observed = true
				scoped, _ = tx.Statement.Context.Value(permissionRequestKey{}).(bool)
				if canceled {
					cancel()
				} else if injected != nil {
					_ = tx.AddError(injected)
				}
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := db.Callback().Query().Remove(observer); err != nil {
					t.Error(err)
				}
			})

			if allowed, err := check.read(ctx); allowed || err != nil || !observed {
				t.Errorf("absence control = %t, %v; observed %t", allowed, err, observed)
			}
			injected = errors.New("permission database unavailable")
			observed, scoped = false, false
			if allowed, err := check.read(ctx); allowed || !errors.Is(err, injected) || !observed || !scoped {
				t.Errorf("error control = %t, %v; observed %t; request context %t", allowed, err, observed, scoped)
			}
			canceled, observed, scoped = true, false, false
			if allowed, err := check.read(ctx); allowed || !errors.Is(err, context.Canceled) || !observed || !scoped {
				t.Errorf("cancel control = %t, %v; observed %t; request context %t", allowed, err, observed, scoped)
			}
		})
	}
}
