// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package rbac

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

type permissionRequestKey struct{}

func openPermissionReadDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("permission regression needs TEST_DATABASE_URL for an isolated fixture database")
	}
	db, err := dbtest.Open(t, dsn, &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestPermissionReadErrors(t *testing.T) {
	readFailed := errors.New("permission query unavailable")
	for _, scenario := range []struct {
		name       string
		table      string
		useSubject bool
		fault      error
	}{
		{"organization membership SQL error", "organization_members", false, readFailed},
		{"organization membership cancellation", "organization_members", false, context.Canceled},
		{"no organization or team membership", "organization_members", false, nil},
		{"team subject SQL error", "teams", true, readFailed},
		{"team subject cancellation", "teams", true, context.Canceled},
		{"missing team subject", "teams", true, nil},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			db := openPermissionReadDB(t)
			org, user, team := uuid.New(), uuid.New(), uuid.New()
			ctx := context.WithValue(t.Context(), permissionRequestKey{}, true)
			if errors.Is(scenario.fault, context.Canceled) {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			receivedContext := false
			observed := false
			callback := db.Callback().Query()
			const name = "t24:observe_permission_read"
			if err := callback.Before("gorm:query").Register(name, func(tx *gorm.DB) {
				if tx.Statement.Table != scenario.table {
					return
				}
				observed = true
				receivedContext, _ = tx.Statement.Context.Value(permissionRequestKey{}).(bool)
				if errors.Is(scenario.fault, readFailed) {
					_ = tx.AddError(scenario.fault)
				}
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := callback.Remove(name); err != nil {
					t.Error(err)
				}
			})
			orgRepo := repository.NewOrganizationRepository(db)
			teamRepo := repository.NewTeamRepository(db)
			var allowed bool
			var permissionErr error
			if scenario.useSubject {
				ctx = WithSubject(ctx, Subject{kind: subjectTeam, organizationID: org, teamID: team})
				teams, err := TeamsInOrg(ctx, orgRepo, teamRepo, user, org)
				allowed, permissionErr = len(teams) > 0, err
			} else {
				service := NewServiceWithTeams(orgRepo, teamRepo, repository.NewProjectRepository(db))
				allowed, permissionErr = service.CheckOrgManageAgentPools(ctx, user, org)
			}
			if !observed {
				t.Fatal("the intended permission read did not run")
			}
			if !receivedContext {
				t.Error("the repository read did not receive the request context")
			}
			if allowed || !errors.Is(permissionErr, scenario.fault) {
				t.Errorf("permission result = %v, %v, want denied, %v", allowed, permissionErr, scenario.fault)
			}
		})
	}
}

func TestPermissionReadErrorsOrganizationAccessFallback(t *testing.T) {
	db := openPermissionReadDB(t)
	suffix := uuid.NewString()
	org := &models.Organization{ID: uuid.New(), Name: "permission-fallback-" + suffix}
	user := &models.User{ID: uuid.New(), ZitadelSubject: "permission-fallback-" + suffix, Email: suffix + "@test.local"}
	team := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "members"}
	membership := &models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: user.ID}
	teamMember := &models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: user.ID}
	t.Cleanup(func() {
		for _, row := range []any{teamMember, membership, team, org, user} {
			if err := db.Delete(row).Error; err != nil {
				t.Error(err)
			}
		}
		if err := db.Where("name = ?", org.Name).Delete(&models.ReservedOrganizationName{}).Error; err != nil {
			t.Error(err)
		}
	})
	for _, row := range []any{org, user, team, membership, teamMember} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	service := NewServiceWithTeams(repository.NewOrganizationRepository(db), repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	unavailable := errors.New("organization access fallback unavailable")
	for _, scenario := range []struct {
		name string
		want error
	}{
		{"no grant row", nil},
		{"query error", unavailable},
		{"request cancellation", context.Canceled},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), permissionRequestKey{}, true))
			defer cancel()
			reads := 0
			var receivedContext bool
			const callback = "permission_read_errors:observe_org_access_fallback"
			if err := db.Callback().Query().Before("gorm:query").Register(callback, func(tx *gorm.DB) {
				if tx.Statement.Table != "team_organization_accesses" {
					return
				}
				reads++
				if reads != 2 {
					return // The team lookup first preloads the missing grant.
				}
				receivedContext, _ = tx.Statement.Context.Value(permissionRequestKey{}).(bool)
				switch scenario.want {
				case context.Canceled:
					cancel()
				case unavailable:
					_ = tx.AddError(unavailable)
				}
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := db.Callback().Query().Remove(callback); err != nil {
					t.Error(err)
				}
			})
			allowed, err := service.CheckOrgManageAgentPools(ctx, user.ID, org.ID)
			if reads != 2 || !receivedContext || allowed || !errors.Is(err, scenario.want) {
				t.Errorf("fallback reads=%d, context=%v, allowed=%v, error=%v, want false and %v", reads, receivedContext, allowed, err, scenario.want)
			}
		})
	}
}

func TestPermissionReadErrorsGrantListings(t *testing.T) {
	db := openPermissionReadDB(t)
	org := &models.Organization{ID: uuid.New(), Name: "permission-list-" + uuid.NewString()}
	team := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "members"}
	grant := &models.TeamOrganizationAccess{ID: uuid.New(), TeamID: team.ID}
	t.Cleanup(func() {
		for _, row := range []any{grant, team, org} {
			if err := db.Delete(row).Error; err != nil {
				t.Error(err)
			}
		}
		if err := db.Where("name = ?", org.Name).Delete(&models.ReservedOrganizationName{}).Error; err != nil {
			t.Error(err)
		}
	})
	for _, row := range []any{org, team, grant} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}

	service := NewServiceWithTeams(repository.NewOrganizationRepository(db), repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	projectID := uuid.New()
	for _, scenario := range []struct {
		name  string
		table string
		list  func(context.Context) (int, error)
	}{
		{"workspace project grant", "team_project_accesses", func(ctx context.Context) (int, error) {
			teams, err := service.ListTeamsWithWorkspaceAccess(ctx, org.ID, projectID, "ws-absent")
			return len(teams), err
		}},
		{"workspace direct grant", "team_workspace_accesses", func(ctx context.Context) (int, error) {
			teams, err := service.ListTeamsWithWorkspaceAccess(ctx, org.ID, projectID, "ws-absent")
			return len(teams), err
		}},
		{"Ansible template project grant", "team_project_accesses", func(ctx context.Context) (int, error) {
			teams, err := service.GetTeamAccessForAnsibleTemplate(ctx, org.ID, projectID)
			return len(teams), err
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), permissionRequestKey{}, true)
			if count, err := scenario.list(ctx); count != 0 || err != nil {
				t.Fatalf("absent grant: got %d teams and %v", count, err)
			}
			readFailed := errors.New("grant read unavailable")
			observed, receivedContext := false, false
			callback := db.Callback().Query()
			const name = "t24:observe_grant_listing"
			if err := callback.Before("gorm:query").Register(name, func(tx *gorm.DB) {
				if tx.Statement.Table == scenario.table {
					observed = true
					receivedContext, _ = tx.Statement.Context.Value(permissionRequestKey{}).(bool)
					_ = tx.AddError(readFailed)
				}
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := callback.Remove(name); err != nil {
					t.Error(err)
				}
			})

			if count, err := scenario.list(ctx); count != 0 || !errors.Is(err, readFailed) {
				t.Errorf("unavailable grant: got %d teams and %v, want the database error", count, err)
			}
			if !observed || !receivedContext {
				t.Errorf("grant query observed = %v, request context received = %v", observed, receivedContext)
			}
		})
	}
}
