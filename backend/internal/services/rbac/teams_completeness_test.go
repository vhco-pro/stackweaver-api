// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Completeness test for #800's team lookups.
//
// Both call sites used to ask TeamRepository.List for a page of 1000, ordered by name, and treat it
// as the organization's whole team set. Past a thousand teams the answer was the alphabetically
// first thousand, so a team whose name sorts later simply stopped being notified or listed - and
// nothing errored.
//
// This seeds exactly that shape: a thousand access-less teams whose names sort first, and one
// access-holding team whose name sorts last. Against the old page the holder was invisible and both
// call sites returned nothing; against the candidate query it is the only row they load.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the dev DB has no backup). Run with:
//
//	cd backend && go test -tags integration ./internal/services/rbac/ -run TestTeamLookupsPastTheOldPage

//go:build integration
// +build integration

package rbac

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// fillerTeams is the size of the page the old code asked for, so the access holder sits one past it.
const fillerTeams = 1000

func TestTeamLookupsPastTheOldPage(t *testing.T) {
	db := setupRBACDB(t)
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "rbacfull-org-" + sfx}
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "rbacfull-proj-" + sfx}
	workspace := &models.Workspace{ID: "ws-full" + sfx + "0000", ProjectID: project.ID, Name: "rbacfull-ws-" + sfx}

	t.Cleanup(func() {
		db.Where("workspace_id = ?", workspace.ID).Delete(&models.TeamWorkspaceAccess{})
		db.Where("project_id = ?", project.ID).Delete(&models.TeamProjectAccess{})
		db.Exec(`DELETE FROM team_organization_accesses WHERE team_id IN
			(SELECT id FROM teams WHERE organization_id = ?)`, org.ID)
		db.Where("organization_id = ?", org.ID).Delete(&models.Team{})
		db.Where("id = ?", workspace.ID).Delete(&models.Workspace{})
		db.Where("id = ?", project.ID).Delete(&models.Project{})
		db.Where("name = ?", org.Name).Delete(&models.ReservedOrganizationName{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
	})

	for _, obj := range []any{org, project, workspace} {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}

	// A thousand teams with no access of any kind, named to sort before the holder.
	fillers := make([]models.Team, 0, fillerTeams)
	for i := range fillerTeams {
		fillers = append(fillers, models.Team{
			ID:             uuid.New(),
			OrganizationID: org.ID,
			Name:           fmt.Sprintf("aaa-%04d-%s", i, sfx),
		})
	}
	if err := db.CreateInBatches(&fillers, 200).Error; err != nil {
		t.Fatalf("seed %d filler teams: %v", fillerTeams, err)
	}

	// The holder, sorting last, reachable through the project leg so both call sites should see it.
	holder := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "zzz-holder-" + sfx}
	if err := db.Create(holder).Error; err != nil {
		t.Fatalf("seed holder team: %v", err)
	}
	access := "admin"
	if err := db.Create(&models.TeamProjectAccess{
		ID: uuid.New(), TeamID: holder.ID, ProjectID: project.ID, Access: &access,
	}).Error; err != nil {
		t.Fatalf("seed holder project access: %v", err)
	}

	teamRepo := repository.NewTeamRepository(db)
	svc := NewServiceWithTeams(repository.NewOrganizationRepository(db), teamRepo, repository.NewProjectRepository(db))

	// The window the old code used really does exclude the holder, which is what makes the
	// assertions below meaningful rather than tautological.
	page, total, err := teamRepo.List(org.ID, fillerTeams, 0)
	if err != nil {
		t.Fatalf("list the old page: %v", err)
	}
	if total < int64(fillerTeams+1) {
		t.Fatalf("expected more than %d teams, got total %d", fillerTeams, total)
	}
	for i := range page {
		if page[i].ID == holder.ID {
			t.Fatalf("the %d-row window unexpectedly contains the holder, so this test cannot prove the cap", fillerTeams)
		}
	}

	// AC1: the notification audience includes the holder.
	audience, err := svc.ListTeamsWithWorkspaceAccess(org.ID, project.ID, workspace.ID)
	if err != nil {
		t.Fatalf("ListTeamsWithWorkspaceAccess: %v", err)
	}
	if !containsTeam(audience, holder.ID) {
		t.Errorf("the workspace notification audience omits the holder team, which sorts past the old %d-row page: got %d team(s)",
			fillerTeams, len(audience))
	}

	// AC2: the ansible template access listing includes it too.
	listing, err := svc.GetTeamAccessForAnsibleTemplate(org.ID, project.ID)
	if err != nil {
		t.Fatalf("GetTeamAccessForAnsibleTemplate: %v", err)
	}
	found := false
	for _, entry := range listing {
		if entry.TeamID == holder.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("the ansible template access listing omits the holder team: got %d entr(ies)", len(listing))
	}
}

func containsTeam(audience []TeamWithWorkspaceAccess, id uuid.UUID) bool {
	for _, a := range audience {
		if a.TeamID == id {
			return true
		}
	}
	return false
}
