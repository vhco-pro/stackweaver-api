// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Differential test for #800's team lookups.
//
// ListTeamsWithWorkspaceAccess and GetTeamAccessForAnsibleTemplate used to load every team in the
// organization - capped at 1000, which is the bug - and decide in Go. They now ask the database for
// candidates first: teams named `owners` or holding any access row for the target. The permission
// decision itself stays in Go, because it is a mapping rather than a row test
// (getPermissionsFromOrganizationAccess alone sets 55 entries and carries TFE's implication rules),
// and expressing that in SQL would put those semantics in two languages.
//
// The risk that narrowing introduces is an omission: a team the mapping would have kept but the
// candidate query never returned. So this test computes the answer BOTH ways over one seeded corpus
// - the old full-scan algorithm written out here against the unexported predicate, and the shipped
// path - and asserts they agree. A leg missing from the candidate query fails it by name.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the dev DB has no backup). Run with:
//
//	cd backend && go test -tags integration ./internal/services/rbac/ -run TestTeamCandidate

//go:build integration
// +build integration

package rbac

import (
	"os"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// legs describes one seeded team: which access rows it gets, and therefore which legs it exercises.
type legs struct {
	name      string
	orgAccess *models.TeamOrganizationAccess // leg 2, when non-nil
	projRead  bool                           // leg 3
	wsRead    bool                           // leg 4
}

func strptr(s string) *string { return &s }

func setupRBACDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	// The full set: rbac reads wide association graphs, and a partial migrate passes only against a
	// database that already has every table.
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestTeamCandidateNarrowingAgreesWithTheFullScan(t *testing.T) {
	db := setupRBACDB(t)
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "rbaccand-org-" + sfx}
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "rbaccand-proj-" + sfx}
	workspace := &models.Workspace{ID: "ws-cand" + sfx + "0000", ProjectID: project.ID, Name: "rbaccand-ws-" + sfx}

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

	// Each leg alone, every pair, all three access rows, none - plus the case that proves narrowing
	// is a superset and not the verdict: an org-access row that grants nothing relevant, so the
	// candidate query must return it and the mapping must still reject it.
	reaching := &models.TeamOrganizationAccess{ReadWorkspaces: true}
	irrelevant := &models.TeamOrganizationAccess{ManagePolicies: true}
	corpus := []legs{
		{name: "owners"}, // leg 1: the name bypass, with no access rows at all
		{name: "org-only", orgAccess: reaching},
		{name: "proj-only", projRead: true},
		{name: "ws-only", wsRead: true},
		{name: "org-and-proj", orgAccess: reaching, projRead: true},
		{name: "org-and-ws", orgAccess: reaching, wsRead: true},
		{name: "proj-and-ws", projRead: true, wsRead: true},
		{name: "all-three", orgAccess: reaching, projRead: true, wsRead: true},
		{name: "no-access", orgAccess: nil},
		{name: "org-row-but-irrelevant", orgAccess: irrelevant},
	}

	for _, spec := range corpus {
		team := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: spec.name + "-" + sfx}
		if spec.name == "owners" {
			team.Name = "owners" // the bypass is by exact name
		}
		if err := db.Create(team).Error; err != nil {
			t.Fatalf("seed team %s: %v", spec.name, err)
		}
		if spec.orgAccess != nil {
			access := *spec.orgAccess
			access.ID = uuid.New()
			access.TeamID = team.ID
			if err := db.Create(&access).Error; err != nil {
				t.Fatalf("seed org access for %s: %v", spec.name, err)
			}
		}
		if spec.projRead {
			if err := db.Create(&models.TeamProjectAccess{
				ID: uuid.New(), TeamID: team.ID, ProjectID: project.ID, Access: strptr("read"),
			}).Error; err != nil {
				t.Fatalf("seed project access for %s: %v", spec.name, err)
			}
		}
		if spec.wsRead {
			if err := db.Create(&models.TeamWorkspaceAccess{
				ID: uuid.New(), TeamID: team.ID, WorkspaceID: workspace.ID, Access: strptr("read"),
			}).Error; err != nil {
				t.Fatalf("seed workspace access for %s: %v", spec.name, err)
			}
		}
	}

	teamRepo := repository.NewTeamRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	svc := NewServiceWithTeams(orgRepo, teamRepo, repository.NewProjectRepository(db))

	names := func(teams []models.Team, keep func(*models.Team) bool) []string {
		out := []string{}
		for i := range teams {
			if keep(&teams[i]) {
				out = append(out, teams[i].Name)
			}
		}
		sort.Strings(out)
		return out
	}

	// The old algorithm, written out: every team in the organization, filtered by the predicate.
	everyTeam, _, err := teamRepo.List(org.ID, 100000, 0)
	if err != nil {
		t.Fatalf("list every team: %v", err)
	}
	wantWorkspace := names(everyTeam, func(team *models.Team) bool {
		return svc.teamReachesWorkspace(team, project.ID, workspace.ID)
	})
	if len(wantWorkspace) == 0 {
		t.Fatal("the corpus produced no reaching teams, so this test would prove nothing")
	}

	// The narrowed set must contain every team the mapping keeps, so filtering it gives the same
	// answer. This is the property that a missing leg breaks.
	candidates, err := teamRepo.ListWithAnyAccess(org.ID, project.ID, workspace.ID)
	if err != nil {
		t.Fatalf("ListWithAnyAccess: %v", err)
	}
	gotNarrowed := names(candidates, func(team *models.Team) bool {
		return svc.teamReachesWorkspace(team, project.ID, workspace.ID)
	})
	if !equalStrings(gotNarrowed, wantWorkspace) {
		t.Errorf("candidate narrowing changed the answer:\n  full scan: %v\n  narrowed:  %v", wantWorkspace, gotNarrowed)
	}

	// And the shipped call site agrees with the full scan.
	shipped, err := svc.ListTeamsWithWorkspaceAccess(org.ID, project.ID, workspace.ID)
	if err != nil {
		t.Fatalf("ListTeamsWithWorkspaceAccess: %v", err)
	}
	gotShipped := make([]string, 0, len(shipped))
	for _, s := range shipped {
		gotShipped = append(gotShipped, s.TeamName)
	}
	sort.Strings(gotShipped)
	if !equalStrings(gotShipped, wantWorkspace) {
		t.Errorf("ListTeamsWithWorkspaceAccess disagrees with the full scan:\n  want: %v\n  got:  %v", wantWorkspace, gotShipped)
	}

	// The ansible path has its own legs - org access and project access, no owners bypass - so it is
	// differentiated separately against the same corpus.
	wantAnsible := names(everyTeam, func(team *models.Team) bool {
		access := svc.ansibleTemplateAccessFor(team, project.ID)
		return access.Read || access.Write || access.Execute
	})
	shippedAnsible, err := svc.GetTeamAccessForAnsibleTemplate(org.ID, project.ID)
	if err != nil {
		t.Fatalf("GetTeamAccessForAnsibleTemplate: %v", err)
	}
	gotAnsible := make([]string, 0, len(shippedAnsible))
	for _, a := range shippedAnsible {
		gotAnsible = append(gotAnsible, a.TeamName)
	}
	sort.Strings(gotAnsible)
	if !equalStrings(gotAnsible, wantAnsible) {
		t.Errorf("GetTeamAccessForAnsibleTemplate disagrees with the full scan:\n  want: %v\n  got:  %v", wantAnsible, gotAnsible)
	}

	// A team with no access row and no owners name cannot reach anything, so it must not even be a
	// candidate - that is what makes the narrowing worth doing.
	for i := range candidates {
		if candidates[i].Name == "no-access-"+sfx {
			t.Errorf("a team with no access rows was returned as a candidate")
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
