// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package handlers

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// TestFilterWorkspacesByInstallation is the AUD-102 assertion: a webhook delivery must only
// trigger workspaces connected through THAT delivery's GitHub App installation. Matching by repo
// full_name + branch alone let an attacker install the app on a same-named repo and drive
// auto-apply runs in a victim org; binding to the installation drops the cross-org workspace.
func TestFilterWorkspacesByInstallation(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://iac:iac_password@localhost:5432/iac_platform?sslmode=disable" //nolint:gosec // G101: test database URL
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Skipf("no test database: %v", err)
	}
	if err := db.AutoMigrate(&models.Organization{}, &models.Project{}, &models.VCSConnection{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	orgA := &models.Organization{ID: uuid.New(), Name: "wh-org-a-" + uuid.New().String()[:8]}
	orgB := &models.Organization{ID: uuid.New(), Name: "wh-org-b-" + uuid.New().String()[:8]}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "wh-proj-a"}
	projB := &models.Project{ID: uuid.New(), OrganizationID: orgB.ID, Name: "wh-proj-b"}
	connA := &models.VCSConnection{ID: uuid.New(), OrganizationID: orgA.ID, Provider: models.VCSProviderGitHub, InstallationID: "111", AccountName: "org-a"}
	connB := &models.VCSConnection{ID: uuid.New(), OrganizationID: orgB.ID, Provider: models.VCSProviderGitHub, InstallationID: "222", AccountName: "org-b"}
	for _, m := range []any{orgA, orgB, projA, projB, connA, connB} {
		if err := db.Create(m).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		db.Exec("DELETE FROM vcs_connections WHERE id IN (?,?)", connA.ID, connB.ID)
		db.Exec("DELETE FROM projects WHERE id IN (?,?)", projA.ID, projB.ID)
		db.Exec("DELETE FROM organizations WHERE id IN (?,?)", orgA.ID, orgB.ID)
	})

	h := &VCSAppInstallationHandlerV2{vcsConnectionRepo: repository.NewVCSConnectionRepository(db)}

	// Same repo full_name + branch across two orgs (the collision the exploit relies on), plus a
	// workspace with no connection.
	//
	// Each workspace has its project since #916. The workspaces here used to carry no project at
	// all, which the filter did not mind: it loaded a workspace's connection by identifier alone.
	// It now loads the connection within the workspace's organization, which is that of its
	// project, so a workspace whose organization cannot be established is matched to no delivery.
	// What this test asserts is unchanged.
	wsA := models.Workspace{ID: uuid.New().String(), ProjectID: projA.ID, VCSConnectionID: &connA.ID, VCSRepository: "acme/infra", VCSBranch: "main"}
	wsB := models.Workspace{ID: uuid.New().String(), ProjectID: projB.ID, VCSConnectionID: &connB.ID, VCSRepository: "acme/infra", VCSBranch: "main"}
	wsNoConn := models.Workspace{ID: uuid.New().String(), ProjectID: projA.ID, VCSRepository: "acme/infra", VCSBranch: "main"}

	// A push delivered for installation 111 (org A) must keep only wsA.
	kept := h.filterWorkspacesByInstallation([]models.Workspace{wsA, wsB, wsNoConn}, "111")
	if len(kept) != 1 || kept[0].ID != wsA.ID {
		t.Fatalf("installation 111 kept %d workspace(s) %v; want only wsA (%s) - cross-org workspace leaked", len(kept), workspaceIDs(kept), wsA.ID)
	}

	// A delivery for an installation that matches no connection triggers nothing.
	if kept := h.filterWorkspacesByInstallation([]models.Workspace{wsA, wsB}, "999"); len(kept) != 0 {
		t.Fatalf("unknown installation kept %d workspace(s); want 0", len(kept))
	}
}

// bindingFixture is two organizations, each with a project, a GitHub App connection and an Azure
// DevOps connection. Every resource below names the same repository and branch in both, which is
// the collision a delivery must not cross.
type bindingFixture struct {
	h                    *VCSAppInstallationHandlerV2
	orgA, orgB           *models.Organization
	projA, projB         *models.Project
	ghA, ghB, adoA, adoB *models.VCSConnection
}

func setupBindingFixture(t *testing.T) *bindingFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://iac:iac_password@localhost:5432/iac_platform?sslmode=disable" //nolint:gosec // G101: test database URL
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Skipf("no test database: %v", err)
	}
	if err := db.AutoMigrate(&models.Organization{}, &models.Project{}, &models.VCSConnection{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	sfx := uuid.New().String()[:8]
	f := &bindingFixture{
		h:    &VCSAppInstallationHandlerV2{vcsConnectionRepo: repository.NewVCSConnectionRepository(db)},
		orgA: &models.Organization{ID: uuid.New(), Name: "whb-a-" + sfx},
		orgB: &models.Organization{ID: uuid.New(), Name: "whb-b-" + sfx},
	}
	f.projA = &models.Project{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "whb-proj-a"}
	f.projB = &models.Project{ID: uuid.New(), OrganizationID: f.orgB.ID, Name: "whb-proj-b"}
	f.ghA = &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgA.ID, Provider: models.VCSProviderGitHub, InstallationID: "111-" + sfx, AccountName: "org-a"}
	f.ghB = &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgB.ID, Provider: models.VCSProviderGitHub, InstallationID: "222-" + sfx, AccountName: "org-b"}
	// Azure DevOps organization names are unique per run, because orgFromADOOrg looks them up
	// across every organization in the database.
	f.adoA = &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgA.ID, Provider: models.VCSProviderAzureDevOps, AccountName: "contoso-" + sfx}
	f.adoB = &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgB.ID, Provider: models.VCSProviderAzureDevOps, AccountName: "fabrikam-" + sfx}
	for _, m := range []any{f.orgA, f.orgB, f.projA, f.projB, f.ghA, f.ghB, f.adoA, f.adoB} {
		if err := db.Create(m).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		db.Exec("DELETE FROM vcs_connections WHERE id IN (?,?,?,?)", f.ghA.ID, f.ghB.ID, f.adoA.ID, f.adoB.ID)
		db.Exec("DELETE FROM projects WHERE id IN (?,?)", f.projA.ID, f.projB.ID)
		db.Exec("DELETE FROM organizations WHERE id IN (?,?)", f.orgA.ID, f.orgB.ID)
	})
	return f
}

// A push syncs every matched playbook and launches its webhook-enabled job templates, so a
// delivery must match only the playbooks connected through its own installation or Azure DevOps
// organization. Matching by repository name let a delivery run another organization's jobs, and
// on Azure DevOps a project/repository name is only unique within one Azure DevOps organization.
func TestFilterPlaybooksByDeliveryConnection(t *testing.T) {
	f := setupBindingFixture(t)

	playbook := func(proj *models.Project, conn *models.VCSConnection) models.AnsiblePlaybook {
		pb := models.AnsiblePlaybook{ID: uuid.New(), ProjectID: proj.ID, VCSRepository: "infra/ansible", VCSBranch: "main"}
		if conn != nil {
			pb.VCSConnectionID = &conn.ID
		}
		return pb
	}
	ghPbA, ghPbB := playbook(f.projA, f.ghA), playbook(f.projB, f.ghB)
	adoPbA, adoPbB := playbook(f.projA, f.adoA), playbook(f.projB, f.adoB)
	noConn := playbook(f.projA, nil)
	// A playbook in organization B whose row names organization A's connection: it must not ride
	// on A's deliveries, because its connection is loaded within its own organization.
	foreign := playbook(f.projB, f.ghA)
	all := []models.AnsiblePlaybook{ghPbA, ghPbB, adoPbA, adoPbB, noConn, foreign}

	if kept := f.h.filterPlaybooksByInstallation(all, f.ghA.InstallationID); len(kept) != 1 || kept[0].ID != ghPbA.ID {
		t.Errorf("installation %s kept %v; want only organization A's GitHub playbook %s", f.ghA.InstallationID, playbookIDs(kept), ghPbA.ID)
	}
	if kept := f.h.filterPlaybooksByInstallation(all, "999"); len(kept) != 0 {
		t.Errorf("unknown installation kept %v; want none", playbookIDs(kept))
	}
	// Azure DevOps organization names compare without case, as filterWorkspacesByADOOrg does.
	if kept := f.h.filterPlaybooksByADOOrg(all, strings.ToUpper(f.adoA.AccountName)); len(kept) != 1 || kept[0].ID != adoPbA.ID {
		t.Errorf("Azure DevOps organization %s kept %v; want only organization A's playbook %s", f.adoA.AccountName, playbookIDs(kept), adoPbA.ID)
	}
	if kept := f.h.filterPlaybooksByADOOrg(all, ""); len(kept) != 0 {
		t.Errorf("unresolved Azure DevOps organization kept %v; want none", playbookIDs(kept))
	}
}

// A tag push publishes a version of every matched module, so it must match only the modules
// connected through the delivery's installation, never another organization's module on a
// repository of the same name.
func TestFilterModulesByInstallation(t *testing.T) {
	f := setupBindingFixture(t)

	modA := models.Module{ID: uuid.New(), OrganizationID: f.orgA.ID, VCSConnectionID: &f.ghA.ID, VCSRepository: "acme/terraform-aws-vpc"}
	modB := models.Module{ID: uuid.New(), OrganizationID: f.orgB.ID, VCSConnectionID: &f.ghB.ID, VCSRepository: "acme/terraform-aws-vpc"}
	foreign := models.Module{ID: uuid.New(), OrganizationID: f.orgB.ID, VCSConnectionID: &f.ghA.ID, VCSRepository: "acme/terraform-aws-vpc"}
	noConn := models.Module{ID: uuid.New(), OrganizationID: f.orgA.ID, VCSRepository: "acme/terraform-aws-vpc"}
	all := []models.Module{modA, modB, foreign, noConn}

	if kept := f.h.filterModulesByInstallation(all, f.ghA.InstallationID); len(kept) != 1 || kept[0].ID != modA.ID {
		t.Errorf("installation %s kept %d module(s); want only organization A's module %s", f.ghA.InstallationID, len(kept), modA.ID)
	}
	if kept := f.h.filterModulesByInstallation(all, "999"); len(kept) != 0 {
		t.Errorf("unknown installation kept %d module(s); want none", len(kept))
	}
}

// orgFromADOOrg names the organization whose connection was made for the delivery's Azure DevOps
// organization, and no organization for one nobody connected.
func TestOrgFromADOOrg(t *testing.T) {
	f := setupBindingFixture(t)

	if got := f.h.orgFromADOOrg(strings.ToUpper(f.adoB.AccountName)); got == nil || *got != f.orgB.ID {
		t.Errorf("orgFromADOOrg(%q) = %v, want organization B %v", f.adoB.AccountName, got, f.orgB.ID)
	}
	if got := f.h.orgFromADOOrg("nobody-connected-" + f.orgA.Name); got != nil {
		t.Errorf("orgFromADOOrg(unconnected) = %v, want nil", got)
	}
	if got := f.h.orgFromADOOrg(""); got != nil {
		t.Errorf("orgFromADOOrg(\"\") = %v, want nil", got)
	}
}

func playbookIDs(pbs []models.AnsiblePlaybook) []string {
	ids := make([]string, len(pbs))
	for i := range pbs {
		ids[i] = pbs[i].ID.String()
	}
	return ids
}

func workspaceIDs(ws []models.Workspace) []string {
	ids := make([]string, len(ws))
	for i := range ws {
		ids[i] = ws[i].ID
	}
	return ids
}
