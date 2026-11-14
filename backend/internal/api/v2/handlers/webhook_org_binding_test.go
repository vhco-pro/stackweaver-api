// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package handlers

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

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
	db                   *gorm.DB
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
		db:   db,
		h:    &VCSAppInstallationHandlerV2{vcsConnectionRepo: repository.NewVCSConnectionRepository(db)},
		orgA: &models.Organization{ID: uuid.New(), Name: "whb-a-" + sfx},
		orgB: &models.Organization{ID: uuid.New(), Name: "whb-b-" + sfx},
	}
	f.projA = &models.Project{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "whb-proj-a"}
	f.projB = &models.Project{ID: uuid.New(), OrganizationID: f.orgB.ID, Name: "whb-proj-b"}
	f.ghA = &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgA.ID, Provider: models.VCSProviderGitHub, InstallationID: "111-" + sfx, AccountName: "org-a"}
	f.ghB = &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgB.ID, Provider: models.VCSProviderGitHub, InstallationID: "222-" + sfx, AccountName: "org-b"}
	// Azure DevOps organization names are unique per run, because orgFromADOOrg looks them up
	// across every organization in the database. Both connections stand for ones made through the
	// OAuth flow, which proves the token against the Azure DevOps organization, so they carry the
	// verification mark: an unverified connection is trusted only after its token proves access
	// (TestADODeliveryTrustsOnlyVerifiedConnections).
	verified := time.Now()
	f.adoA = &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgA.ID, Provider: models.VCSProviderAzureDevOps, AccountName: "contoso-" + sfx, AccountVerifiedAt: &verified}
	f.adoB = &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgB.ID, Provider: models.VCSProviderAzureDevOps, AccountName: "fabrikam-" + sfx, AccountVerifiedAt: &verified}
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

// A connection made through the direct-create API names an Azure DevOps organization nobody
// proved. Such a connection must not receive another organization's deliveries just by claiming
// its Azure DevOps organization name: a delivery reaches an Azure DevOps connection only once its
// stored token has proven access to that organization, and the proof is remembered.
func TestADODeliveryTrustsOnlyVerifiedConnections(t *testing.T) {
	f := setupBindingFixture(t)

	// Organization B claims organization A's Azure DevOps organization with a connection that was
	// never verified, created before A's so the oldest-first lookup would reach it first.
	claim := &models.VCSConnection{
		ID: uuid.New(), OrganizationID: f.orgB.ID, Provider: models.VCSProviderAzureDevOps,
		AccountName: f.adoA.AccountName, CreatedAt: time.Now().Add(-time.Hour),
	}
	// An unverified connection whose token does reach its Azure DevOps organization, as one made
	// before verification was recorded would.
	legacy := &models.VCSConnection{
		ID: uuid.New(), OrganizationID: f.orgB.ID, Provider: models.VCSProviderAzureDevOps,
		AccountName: "legacy-" + f.orgB.Name,
	}
	for _, c := range []*models.VCSConnection{claim, legacy} {
		if err := f.db.Create(c).Error; err != nil {
			t.Fatalf("seed connection: %v", err)
		}
	}
	t.Cleanup(func() { f.db.Exec("DELETE FROM vcs_connections WHERE id IN (?,?)", claim.ID, legacy.ID) })

	calls := map[uuid.UUID]int{}
	f.h.verifyADOAccount = func(_ context.Context, conn *models.VCSConnection) error {
		calls[conn.ID]++
		if conn.ID == legacy.ID {
			return nil
		}
		return errors.New("token cannot reach the Azure DevOps organization")
	}

	if got := f.h.orgFromADOOrg(f.adoA.AccountName); got == nil || *got != f.orgA.ID {
		t.Errorf("orgFromADOOrg(%q) = %v, want organization A %v, not the unverified claimant", f.adoA.AccountName, got, f.orgA.ID)
	}

	wsA := models.Workspace{ID: uuid.New().String(), ProjectID: f.projA.ID, VCSConnectionID: &f.adoA.ID, VCSRepository: "proj/infra", VCSBranch: "main"}
	wsClaim := models.Workspace{ID: uuid.New().String(), ProjectID: f.projB.ID, VCSConnectionID: &claim.ID, VCSRepository: "proj/infra", VCSBranch: "main"}
	if kept := f.h.filterWorkspacesByADOOrg([]models.Workspace{wsA, wsClaim}, f.adoA.AccountName); len(kept) != 1 || kept[0].ID != wsA.ID {
		t.Errorf("workspaces kept %v; want only organization A's %s", workspaceIDs(kept), wsA.ID)
	}

	pbA := models.AnsiblePlaybook{ID: uuid.New(), ProjectID: f.projA.ID, VCSConnectionID: &f.adoA.ID, VCSRepository: "proj/ansible", VCSBranch: "main"}
	pbClaim := models.AnsiblePlaybook{ID: uuid.New(), ProjectID: f.projB.ID, VCSConnectionID: &claim.ID, VCSRepository: "proj/ansible", VCSBranch: "main"}
	if kept := f.h.filterPlaybooksByADOOrg([]models.AnsiblePlaybook{pbA, pbClaim}, f.adoA.AccountName); len(kept) != 1 || kept[0].ID != pbA.ID {
		t.Errorf("playbooks kept %v; want only organization A's %s", playbookIDs(kept), pbA.ID)
	}

	invA := models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.orgA.ID, ProjectID: &f.projA.ID, VCSConnectionID: &f.adoA.ID}
	invClaim := models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.orgB.ID, ProjectID: &f.projB.ID, VCSConnectionID: &claim.ID}
	if kept := f.h.filterInventoriesByADOOrg([]models.AnsibleInventory{invA, invClaim}, f.adoA.AccountName); len(kept) != 1 || kept[0].ID != invA.ID {
		t.Errorf("inventories kept %d; want only organization A's %s", len(kept), invA.ID)
	}

	if calls[f.adoA.ID] != 0 {
		t.Errorf("a verified connection was verified again %d time(s)", calls[f.adoA.ID])
	}

	// The legacy connection proves access on its first delivery and keeps the mark.
	if got := f.h.orgFromADOOrg(legacy.AccountName); got == nil || *got != f.orgB.ID {
		t.Errorf("orgFromADOOrg(%q) = %v, want organization B %v once its token proves access", legacy.AccountName, got, f.orgB.ID)
	}
	var stored models.VCSConnection
	if err := f.db.First(&stored, "id = ?", legacy.ID).Error; err != nil || stored.AccountVerifiedAt == nil {
		t.Fatalf("the proven connection was not marked verified: %v", err)
	}
	_ = f.h.orgFromADOOrg(legacy.AccountName)
	if calls[legacy.ID] != 1 {
		t.Errorf("the proven connection was verified %d times, want once", calls[legacy.ID])
	}
	var claimed models.VCSConnection
	if err := f.db.First(&claimed, "id = ?", claim.ID).Error; err != nil || claimed.AccountVerifiedAt != nil {
		t.Errorf("the claimant was marked verified after failing: %v", err)
	}
}
