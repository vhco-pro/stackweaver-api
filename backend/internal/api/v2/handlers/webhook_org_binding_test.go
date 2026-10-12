// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package handlers

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
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
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
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

func workspaceIDs(ws []models.Workspace) []string {
	ids := make([]string, len(ws))
	for i := range ws {
		ids[i] = ws[i].ID
	}
	return ids
}
