// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What the runner control plane and the push webhook hand out when the row they act on names a
// VCS connection of another organization (#916). The API refuses to store such an identifier,
// but a row written before it did may hold one, and these are the places a stored identifier
// becomes a token-embedded clone URL with no caller to authorize: for a self-hosted runner, and
// for the sync a push queues.
//
// The defect these tests were written against: both loaded the connection by identifier alone,
// so the runner of one organization, or its sync worker, received a clone URL built with another
// organization's token.
//
// The rows are written directly, the way one stored before the API checked would be. GitLab is
// the provider whose clone URL is built from the stored token with no network.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Every row is created under
// a unique name and removed by primary key. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run 'VCSConnectionOfAnotherOrganization'

//go:build integration

package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"gorm.io/gorm"
)

// The token of the second organization's connection: a string that shows up in anything built
// with it.
const otherVCSToken = "token-of-the-other-organization"

// seedOtherConnection adds a connection of organization B to the agent fixture.
func (f *agentPrepFixture) seedOtherConnection(t *testing.T) *models.VCSConnection {
	t.Helper()
	other := &models.VCSConnection{
		ID: uuid.New(), OrganizationID: f.runnerB1.OrganizationID, Provider: models.VCSProviderGitLab,
		AccessToken: otherVCSToken, AccountName: "vcsscope-b-" + uuid.NewString()[:8],
	}
	if err := f.db.Create(other).Error; err != nil {
		t.Fatalf("seeding the other organization's connection: %v", err)
	}
	// Registered before the rows that name it are seeded, so it runs after their cleanup.
	t.Cleanup(func() { f.db.Where("id = ?", other.ID).Delete(&models.VCSConnection{}) })
	return other
}

// storedPlaybookNaming seeds a playbook of organization A and rewrites its connection directly.
func (f *agentPrepFixture) storedPlaybookNaming(t *testing.T, spec playbookSpec, connection *models.VCSConnection) *models.AnsiblePlaybook {
	t.Helper()
	playbook := f.seedPlaybook(t, spec)
	if err := f.db.Model(&models.AnsiblePlaybook{}).Where("id = ?", playbook.ID).Update("vcs_connection_id", connection.ID).Error; err != nil {
		t.Fatalf("rewriting the playbook's connection: %v", err)
	}
	playbook.VCSConnectionID = &connection.ID
	return playbook
}

// TestRunnerJobArtifacts_PlaybookVCSConnectionOfAnotherOrganization is the payload of a
// self-hosted Ansible runner: the clone instructions for a fresh playbook, and for a cached one
// that has no snapshot yet (which also queues a sync).
func TestRunnerJobArtifacts_PlaybookVCSConnectionOfAnotherOrganization(t *testing.T) {
	for _, mode := range []string{models.PlaybookSourceModeFresh, models.PlaybookSourceModeCached} {
		t.Run(mode, func(t *testing.T) {
			f := setupAgentPrepFixture(t)
			other := f.seedOtherConnection(t)
			store, q := newSnapshotStore(), &recordingQueue{}
			router := f.artifactsRouter(store, q)
			playbook := f.storedPlaybookNaming(t, playbookSpec{mode: mode}, other)
			job := f.seedJob(t, &playbook.ID, nil)

			rec := runnerGet(t, router, "a1", "/api/v2/runner/jobs/"+job.ID.String()+"/artifacts")

			if strings.Contains(rec.Body.String(), otherVCSToken) {
				t.Errorf("the artifacts carry the other organization's token")
			}
			var doc map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err == nil {
				if _, ok := doc["vcs"]; ok {
					t.Errorf("the artifacts carry clone instructions for a playbook naming another organization's connection: %v", doc["vcs"])
				}
			}
			for _, payload := range q.payloads {
				if raw, err := json.Marshal(payload); err != nil || strings.Contains(string(raw), otherVCSToken) {
					t.Errorf("a queued sync carries the other organization's token (marshal error %v)", err)
				}
			}
		})
	}
}

// storedWorkspaceNaming writes an agent-executed workspace of organization A that names the given
// connection, with one pending run that has no configuration version: the shape of a workspace
// row stored before the API checked the connection, at the point a self-hosted runner asks what
// to clone for it.
func (f *agentPrepFixture) storedWorkspaceNaming(t *testing.T, connection uuid.UUID) (*models.Workspace, *models.Run) {
	t.Helper()
	sfx := uuid.NewString()[:8]
	workspace := &models.Workspace{
		ID: "ws-" + sfx + "9160000", ProjectID: f.projectA, Name: "vcsscope-ws-" + sfx,
		VCSConnectionID: &connection, VCSRepository: "acme/infra", VCSBranch: "main",
		ExecutionMode: "agent", AgentPoolID: &f.poolA, AutoQueueRuns: true,
	}
	run := &models.Run{
		ID: "run-" + sfx + "9160000", WorkspaceID: workspace.ID, Status: models.RunStatusPending,
		Operation: models.RunOperationPlanOnly, AgentPoolID: &f.poolA,
	}
	for _, row := range []any{workspace, run} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatalf("writing %T: %v", row, err)
		}
	}
	t.Cleanup(func() {
		f.db.Where("id = ?", run.ID).Delete(&models.Run{})
		f.db.Where("id = ?", workspace.ID).Delete(&models.Workspace{})
	})
	return workspace, run
}

// TestRunnerRunArtifacts_WorkspaceVCSConnectionOfAnotherOrganization is the payload of a
// self-hosted OpenTofu runner. The platform runner never resolves a connection: it downloads the
// configuration version the API or a webhook cloned.
func TestRunnerRunArtifacts_WorkspaceVCSConnectionOfAnotherOrganization(t *testing.T) {
	f := setupAgentPrepFixture(t)
	other := f.seedOtherConnection(t)
	h := &RunnerAgentHandler{db: f.db, vcsRegistry: vcs.NewProviderRegistry(nil, nil, nil, nil)}
	router := f.router(func(authed *gin.RouterGroup) {
		authed.GET("/jobs/:id/artifacts", h.GetJobArtifacts)
	})
	artifacts := func(t *testing.T, run *models.Run) (string, map[string]any) {
		t.Helper()
		rec := runnerGet(t, router, "a1", "/api/v2/runner/jobs/"+run.ID+"/artifacts")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET artifacts: status = %d (%s)", rec.Code, rec.Body.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("decoding the artifacts: %v", err)
		}
		return rec.Body.String(), doc
	}

	_, storedRun := f.storedWorkspaceNaming(t, other.ID)
	body, doc := artifacts(t, storedRun)
	if strings.Contains(body, otherVCSToken) {
		t.Errorf("the artifacts carry the other organization's token")
	}
	if _, ok := doc["vcs"]; ok {
		t.Errorf("the artifacts carry clone instructions for a workspace naming another organization's connection: %v", doc["vcs"])
	}

	_, ownRun := f.storedWorkspaceNaming(t, f.vcsConn)
	_, doc = artifacts(t, ownRun)
	vcsInfo, _ := doc["vcs"].(map[string]any)
	if repoURL, _ := vcsInfo["repo_url"].(string); !strings.HasSuffix(repoURL, "@gitlab.com/acme/infra.git") {
		t.Errorf("vcs.repo_url = %q, want the clone URL of the organization's own connection", vcsInfo["repo_url"])
	}
}

// TestWebhook_WorkspaceVCSConnectionOfAnotherOrganization is a push or a pull request for a
// workspace. The match of a workspace to a delivery goes by the installation of the workspace's
// connection, and it is what decides whether a run is started and cloned for: a workspace of one
// organization that names the other's connection must not be matched to a delivery of the
// other's installation.
func TestWebhook_WorkspaceVCSConnectionOfAnotherOrganization(t *testing.T) {
	f := setupAgentPrepFixture(t)
	other := f.seedOtherConnection(t)
	const ownInstallation, otherInstallation = "880003", "880004"
	for id, installation := range map[uuid.UUID]string{f.vcsConn: ownInstallation, other.ID: otherInstallation} {
		if err := f.db.Model(&models.VCSConnection{}).Where("id = ?", id).Update("installation_id", installation).Error; err != nil {
			t.Fatalf("setting the installation of connection %s: %v", id, err)
		}
	}
	storedEarlier, _ := f.storedWorkspaceNaming(t, other.ID)
	own, _ := f.storedWorkspaceNaming(t, f.vcsConn)
	h := &VCSAppInstallationHandlerV2{
		vcsRegistry:       vcs.NewProviderRegistry(nil, nil, nil, nil),
		vcsConnectionRepo: repository.NewVCSConnectionRepository(f.db),
	}

	if conn, err := h.workspaceConnection(storedEarlier); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("a workspace naming another organization's connection resolved to %v (err %v), want not found", conn, err)
	}
	if conn, err := h.workspaceConnection(own); err != nil || conn.ID != f.vcsConn {
		t.Errorf("a workspace naming its organization's connection resolved to %v (err %v)", conn, err)
	}

	both := []models.Workspace{*storedEarlier, *own}
	if kept := h.filterWorkspacesByInstallation(both, otherInstallation); len(kept) != 0 {
		t.Errorf("a delivery of the other organization's installation is matched to %d workspace(s) of the first", len(kept))
	}
	kept := h.filterWorkspacesByInstallation(both, ownInstallation)
	if len(kept) != 1 || kept[0].ID != own.ID {
		t.Errorf("a delivery of the organization's own installation is matched to %d workspace(s), want the one naming its own connection", len(kept))
	}
}

// TestWebhookSyncPayload_PlaybookVCSConnectionOfAnotherOrganization is the sync a push queues for
// a playbook.
func TestWebhookSyncPayload_PlaybookVCSConnectionOfAnotherOrganization(t *testing.T) {
	f := setupAgentPrepFixture(t)
	other := f.seedOtherConnection(t)
	h := &VCSAppInstallationHandlerV2{
		vcsRegistry:       vcs.NewProviderRegistry(nil, nil, nil, nil),
		vcsConnectionRepo: repository.NewVCSConnectionRepository(f.db),
	}

	stored := f.storedPlaybookNaming(t, playbookSpec{}, other)
	payload := h.playbookSyncPayload(t.Context(), stored)
	if _, ok := payload["clone_url"]; ok {
		t.Errorf("the sync payload carries a clone URL for a playbook naming another organization's connection")
	}
	if payload["playbook_id"] != stored.ID.String() {
		t.Errorf("payload = %v, want the sync still requested for playbook %s", payload, stored.ID)
	}

	own := h.playbookSyncPayload(t.Context(), f.seedPlaybook(t, playbookSpec{}))
	if cloneURL, _ := own["clone_url"].(string); !strings.HasSuffix(cloneURL, "@gitlab.com/acme/playbooks.git") {
		t.Errorf("clone_url = %q, want the clone URL of the organization's own connection", own["clone_url"])
	}
}

// TestWebhook_InventoryVCSConnectionOfAnotherOrganization is a push for a VCS inventory: which
// inventories a delivery is matched to, and the sync it queues for one.
//
// The match is by the installation of the inventory's connection. An inventory of one
// organization that names the other's connection must not be matched to a delivery of the
// other's installation, or a push there would sync the first organization's inventory from the
// other's repository.
func TestWebhook_InventoryVCSConnectionOfAnotherOrganization(t *testing.T) {
	f := setupAgentPrepFixture(t)
	other := f.seedOtherConnection(t)
	const ownInstallation, otherInstallation = "880001", "880002"
	for id, installation := range map[uuid.UUID]string{f.vcsConn: ownInstallation, other.ID: otherInstallation} {
		if err := f.db.Model(&models.VCSConnection{}).Where("id = ?", id).Update("installation_id", installation).Error; err != nil {
			t.Fatalf("setting the installation of connection %s: %v", id, err)
		}
	}
	// Written directly: the shape of an inventory row stored before the API checked the connection.
	stored := func(connection uuid.UUID) models.AnsibleInventory {
		t.Helper()
		inventory := models.AnsibleInventory{
			ID: uuid.New(), OrganizationID: f.orgA, Name: "vcsscope-inv-" + uuid.NewString()[:8], Type: models.InventoryTypeVCS,
			VCSConnectionID: &connection, VCSRepository: "acme/inventories", VCSBranch: "main", InventoryPath: "hosts.yml",
		}
		if err := f.db.Create(&inventory).Error; err != nil {
			t.Fatalf("writing the inventory row: %v", err)
		}
		t.Cleanup(func() { f.db.Where("id = ?", inventory.ID).Delete(&models.AnsibleInventory{}) })
		return inventory
	}
	storedEarlier, own := stored(other.ID), stored(f.vcsConn)
	h := &VCSAppInstallationHandlerV2{
		vcsRegistry:       vcs.NewProviderRegistry(nil, nil, nil, nil),
		vcsConnectionRepo: repository.NewVCSConnectionRepository(f.db),
	}

	t.Run("the sync payload", func(t *testing.T) {
		if _, ok := h.inventorySyncPayload(t.Context(), &storedEarlier)["clone_url"]; ok {
			t.Errorf("the sync payload carries a clone URL for an inventory naming another organization's connection")
		}
		payload := h.inventorySyncPayload(t.Context(), &own)
		if cloneURL, _ := payload["clone_url"].(string); !strings.HasSuffix(cloneURL, "@gitlab.com/acme/inventories.git") {
			t.Errorf("clone_url = %q, want the clone URL of the organization's own connection", payload["clone_url"])
		}
	})
	t.Run("the delivery match", func(t *testing.T) {
		both := []models.AnsibleInventory{storedEarlier, own}
		if kept := h.filterInventoriesByInstallation(both, otherInstallation); len(kept) != 0 {
			t.Errorf("a delivery of the other organization's installation is matched to %d inventor(ies) of the first", len(kept))
		}
		kept := h.filterInventoriesByInstallation(both, ownInstallation)
		if len(kept) != 1 || kept[0].ID != own.ID {
			t.Errorf("a delivery of the organization's own installation is matched to %d inventor(ies), want the one naming its own connection", len(kept))
		}
	})
}
