// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A push syncs the Ansible playbooks and inventories that track the pushed repository and branch,
// whether or not any workspace tracks it too.
//
// Both push handlers used to look for workspaces first and return when none matched, before they
// reached the playbook and inventory sync. A repository that held only Ansible content never synced
// on a push, and its webhook-launched job templates never ran, although a playbook or inventory is
// linked to its repository and has nothing to do with a Terraform workspace.
//
// These cases send a push for a repository that only a playbook and an inventory track, through
// the real webhook handler, and assert both are queued for sync and the delivery is recorded as a
// success. A push that changes neither path syncs nothing and is recorded as ignored.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// syncQueue records ansible_sync jobs. The handlers enqueue from goroutines, so it is guarded.
type syncQueue struct {
	mu   sync.Mutex
	jobs []map[string]any
}

func (q *syncQueue) Enqueue(_ context.Context, queueName string, job any) error {
	if queueName != "ansible_sync" {
		return nil
	}
	m, _ := job.(map[string]any)
	q.mu.Lock()
	defer q.mu.Unlock()
	q.jobs = append(q.jobs, m)
	return nil
}

func (q *syncQueue) Close() error { return nil }

// waitFor reports whether a job naming id under key arrives within two seconds.
func (q *syncQueue) waitFor(key, id string) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		q.mu.Lock()
		for _, j := range q.jobs {
			if fmt.Sprint(j[key]) == id {
				q.mu.Unlock()
				return true
			}
		}
		q.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func (q *syncQueue) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.jobs)
}

// ansibleOnlyRepo seeds a project, the given connection, and a VCS playbook and inventory that
// track repo on main through it. No workspace tracks repo.
func ansibleOnlyRepo(t *testing.T, f *installationWebhookFixture, org *models.Organization, conn *models.VCSConnection, repo string) (*models.AnsiblePlaybook, *models.AnsibleInventory) {
	t.Helper()
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "push-sync-" + uuid.NewString()[:8]}
	playbook := &models.AnsiblePlaybook{
		ID: uuid.New(), ProjectID: project.ID, Name: "site", VCSConnectionID: &conn.ID,
		VCSRepository: repo, VCSBranch: "main", PlaybookPath: "playbooks/site.yml",
	}
	inventory := &models.AnsibleInventory{
		ID: uuid.New(), OrganizationID: org.ID, Name: "prod-" + uuid.NewString()[:8], Type: models.InventoryTypeVCS,
		VCSConnectionID: &conn.ID, VCSRepository: repo, VCSBranch: "main", InventoryPath: "inventories/prod.yml",
	}
	for _, row := range []any{conn, project, playbook, inventory} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	t.Cleanup(func() {
		f.db.Delete(&models.WebhookEvent{}, "repository = ?", repo)
		f.db.Delete(&models.AnsibleInventory{}, "id = ?", inventory.ID)
		f.db.Delete(&models.AnsiblePlaybook{}, "id = ?", playbook.ID)
		f.db.Delete(&models.Project{}, "id = ?", project.ID)
		f.db.Delete(&models.VCSConnection{}, "id = ?", conn.ID)
	})
	return playbook, inventory
}

// pushHandler wires the fixture's handler for push deliveries, with a recording queue.
func pushHandler(f *installationWebhookFixture) *syncQueue {
	q := &syncQueue{}
	f.handler.workspaceRepo = repository.NewWorkspaceRepository(f.db)
	f.handler.inventoryRepo = repository.NewAnsibleInventoryRepository(f.db)
	f.handler.playbookRepo = repository.NewAnsiblePlaybookRepository(f.db)
	f.handler.webhookEventRepo = repository.NewWebhookEventRepository(f.db)
	f.handler.ansibleQueue = q
	return q
}

func lastEvent(t *testing.T, f *installationWebhookFixture, repo string) models.WebhookEvent {
	t.Helper()
	var ev models.WebhookEvent
	if err := f.db.Where("repository = ?", repo).Order("delivered_at DESC").First(&ev).Error; err != nil {
		t.Fatalf("load webhook event for %s: %v", repo, err)
	}
	return ev
}

func TestGitHubPush_SyncsAnsibleWithoutAWorkspace(t *testing.T) {
	f := setupInstallationWebhook(t)
	q := pushHandler(f)
	org := f.organization(t)
	installation := f.installation(t)
	conn := &models.VCSConnection{
		ID: uuid.New(), OrganizationID: org.ID, Provider: models.VCSProviderGitHub,
		InstallationID: strconv.FormatInt(installation, 10), AccountName: "acme",
	}
	repo := "acme/ansible-only-" + uuid.NewString()[:8]
	playbook, inventory := ansibleOnlyRepo(t, f, org, conn, repo)

	push := func(t *testing.T, changed ...string) *httptest.ResponseRecorder {
		t.Helper()
		payload, err := json.Marshal(map[string]any{
			"ref": "refs/heads/main", "after": "0123456789abcdef0123456789abcdef01234567",
			"repository":   map[string]any{"full_name": repo, "id": 1},
			"installation": map[string]any{"id": installation},
			"commits": []map[string]any{{
				"id": "0123456789abcdef0123456789abcdef01234567", "modified": changed,
				"author": map[string]any{"name": "acceptance", "email": "acceptance@example.test"},
			}},
		})
		if err != nil {
			t.Fatalf("marshal push: %v", err)
		}
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost,
			"/api/v2/vcs-connections/github/webhook", bytes.NewReader(payload))
		c.Request.Header.Set("X-GitHub-Event", "push")
		c.Request.Header.Set("X-Hub-Signature-256", githubSign(payload, f.secret))
		f.handler.HandleInstallationWebhook(c)
		c.Writer.WriteHeaderNow()
		return w
	}

	t.Run("a push to the tracked paths syncs the playbook and the inventory", func(t *testing.T) {
		w := push(t, "playbooks/site.yml", "inventories/prod.yml")
		if w.Code != http.StatusOK {
			t.Fatalf("delivery = %d, want 200.\nbody: %s", w.Code, w.Body.String())
		}
		if !q.waitFor("playbook_id", playbook.ID.String()) {
			t.Errorf("no ansible_sync job for playbook %s; a repository no workspace tracks must still sync its playbooks", playbook.ID)
		}
		if !q.waitFor("inventory_id", inventory.ID.String()) {
			t.Errorf("no ansible_sync job for inventory %s; a repository no workspace tracks must still sync its inventories", inventory.ID)
		}
		ev := lastEvent(t, f, repo)
		if ev.Status != "success" || ev.OrganizationID == nil || *ev.OrganizationID != org.ID {
			t.Errorf("event = status %q, org %v, message %q; want success in org %s", ev.Status, ev.OrganizationID, ev.Message, org.ID)
		}
		if want := "1 playbook(s) and 1 inventory(ies) synced; 0 workspace(s) triggered"; ev.Message != want {
			t.Errorf("event message = %q, want %q", ev.Message, want)
		}
	})

	t.Run("a push that changes neither path syncs nothing", func(t *testing.T) {
		before := q.count()
		w := push(t, "README.md")
		if w.Code != http.StatusOK {
			t.Fatalf("delivery = %d, want 200.\nbody: %s", w.Code, w.Body.String())
		}
		time.Sleep(200 * time.Millisecond)
		if n := q.count() - before; n != 0 {
			t.Errorf("%d ansible_sync job(s) queued for a push that changed no tracked path; want none", n)
		}
		if ev := lastEvent(t, f, repo); ev.Status != "ignored" {
			t.Errorf("event status = %q (%q), want ignored", ev.Status, ev.Message)
		}
	})
}

func TestAzureDevOpsPush_SyncsAnsibleWithoutAWorkspace(t *testing.T) {
	f := setupInstallationWebhook(t)
	q := pushHandler(f)
	const secret = "ado-push-sync-test-secret"
	t.Setenv("AZURE_DEVOPS_CLIENT_ID", "") // a disabled manager still carries the webhook secret
	t.Setenv("AZURE_DEVOPS_WEBHOOK_SECRET", secret)
	manager, err := vcs.NewAzureDevOpsManager()
	if err != nil {
		t.Fatalf("NewAzureDevOpsManager: %v", err)
	}
	f.handler.azureDevOpsManager = manager

	org := f.organization(t)
	adoOrg := "ado-push-sync-" + uuid.NewString()[:8]
	conn := &models.VCSConnection{ID: uuid.New(), OrganizationID: org.ID, Provider: models.VCSProviderAzureDevOps, AccountName: adoOrg}
	repo := "infra/ansible-only-" + uuid.NewString()[:8] // project/repository
	playbook, inventory := ansibleOnlyRepo(t, f, org, conn, repo)

	project, repoName := "infra", repo[len("infra/"):]
	payload, err := json.Marshal(map[string]any{
		"eventType": "git.push",
		"resource": map[string]any{
			"refUpdates": []map[string]any{{"name": "refs/heads/main", "newObjectId": "0123456789abcdef0123456789abcdef01234567"}},
			"commits": []map[string]any{{
				"commitId": "0123456789abcdef0123456789abcdef01234567",
				"author":   map[string]any{"name": "acceptance", "email": "acceptance@example.test"},
				"changes": []map[string]any{
					{"item": map[string]any{"path": "/playbooks/site.yml"}},
					{"item": map[string]any{"path": "/inventories/prod.yml"}},
				},
			}},
			"repository": map[string]any{
				"name": repoName, "project": map[string]any{"name": project},
				"remoteUrl": fmt.Sprintf("https://%s@dev.azure.com/%s/%s/_git/%s", adoOrg, adoOrg, project, repoName),
				"url":       fmt.Sprintf("https://dev.azure.com/%s/_apis/git/repositories/%s", adoOrg, repoName),
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal push: %v", err)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v2/vcs-connections/azure-devops/webhook", bytes.NewReader(payload))
	c.Request.SetBasicAuth("stackweaver", secret)
	f.handler.HandleAzureDevOpsWebhook(c)
	c.Writer.WriteHeaderNow()

	if w.Code != http.StatusOK {
		t.Fatalf("delivery = %d, want 200.\nbody: %s", w.Code, w.Body.String())
	}
	if !q.waitFor("playbook_id", playbook.ID.String()) {
		t.Errorf("no ansible_sync job for playbook %s; a repository no workspace tracks must still sync its playbooks", playbook.ID)
	}
	if !q.waitFor("inventory_id", inventory.ID.String()) {
		t.Errorf("no ansible_sync job for inventory %s; a repository no workspace tracks must still sync its inventories", inventory.ID)
	}
	ev := lastEvent(t, f, repo)
	if ev.Status != "success" || ev.OrganizationID == nil || *ev.OrganizationID != org.ID {
		t.Errorf("event = status %q, org %v, message %q; want success in org %s", ev.Status, ev.OrganizationID, ev.Message, org.ID)
	}
}
