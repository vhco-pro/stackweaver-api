// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Several organizations can connect one GitHub App installation or one Azure DevOps organization
// (#938). A delivery is recorded once in each connected organization's webhook-event log, and in
// no other, and each organization's event names only its own resources with its own counts
// (AC-07, AC-17). An Azure DevOps connection that cannot prove access to the delivery's Azure
// DevOps organization receives nothing.

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

const attributionCommit = "0123456789abcdef0123456789abcdef01234567"

// attributedOrg is one organization's connection and the resources it holds on the repository.
type attributedOrg struct {
	org       *models.Organization
	workspace string
}

// seedAttributedOrg gives org a project, the connection, a speculative workspace named after the
// organization, and a playbook and an inventory, all tracking repo on main through conn.
func seedAttributedOrg(t *testing.T, f *installationWebhookFixture, q *syncRecorder, org *models.Organization, conn *models.VCSConnection, repo, name string) attributedOrg {
	t.Helper()
	ansibleOnlyRepo(t, f, q, org, conn, repo)
	var project models.Project
	if err := f.db.Where("organization_id = ?", org.ID).First(&project).Error; err != nil {
		t.Fatalf("load project: %v", err)
	}
	ws := &models.Workspace{
		ProjectID: project.ID, Name: name, VCSConnectionID: &conn.ID, VCSRepository: repo, VCSBranch: "main",
		SpeculativeEnabled: true, FileTriggersEnabled: false, AutoQueueRuns: true,
	}
	if err := f.db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	t.Cleanup(func() {
		f.db.Delete(&models.Run{}, "workspace_id = ?", ws.ID)
		f.db.Delete(&models.ConfigurationVersion{}, "workspace_id = ?", ws.ID)
		f.db.Delete(&models.Workspace{}, "id = ?", ws.ID)
	})
	return attributedOrg{org: org, workspace: name}
}

// eventsFor returns every webhook event recorded for repo, oldest first.
func eventsFor(t *testing.T, f *installationWebhookFixture, repo string) []models.WebhookEvent {
	t.Helper()
	var evs []models.WebhookEvent
	if err := f.db.Where("repository = ?", repo).Order("delivered_at").Find(&evs).Error; err != nil {
		t.Fatalf("load webhook events: %v", err)
	}
	return evs
}

// assertAttributed checks that repo has exactly one event in each of want's organizations, none in
// any other, and that each names its own workspace with wantMessage and never another's.
func assertAttributed(t *testing.T, f *installationWebhookFixture, repo string, want []attributedOrg, wantMessage func(attributedOrg) string) {
	t.Helper()
	evs := eventsFor(t, f, repo)
	byOrg := map[uuid.UUID][]models.WebhookEvent{}
	for _, ev := range evs {
		if ev.OrganizationID == nil {
			t.Errorf("an event was recorded without an organization: %q", ev.Message)
			continue
		}
		byOrg[*ev.OrganizationID] = append(byOrg[*ev.OrganizationID], ev)
	}
	if len(byOrg) != len(want) {
		t.Errorf("events were recorded in %d organization(s), want %d", len(byOrg), len(want))
	}
	for _, w := range want {
		got := byOrg[w.org.ID]
		if len(got) != 1 {
			t.Errorf("organization %s has %d event(s), want 1", w.org.Name, len(got))
			continue
		}
		if msg := wantMessage(w); got[0].Message != msg {
			t.Errorf("organization %s's event says %q, want %q", w.org.Name, got[0].Message, msg)
		}
		for _, other := range want {
			if other.org.ID != w.org.ID && strings.Contains(got[0].Message, other.workspace) {
				t.Errorf("organization %s's event names %s's workspace %q", w.org.Name, other.org.Name, other.workspace)
			}
		}
	}
}

func deliverGitHub(t *testing.T, f *installationWebhookFixture, event string, body map[string]any) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal delivery: %v", err)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v2/vcs-connections/github/webhook", bytes.NewReader(payload))
	c.Request.Header.Set("X-GitHub-Event", event)
	c.Request.Header.Set("X-Hub-Signature-256", githubSign(payload, f.secret))
	f.handler.HandleInstallationWebhook(c)
	c.Writer.WriteHeaderNow()
	if w.Code != http.StatusOK {
		t.Fatalf("%s delivery = %d, want 200.\nbody: %s", event, w.Code, w.Body.String())
	}
}

func TestGitHubDeliveryIsRecordedInEveryConnectedOrganization(t *testing.T) {
	f := setupInstallationWebhook(t)
	q := pushHandler(f)
	installation := strconv.FormatInt(f.installation(t), 10)
	sfx := uuid.NewString()[:8]
	repo := "acme/shared-" + sfx

	orgA, orgB, unconnected := f.organization(t), f.organization(t), f.organization(t)
	a := seedAttributedOrg(t, f, q, orgA, &models.VCSConnection{ID: uuid.New(), OrganizationID: orgA.ID, Provider: models.VCSProviderGitHub, InstallationID: installation, AccountName: "acme"}, repo, "alpha-"+sfx)
	b := seedAttributedOrg(t, f, q, orgB, &models.VCSConnection{ID: uuid.New(), OrganizationID: orgB.ID, Provider: models.VCSProviderGitHub, InstallationID: installation, AccountName: "acme"}, repo, "beta-"+sfx)
	_ = unconnected
	instID, _ := strconv.ParseInt(installation, 10, 64)

	t.Run("push", func(t *testing.T) {
		deliverGitHub(t, f, "push", map[string]any{
			"ref": "refs/heads/main", "after": attributionCommit,
			"repository":   map[string]any{"full_name": repo, "id": 1},
			"installation": map[string]any{"id": instID},
			"commits": []map[string]any{{
				"id": attributionCommit, "modified": []string{"playbooks/site.yml", "inventories/prod.yml", "main.tf"},
				"author": map[string]any{"name": "acceptance", "email": "acceptance@example.test"},
			}},
		})
		assertAttributed(t, f, repo, []attributedOrg{a, b}, func(o attributedOrg) string {
			return "1 playbook(s) and 1 inventory(ies) synced; 1 workspace(s) triggered: " + o.workspace
		})
	})

	f.db.Delete(&models.WebhookEvent{}, "repository = ?", repo)

	t.Run("pull request", func(t *testing.T) {
		deliverGitHub(t, f, "pull_request", map[string]any{
			"action": "opened", "number": 7,
			"pull_request": map[string]any{
				"head": map[string]any{"ref": "feature", "sha": attributionCommit},
				"base": map[string]any{"ref": "main"},
				"user": map[string]any{"login": "acceptance"},
			},
			"repository":   map[string]any{"full_name": repo, "id": 1},
			"installation": map[string]any{"id": instID},
		})
		assertAttributed(t, f, repo, []attributedOrg{a, b}, func(o attributedOrg) string {
			return "PR #7: 1 workspace(s) triggered: " + o.workspace
		})
	})
}

func TestAzureDevOpsDeliveryIsRecordedInEveryTrustedOrganization(t *testing.T) {
	f := setupInstallationWebhook(t)
	q := pushHandler(f)
	const secret = "ado-attribution-test-secret"
	t.Setenv("AZURE_DEVOPS_CLIENT_ID", "") // a disabled manager still carries the webhook secret
	t.Setenv("AZURE_DEVOPS_WEBHOOK_SECRET", secret)
	manager, err := vcs.NewAzureDevOpsManager()
	if err != nil {
		t.Fatalf("NewAzureDevOpsManager: %v", err)
	}
	f.handler.azureDevOpsManager = manager
	// The claimant's token cannot reach the Azure DevOps organization.
	f.handler.verifyADOAccount = func(context.Context, *models.VCSConnection) error { return errors.New("no access") }

	sfx := uuid.NewString()[:8]
	adoOrg := "ado-shared-" + sfx
	project, repoName := "infra", "shared-"+sfx
	repo := project + "/" + repoName
	verified := time.Now()
	orgA, orgB, orgC := f.organization(t), f.organization(t), f.organization(t)
	a := seedAttributedOrg(t, f, q, orgA, &models.VCSConnection{ID: uuid.New(), OrganizationID: orgA.ID, Provider: models.VCSProviderAzureDevOps, AccountName: adoOrg, AccountVerifiedAt: &verified}, repo, "alpha-"+sfx)
	b := seedAttributedOrg(t, f, q, orgB, &models.VCSConnection{ID: uuid.New(), OrganizationID: orgB.ID, Provider: models.VCSProviderAzureDevOps, AccountName: strings.ToUpper(adoOrg), AccountVerifiedAt: &verified}, repo, "beta-"+sfx)
	seedAttributedOrg(t, f, q, orgC, &models.VCSConnection{ID: uuid.New(), OrganizationID: orgC.ID, Provider: models.VCSProviderAzureDevOps, AccountName: adoOrg}, repo, "claimant-"+sfx)

	repository := map[string]any{
		"name": repoName, "project": map[string]any{"name": project},
		"remoteUrl": fmt.Sprintf("https://%s@dev.azure.com/%s/%s/_git/%s", adoOrg, adoOrg, project, repoName),
		"url":       fmt.Sprintf("https://dev.azure.com/%s/_apis/git/repositories/%s", adoOrg, repoName),
	}
	deliver := func(t *testing.T, body map[string]any) {
		t.Helper()
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal delivery: %v", err)
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
	}

	t.Run("push", func(t *testing.T) {
		deliver(t, map[string]any{
			"eventType": "git.push",
			"resource": map[string]any{
				"refUpdates": []map[string]any{{"name": "refs/heads/main", "newObjectId": attributionCommit}},
				"commits": []map[string]any{{
					"commitId": attributionCommit,
					"author":   map[string]any{"name": "acceptance", "email": "acceptance@example.test"},
					"changes": []map[string]any{
						{"item": map[string]any{"path": "/playbooks/site.yml"}},
						{"item": map[string]any{"path": "/inventories/prod.yml"}},
						{"item": map[string]any{"path": "/main.tf"}},
					},
				}},
				"repository": repository,
			},
		})
		assertAttributed(t, f, repo, []attributedOrg{a, b}, func(o attributedOrg) string {
			return "1 playbook(s) and 1 inventory(ies) synced; 1 workspace(s) triggered: " + o.workspace
		})
	})

	f.db.Delete(&models.WebhookEvent{}, "repository = ?", repo)

	t.Run("pull request", func(t *testing.T) {
		deliver(t, map[string]any{
			"eventType": "git.pullrequest.created",
			"resource": map[string]any{
				"pullRequestId": 7, "status": "active",
				"sourceRefName": "refs/heads/feature", "targetRefName": "refs/heads/main",
				"lastMergeSourceCommit": map[string]any{"commitId": attributionCommit},
				"createdBy":             map[string]any{"displayName": "acceptance", "uniqueName": "acceptance@example.test"},
				"repository":            repository,
			},
		})
		assertAttributed(t, f, repo, []attributedOrg{a, b}, func(o attributedOrg) string {
			return "PR #7: 1 workspace(s) triggered: " + o.workspace
		})
	})
}
