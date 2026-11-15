// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A push or pull-request delivery creates its run with a configuration version in status fetching,
// pinned to the delivery's commit, in the same transaction; an executor captures it (#938, AC-01,
// AC-03, AC-20). The API clones nothing. The version carries what later steps read: the commit,
// the ref to fetch, the pull request's number and branch and whether the run is speculative. One
// pair is created per commit however the delivery is repeated, and the capture's clone uses the
// workspace's own connection.

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	terraform "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers/terraform"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	coreansible "github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

const (
	captureHead = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	captureNext = "0123401234012340123401234012340123401234"
	// tokenlessInstallation is an installation the faked GitHub refuses to mint a token for.
	tokenlessInstallation = "404404"
)

// captureFixture is the webhook fixture with the repositories the capture paths write, an
// organization with a GitHub App connection on two installations, an Azure DevOps connection, and
// a speculative workspace on each.
type captureFixture struct {
	*installationWebhookFixture
	org           *models.Organization
	connA, connB  *models.VCSConnection
	ado           *models.VCSConnection
	instA, instB  int64
	adoOrg, repo  string
	wsApp, wsADO  *models.Workspace
	adoSecret     string
	githubAPI     *httptest.Server
	githubManager *vcs.GitHubAppManager
	// prFiles answers GitHub's List pull request files call; nil lists main.tf.
	prFiles http.HandlerFunc
}

func setupCapture(t *testing.T) *captureFixture {
	t.Helper()
	f := &captureFixture{installationWebhookFixture: setupInstallationWebhook(t)}
	pushHandler(f.installationWebhookFixture)
	f.handler.runRepo = repository.NewRunRepository(f.db)
	f.handler.configVersionRepo = repository.NewConfigurationVersionRepository(f.db)
	f.org = f.organization(t)
	f.instA, f.instB = f.installation(t), f.installation(t)
	sfx := uuid.NewString()[:8]
	f.repo, f.adoOrg = "acme/capture-"+sfx, "ado-capture-"+sfx
	verified := time.Now()
	f.connA = &models.VCSConnection{ID: uuid.New(), OrganizationID: f.org.ID, Provider: models.VCSProviderGitHub, InstallationID: strconv.FormatInt(f.instA, 10), AccountName: "acme"}
	f.connB = &models.VCSConnection{ID: uuid.New(), OrganizationID: f.org.ID, Provider: models.VCSProviderGitHub, InstallationID: strconv.FormatInt(f.instB, 10), AccountName: "octo"}
	f.ado = &models.VCSConnection{ID: uuid.New(), OrganizationID: f.org.ID, Provider: models.VCSProviderAzureDevOps, AccountName: f.adoOrg, AccessToken: "ado-token-of-x", AccountVerifiedAt: &verified}
	hosted := models.NewHostedPool(f.org.ID)
	project := &models.Project{ID: uuid.New(), OrganizationID: f.org.ID, Name: "capture-" + sfx}
	for _, row := range []any{hosted, f.connA, f.connB, f.ado, project} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	workspace := func(name string, conn *models.VCSConnection, repo string) *models.Workspace {
		ws := &models.Workspace{
			ProjectID: project.ID, Name: name + "-" + sfx, VCSConnectionID: &conn.ID, VCSRepository: repo, VCSBranch: "main",
			SpeculativeEnabled: true, AutoQueueRuns: true, ExecutionMode: "remote",
		}
		if err := f.db.Create(ws).Error; err != nil {
			t.Fatalf("seed workspace: %v", err)
		}
		return ws
	}
	f.wsApp = workspace("app", f.connA, f.repo)
	f.wsADO = workspace("ado", f.ado, "infra/capture-"+sfx)
	t.Cleanup(func() {
		ids := []string{f.wsApp.ID, f.wsADO.ID}
		f.db.Where("organization_id = ?", f.org.ID).Delete(&models.WorkItem{})
		f.db.Where("workspace_id IN ?", ids).Delete(&models.Run{})
		f.db.Where("workspace_id IN ?", ids).Delete(&models.ConfigurationVersion{})
		f.db.Where("id IN ?", ids).Delete(&models.Workspace{})
		f.db.Where("id = ?", project.ID).Delete(&models.Project{})
		f.db.Where("id = ?", hosted.ID).Delete(&models.AgentPool{})
		f.db.Where("repository IN ?", []string{f.repo, "infra/capture-" + sfx}).Delete(&models.WebhookEvent{})
	})

	f.adoSecret = "ado-capture-secret"
	t.Setenv("AZURE_DEVOPS_CLIENT_ID", "")
	t.Setenv("AZURE_DEVOPS_WEBHOOK_SECRET", f.adoSecret)
	ado, err := vcs.NewAzureDevOpsManager()
	if err != nil {
		t.Fatal(err)
	}
	f.handler.azureDevOpsManager = ado

	// A GitHub App whose installation tokens name their installation, so a capture's clone shows
	// which connection it authenticated with.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") == tokenlessInstallation {
			http.Error(w, "installation suspended", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"token":"ghs-of-%s","expires_at":"%s"}`, r.PathValue("id"), time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/pulls/{n}/files", func(w http.ResponseWriter, r *http.Request) {
		if f.prFiles != nil {
			f.prFiles(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `[{"filename":"main.tf"}]`)
	})
	f.githubAPI = httptest.NewServer(mux)
	t.Cleanup(f.githubAPI.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_APP_ID", "1")
	t.Setenv("GITHUB_APP_NAME", "stackweaver-capture-test")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	t.Setenv("GITHUB_APP_PRIVATE_KEY_PATH", "")
	m, err := vcs.NewGitHubAppManager()
	if err != nil || !m.IsEnabled() {
		t.Fatalf("configure the GitHub App: %v", err)
	}
	m.SetEndpoints(f.githubAPI.URL, f.githubAPI.URL)
	f.githubManager = m
	f.handler.githubAppManager = m
	f.handler.vcsRegistry = vcs.NewProviderRegistry(m, ado, nil, nil)
	gin.SetMode(gin.TestMode)
	return f
}

func (f *captureFixture) github(t *testing.T, event string, body map[string]any) {
	t.Helper()
	payload, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/vcs-connections/github/webhook", bytes.NewReader(payload))
	c.Request.Header.Set("X-GitHub-Event", event)
	c.Request.Header.Set("X-Hub-Signature-256", githubSign(payload, f.secret))
	f.handler.HandleInstallationWebhook(c)
	c.Writer.WriteHeaderNow()
	if w.Code != http.StatusOK {
		t.Fatalf("%s delivery = %d.\nbody: %s", event, w.Code, w.Body.String())
	}
}

func (f *captureFixture) azure(t *testing.T, body map[string]any) {
	t.Helper()
	payload, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/vcs-connections/azure-devops/webhook", bytes.NewReader(payload))
	c.Request.SetBasicAuth("stackweaver", f.adoSecret)
	f.handler.HandleAzureDevOpsWebhook(c)
	c.Writer.WriteHeaderNow()
	if w.Code != http.StatusOK {
		t.Fatalf("delivery = %d.\nbody: %s", w.Code, w.Body.String())
	}
}

func (f *captureFixture) githubPush(commit string) map[string]any {
	return map[string]any{
		"ref": "refs/heads/main", "after": commit,
		"repository":   map[string]any{"full_name": f.repo, "id": 1},
		"installation": map[string]any{"id": f.instA},
		"commits":      []map[string]any{{"id": commit, "modified": []string{"main.tf"}, "author": map[string]any{"name": "a", "email": "a@example.test"}}},
	}
}

func (f *captureFixture) githubPullRequest(commit string) map[string]any {
	return map[string]any{
		"action": "synchronize", "number": 7,
		"pull_request": map[string]any{
			"head": map[string]any{"ref": "feature", "sha": commit, "repo": map[string]any{"full_name": "forker/capture"}},
			"base": map[string]any{"ref": "main"},
			"user": map[string]any{"login": "forker"},
		},
		"repository":   map[string]any{"full_name": f.repo, "id": 1},
		"installation": map[string]any{"id": f.instA},
	}
}

func (f *captureFixture) adoRepository() map[string]any {
	name := strings.TrimPrefix(f.wsADO.VCSRepository, "infra/")
	return map[string]any{
		"name": name, "project": map[string]any{"name": "infra"},
		"remoteUrl": fmt.Sprintf("https://%s@dev.azure.com/%s/infra/_git/%s", f.adoOrg, f.adoOrg, name),
		"url":       fmt.Sprintf("https://dev.azure.com/%s/_apis/git/repositories/%s", f.adoOrg, name),
	}
}

func (f *captureFixture) adoPush(commit string) map[string]any {
	return map[string]any{"eventType": "git.push", "resource": map[string]any{
		"refUpdates": []map[string]any{{"name": "refs/heads/main", "newObjectId": commit}},
		"commits":    []map[string]any{{"commitId": commit, "author": map[string]any{"name": "a", "email": "a@example.test"}, "changes": []map[string]any{{"item": map[string]any{"path": "/main.tf"}}}}},
		"repository": f.adoRepository(),
	}}
}

func (f *captureFixture) adoPullRequest(commit string) map[string]any {
	return map[string]any{"eventType": "git.pullrequest.updated", "resource": map[string]any{
		"pullRequestId": 7, "status": "active", "sourceRefName": "refs/heads/feature", "targetRefName": "refs/heads/main",
		"lastMergeSourceCommit": map[string]any{"commitId": commit},
		"createdBy":             map[string]any{"displayName": "a", "uniqueName": "a@example.test"},
		"repository":            f.adoRepository(),
	}}
}

type capturedPair struct {
	run models.Run
	cv  models.ConfigurationVersion
}

// pairs returns the workspace's runs with the configuration version each names, oldest first.
func (f *captureFixture) pairs(t *testing.T, ws *models.Workspace) []capturedPair {
	t.Helper()
	var runs []models.Run
	if err := f.db.Where("workspace_id = ?", ws.ID).Order("created_at").Find(&runs).Error; err != nil {
		t.Fatal(err)
	}
	out := make([]capturedPair, 0, len(runs))
	for _, r := range runs {
		p := capturedPair{run: r}
		if r.ConfigurationVersionID != nil {
			f.db.First(&p.cv, "id = ?", *r.ConfigurationVersionID)
		}
		out = append(out, p)
	}
	return out
}

func (f *captureFixture) reset(t *testing.T) {
	t.Helper()
	ids := []string{f.wsApp.ID, f.wsADO.ID}
	f.db.Where("organization_id = ?", f.org.ID).Delete(&models.WorkItem{})
	f.db.Where("workspace_id IN ?", ids).Delete(&models.Run{})
	f.db.Where("workspace_id IN ?", ids).Delete(&models.ConfigurationVersion{})
}

// servedClone requests the run's capture and returns the clone source the executor is given.
func (f *captureFixture) servedClone(t *testing.T, run *models.Run) (token, commit, fetchRef string) {
	t.Helper()
	item, err := coreansible.NewWorkItemService(f.db, nil).RequestConfigurationSnapshot(t.Context(), run)
	if err != nil {
		t.Fatal(err)
	}
	h := &RunnerAgentHandler{db: f.db, vcsRegistry: f.handler.vcsRegistry}
	art, err := h.workItemArtifacts(context.Background(), item)
	if err != nil || art.Clone == nil {
		t.Fatalf("artifacts of capture %s: %v", item.ID, err)
	}
	return art.Clone.Token, art.Clone.Commit, art.Clone.FetchRef
}

func TestWebhookCapture_EachPathCreatesAPinnedFetchingVersion(t *testing.T) {
	f := setupCapture(t)
	cases := []struct {
		name        string
		ws          func() *models.Workspace
		deliver     func(t *testing.T)
		fetchRef    string
		speculative bool
		wantToken   string
	}{
		{"GitHub push", func() *models.Workspace { return f.wsApp }, func(t *testing.T) { f.github(t, "push", f.githubPush(captureHead)) }, "", false, "ghs-of-" + strconv.FormatInt(f.instA, 10)},
		{"GitHub pull request from a fork", func() *models.Workspace { return f.wsApp }, func(t *testing.T) { f.github(t, "pull_request", f.githubPullRequest(captureHead)) }, "refs/pull/7/head", true, "ghs-of-" + strconv.FormatInt(f.instA, 10)},
		{"Azure DevOps push", func() *models.Workspace { return f.wsADO }, func(t *testing.T) { f.azure(t, f.adoPush(captureHead)) }, "", false, "ado-token-of-x"},
		{"Azure DevOps pull request", func() *models.Workspace { return f.wsADO }, func(t *testing.T) { f.azure(t, f.adoPullRequest(captureHead)) }, "refs/heads/feature", true, "ado-token-of-x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.reset(t)
			tc.deliver(t)
			got := f.pairs(t, tc.ws())
			if len(got) != 1 {
				t.Fatalf("%d runs, want 1", len(got))
			}
			cv := got[0].cv
			if cv.Status != models.ConfigurationVersionStatusFetching || cv.CommitHash != captureHead || cv.FetchRef != tc.fetchRef || cv.Speculative != tc.speculative {
				t.Errorf("configuration version = status %s commit %s fetch ref %q speculative %v, want fetching at %s, %q, %v",
					cv.Status, cv.CommitHash, cv.FetchRef, cv.Speculative, captureHead, tc.fetchRef, tc.speculative)
			}
			if tc.speculative && (cv.PRNumber != 7 || cv.SourceBranch != "feature") {
				t.Errorf("pull request fields = number %d branch %q, want 7 and feature", cv.PRNumber, cv.SourceBranch)
			}
			token, commit, fetchRef := f.servedClone(t, &got[0].run)
			if token != tc.wantToken || commit != captureHead || fetchRef != tc.fetchRef {
				t.Errorf("served clone = token %q commit %s fetch ref %q, want the workspace's own connection (%s) at %s", token, commit, fetchRef, tc.wantToken, captureHead)
			}
		})
	}
}

func TestWebhookCapture_OnePairPerCommit(t *testing.T) {
	f := setupCapture(t)
	deliveries := map[string]func(t *testing.T){
		"GitHub push":               func(t *testing.T) { f.github(t, "push", f.githubPush(captureHead)) },
		"GitHub pull request":       func(t *testing.T) { f.github(t, "pull_request", f.githubPullRequest(captureHead)) },
		"Azure DevOps push":         func(t *testing.T) { f.azure(t, f.adoPush(captureHead)) },
		"Azure DevOps pull request": func(t *testing.T) { f.azure(t, f.adoPullRequest(captureHead)) },
	}
	wsOf := func(name string) *models.Workspace {
		if strings.HasPrefix(name, "Azure") {
			return f.wsADO
		}
		return f.wsApp
	}
	for name, deliver := range deliveries {
		t.Run(name, func(t *testing.T) {
			f.reset(t)
			var wg sync.WaitGroup
			for range 2 {
				wg.Add(1)
				go func() { defer wg.Done(); deliver(t) }()
			}
			wg.Wait()
			deliver(t)
			got := f.pairs(t, wsOf(name))
			if len(got) != 1 {
				t.Fatalf("a delivery repeated, twice at once, created %d runs, want 1", len(got))
			}
			if err := f.db.Model(&models.ConfigurationVersion{}).Where("id = ?", got[0].cv.ID).Update("status", models.ConfigurationVersionStatusErrored).Error; err != nil {
				t.Fatal(err)
			}
			deliver(t)
			if n := len(f.pairs(t, wsOf(name))); n != 2 {
				t.Errorf("a redelivery after an errored capture made %d runs in all, want 2", n)
			}
		})
	}
}

func TestWebhookCapture_PullRequestStatusFollowsAPendingCapture(t *testing.T) {
	f := setupCapture(t)
	f.azure(t, f.adoPullRequest(captureHead))
	first := f.pairs(t, f.wsADO)
	if len(first) != 1 {
		t.Fatalf("%d runs, want 1", len(first))
	}
	listed := func(runID string) bool {
		runs, err := repository.NewRunRepository(f.db).ListPRRunsForStatusChecks(500)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range runs {
			if r.ID == runID {
				return true
			}
		}
		return false
	}
	if !listed(first[0].run.ID) {
		t.Error("a pull request run whose capture is pending is not among the runs whose status is posted")
	}

	// A newer delivery for the same pull request supersedes the pending run.
	f.azure(t, f.adoPullRequest(captureNext))
	var older models.Run
	f.db.First(&older, "id = ?", first[0].run.ID)
	if older.Status == models.RunStatusPending {
		t.Errorf("the older pull request run is still pending after a newer delivery")
	}

	// A failed capture is reported on its commit as failed.
	latest := f.pairs(t, f.wsADO)
	newest := latest[len(latest)-1]
	f.db.Model(&models.ConfigurationVersion{}).Where("id = ?", newest.cv.ID).Update("status", models.ConfigurationVersionStatusErrored)
	f.db.Model(&models.Run{}).Where("id = ?", newest.run.ID).Update("status", models.RunStatusErrored)
	if !listed(newest.run.ID) {
		t.Error("an errored pull request run is not among the runs whose status is posted")
	}
}

// pathWorkspaces gives the fixture's repository two speculative workspaces with file triggers on,
// in working directories a and b, and returns them.
func (f *captureFixture) pathWorkspaces(t *testing.T) (a, b *models.Workspace) {
	t.Helper()
	mk := func(dir string) *models.Workspace {
		ws := &models.Workspace{
			ProjectID: f.wsApp.ProjectID, Name: "path-" + dir + "-" + uuid.NewString()[:6], VCSConnectionID: &f.connA.ID,
			VCSRepository: f.repo, VCSBranch: "main", SpeculativeEnabled: true, FileTriggersEnabled: true,
			AutoQueueRuns: true, WorkingDirectory: dir,
		}
		if err := f.db.Create(ws).Error; err != nil {
			t.Fatalf("seed workspace: %v", err)
		}
		t.Cleanup(func() {
			f.db.Where("workspace_id = ?", ws.ID).Delete(&models.Run{})
			f.db.Where("workspace_id = ?", ws.ID).Delete(&models.ConfigurationVersion{})
			f.db.Where("id = ?", ws.ID).Delete(&models.Workspace{})
		})
		return ws
	}
	// The fixture's own workspace has file triggers off, so it would match every change.
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.wsApp.ID).Update("speculative_enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	return mk("a"), mk("b")
}

func TestWebhookCapture_PullRequestTriggersTheChangedWorkspaces(t *testing.T) {
	f := setupCapture(t)
	a, b := f.pathWorkspaces(t)
	cases := []struct {
		name         string
		files        http.HandlerFunc
		changedFiles int
		wantA, wantB int
	}{
		{"the listed files touch only a", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("page") != "" && r.URL.Query().Get("page") != "1" {
				_, _ = fmt.Fprint(w, `[]`)
				return
			}
			_, _ = fmt.Fprint(w, `[{"filename":"a/main.tf"}]`)
		}, 1, 1, 0},
		{"a file renamed from a to b", func(w http.ResponseWriter, r *http.Request) {
			// The workspace the file left changed as much as the one it moved to.
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("page") != "" && r.URL.Query().Get("page") != "1" {
				_, _ = fmt.Fprint(w, `[]`)
				return
			}
			_, _ = fmt.Fprint(w, `[{"filename":"b/main.tf","previous_filename":"a/main.tf","status":"renamed"}]`)
		}, 1, 1, 1},
		{"the file list fails", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unavailable", http.StatusBadGateway)
		}, 1, 1, 1},
		{"the file list is truncated", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("page") != "" && r.URL.Query().Get("page") != "1" {
				_, _ = fmt.Fprint(w, `[]`)
				return
			}
			_, _ = fmt.Fprint(w, `[{"filename":"a/main.tf"}]`)
		}, 3001, 1, 1},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.prFiles = tc.files
			commit := strings.Repeat(strconv.Itoa(i+1), 40)
			body := f.githubPullRequest(commit)
			body["pull_request"].(map[string]any)["changed_files"] = tc.changedFiles
			f.github(t, "pull_request", body)
			if got := len(f.pairs(t, a)); got != tc.wantA {
				t.Errorf("workspace a has %d runs, want %d", got, tc.wantA)
			}
			if got := len(f.pairs(t, b)); got != tc.wantB {
				t.Errorf("workspace b has %d runs, want %d", got, tc.wantB)
			}
			for _, ws := range []*models.Workspace{a, b} {
				f.db.Where("workspace_id = ?", ws.ID).Delete(&models.Run{})
				f.db.Where("workspace_id = ?", ws.ID).Delete(&models.ConfigurationVersion{})
			}
		})
	}
}

// A pull request that triggers no workspace is still recorded, ignored, in the organization the
// installation is connected to, as an Azure DevOps pull request is.
func TestWebhookCapture_PullRequestThatTriggersNothingIsRecorded(t *testing.T) {
	f := setupCapture(t)
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.wsApp.ID).Update("speculative_enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	f.github(t, "pull_request", f.githubPullRequest(captureHead))
	var events []models.WebhookEvent
	if err := f.db.Where("repository = ? AND event_type = ? AND provider = ?", f.repo, "pull_request", "github").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].OrganizationID == nil || *events[0].OrganizationID != f.org.ID || events[0].Status != "ignored" {
		t.Fatalf("recorded events = %+v, want one ignored event in the connected organization", events)
	}
	if got := len(f.pairs(t, f.wsApp)); got != 0 {
		t.Errorf("a workspace without speculative plans got %d runs, want none", got)
	}
}

// A replacement delivery whose run cannot be created cancels nothing: the supersede step runs in
// the transaction that creates the pair, so the older run stays as it was.
func TestWebhookCapture_AFailedReplacementCancelsNothing(t *testing.T) {
	f := setupCapture(t)
	f.github(t, "pull_request", f.githubPullRequest(captureHead))
	first := f.pairs(t, f.wsApp)
	if len(first) != 1 || first[0].run.Status != models.RunStatusPending {
		t.Fatalf("first delivery = %+v, want one pending run", first)
	}
	cv := &models.ConfigurationVersion{
		WorkspaceID: f.wsApp.ID, Status: models.ConfigurationVersionStatusFetching, Source: "tfe-vcs", Speculative: true,
		CommitHash: captureNext, FetchRef: "refs/pull/7/head", PRNumber: 7, SourceBranch: "feature",
	}
	// The replacement reuses the first run's id, so its insert fails after the supersede step.
	broken := &models.Run{ID: first[0].run.ID, WorkspaceID: f.wsApp.ID, Status: models.RunStatusPending, Operation: models.RunOperationPlanOnly}
	created, err := f.handler.runRepo.CreateCaptured(cv, broken, func(runs *repository.RunRepository, versions *repository.ConfigurationVersionRepository) {
		terraform.AutoCancelSupersededSpeculativeRuns(runs, versions, f.wsApp.ID, "feature", 7)
	})
	if err == nil || created {
		t.Fatalf("a replacement whose run insert fails = created %v, err %v; want an error", created, err)
	}
	var older models.Run
	f.db.First(&older, "id = ?", first[0].run.ID)
	if older.Status != models.RunStatusPending {
		t.Errorf("the older run is %s after a failed replacement, want still pending", older.Status)
	}
	var orphans int64
	f.db.Model(&models.ConfigurationVersion{}).Where("workspace_id = ? AND commit_hash = ?", f.wsApp.ID, captureNext).Count(&orphans)
	if orphans != 0 {
		t.Errorf("a failed replacement left %d configuration versions, want none", orphans)
	}
}

// A pull request whose changed files reach no workspace is recorded in each organization connected
// through the installation, and each organization's event describes only that organization: a
// count across organizations would tell one tenant how many workspaces another has.
func TestWebhookCapture_IgnoredPullRequestEventsStayWithinTheirOrganization(t *testing.T) {
	f := setupCapture(t)
	other := f.organization(t)
	// Registered after the organization's own cleanup, so it runs first: the event this delivery
	// records in the second organization goes before that organization does.
	t.Cleanup(func() { f.db.Where("organization_id = ?", other.ID).Delete(&models.WebhookEvent{}) })
	otherConn := &models.VCSConnection{ID: uuid.New(), OrganizationID: other.ID, Provider: models.VCSProviderGitHub, InstallationID: strconv.FormatInt(f.instA, 10), AccountName: "acme"}
	otherProject := &models.Project{ID: uuid.New(), OrganizationID: other.ID, Name: "capture-other-" + uuid.NewString()[:6]}
	otherWS := &models.Workspace{
		ProjectID: otherProject.ID, Name: "other-" + uuid.NewString()[:6], VCSConnectionID: &otherConn.ID, VCSRepository: f.repo,
		VCSBranch: "main", SpeculativeEnabled: true, FileTriggersEnabled: true, AutoQueueRuns: true, WorkingDirectory: "z",
	}
	for _, row := range []any{otherConn, otherProject, otherWS} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	t.Cleanup(func() {
		f.db.Where("workspace_id = ?", otherWS.ID).Delete(&models.Run{})
		f.db.Where("id = ?", otherWS.ID).Delete(&models.Workspace{})
		f.db.Where("id = ?", otherProject.ID).Delete(&models.Project{})
	})
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.wsApp.ID).Updates(map[string]any{"file_triggers_enabled": true, "working_directory": "y"}).Error; err != nil {
		t.Fatal(err)
	}
	f.prFiles = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if p := r.URL.Query().Get("page"); p != "" && p != "1" {
			_, _ = fmt.Fprint(w, `[]`)
			return
		}
		_, _ = fmt.Fprint(w, `[{"filename":"docs/readme.md"}]`)
	}
	f.github(t, "pull_request", f.githubPullRequest(captureHead))
	var events []models.WebhookEvent
	if err := f.db.Where("repository = ? AND event_type = ?", f.repo, "pull_request").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	orgs := map[uuid.UUID]bool{}
	for _, ev := range events {
		if ev.OrganizationID != nil {
			orgs[*ev.OrganizationID] = true
		}
		if ev.Status != "ignored" || strings.Contains(ev.Message, "2 workspace") {
			t.Errorf("event %q (status %s) speaks for more than its own organization", ev.Message, ev.Status)
		}
	}
	if len(events) != 2 || !orgs[f.org.ID] || !orgs[other.ID] {
		t.Errorf("events = %+v, want one ignored event in each of the two organizations", events)
	}
}

// A configuration capture whose connection cannot mint a token is refused (R-19 F-01): the
// executor is never served an unauthenticated clone of the workspace's repository.
func TestWebhookCapture_ATokenlessConnectionServesNoClone(t *testing.T) {
	f := setupCapture(t)
	tokenless := &models.VCSConnection{ID: uuid.New(), OrganizationID: f.org.ID, Provider: models.VCSProviderGitHub, InstallationID: tokenlessInstallation, AccountName: "suspended"}
	if err := f.db.Create(tokenless).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.wsApp.ID).Update("vcs_connection_id", tokenless.ID).Error; err != nil {
		t.Fatal(err)
	}
	cv := &models.ConfigurationVersion{WorkspaceID: f.wsApp.ID, Status: models.ConfigurationVersionStatusFetching, Source: "tfe-vcs", CommitHash: captureHead}
	if err := f.db.Create(cv).Error; err != nil {
		t.Fatal(err)
	}
	run := &models.Run{WorkspaceID: f.wsApp.ID, ConfigurationVersionID: &cv.ID, Status: models.RunStatusPending, Operation: models.RunOperationPlanAndApply}
	if err := f.db.Create(run).Error; err != nil {
		t.Fatal(err)
	}
	item, err := coreansible.NewWorkItemService(f.db, nil).RequestConfigurationSnapshot(t.Context(), run)
	if err != nil {
		t.Fatal(err)
	}
	h := &RunnerAgentHandler{db: f.db, vcsRegistry: f.handler.vcsRegistry}
	if art, err := h.workItemArtifacts(context.Background(), item); err == nil {
		t.Errorf("a connection that cannot mint a token served clone %+v, want the capture refused", art.Clone)
	}
}
