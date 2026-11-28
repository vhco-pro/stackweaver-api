// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A file sync's clone inputs (#1113, D2; AC-23, AC-25, AC-26): the artifacts route reads the
// inventory once and builds the clone from that row; an attempt whose inventory moved project, or
// that holds no recorded decision, gets 409 and no clone inputs; a stored credential bound for an
// agent pool the organization no longer allows it on gets 409 before any token is fetched; and a
// GitHub App connection's clone token is narrowed to the inventory's repository, read-only, with
// GitHub's refusal failing the work item and an outage left for a retry.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration

package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// fakeTokenGitHub answers installation token requests with status, recording each request body.
type fakeTokenGitHub struct {
	mu     sync.Mutex
	status int
	bodies []map[string]any
}

func (g *fakeTokenGitHub) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	g.mu.Lock()
	g.bodies = append(g.bodies, body)
	status := g.status
	g.mu.Unlock()
	if status == 0 {
		status = http.StatusCreated
	}
	w.WriteHeader(status)
	if status == http.StatusCreated {
		_, _ = io.WriteString(w, `{"token":"ghs_narrowed","expires_at":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`)
		return
	}
	_, _ = io.WriteString(w, `{"message":"no access to that repository"}`)
}

func (g *fakeTokenGitHub) requests() []map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]map[string]any(nil), g.bodies...)
}

// githubApp gives the handler a GitHub App registry pointed at a fake GitHub, and returns a GitHub
// App connection of organization A.
func (f *workItemRunnerFixture) githubApp(t *testing.T) (*fakeTokenGitHub, *models.VCSConnection) {
	t.Helper()
	g := &fakeTokenGitHub{}
	api := httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(api.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_APP_ID", "1")
	t.Setenv("GITHUB_APP_NAME", "stackweaver-artifacts-test")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	t.Setenv("GITHUB_APP_PRIVATE_KEY_PATH", "")
	manager, err := vcs.NewGitHubAppManager()
	if err != nil || !manager.IsEnabled() {
		t.Fatalf("configuring the GitHub App: %v", err)
	}
	manager.SetEndpoints(api.URL, api.URL)
	f.h.vcsRegistry = vcs.NewProviderRegistry(manager, nil, nil, nil)
	conn := &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgA, Provider: models.VCSProviderGitHub, InstallationID: "77", AccountName: "acme-" + uuid.NewString()[:6]}
	if err := f.db.Create(conn).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", conn.ID).Delete(&models.VCSConnection{}) })
	return g, conn
}

// syncOnPoolA queues and claims, as a1 with token key name, a file sync of a fresh project
// inventory on conn selecting a binding on pool A.
func (f *workItemRunnerFixture) syncOnPoolA(t *testing.T, conn uuid.UUID, name string) (*models.AnsibleInventory, *models.WorkItem) {
	t.Helper()
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	if err := f.db.Model(inv).Updates(map[string]any{"vcs_connection_id": conn, "identity_binding_id": b.ID}).Error; err != nil {
		t.Fatal(err)
	}
	inv.VCSConnectionID = &conn
	item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	f.claim(t, "a1", item.ID, name)
	return inv, item
}

func (f *workItemRunnerFixture) artifacts(t *testing.T, key, id string) (*httptest.ResponseRecorder, runnercontract.WorkItemArtifacts) {
	t.Helper()
	rec := runnerDo(t, f.r, key, http.MethodGet, "/api/v2/runner/jobs/"+id+"/artifacts", nil)
	var art runnercontract.WorkItemArtifacts
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &art); err != nil {
			t.Fatal(err)
		}
	}
	return rec, art
}

func TestFileSyncArtifacts_NarrowedGitHubAppToken(t *testing.T) {
	f := setupWorkItemRunner(t)
	g, conn := f.githubApp(t)
	_, item := f.syncOnPoolA(t, conn.ID, "fs-customer")
	rec, art := f.artifacts(t, "fs-customer", item.ID)
	if rec.Code != http.StatusOK || art.Clone == nil || art.Clone.Token != "ghs_narrowed" {
		t.Fatalf("customer-pool artifacts = %d %s, want the narrowed token", rec.Code, rec.Body.String())
	}
	reqs := g.requests()
	if len(reqs) != 1 {
		t.Fatalf("GitHub received %d token requests, want 1", len(reqs))
	}
	repos, _ := reqs[0]["repositories"].([]any)
	perms, _ := reqs[0]["permissions"].(map[string]any)
	if len(repos) != 1 || repos[0] != "inventories" || len(perms) != 1 || perms["contents"] != "read" {
		t.Errorf("token request = %v, want the inventory's repository, contents read", reqs[0])
	}

	// On hosted capacity too.
	hostedPool, _, err := repository.HostedPoolOf(f.db, f.orgA)
	if err != nil {
		t.Fatal(err)
	}
	runner := f.hostedKubernetesRunner(t, hostedPool)
	hostedInv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	if err := f.db.Model(hostedInv).Update("vcs_connection_id", conn.ID).Error; err != nil {
		t.Fatal(err)
	}
	hostedInv.VCSConnectionID = &conn.ID
	hosted, err := f.items.RequestInventorySync(t.Context(), hostedInv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	f.startAs(t, runner, hosted.ID)
	code, tok := f.mintJobToken(t, f.r, f.svc, "hosted", hosted.ID, "fs-hosted")
	if code != http.StatusOK || tok.Token == "" {
		t.Fatalf("hosted token = %d", code)
	}
	if rec, art := f.artifacts(t, "fs-hosted", hosted.ID); rec.Code != http.StatusOK || art.Clone == nil || art.Clone.Token != "ghs_narrowed" {
		t.Errorf("hosted artifacts = %d %s, want the narrowed token", rec.Code, rec.Body.String())
	}
	for _, body := range g.requests() {
		if body["repositories"] == nil {
			t.Errorf("an installation-wide token was requested: %v", body)
		}
	}
}

func TestFileSyncArtifacts_GitHubRefusalFailsTheWorkItem(t *testing.T) {
	f := setupWorkItemRunner(t)
	g, conn := f.githubApp(t)
	g.status = http.StatusNotFound
	_, item := f.syncOnPoolA(t, conn.ID, "fs-refused")
	rec, art := f.artifacts(t, "fs-refused", item.ID)
	if rec.Code != http.StatusConflict || art.Clone != nil || !strings.Contains(rec.Body.String(), "no access to that repository") {
		t.Fatalf("refused narrowed token = %d %s, want 409 with GitHub's reason and no clone inputs", rec.Code, rec.Body.String())
	}
	if got := f.reload(t, item.ID); got.Status != models.WorkItemStatusFailed {
		t.Errorf("work item = %s, want failed", got.Status)
	}
	for _, body := range g.requests() {
		if body["repositories"] == nil {
			t.Errorf("a wider token was requested after the refusal: %v", body)
		}
	}
}

func TestFileSyncArtifacts_GitHubOutageIsLeftForARetry(t *testing.T) {
	f := setupWorkItemRunner(t)
	g, conn := f.githubApp(t)
	g.status = http.StatusBadGateway
	_, item := f.syncOnPoolA(t, conn.ID, "fs-outage")
	if rec, _ := f.artifacts(t, "fs-outage", item.ID); rec.Code != http.StatusInternalServerError {
		t.Fatalf("GitHub outage = %d %s, want 500", rec.Code, rec.Body.String())
	}
	if got := f.reload(t, item.ID); got.Status != models.WorkItemStatusRunning {
		t.Errorf("work item = %s, want it left running for the executor's retry", got.Status)
	}
}

func TestFileSyncArtifacts_MovedInventoryOrNoDecisionGetsNoCloneInputs(t *testing.T) {
	f := setupWorkItemRunner(t)
	inv, item := f.syncOnPoolA(t, f.vcsConn, "fs-moved")
	other := &models.Project{ID: uuid.New(), OrganizationID: f.orgA, Name: "artifacts-moved-" + uuid.NewString()[:8]}
	if err := f.db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("project_id", f.projectA)
		f.db.Where("id = ?", other.ID).Delete(&models.Project{})
	})
	if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("project_id", other.ID).Error; err != nil {
		t.Fatal(err)
	}
	if rec, art := f.artifacts(t, "fs-moved", item.ID); rec.Code != http.StatusConflict || art.Clone != nil {
		t.Errorf("artifacts after a move = %d %s, want 409 and no clone inputs", rec.Code, rec.Body.String())
	}

	// An attempt that holds an executor token from before decisions were recorded.
	pre := f.fileSyncInventory(t, models.InventoryTypeVCS)
	preItem, err := f.items.RequestInventorySync(t.Context(), pre, "manual")
	if err != nil {
		t.Fatal(err)
	}
	f.onPool(t, preItem)
	if rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+preItem.ID+"/start", runnercontract.JobStartRequest{RunnerID: f.keyRunner("a1")}); rec.Code != http.StatusOK {
		t.Fatalf("claiming: %d %s", rec.Code, rec.Body.String())
	}
	claimed := f.reload(t, preItem.ID)
	key, _, err := f.svc.CreateJobToken(f.orgA, f.runnerA1.AgentPoolID, apikey.JobPrincipal{Kind: models.JobTypeWorkItem, JobID: preItem.ID, RunnerID: f.runnerA1.ID, Attempt: claimed.Attempt}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })
	f.keys["fs-pre"] = key
	rec, art := f.artifacts(t, "fs-pre", preItem.ID)
	if rec.Code != http.StatusConflict || art.Clone != nil || !strings.Contains(rec.Body.String(), "no validated inventory scope") {
		t.Errorf("artifacts for an attempt with no decision = %d %s, want 409 naming the missing scope", rec.Code, rec.Body.String())
	}
}

func TestFileSyncArtifacts_StoredCredentialAfterTheSettingIsTurnedOff(t *testing.T) {
	f := setupWorkItemRunner(t)
	_, item := f.syncOnPoolA(t, f.vcsConn, "fs-stored")
	if err := f.db.Model(&models.Organization{}).Where("id = ?", f.orgA).Update("allow_stored_vcs_credentials_on_agent_pools", false).Error; err != nil {
		t.Fatal(err)
	}
	rec, art := f.artifacts(t, "fs-stored", item.ID)
	if rec.Code != http.StatusConflict || art.Clone != nil {
		t.Fatalf("artifacts with the setting off = %d %s, want 409 and no clone inputs", rec.Code, rec.Body.String())
	}
	for _, term := range []string{"stored credential", "Allow stored VCS credentials on agent pools"} {
		if !strings.Contains(rec.Body.String(), term) {
			t.Errorf("refusal %s does not say %q", rec.Body.String(), term)
		}
	}
}

// holdingTransport stops every request to host until released, then fails it; any other request
// goes through next.
type holdingTransport struct {
	host          string
	next          http.RoundTripper
	held, release chan struct{}
	once          sync.Once
}

func (h *holdingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != h.host {
		return h.next.RoundTrip(r)
	}
	h.once.Do(func() { close(h.held) })
	<-h.release
	return nil, io.ErrUnexpectedEOF
}

// The artifacts route holds no database lock while it fetches the provider token: a move of the
// inventory commits while GetFreshToken waits on the provider, and the response carries the clone
// inputs of the inventory as the route read it (#1113, D2; AC-23).
func TestFileSyncArtifacts_NoLockWhileFetchingTheToken(t *testing.T) {
	f := setupWorkItemRunner(t)
	t.Setenv("AZURE_DEVOPS_CLIENT_ID", "artifacts-test")
	t.Setenv("AZURE_DEVOPS_CLIENT_SECRET", "artifacts-test")
	t.Setenv("AZURE_DEVOPS_TENANT_ID", "artifacts-test")
	ado, err := vcs.NewAzureDevOpsManager()
	if err != nil || !ado.IsEnabled() {
		t.Fatalf("configuring Azure DevOps: %v", err)
	}
	f.h.vcsRegistry = vcs.NewProviderRegistry(nil, ado, nil, nil)
	// An Azure DevOps connection whose token has expired: GetFreshToken asks Microsoft for a new one.
	expired := time.Now().Add(-time.Hour)
	conn := &models.VCSConnection{
		ID: uuid.New(), OrganizationID: f.orgA, Provider: models.VCSProviderAzureDevOps, AccountName: "acme-" + uuid.NewString()[:6],
		AccessToken: "stored-token", RefreshToken: "refresh-token", TokenExpiresAt: &expired,
	}
	if err := f.db.Create(conn).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", conn.ID).Delete(&models.VCSConnection{}) })
	inv, item := f.syncOnPoolA(t, conn.ID, "fs-no-lock")
	if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("vcs_repository", "proj/inventories").Error; err != nil {
		t.Fatal(err)
	}

	hold := &holdingTransport{host: "login.microsoftonline.com", next: http.DefaultTransport, held: make(chan struct{}), release: make(chan struct{})}
	prev := http.DefaultTransport
	http.DefaultTransport = hold
	t.Cleanup(func() { http.DefaultTransport = prev })
	release := sync.OnceFunc(func() { close(hold.release) })
	t.Cleanup(release)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- runnerDo(t, f.r, "fs-no-lock", http.MethodGet, "/api/v2/runner/jobs/"+item.ID+"/artifacts", nil)
	}()
	select {
	case <-hold.held:
	case <-time.After(20 * time.Second):
		t.Fatal("the route never asked the provider for a token")
	}

	// While the provider holds the token request, the inventory moves to another project and
	// repository; this commits only if the route holds no lock on it.
	other := &models.Project{ID: uuid.New(), OrganizationID: f.orgA, Name: "no-lock-" + uuid.NewString()[:8]}
	if err := f.db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	origin := f.projectA
	t.Cleanup(func() {
		f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("project_id", origin)
		f.db.Where("id = ?", other.ID).Delete(&models.Project{})
	})
	moved := make(chan error, 1)
	go func() {
		moved <- f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).
			Updates(map[string]any{"project_id": other.ID, "vcs_repository": "proj/other"}).Error
	}()
	select {
	case err := <-moved:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		release()
		t.Fatal("the move waited on a lock the artifacts route held while it fetched the token")
	}
	release()

	rec := <-done
	if rec.Code != http.StatusOK {
		t.Fatalf("artifacts = %d %s, want 200 for the inventory as read", rec.Code, rec.Body.String())
	}
	var art runnercontract.WorkItemArtifacts
	if err := json.Unmarshal(rec.Body.Bytes(), &art); err != nil {
		t.Fatal(err)
	}
	if art.Clone == nil || !strings.Contains(art.Clone.URL, "proj/_git/inventories") || strings.Contains(art.Clone.URL, "other") {
		t.Errorf("clone inputs = %+v, want the repository the route read (proj/inventories)", art.Clone)
	}
}

// An attempt that holds an executor token from before the upgrade gets 409 and no clone inputs from
// the artifacts route also after a recovered token was issued for it, with the inventory's
// selection changed in one case and its project in the other (#1113, D2, D3; AC-23). Either token
// may ask first: the first request gets 409 naming the missing scope, and the request after it,
// with the work item failed, gets no clone inputs either.
func TestFileSyncArtifacts_PreUpgradeAttemptAfterARecoveredToken(t *testing.T) {
	for _, change := range []string{"selection", "project"} {
		for _, first := range []string{"pre-upgrade", "recovered"} {
			t.Run(change+" changed, "+first+" token first", func(t *testing.T) {
				f := setupWorkItemRunner(t)
				f.kubernetesRunners(t)
				b := f.binding(t, f.poolA, "pre")
				inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
				if err := f.db.Model(inv).Update("identity_binding_id", b.ID).Error; err != nil {
					t.Fatal(err)
				}
				inv.IdentityBindingID = &b.ID
				item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
				if err != nil {
					t.Fatal(err)
				}
				if rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/start", runnercontract.JobStartRequest{RunnerID: f.keyRunner("a1")}); rec.Code != http.StatusOK {
					t.Fatalf("claiming: %d %s", rec.Code, rec.Body.String())
				}
				// The executor's token, minted before the upgrade: no decision is recorded.
				claimed := f.reload(t, item.ID)
				key, _, err := f.svc.CreateJobToken(f.orgA, f.runnerA1.AgentPoolID, apikey.JobPrincipal{Kind: models.JobTypeWorkItem, JobID: item.ID, RunnerID: f.runnerA1.ID, Attempt: claimed.Attempt}, time.Now().Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })
				f.keys["pre-upgrade"] = key

				switch change {
				case "selection":
					other := f.binding(t, f.poolA, "pre-new")
					if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("identity_binding_id", other.ID).Error; err != nil {
						t.Fatal(err)
					}
				case "project":
					moved := &models.Project{ID: uuid.New(), OrganizationID: f.orgA, Name: "pre-upgrade-moved-" + uuid.NewString()[:8]}
					if err := f.db.Create(moved).Error; err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("project_id", f.projectA)
						f.db.Where("id = ?", moved.ID).Delete(&models.Project{})
					})
					if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("project_id", moved.ID).Error; err != nil {
						t.Fatal(err)
					}
				}

				// The launcher recovers its claim and asks for a token again.
				code, tok := f.mintJobToken(t, f.r, f.svc, "a1", item.ID, "recovered")
				if code != http.StatusOK || tok.Identity != nil {
					t.Fatalf("recovered token = %d, identity %+v; want 200 with no identity", code, tok.Identity)
				}
				if got := f.reload(t, item.ID).Placement; got.IdentityAttempt != 0 || got.Identity != nil {
					t.Fatalf("the recovered token recorded a decision: attempt %d, %+v", got.IdentityAttempt, got.Identity)
				}

				second := map[string]string{"pre-upgrade": "recovered", "recovered": "pre-upgrade"}[first]
				rec, art := f.artifacts(t, first, item.ID)
				if rec.Code != http.StatusConflict || art.Clone != nil || !strings.Contains(rec.Body.String(), "no validated inventory scope") {
					t.Errorf("artifacts with the %s token = %d %s, want 409 naming the missing scope and no clone inputs", first, rec.Code, rec.Body.String())
				}
				if rec, art := f.artifacts(t, second, item.ID); rec.Code == http.StatusOK || art.Clone != nil {
					t.Errorf("artifacts with the %s token after = %d %s, want no clone inputs", second, rec.Code, rec.Body.String())
				}
			})
		}
	}
}

// countingTransport counts and fails every request to host; any other request goes through next.
type countingTransport struct {
	host string
	next http.RoundTripper
	n    atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != c.host {
		return c.next.RoundTrip(r)
	}
	c.n.Add(1)
	return nil, io.ErrUnexpectedEOF
}

// The artifacts request of a stored-credential sync claimed after the organization turned the
// setting off answers 409 with no clone inputs and never asks the provider for a token (#1113, D2;
// AC-26). The connection is an Azure DevOps one whose token has expired, so any token fetch is a
// request to Microsoft; with the setting on, the same route does make that request.
func TestFileSyncArtifacts_StoredCredentialRefusalMakesNoTokenRequest(t *testing.T) {
	f := setupWorkItemRunner(t)
	t.Setenv("AZURE_DEVOPS_CLIENT_ID", "artifacts-test")
	t.Setenv("AZURE_DEVOPS_CLIENT_SECRET", "artifacts-test")
	t.Setenv("AZURE_DEVOPS_TENANT_ID", "artifacts-test")
	ado, err := vcs.NewAzureDevOpsManager()
	if err != nil || !ado.IsEnabled() {
		t.Fatalf("configuring Azure DevOps: %v", err)
	}
	f.h.vcsRegistry = vcs.NewProviderRegistry(nil, ado, nil, nil)
	expired := time.Now().Add(-time.Hour)
	conn := &models.VCSConnection{
		ID: uuid.New(), OrganizationID: f.orgA, Provider: models.VCSProviderAzureDevOps, AccountName: "acme-" + uuid.NewString()[:6],
		AccessToken: "stored-token", RefreshToken: "refresh-token", TokenExpiresAt: &expired,
	}
	if err := f.db.Create(conn).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", conn.ID).Delete(&models.VCSConnection{}) })
	counter := &countingTransport{host: "login.microsoftonline.com", next: http.DefaultTransport}
	prev := http.DefaultTransport
	http.DefaultTransport = counter
	t.Cleanup(func() { http.DefaultTransport = prev })

	// Queued and claimed while the setting is on, then the setting is turned off.
	inv, item := f.syncOnPoolA(t, conn.ID, "fs-stored-off")
	if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("vcs_repository", "proj/inventories").Error; err != nil {
		t.Fatal(err)
	}
	f.allowStoredOnOrgA(t, false)
	rec, art := f.artifacts(t, "fs-stored-off", item.ID)
	if rec.Code != http.StatusConflict || art.Clone != nil {
		t.Fatalf("artifacts with the setting off = %d %s, want 409 and no clone inputs", rec.Code, rec.Body.String())
	}
	for _, term := range []string{"stored credential", "Allow stored VCS credentials on agent pools", conn.AccountName} {
		if !strings.Contains(rec.Body.String(), term) {
			t.Errorf("refusal %s does not say %q", rec.Body.String(), term)
		}
	}
	if n := counter.n.Load(); n != 0 {
		t.Errorf("the provider was asked for a token %d times, want none", n)
	}

	// The control: with the setting on, the same route asks Microsoft for the token (the failed
	// refresh then falls back to the stored token, which the response does not need here).
	f.allowStoredOnOrgA(t, true)
	_, onItem := f.syncOnPoolA(t, conn.ID, "fs-stored-on")
	f.artifacts(t, "fs-stored-on", onItem.ID)
	if counter.n.Load() == 0 {
		t.Error("with the setting on the route made no token request, so the probe proves nothing")
	}
}
