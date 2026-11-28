// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// An attempt's identity is fixed by its first job token (#1113, D3, owner decision Q10; AC-03,
// AC-22): the first token records the binding, mechanism, ServiceAccount and annotations with the
// attempt in the transaction that mints it, and a later token for the same active claim, as a
// launcher recovering its claim sends, replays that decision unchanged.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration

package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
)

// kubernetesRunners makes runners a1 and a2 non-strict Kubernetes launchers, the only launchers
// that are issued an identity (D3).
func (f *workItemRunnerFixture) kubernetesRunners(t *testing.T) {
	t.Helper()
	for _, r := range []*models.Runner{f.runnerA1, f.runnerA2} {
		if err := f.db.Model(r).Updates(map[string]any{"driver": "kubernetes", "hosted_strict": false}).Error; err != nil {
			t.Fatal(err)
		}
	}
}

// fileSyncOnPoolA queues a file sync of a fresh VCS inventory whose project selects binding b on
// pool A, and claims it as a1.
func (f *workItemRunnerFixture) fileSyncClaimed(t *testing.T) (*models.AnsibleInventory, *models.WorkItem) {
	t.Helper()
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/start", runnercontract.JobStartRequest{RunnerID: f.keyRunner("a1")}); rec.Code != http.StatusOK {
		t.Fatalf("claiming %s: %d %s", item.ID, rec.Code, rec.Body.String())
	}
	return inv, item
}

func (f *workItemRunnerFixture) token(t *testing.T, id string) (int, runnercontract.JobToken) {
	t.Helper()
	return f.mintJobToken(t, f.r, f.svc, "a1", id, "tok-"+uuid.NewString()[:6])
}

func TestJobTokenIdentity_FirstTokenRecordsTheDecision(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	_, item := f.fileSyncClaimed(t)

	code, tok := f.token(t, item.ID)
	if code != http.StatusOK || tok.Identity == nil || tok.Identity.BindingID != b.ID.String() {
		t.Fatalf("first token = %d, identity %+v; want binding %s", code, tok.Identity, b.ID)
	}
	got := f.reload(t, item.ID).Placement
	if got.IdentityAttempt != tok.Attempt || got.Identity == nil {
		t.Fatalf("decision = attempt %d, identity %+v; want attempt %d", got.IdentityAttempt, got.Identity, tok.Attempt)
	}
	id := got.Identity
	if id.BindingID == nil || *id.BindingID != b.ID || id.Mechanism != b.Mechanism || id.ServiceAccount != b.ServiceAccount ||
		id.Annotations["azure.workload.identity/client-id"] != "11111111-2222-3333-4444-555555555555" || id.Name != b.Name {
		t.Errorf("recorded snapshot = %+v, want binding %s as it stood", id, b.ID)
	}
	if got.IdentityBindingID == nil || *got.IdentityBindingID != b.ID {
		t.Errorf("placement binding = %v, want %s", got.IdentityBindingID, b.ID)
	}
}

func TestJobTokenIdentity_ReplayIgnoresLaterChanges(t *testing.T) {
	changes := map[string]func(t *testing.T, f *workItemRunnerFixture, b *models.IdentityBinding){
		"binding edited": func(t *testing.T, f *workItemRunnerFixture, b *models.IdentityBinding) {
			if err := f.db.Model(b).Updates(map[string]any{"service_account": "sw-edited", "annotations": models.JSONB{"azure.workload.identity/client-id": "99999999-2222-3333-4444-555555555555"}}).Error; err != nil {
				t.Fatal(err)
			}
		},
		"selection changed": func(t *testing.T, f *workItemRunnerFixture, _ *models.IdentityBinding) {
			other := f.binding(t, f.poolA, "other")
			f.selectOnProject(t, other.ID)
		},
		"binding row deleted": func(t *testing.T, f *workItemRunnerFixture, b *models.IdentityBinding) {
			if err := repository.NewIdentityBindingRepository(f.db).Delete(b.ID); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := setupWorkItemRunner(t)
			f.kubernetesRunners(t)
			b := f.binding(t, f.poolA, "files")
			f.selectOnProject(t, b.ID)
			_, item := f.fileSyncClaimed(t)
			code, first := f.token(t, item.ID)
			if code != http.StatusOK || first.Identity == nil {
				t.Fatalf("first token = %d, %+v", code, first.Identity)
			}
			change(t, f, b)
			code, again := f.token(t, item.ID)
			if code != http.StatusOK {
				t.Fatalf("replayed token = %d, want 200: a recovered claim is never refused on identity grounds", code)
			}
			if again.Identity == nil {
				t.Fatalf("replayed token carries no identity, want the first token's %+v", first.Identity)
			}
			if again.Identity.BindingID != first.Identity.BindingID || again.Identity.ServiceAccount != first.Identity.ServiceAccount ||
				again.Identity.Annotations["azure.workload.identity/client-id"] != first.Identity.Annotations["azure.workload.identity/client-id"] {
				t.Errorf("replayed identity = %+v, want the first token's %+v", again.Identity, first.Identity)
			}
			if got := f.reload(t, item.ID).Placement; got.Identity == nil || got.Identity.ServiceAccount != first.Identity.ServiceAccount {
				t.Errorf("stored decision changed: %+v", got.Identity)
			}
		})
	}
}

func TestJobTokenIdentity_PlatformDecisionReplays(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	// A file sync with no binding, moved onto pool A so runner a1 claims it.
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	queued, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	item := f.onPool(t, queued)
	if rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/start", runnercontract.JobStartRequest{RunnerID: f.keyRunner("a1")}); rec.Code != http.StatusOK {
		t.Fatalf("claiming %s: %d %s", item.ID, rec.Code, rec.Body.String())
	}
	code, first := f.token(t, item.ID)
	if code != http.StatusOK || first.Identity != nil {
		t.Fatalf("first token = %d, identity %+v; want the platform identity", code, first.Identity)
	}
	got := f.reload(t, item.ID).Placement
	if got.IdentityAttempt != first.Attempt || got.Identity == nil || got.Identity.BindingID != nil {
		t.Fatalf("platform decision = attempt %d, identity %+v; want a recorded decision with no binding", got.IdentityAttempt, got.Identity)
	}
	// A binding selected afterwards does not reach the running attempt.
	b := f.binding(t, f.poolA, "late")
	f.selectOnProject(t, b.ID)
	if code, again := f.token(t, item.ID); code != http.StatusOK || again.Identity != nil {
		t.Errorf("replayed token = %d, identity %+v; want the platform identity again", code, again.Identity)
	}
}

// A hosted decision replays after the hosted binding is renamed and, separately, disabled (AC-22).
func TestJobTokenIdentity_HostedRenameReplays(t *testing.T) {
	for name, after := range map[string]string{"renamed": "renamed-identity", "disabled": ""} {
		t.Run(name, func(t *testing.T) { hostedDecisionReplays(t, after) })
	}
}

// hostedDecisionReplays records a hosted file sync's first decision, then renames the hosted
// binding to after, or disables it when after is empty, and asserts the next token replays it.
func hostedDecisionReplays(t *testing.T, after string) {
	t.Helper()
	f := setupWorkItemRunner(t)
	hosted := configureHosted(t, "hosted-workload-identity")
	hostedPool, _, err := repository.HostedPoolOf(f.db, f.orgA)
	if err != nil {
		t.Fatal(err)
	}
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	if err := f.db.Model(inv).Update("identity_binding_id", hosted).Error; err != nil {
		t.Fatal(err)
	}
	item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if item.AgentPoolID == nil || *item.AgentPoolID != hostedPool {
		t.Fatalf("queued on %v, want the hosted pool", item.AgentPoolID)
	}
	// Claim it on the hosted pool through the handler's own path, as a hosted launcher's token would.
	runner := f.hostedKubernetesRunner(t, hostedPool)
	f.startAs(t, runner, item.ID)
	first, err := f.tokenAs(t, runner, item.ID)
	if err != nil || first.Identity == nil || first.Identity.BindingID != hosted.String() {
		t.Fatalf("first hosted token = %+v, %v", first.Identity, err)
	}
	if after == "" {
		repository.SetHostedBinding(nil)
	} else {
		configureHosted(t, after)
	}
	again, err := f.tokenAs(t, runner, item.ID)
	if err != nil || again.Identity == nil || again.Identity.BindingID != hosted.String() || again.Identity.ServiceAccount != first.Identity.ServiceAccount {
		t.Errorf("replayed hosted token after the change = %+v, %v; want the first decision", again.Identity, err)
	}
	if got := f.reload(t, item.ID).Placement; got.Identity == nil || got.Identity.BindingID == nil || *got.Identity.BindingID != hosted {
		t.Errorf("stored decision after the change = %+v, want the hosted binding %s", got.Identity, hosted)
	}
}

func TestJobTokenIdentity_PreUpgradeAttemptGetsNoIdentity(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	_, item := f.fileSyncClaimed(t)
	claimed := f.reload(t, item.ID)
	// A job token minted before the upgrade exists for this attempt, and no decision was recorded.
	principal := apikey.JobPrincipal{Kind: models.JobTypeWorkItem, JobID: item.ID, RunnerID: f.runnerA1.ID, Attempt: claimed.Attempt}
	key, _, err := f.svc.CreateJobToken(f.orgA, f.runnerA1.AgentPoolID, principal, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })

	code, tok := f.token(t, item.ID)
	if code != http.StatusOK || tok.Identity != nil {
		t.Fatalf("recovered pre-upgrade token = %d, identity %+v; want 200 with no identity", code, tok.Identity)
	}
	if got := f.reload(t, item.ID).Placement; got.IdentityAttempt != 0 || got.Identity != nil {
		t.Errorf("a pre-upgrade attempt recorded a decision: attempt %d, %+v", got.IdentityAttempt, got.Identity)
	}
}

func TestJobTokenIdentity_NewAttemptResolvesAfresh(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	_, item := f.fileSyncClaimed(t)
	if code, first := f.token(t, item.ID); code != http.StatusOK || first.Identity == nil || first.Identity.BindingID != b.ID.String() {
		t.Fatalf("first attempt token = %d, %+v", code, first.Identity)
	}
	other := f.binding(t, f.poolA, "retry")
	f.selectOnProject(t, other.ID)
	// The work item is queued again for a new attempt.
	now := time.Now()
	if err := f.db.Model(&models.WorkItem{}).Where("id = ?", item.ID).Updates(map[string]any{
		"status": models.WorkItemStatusPending, "runner_id": nil, "queued_at": now, "claim_recovery": false,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/start", runnercontract.JobStartRequest{RunnerID: f.keyRunner("a1")}); rec.Code != http.StatusOK {
		t.Fatalf("second claim: %d %s", rec.Code, rec.Body.String())
	}
	code, tok := f.token(t, item.ID)
	if code != http.StatusOK || tok.Identity == nil || tok.Identity.BindingID != other.ID.String() {
		t.Errorf("new attempt token = %d, %+v; want the current selection %s", code, tok.Identity, other.ID)
	}
	if got := f.reload(t, item.ID).Placement; got.IdentityAttempt != tok.Attempt || got.IdentityAttempt < 2 {
		t.Errorf("new attempt decision attempt = %d, token attempt %d", got.IdentityAttempt, tok.Attempt)
	}
}

func TestJobTokenIdentity_RefusedRequestRecordsNothing(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	// A binding of another pool resolves for a sync queued on pool A: the token is refused.
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	_, item := f.fileSyncClaimed(t)
	elsewhere := f.otherPoolBinding(t)
	f.selectOnProject(t, elsewhere.ID)
	if code, _ := f.token(t, item.ID); code != http.StatusConflict {
		t.Fatalf("token for a binding the pool does not offer = %d, want 409", code)
	}
	if got := f.reload(t, item.ID).Placement; got.IdentityAttempt != 0 || got.Identity != nil {
		t.Errorf("a refused request recorded a decision: attempt %d, %+v", got.IdentityAttempt, got.Identity)
	}
	if n := f.jobTokenRows(t, models.JobTypeWorkItem, item.ID); n != 0 {
		t.Errorf("a refused request minted %d tokens", n)
	}
}

func TestJobTokenIdentity_AttemptZeroResolvesAsFirstToken(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	_, item := f.fileSyncClaimed(t)
	if err := f.db.Model(&models.WorkItem{}).Where("id = ?", item.ID).Updates(map[string]any{"attempt": 0, "claim_recovery": false}).Error; err != nil {
		t.Fatal(err)
	}
	code, tok := f.token(t, item.ID)
	if code != http.StatusOK || tok.Attempt != 1 || tok.Identity == nil || tok.Identity.BindingID != b.ID.String() {
		t.Fatalf("legacy attempt-zero token = %d, attempt %d, %+v", code, tok.Attempt, tok.Identity)
	}
	if got := f.reload(t, item.ID).Placement; got.IdentityAttempt != 1 {
		t.Errorf("decision attempt = %d, want 1", got.IdentityAttempt)
	}
}

func TestJobTokenIdentity_TemplateReadFailureRecordsNothing(t *testing.T) {
	f := setupAgentPrepFixture(t)
	for _, r := range []*models.Runner{f.runnerA1} {
		if err := f.db.Model(r).Updates(map[string]any{"driver": "kubernetes", "hosted_strict": false}).Error; err != nil {
			t.Fatal(err)
		}
	}
	r, _ := f.jobDataRouter(t)
	pb := f.seedPlaybook(t, playbookSpec{noVCS: true})
	template := seedTemplate(t, f, "identity-read-"+uuid.NewString(), pb.ID)
	b := &models.IdentityBinding{
		OrganizationID: f.orgA, AgentPoolID: f.poolA, Name: "tmpl-" + uuid.NewString()[:6], Mechanism: models.IdentityMechanismAzureWorkloadIdentity,
		ServiceAccount: "sw-template", Annotations: models.JSONB{"azure.workload.identity/client-id": "11111111-2222-3333-4444-555555555555"},
	}
	if err := f.db.Create(b).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", b.ID).Delete(&models.IdentityBinding{}) })
	if err := f.db.Model(template).Update("identity_binding_id", b.ID).Error; err != nil {
		t.Fatal(err)
	}
	job := f.seedJob(t, &pb.ID, f.runnerA1)
	if err := f.db.Model(job).Updates(map[string]any{"template_id": template.ID, "agent_pool_id": f.poolA}).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("kind = ? AND name LIKE ?", models.APIKeyKindJob, fmt.Sprintf("job ansible_job %s attempt %%", job.ID)).Delete(&models.APIKey{})
	})
	path := "/api/v2/runner/jobs/" + job.ID.String() + "/token"
	rec := runnerReadFailure(t, f.db, "ansible_job_templates", 2, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
		return runnerDo(t, r, "a1", http.MethodPost, path, nil)
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("template read failure = %d, want 500", rec.Code)
	}
	var stored models.AnsibleJob
	if err := f.db.First(&stored, "id = ?", job.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Placement.IdentityAttempt != 0 || stored.Placement.Identity != nil {
		t.Fatalf("a failed template read recorded a decision: %+v", stored.Placement)
	}
	if n := f.jobTokenRows(t, models.JobTypeAnsibleJob, job.ID.String()); n != 0 {
		t.Fatalf("a failed template read left %d job token rows, want none", n)
	}
	// The next request reads the template and resolves its binding.
	rec = runnerDo(t, r, "a1", http.MethodPost, path, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("next token = %d %s", rec.Code, rec.Body.String())
	}
	if err := f.db.First(&stored, "id = ?", job.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Placement.Identity == nil || stored.Placement.Identity.BindingID == nil || *stored.Placement.Identity.BindingID != b.ID {
		t.Errorf("decision after recovery = %+v, want the template's binding %s", stored.Placement.Identity, b.ID)
	}
}

// otherPoolBinding is a binding of organization A on its second pool, the one runner a3 serves,
// which pool A does not offer.
func (f *workItemRunnerFixture) otherPoolBinding(t *testing.T) *models.IdentityBinding {
	t.Helper()
	return f.binding(t, *f.runnerA3.AgentPoolID, "elsewhere")
}

// hostedKubernetesRunner registers a non-strict hosted Kubernetes launcher serving hostedPool's
// group, with the key "hosted".
func (f *workItemRunnerFixture) hostedKubernetesRunner(t *testing.T, hostedPool uuid.UUID) *models.Runner {
	t.Helper()
	var pool models.AgentPool
	if err := f.db.First(&pool, "id = ?", hostedPool).Error; err != nil {
		t.Fatal(err)
	}
	group := pool.PlacementGroup
	if group == "" {
		group = "default"
	}
	r := &models.Runner{
		ID: uuid.New(), Kind: models.RunnerKindHosted, HostedGroup: group, Name: "id-hosted-" + uuid.NewString()[:8],
		Status: models.RunnerStatusOnline, MaxConcurrentJobs: 2, Driver: "kubernetes",
	}
	if err := f.db.Create(r).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", r.ID).Delete(&models.Runner{}) })
	f.declareCapabilities(t, r, runnercontract.CapabilityJobToken, runnercontract.CapabilityWorkItems)
	f.keys["hosted"] = &models.APIKey{ID: uuid.New(), Kind: models.APIKeyKindHosted, Scopes: models.StringArray{"runner:" + r.ID.String() + ":heartbeat", "runner:" + r.ID.String() + ":jobs"}}
	return r
}

func (f *workItemRunnerFixture) startAs(t *testing.T, r *models.Runner, id string) {
	t.Helper()
	// A hosted launcher claims only work its heartbeat reserved to it.
	if err := f.db.Model(&models.WorkItem{}).Where("id = ?", id).Update("runner_id", r.ID).Error; err != nil {
		t.Fatal(err)
	}
	if rec := runnerDo(t, f.r, "hosted", http.MethodPost, "/api/v2/runner/jobs/"+id+"/start", runnercontract.JobStartRequest{RunnerID: r.ID.String()}); rec.Code != http.StatusOK {
		t.Fatalf("claiming %s as the hosted launcher: %d %s", id, rec.Code, rec.Body.String())
	}
}

func (f *workItemRunnerFixture) tokenAs(t *testing.T, _ *models.Runner, id string) (runnercontract.JobToken, error) {
	t.Helper()
	code, tok := f.mintJobToken(t, f.r, f.svc, "hosted", id, "hosted-tok-"+uuid.NewString()[:6])
	if code != http.StatusOK {
		return tok, fmt.Errorf("token status %d", code)
	}
	return tok, nil
}

// The API hands an identity only to a launcher that can apply it (#1113, D3, owner decision Q9;
// AC-11, AC-21): a strict hosted launcher, on any driver, gets the strict-isolation refusal, and a
// non-strict launcher on the container or in-process driver gets a refusal naming the binding and
// the driver; neither records a decision or mints a token.
func TestJobTokenIdentity_RefusedToALauncherThatCannotApplyIt(t *testing.T) {
	cases := []struct {
		name, driver string
		strict       bool
		want         []string
	}{
		{name: "strict kubernetes", driver: "kubernetes", strict: true, want: []string{"strict hosted isolation", "platform identity"}},
		{name: "strict container", driver: "container", strict: true, want: []string{"strict hosted isolation"}},
		{name: "container", driver: "container", want: []string{"container driver"}},
		{name: "in-process", driver: "inprocess", want: []string{"inprocess driver"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setupWorkItemRunner(t)
			if err := f.db.Model(f.runnerA1).Updates(map[string]any{"driver": tc.driver, "hosted_strict": tc.strict}).Error; err != nil {
				t.Fatal(err)
			}
			b := f.binding(t, f.poolA, "files")
			f.selectOnProject(t, b.ID)
			_, item := f.fileSyncClaimed(t)
			rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/token", nil)
			if rec.Code != http.StatusConflict {
				t.Fatalf("token = %d %s, want 409", rec.Code, rec.Body.String())
			}
			for _, w := range tc.want {
				if !strings.Contains(rec.Body.String(), w) {
					t.Errorf("refusal %s does not say %q", rec.Body.String(), w)
				}
			}
			// The refusal is D3's text, word for word.
			want := fmt.Sprintf(`identity binding \"%s\" (%s) needs the kubernetes driver; this pool's launcher uses the %s driver; run the job on a Kubernetes pool or select no binding`, b.Name, b.Mechanism, tc.driver)
			if tc.strict {
				want = fmt.Sprintf(`strict hosted isolation runs every job with the platform identity; identity binding \"%s\" cannot be used here`, b.Name)
			}
			if !strings.Contains(rec.Body.String(), want) {
				t.Errorf("refusal %s does not carry D3's message %s", rec.Body.String(), want)
			}
			if !tc.strict && !strings.Contains(rec.Body.String(), b.Name) {
				t.Errorf("refusal %s does not name the binding %s", rec.Body.String(), b.Name)
			}
			if got := f.reload(t, item.ID).Placement; got.IdentityAttempt != 0 || got.Identity != nil || got.IdentityBindingID != nil {
				t.Errorf("a refused launcher recorded %+v", got)
			}
			if n := f.jobTokenRows(t, models.JobTypeWorkItem, item.ID); n != 0 {
				t.Errorf("a refused launcher was minted %d tokens", n)
			}

			// The same job, queued again and claimed by a2, a non-strict Kubernetes launcher of
			// the pool, is issued the binding (AC-21).
			if err := f.db.Model(&models.WorkItem{}).Where("id = ?", item.ID).Updates(map[string]any{
				"status": models.WorkItemStatusPending, "runner_id": nil, "queued_at": time.Now(), "claim_recovery": false,
			}).Error; err != nil {
				t.Fatal(err)
			}
			if rec := runnerDo(t, f.r, "a2", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/start", runnercontract.JobStartRequest{RunnerID: f.keyRunner("a2")}); rec.Code != http.StatusOK {
				t.Fatalf("claiming as a2: %d %s", rec.Code, rec.Body.String())
			}
			code, tok := f.mintJobToken(t, f.r, f.svc, "a2", item.ID, "k8s-"+uuid.NewString()[:6])
			if code != http.StatusOK || tok.Identity == nil || tok.Identity.BindingID != b.ID.String() {
				t.Errorf("token for the Kubernetes launcher = %d, %+v; want binding %s", code, tok.Identity, b.ID)
			}
			if got := f.reload(t, item.ID).Placement; got.IdentityAttempt != tok.Attempt || got.IdentityBindingID == nil || *got.IdentityBindingID != b.ID {
				t.Errorf("decision for the Kubernetes launcher = attempt %d, binding %v; want %s at attempt %d", got.IdentityAttempt, got.IdentityBindingID, b.ID, tok.Attempt)
			}
		})
	}
}

// hostedCapacity configures the hosted binding under name and registers a non-strict Kubernetes
// hosted launcher for organization A's hosted pool.
func (f *workItemRunnerFixture) hostedCapacity(t *testing.T, name string) (uuid.UUID, uuid.UUID, *models.Runner) {
	t.Helper()
	hosted := configureHosted(t, name)
	hostedPool, _, err := repository.HostedPoolOf(f.db, f.orgA)
	if err != nil {
		t.Fatal(err)
	}
	return hosted, hostedPool, f.hostedKubernetesRunner(t, hostedPool)
}

// hostedSourceSync queues a cloud-source sync of a fresh dynamic inventory of project A, which
// defers to the project's selection, on hosted capacity and claims it as runner.
func (f *workItemRunnerFixture) hostedSourceSync(t *testing.T, hostedPool uuid.UUID, runner *models.Runner) *models.WorkItem {
	t.Helper()
	inv := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.orgA, ProjectID: &f.projectA, Name: "hosted-dyn-" + uuid.NewString()[:8], Type: models.InventoryTypeDynamic}
	if err := f.db.Create(inv).Error; err != nil {
		t.Fatal(err)
	}
	src := &models.AnsibleInventorySource{ID: uuid.New(), InventoryID: inv.ID, Name: "hosted-src-" + uuid.NewString()[:8], Type: models.InventorySourceTypeAWS, Enabled: true}
	if err := f.db.Create(src).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("inventory_id = ?", inv.ID).Delete(&models.WorkItem{})
		f.db.Where("inventory_id = ?", inv.ID).Delete(&models.AnsibleInventorySync{})
		f.db.Where("id = ?", src.ID).Delete(&models.AnsibleInventorySource{})
		f.db.Where("id = ?", inv.ID).Delete(&models.AnsibleInventory{})
	})
	sync, err := f.items.RequestSourceSync(t.Context(), src, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if sync.AgentPoolID == nil || *sync.AgentPoolID != hostedPool {
		t.Fatalf("cloud-source sync queued on %v, want the hosted pool", sync.AgentPoolID)
	}
	f.startAs(t, runner, sync.ID)
	return sync
}

// runningJob is an Ansible job of project A running its first attempt on pool, held by runner.
func (f *workItemRunnerFixture) runningJob(t *testing.T, pool uuid.UUID, runner *models.Runner) *models.AnsibleJob {
	t.Helper()
	pb := f.seedPlaybook(t, playbookSpec{noVCS: true})
	job := f.seedJob(t, &pb.ID, nil)
	if err := f.db.Model(job).Updates(map[string]any{"agent_pool_id": pool, "runner_id": runner.ID, "status": models.AnsibleJobStatusRunning, "started_at": time.Now(), "attempt": 1}).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("kind = ? AND name LIKE ?", models.APIKeyKindJob, fmt.Sprintf("job ansible_job %s attempt %%", job.ID)).Delete(&models.APIKey{})
	})
	return job
}

// hostedRun is a plan-only OpenTofu run of a workspace of project A selecting binding, its plan
// claimed on hosted capacity by runner.
func (f *workItemRunnerFixture) hostedRun(t *testing.T, hostedPool, binding uuid.UUID, runner *models.Runner) *models.Run {
	t.Helper()
	ws := &models.Workspace{ProjectID: f.projectA, Name: "id-hosted-run-" + uuid.NewString()[:8], ExecutionMode: "remote", IdentityBindingID: &binding}
	if err := f.db.Create(ws).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	run := &models.Run{
		WorkspaceID: ws.ID, Status: models.RunStatusPlanning, Operation: models.RunOperationPlanOnly, AgentPoolID: &hostedPool,
		RunnerID: &runner.ID, Attempt: 1, PhaseAttempt: 1, ClaimedPhase: "plan", ClaimedRunType: "plan", DispatchedAt: &now,
	}
	if err := f.db.Create(run).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("kind = ? AND name LIKE ?", models.APIKeyKindJob, fmt.Sprintf("job tofu_run %s attempt %%", run.ID)).Delete(&models.APIKey{})
		f.db.Where("id = ?", run.ID).Delete(&models.Run{})
		f.db.Where("id = ?", ws.ID).Delete(&models.Workspace{})
	})
	return run
}

// After a rename or a disable and an API restart, a file sync requested for an inventory still
// selecting the old hosted ID is accepted on hosted capacity, and it, an Ansible job and a
// cloud-source sync selecting the old ID are refused at their first token with 409 naming the
// binding as no longer existing (#1113, D3, AC-06).
func TestJobTokenIdentity_OldHostedIDRefusedForJobAndSource(t *testing.T) {
	for name, after := range map[string]string{"renamed": "renamed-identity", "disabled": ""} {
		t.Run(name, func(t *testing.T) {
			f := setupWorkItemRunner(t)
			old, hostedPool, runner := f.hostedCapacity(t, "hosted-workload-identity")
			f.selectOnProject(t, old)
			sync := f.hostedSourceSync(t, hostedPool, runner)
			job := f.runningJob(t, hostedPool, runner)
			inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
			if err := f.db.Model(inv).Update("identity_binding_id", old).Error; err != nil {
				t.Fatal(err)
			}
			inv.IdentityBindingID = &old

			if after == "" {
				repository.SetHostedBinding(nil)
			} else {
				configureHosted(t, after)
			}
			fileSync, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
			if err != nil {
				t.Fatalf("a file sync selecting the old hosted ID must still be accepted: %v", err)
			}
			if fileSync.AgentPoolID == nil || *fileSync.AgentPoolID != hostedPool {
				t.Fatalf("file sync selecting the old hosted ID queued on %v, want the hosted pool", fileSync.AgentPoolID)
			}
			f.startAs(t, runner, fileSync.ID)
			for kind, id := range map[string]string{"cloud-source sync": sync.ID, "Ansible job": job.ID.String(), "file sync": fileSync.ID} {
				rec := runnerDo(t, f.r, "hosted", http.MethodPost, "/api/v2/runner/jobs/"+id+"/token", nil)
				if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "no longer exists") || !strings.Contains(rec.Body.String(), old.String()) {
					t.Errorf("first token of the %s selecting the old hosted ID = %d %s, want 409 naming the binding as no longer existing", kind, rec.Code, rec.Body.String())
				}
			}
		})
	}
}

// An OpenTofu run, an Ansible job and a cloud-source sync placed on hosted capacity and selecting
// the hosted binding each receive it on the token a non-strict Kubernetes hosted launcher is
// issued, and record it as the attempt's decision (#1113, D3, AC-09). The file sync case is
// TestJobTokenIdentity_HostedRenameReplays.
func TestJobTokenIdentity_HostedBindingOnHostedWork(t *testing.T) {
	cases := map[string]func(t *testing.T, f *workItemRunnerFixture, hosted, hostedPool uuid.UUID, runner *models.Runner) (string, func() models.JobPlacement){
		"OpenTofu run": func(t *testing.T, f *workItemRunnerFixture, hosted, hostedPool uuid.UUID, runner *models.Runner) (string, func() models.JobPlacement) {
			run := f.hostedRun(t, hostedPool, hosted, runner)
			return run.ID, func() models.JobPlacement {
				var stored models.Run
				if err := f.db.First(&stored, "id = ?", run.ID).Error; err != nil {
					t.Fatal(err)
				}
				return stored.Placement
			}
		},
		"Ansible job": func(t *testing.T, f *workItemRunnerFixture, hosted, hostedPool uuid.UUID, runner *models.Runner) (string, func() models.JobPlacement) {
			f.selectOnProject(t, hosted)
			job := f.runningJob(t, hostedPool, runner)
			return job.ID.String(), func() models.JobPlacement {
				var stored models.AnsibleJob
				if err := f.db.First(&stored, "id = ?", job.ID).Error; err != nil {
					t.Fatal(err)
				}
				return stored.Placement
			}
		},
		"cloud-source sync": func(t *testing.T, f *workItemRunnerFixture, hosted, hostedPool uuid.UUID, runner *models.Runner) (string, func() models.JobPlacement) {
			f.selectOnProject(t, hosted)
			sync := f.hostedSourceSync(t, hostedPool, runner)
			return sync.ID, func() models.JobPlacement { return f.reload(t, sync.ID).Placement }
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := setupWorkItemRunner(t)
			hosted, hostedPool, runner := f.hostedCapacity(t, "hosted-workload-identity")
			id, placement := setup(t, f, hosted, hostedPool, runner)
			tok, err := f.tokenAs(t, runner, id)
			if err != nil {
				t.Fatalf("hosted token of the %s: %v", name, err)
			}
			if tok.Identity == nil || tok.Identity.BindingID != hosted.String() || tok.Identity.ServiceAccount != "stackweaver-hosted-identity" ||
				tok.Identity.Mechanism != models.IdentityMechanismAzureWorkloadIdentity {
				t.Errorf("identity on the %s's token = %+v, want the hosted binding %s", name, tok.Identity, hosted)
			}
			if got := placement(); got.IdentityAttempt != tok.Attempt || got.Identity == nil || got.Identity.BindingID == nil || *got.Identity.BindingID != hosted {
				t.Errorf("decision of the %s = attempt %d, %+v; want the hosted binding at attempt %d", name, got.IdentityAttempt, got.Identity, tok.Attempt)
			}
		})
	}
}

// The hosted binding resolved for a job on a customer pool, and a customer-pool binding resolved
// for a hosted job, are refused at the token route with 409 and record no decision (#1113, D3,
// AC-09).
func TestJobTokenIdentity_BindingOfTheOtherCapacityRefused(t *testing.T) {
	t.Run("hosted binding on a customer pool", func(t *testing.T) {
		f := setupWorkItemRunner(t)
		f.kubernetesRunners(t)
		hosted := configureHosted(t, "hosted-workload-identity")
		f.selectOnProject(t, hosted)
		job := f.runningJob(t, f.poolA, f.runnerA1)
		rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+job.ID.String()+"/token", nil)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "hosted-workload-identity") {
			t.Errorf("token of a customer-pool job resolving the hosted binding = %d %s, want 409 naming it", rec.Code, rec.Body.String())
		}
		f.assertNoJobDecision(t, job.ID)
	})
	t.Run("customer binding on hosted capacity", func(t *testing.T) {
		f := setupWorkItemRunner(t)
		_, hostedPool, runner := f.hostedCapacity(t, "hosted-workload-identity")
		customer := f.binding(t, f.poolA, "customer")
		f.selectOnProject(t, customer.ID)
		job := f.runningJob(t, hostedPool, runner)
		rec := runnerDo(t, f.r, "hosted", http.MethodPost, "/api/v2/runner/jobs/"+job.ID.String()+"/token", nil)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), customer.Name) {
			t.Errorf("token of a hosted job resolving a customer binding = %d %s, want 409 naming it", rec.Code, rec.Body.String())
		}
		f.assertNoJobDecision(t, job.ID)
	})
}

// assertNoJobDecision checks that an Ansible job recorded no identity decision and holds no token.
func (f *workItemRunnerFixture) assertNoJobDecision(t *testing.T, id uuid.UUID) {
	t.Helper()
	var stored models.AnsibleJob
	if err := f.db.First(&stored, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	if got := stored.Placement; got.IdentityAttempt != 0 || got.Identity != nil || got.IdentityBindingID != nil {
		t.Errorf("a refused token recorded %+v", got)
	}
	if n := f.jobTokenRows(t, models.JobTypeAnsibleJob, id.String()); n != 0 {
		t.Errorf("a refused token left %d job token rows", n)
	}
}

// The pool restriction is checked once per attempt, at its first token, against the customer pool
// the sync is queued on and the inventory's current project (#1113, D2, owner decision Q12; AC-19,
// AC-23): a pool that lost access never receives a new attempt's token, even when the selection was
// cleared, and the decision records the inventory scope it validated.
func TestJobTokenIdentity_FirstTokenChecksThePoolRestriction(t *testing.T) {
	for name, clear := range map[string]bool{"binding kept": false, "selection cleared": true} {
		t.Run(name, func(t *testing.T) {
			f := setupWorkItemRunner(t)
			f.kubernetesRunners(t)
			b := f.binding(t, f.poolA, "files")
			f.selectOnProject(t, b.ID)
			_, item := f.fileSyncClaimed(t)
			// Pool A no longer lets project A use it.
			if err := f.db.Exec("DELETE FROM agent_pool_allowed_projects WHERE agent_pool_id = ?", f.poolA).Error; err != nil {
				t.Fatal(err)
			}
			if clear {
				f.selectOnProject(t, nil)
			}
			rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/token", nil)
			if rec.Code != http.StatusConflict {
				t.Fatalf("first token after the pool lost access = %d %s, want 409", rec.Code, rec.Body.String())
			}
			if got := f.reload(t, item.ID).Placement; got.IdentityAttempt != 0 || got.Identity != nil {
				t.Errorf("a refused first token recorded %+v", got.Identity)
			}
		})
	}
}

func TestJobTokenIdentity_DecisionRecordsTheValidatedScope(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	_, item := f.fileSyncClaimed(t)
	if code, _ := f.token(t, item.ID); code != http.StatusOK {
		t.Fatalf("first token = %d", code)
	}
	got := f.reload(t, item.ID).Placement.Identity
	if got == nil || got.Scope == nil || got.Scope.ProjectID == nil || *got.Scope.ProjectID != f.projectA {
		t.Errorf("recorded scope = %+v, want project %s", got, f.projectA)
	}
}

func TestJobTokenIdentity_MovedInventoryIsCheckedAgainstItsNewProject(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	inv, item := f.fileSyncClaimed(t)
	// The inventory moves to a project pool A does not allow before the first token.
	other := &models.Project{ID: uuid.New(), OrganizationID: f.orgA, Name: "moved-" + uuid.NewString()[:8], IdentityBindingID: &b.ID}
	if err := f.db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Model(inv).Update("project_id", f.projectA)
		f.db.Where("id = ?", other.ID).Delete(&models.Project{})
	})
	if err := f.db.Model(inv).Update("project_id", other.ID).Error; err != nil {
		t.Fatal(err)
	}
	rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/token", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("first token after a move to a project the pool does not allow = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if got := f.reload(t, item.ID).Placement; got.Identity != nil {
		t.Errorf("a refused first token recorded %+v", got.Identity)
	}
}

// placementOf is the identity part of a work item's placement, for comparing a decision before and
// after a request.
func (f *workItemRunnerFixture) placementOf(t *testing.T, id string) string {
	t.Helper()
	p := f.reload(t, id).Placement
	raw, err := json.Marshal(map[string]any{"attempt": p.IdentityAttempt, "identity": p.Identity, "binding": p.IdentityBindingID})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// A job token write that fails inside the token transaction answers 500 and rolls the decision
// back with it: no decision, no binding and no token row; the retry records the binding (AC-22;
// R-30 F-02).
func TestJobTokenIdentity_FailedTokenWriteRecordsNothing(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	_, item := f.fileSyncClaimed(t)

	name := "test:fail-job-token-write-" + uuid.NewString()
	failed := 0
	if err := f.db.Callback().Create().Before("gorm:create").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table == "api_keys" {
			failed++
			_ = tx.AddError(errors.New("database write interrupted"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	removed := false
	remove := func() {
		if !removed {
			removed = true
			if err := f.db.Callback().Create().Remove(name); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(remove)
	rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/token", nil)
	remove()
	if failed == 0 {
		t.Fatal("the job token insert was never reached")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("token with a failed write = %d %s, want 500", rec.Code, rec.Body.String())
	}
	if got := f.reload(t, item.ID).Placement; got.IdentityAttempt != 0 || got.Identity != nil || got.IdentityBindingID != nil {
		t.Errorf("a failed token write recorded attempt %d, identity %+v, binding %v; want nothing", got.IdentityAttempt, got.Identity, got.IdentityBindingID)
	}
	if n := f.jobTokenRows(t, models.JobTypeWorkItem, item.ID); n != 0 {
		t.Errorf("a failed token write left %d job token rows", n)
	}

	code, tok := f.token(t, item.ID)
	if code != http.StatusOK || tok.Identity == nil || tok.Identity.BindingID != b.ID.String() {
		t.Fatalf("retried token = %d, %+v; want binding %s", code, tok.Identity, b.ID)
	}
	got := f.reload(t, item.ID).Placement
	if got.IdentityAttempt != tok.Attempt || got.Identity == nil || got.Identity.BindingID == nil || *got.Identity.BindingID != b.ID ||
		got.IdentityBindingID == nil || *got.IdentityBindingID != b.ID {
		t.Errorf("decision after the retry = attempt %d, %+v, binding %v; want %s at attempt %d", got.IdentityAttempt, got.Identity, got.IdentityBindingID, b.ID, tok.Attempt)
	}
}

// A terminal, superseded or other runner's claim is still refused once the attempt holds a
// decision, and the refusal leaves the decision as it was (AC-22).
func TestJobTokenIdentity_RefusedClaimsKeepTheDecision(t *testing.T) {
	cases := map[string]struct {
		change func(t *testing.T, f *workItemRunnerFixture, item *models.WorkItem, attempt int)
		key    string
		body   func(attempt int) any
		want   int
	}{
		"terminal": {
			change: func(t *testing.T, f *workItemRunnerFixture, item *models.WorkItem, _ int) {
				if err := f.db.Model(&models.WorkItem{}).Where("id = ?", item.ID).Update("status", models.WorkItemStatusCompleted).Error; err != nil {
					t.Fatal(err)
				}
			},
			key: "a1", want: http.StatusForbidden,
		},
		"superseded": {
			// A later claim moved the work item past the attempt the launcher still names.
			change: func(t *testing.T, f *workItemRunnerFixture, item *models.WorkItem, attempt int) {
				if err := f.db.Model(&models.WorkItem{}).Where("id = ?", item.ID).Update("attempt", attempt+1).Error; err != nil {
					t.Fatal(err)
				}
			},
			key: "a1", want: http.StatusConflict,
			body: func(attempt int) any { return runnercontract.JobTokenRequest{Attempt: attempt} },
		},
		"other runner": {
			change: func(*testing.T, *workItemRunnerFixture, *models.WorkItem, int) {},
			key:    "a2", want: http.StatusForbidden,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := setupWorkItemRunner(t)
			f.kubernetesRunners(t)
			b := f.binding(t, f.poolA, "files")
			f.selectOnProject(t, b.ID)
			_, item := f.fileSyncClaimed(t)
			code, first := f.token(t, item.ID)
			if code != http.StatusOK || first.Identity == nil {
				t.Fatalf("first token = %d, %+v", code, first.Identity)
			}
			before := f.placementOf(t, item.ID)
			tc.change(t, f, item, first.Attempt)
			var body any
			if tc.body != nil {
				body = tc.body(first.Attempt)
			}
			rec := runnerDo(t, f.r, tc.key, http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/token", body)
			if rec.Code != tc.want {
				t.Fatalf("token for a %s claim = %d %s, want %d", name, rec.Code, rec.Body.String(), tc.want)
			}
			if after := f.placementOf(t, item.ID); after != before {
				t.Errorf("a refused %s claim changed the decision: %s, was %s", name, after, before)
			}
		})
	}
}

// A running attempt whose placement carries a binding, as a report before the upgrade wrote it,
// but no decision and no job token resolves and records its identity as a first token (AC-22).
func TestJobTokenIdentity_PlacementBindingWithoutDecisionResolvesAsFirstToken(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	stale := f.binding(t, f.poolA, "stale")
	f.selectOnProject(t, b.ID)
	_, item := f.fileSyncClaimed(t)
	if err := f.db.Model(&models.WorkItem{}).Where("id = ?", item.ID).Update("placement_identity_binding_id", stale.ID).Error; err != nil {
		t.Fatal(err)
	}
	if n := f.jobTokenRows(t, models.JobTypeWorkItem, item.ID); n != 0 {
		t.Fatalf("the attempt already holds %d job tokens", n)
	}
	code, tok := f.token(t, item.ID)
	if code != http.StatusOK || tok.Identity == nil || tok.Identity.BindingID != b.ID.String() {
		t.Fatalf("token = %d, %+v; want the current selection %s", code, tok.Identity, b.ID)
	}
	got := f.reload(t, item.ID).Placement
	if got.IdentityAttempt != tok.Attempt || got.Identity == nil || got.Identity.BindingID == nil || *got.Identity.BindingID != b.ID {
		t.Errorf("decision = attempt %d, %+v; want %s at attempt %d", got.IdentityAttempt, got.Identity, b.ID, tok.Attempt)
	}
	if got.IdentityBindingID == nil || *got.IdentityBindingID != b.ID {
		t.Errorf("placement binding = %v, want the first token's %s", got.IdentityBindingID, b.ID)
	}
}

// An attempt that holds a job token from before the upgrade, on a container launcher that may not
// receive the binding its job now selects, is issued a token with no identity: no refusal, no
// decision, and the placement's binding column as it was (AC-22).
func TestJobTokenIdentity_PreUpgradeTokenOnALauncherThatCannotApplyIt(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	_, item := f.fileSyncClaimed(t)
	if err := f.db.Model(f.runnerA1).Update("driver", "container").Error; err != nil {
		t.Fatal(err)
	}
	placed := f.binding(t, f.poolA, "placed")
	if err := f.db.Model(&models.WorkItem{}).Where("id = ?", item.ID).Update("placement_identity_binding_id", placed.ID).Error; err != nil {
		t.Fatal(err)
	}
	claimed := f.reload(t, item.ID)
	principal := apikey.JobPrincipal{Kind: models.JobTypeWorkItem, JobID: item.ID, RunnerID: f.runnerA1.ID, Attempt: claimed.Attempt}
	key, _, err := f.svc.CreateJobToken(f.orgA, f.runnerA1.AgentPoolID, principal, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })

	code, tok := f.token(t, item.ID)
	if code != http.StatusOK || tok.Identity != nil {
		t.Fatalf("token on a container launcher with a pre-upgrade token = %d, identity %+v; want 200 with no identity", code, tok.Identity)
	}
	got := f.reload(t, item.ID).Placement
	if got.IdentityAttempt != 0 || got.Identity != nil {
		t.Errorf("a pre-upgrade attempt recorded a decision: attempt %d, %+v", got.IdentityAttempt, got.Identity)
	}
	if got.IdentityBindingID == nil || *got.IdentityBindingID != placed.ID {
		t.Errorf("placement binding = %v, want it unchanged at %s", got.IdentityBindingID, placed.ID)
	}
}

// A customer-pool sync whose selection is cleared before its first token records the platform
// decision with the inventory scope it validated, and the artifacts route accepts that scope and
// refuses it once the inventory moved, for a project inventory and an organization-scoped one
// (AC-22, AC-23).
func TestJobTokenIdentity_ClearedSelectionScopeGuardsTheArtifacts(t *testing.T) {
	t.Run("project inventory", func(t *testing.T) {
		f := setupWorkItemRunner(t)
		f.kubernetesRunners(t)
		b := f.binding(t, f.poolA, "files")
		f.selectOnProject(t, b.ID)
		inv, item := f.fileSyncClaimed(t)
		f.selectOnProject(t, nil)
		other := &models.Project{ID: uuid.New(), OrganizationID: f.orgA, Name: "scope-moved-" + uuid.NewString()[:8]}
		if err := f.db.Create(other).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("project_id", f.projectA)
			f.db.Where("id = ?", other.ID).Delete(&models.Project{})
		})
		f.clearedScopeGuardsArtifacts(t, item, &f.projectA, &other.ID, inv.ID)
	})
	t.Run("organization-scoped inventory", func(t *testing.T) {
		f := setupWorkItemRunner(t)
		f.kubernetesRunners(t)
		// Pool A lets every inventory of the organization use it, so an organization-scoped
		// inventory's sync queues there.
		if err := f.db.Model(&models.AgentPool{}).Where("id = ?", f.poolA).Update("organization_scoped", true).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.db.Model(&models.AgentPool{}).Where("id = ?", f.poolA).Update("organization_scoped", false) })
		b := f.binding(t, f.poolA, "files")
		inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
		if err := f.db.Model(inv).Updates(map[string]any{"project_id": nil, "identity_binding_id": b.ID}).Error; err != nil {
			t.Fatal(err)
		}
		inv.ProjectID, inv.IdentityBindingID = nil, &b.ID
		item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
		if err != nil {
			t.Fatal(err)
		}
		if item.AgentPoolID == nil || *item.AgentPoolID != f.poolA {
			t.Fatalf("organization-scoped sync queued on %v, want pool A", item.AgentPoolID)
		}
		if rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/start", runnercontract.JobStartRequest{RunnerID: f.keyRunner("a1")}); rec.Code != http.StatusOK {
			t.Fatalf("claiming %s: %d %s", item.ID, rec.Code, rec.Body.String())
		}
		if err := f.db.Model(inv).Update("identity_binding_id", nil).Error; err != nil {
			t.Fatal(err)
		}
		f.clearedScopeGuardsArtifacts(t, item, nil, &f.projectA, inv.ID)
	})
}

// clearedScopeGuardsArtifacts issues item's first token, asserts the platform decision records
// scope as its project, that the artifacts route serves the clone, and that it refuses once the
// inventory moved to moveTo.
func (f *workItemRunnerFixture) clearedScopeGuardsArtifacts(t *testing.T, item *models.WorkItem, scope, moveTo *uuid.UUID, inventory uuid.UUID) {
	t.Helper()
	name := "scope-" + uuid.NewString()[:6]
	code, tok := f.mintJobToken(t, f.r, f.svc, "a1", item.ID, name)
	if code != http.StatusOK || tok.Identity != nil {
		t.Fatalf("first token after the selection was cleared = %d, %+v; want the platform identity", code, tok.Identity)
	}
	got := f.reload(t, item.ID).Placement
	if got.IdentityAttempt != tok.Attempt || got.Identity == nil || got.Identity.BindingID != nil || got.Identity.Scope == nil {
		t.Fatalf("decision = attempt %d, %+v; want a platform decision with a scope", got.IdentityAttempt, got.Identity)
	}
	if want, have := scope, got.Identity.Scope.ProjectID; (want == nil) != (have == nil) || (want != nil && *want != *have) {
		t.Fatalf("recorded scope project = %v, want %v", have, want)
	}
	if rec, art := f.artifacts(t, name, item.ID); rec.Code != http.StatusOK || art.Clone == nil {
		t.Fatalf("artifacts within the validated scope = %d %s, want 200 with clone inputs", rec.Code, rec.Body.String())
	}
	if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inventory).Update("project_id", moveTo).Error; err != nil {
		t.Fatal(err)
	}
	if rec, art := f.artifacts(t, name, item.ID); rec.Code != http.StatusConflict || art.Clone != nil {
		t.Errorf("artifacts after the inventory moved = %d %s, want 409 and no clone inputs", rec.Code, rec.Body.String())
	}
}

// Placement reports through the output route, from the executor's job token, merge where the job
// runs but never change the identity decision or the placement's binding (AC-22).
func TestJobTokenIdentity_PlacementReportsKeepTheDecision(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	other := f.binding(t, f.poolA, "reported")
	f.selectOnProject(t, b.ID)
	_, item := f.fileSyncClaimed(t)
	name := "report-" + uuid.NewString()[:6]
	if code, tok := f.mintJobToken(t, f.r, f.svc, "a1", item.ID, name); code != http.StatusOK || tok.Identity == nil {
		t.Fatalf("first token = %d, %+v", code, tok.Identity)
	}
	before := f.placementOf(t, item.ID)
	for i, report := range []*runnercontract.Placement{
		{Driver: "kubernetes", PlacementID: "sw-job-pod", Node: "node-a"},
		{Node: "node-b", IdentityBindingID: other.ID.String()},
	} {
		rec := runnerDo(t, f.r, name, http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/output", runnercontract.JobOutputRequest{RunnerID: f.keyRunner("a1"), Placement: report})
		if rec.Code != http.StatusOK {
			t.Fatalf("placement report %d = %d %s", i, rec.Code, rec.Body.String())
		}
	}
	got := f.reload(t, item.ID).Placement
	if got.PlacementID != "sw-job-pod" || got.Node != "node-b" {
		t.Fatalf("placement = %+v, want the reports merged", got)
	}
	if after := f.placementOf(t, item.ID); after != before {
		t.Errorf("placement reports changed the decision: %s, was %s", after, before)
	}
}
