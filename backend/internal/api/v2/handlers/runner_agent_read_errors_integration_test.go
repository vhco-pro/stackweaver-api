// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"gorm.io/gorm"
)

// runnerReadFailure injects one query failure into this fixture's database handle.
// The callback is removed before state assertions and row-scoped cleanup.
func runnerReadFailure(t *testing.T, db *gorm.DB, table string, occurrence int, failure error, call func() *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	name := "runner-read-failure-" + uuid.NewString()
	seen := 0
	if err := db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table == table {
			seen++
			if seen == occurrence {
				_ = tx.AddError(failure)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Callback().Query().Remove(name); err != nil {
			t.Error(err)
		}
	}()
	rec := call()
	if seen < occurrence {
		t.Fatalf("injected query %s #%d was not reached (%d reads)", table, occurrence, seen)
	}
	return rec
}

func TestRunnerReadErrors_ControlRoutes(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.jobDataRouter(t)
	h := &RunnerAgentHandler{db: f.db, ansibleJobRepo: repository.NewAnsibleJobRepository(f.db)}
	extra := r.Group("/api/v2/runner", middleware.RunnerAuth(repository.NewRunnerRepository(f.db), nil))
	extra.POST("/jobs/:id/start", middleware.RequireRunnerToken(), h.JobStart)
	extra.POST("/jobs/:id/events", h.JobEvents)
	for _, tt := range []struct {
		name, method, route, table, actor string
		occurrence                        int
		body                              any
	}{
		{"status", http.MethodGet, "status", "ansible_jobs", "job", 1, nil},
		{"output", http.MethodPost, "output", "ansible_jobs", "job", 1, JobOutputRequest{RunnerID: f.runnerA1.ID.String(), Output: "retained output"}},
		{"events", http.MethodPost, "events", "ansible_jobs", "job", 1, JobEventRequest{Event: "runner_output", Stdout: "retained event"}},
		{"token", http.MethodPost, "token", "ansible_jobs", "a1", 1, nil},
		{"token_pool", http.MethodPost, "token", "agent_pools", "a1", 3, nil},
		{"start", http.MethodPost, "start", "ansible_jobs", "a1", 1, runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String()}},
		{"start_authoritative_runner", http.MethodPost, "start", "runners", "a1", 2, runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String()}},
		{"complete_execution", http.MethodPost, "complete", "runner_job_executions", "job", 1, JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Status: "completed"}},
		{"complete_job", http.MethodPost, "complete", "ansible_jobs", "job", 1, JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Status: "completed"}},
		{"complete_event_count", http.MethodPost, "complete", "ansible_job_events", "job", 1, JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Status: "completed"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			job := f.seedJob(t, nil, f.runnerA1)
			t.Cleanup(func() {
				f.db.Where("kind = ? AND name = ?", models.APIKeyKindJob, "job ansible_job "+job.ID.String()+" attempt 1").Delete(&models.APIKey{})
			})
			exec := &models.RunnerJobExecution{RunnerID: f.runnerA1.ID, JobID: job.ID, JobType: models.JobTypeAnsibleJob, Status: models.JobExecutionStatusRunning}
			if err := f.db.Create(exec).Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.db.Where("id = ?", exec.ID).Delete(&models.RunnerJobExecution{}) })
			if code, _ := f.mintJobToken(t, r, svc, "a1", job.ID.String(), "job"); code != http.StatusOK {
				t.Fatalf("mint: %d", code)
			}
			liveTokens := f.jobTokenRows(t, models.JobTypeAnsibleJob, job.ID.String())
			rec := runnerReadFailure(t, f.db, tt.table, tt.occurrence, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
				return runnerDo(t, r, tt.actor, tt.method, "/api/v2/runner/jobs/"+job.ID.String()+"/"+tt.route, tt.body)
			})
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("response = %d, want 500", rec.Code)
			}
			if code := errorCode(t, rec.Body.Bytes()); code != "" {
				t.Errorf("database failure has terminal code %q", code)
			}
			var stored models.AnsibleJob
			if err := f.db.First(&stored, "id = ?", job.ID).Error; err != nil {
				t.Fatal(err)
			}
			if stored.Status != job.Status || stored.FinishedAt != nil {
				t.Errorf("read failure mutated job to %s at %v", stored.Status, stored.FinishedAt)
			}
			var execution models.RunnerJobExecution
			if err := f.db.First(&execution, "id = ?", exec.ID).Error; err != nil {
				t.Fatal(err)
			}
			if execution.Status != models.JobExecutionStatusRunning || execution.FinishedAt != nil {
				t.Errorf("read failure ended execution as %s at %v", execution.Status, execution.FinishedAt)
			}
			if got := f.jobTokenRows(t, models.JobTypeAnsibleJob, job.ID.String()); got != liveTokens {
				t.Errorf("live tokens = %d, want %d", got, liveTokens)
			}
			if events := f.jobEvents(t, job.ID); len(events) != 0 {
				t.Errorf("read failure wrote %d events", len(events))
			}
		})
	}
}

func TestRunnerReadErrors_RunOutput(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _ := f.jobDataRouter(t)
	run := f.seedRun(t, f.runnerA1)
	rec := runnerReadFailure(t, f.db, "runs", 1, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
		return runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+run.ID+"/output", JobOutputRequest{RunnerID: f.runnerA1.ID.String(), Output: "retained output"})
	})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("response = %d, want 500", rec.Code)
	}
}

func TestRunnerReadErrors_DeletedStatusHasExplicitCode(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _ := f.jobDataRouter(t)
	for _, id := range []string{uuid.NewString(), "run-deleted-read-test"} {
		t.Run(id, func(t *testing.T) {
			rec := runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+id+"/status")
			if rec.Code != http.StatusNotFound || errorCode(t, rec.Body.Bytes()) != runnercontract.ErrorCodeJobDeleted {
				t.Errorf("deleted response = %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRunnerReadErrors_WrappedAbsence(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _ := f.jobDataRouter(t)
	job := f.seedJob(t, nil, f.runnerA1)
	rec := runnerReadFailure(t, f.db, "ansible_jobs", 1, fmt.Errorf("reading job: %w", gorm.ErrRecordNotFound), func() *httptest.ResponseRecorder {
		return runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+job.ID.String()+"/status")
	})
	if rec.Code != http.StatusNotFound || errorCode(t, rec.Body.Bytes()) != runnercontract.ErrorCodeJobDeleted {
		t.Errorf("wrapped absence = %d %s", rec.Code, rec.Body.String())
	}
}

func TestRunnerReadErrors_PlaybookLookup(t *testing.T) {
	f := setupAgentPrepFixture(t)
	pb := f.seedPlaybook(t, playbookSpec{noVCS: true})
	job := f.seedJob(t, &pb.ID, f.runnerA1)
	r := f.artifactsRouter(newSnapshotStore(), nil)
	// First playbook read is the job repository's preload. The second is the route's own lookup.
	for _, route := range []string{"artifacts", "playbook-snapshot"} {
		t.Run(route, func(t *testing.T) {
			rec := runnerReadFailure(t, f.db, "ansible_playbooks", 2, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
				return runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+job.ID.String()+"/"+route)
			})
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("response = %d, want 500", rec.Code)
			}
		})
	}
}

func TestRunnerReadErrors_PullCredential(t *testing.T) {
	f := setupAgentPrepFixture(t)
	credential := &models.AnsibleCredential{
		ID: uuid.New(), OrganizationID: f.orgA, Name: "read-error-" + uuid.NewString(),
		Type: models.CredentialTypeRegistry, Username: "pull-user",
	}
	image := &models.RunImage{
		OrganizationID: f.orgA, Name: "read-error-" + uuid.NewString(),
		Kind: models.RunImageKindAnsible, Image: "registry.example.test/jobs:1",
		RegistryCredentialID: &credential.ID,
	}
	for _, row := range []any{credential, image} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.db.Where("id = ?", image.ID).Delete(&models.RunImage{})
		f.db.Where("id = ?", credential.ID).Delete(&models.AnsibleCredential{})
	})
	h := &RunnerAgentHandler{db: f.db}
	r := f.router(func(g *gin.RouterGroup) { g.GET("/images/:id/pull-credential", h.GetPullCredential) })
	for _, table := range []string{"run_images", "ansible_credentials"} {
		t.Run(table, func(t *testing.T) {
			rec := runnerReadFailure(t, f.db, table, 1, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
				return runnerGet(t, r, "a1", "/api/v2/runner/images/"+image.ID.String()+"/pull-credential")
			})
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("response = %d, want 500", rec.Code)
			}
		})
	}
	if rec := runnerGet(t, r, "b1", "/api/v2/runner/images/"+image.ID.String()+"/pull-credential"); rec.Code != http.StatusForbidden {
		t.Errorf("foreign tenant received %d", rec.Code)
	}
}

func TestRunnerReadErrors_WorkItemArtifacts(t *testing.T) {
	f := setupWorkItemRunner(t)
	pb := f.seedPlaybook(t, playbookSpec{})
	for _, table := range []string{"ansible_playbooks", "projects", "vcs_connections"} {
		t.Run(table, func(t *testing.T) {
			item, err := f.items.RequestPlaybookSnapshot(t.Context(), pb, "manual")
			if err != nil {
				t.Fatal(err)
			}
			f.onPool(t, item)
			f.claim(t, "a1", item.ID, "wi")

			tokens := f.jobTokenRows(t, models.JobTypeWorkItem, item.ID)
			rec := runnerReadFailure(t, f.db, table, 1, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
				return runnerGet(t, f.r, "wi", "/api/v2/runner/jobs/"+item.ID+"/artifacts")
			})
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("response = %d, want 500", rec.Code)
			}
			got := f.reload(t, item.ID)
			if got.Status != models.WorkItemStatusRunning || got.FinishedAt != nil {
				t.Errorf("read failure ended work item: %s at %v", got.Status, got.FinishedAt)
			}
			if got := f.jobTokenRows(t, models.JobTypeWorkItem, item.ID); got != tokens {
				t.Errorf("live tokens = %d, want %d", got, tokens)
			}
		})
	}
}

func TestRunnerReadErrors_HostedPool(t *testing.T) {
	f := setupAgentPrepFixture(t)
	var pool models.AgentPool
	if err := f.db.Where("organization_id = ? AND kind = ?", f.orgA, models.AgentPoolKindHosted).First(&pool).Error; err != nil {
		t.Fatal(err)
	}
	runner := &models.Runner{ID: uuid.New(), Kind: models.RunnerKindHosted}
	h := &RunnerAgentHandler{db: f.db}
	rec := runnerReadFailure(t, f.db, "agent_pools", 1, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
		out := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(out)
		if h.authorizePool(c, runner, f.orgA, &pool.ID, &runner.ID, "job") {
			t.Error("failed pool read authorized the caller")
		}
		return out
	})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("pool read = %d %s, want 500", rec.Code, rec.Body.String())
	}
}

func TestRunnerReadErrors_AnsibleArtifactInputs(t *testing.T) {
	f := setupAgentPrepFixture(t)
	cs, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	inv := repository.NewAnsibleInventoryRepository(f.db)
	h := &RunnerAgentHandler{
		db: f.db, cryptoService: cs,
		ansibleJobRepo:    repository.NewAnsibleJobRepository(f.db),
		credentialRepo:    repository.NewAnsibleCredentialRepository(f.db),
		inventoryService:  ansible.NewInventoryService(inv, repository.NewOrganizationRepository(f.db)),
		ansibleConfigRepo: repository.NewAnsibleConfigRepository(f.db),
	}
	r := f.router(func(g *gin.RouterGroup) { g.GET("/jobs/:id/artifacts", h.GetJobArtifacts) })
	credential := &models.AnsibleCredential{
		ID: uuid.New(), OrganizationID: f.orgA, Name: "read-error-" + uuid.NewString(),
		Type: models.CredentialTypeMachineSSH, Username: "fixture-user",
	}
	if err := f.db.Create(credential).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", credential.ID).Delete(&models.AnsibleCredential{}) })
	for _, tt := range []struct {
		table      string
		occurrence int
	}{{"ansible_credentials", 3}, {"ansible_credentials", 4}, {"ansible_inventories", 2}, {"ansible_configs", 1}} {
		t.Run(fmt.Sprintf("%s_%d", tt.table, tt.occurrence), func(t *testing.T) {
			job := f.seedJob(t, nil, f.runnerA1)
			t.Cleanup(func() { f.db.Exec("DELETE FROM ansible_job_credentials WHERE ansible_job_id = ?", job.ID) })
			if err := f.db.Exec("INSERT INTO ansible_job_credentials (ansible_job_id, ansible_credential_id) VALUES (?, ?)", job.ID, credential.ID).Error; err != nil {
				t.Fatal(err)
			}
			rec := runnerReadFailure(t, f.db, tt.table, tt.occurrence, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
				return runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+job.ID.String()+"/artifacts")
			})
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("artifact read = %d, want 500", rec.Code)
			}
			var after models.AnsibleJob
			if err := f.db.First(&after, "id = ?", job.ID).Error; err != nil {
				t.Fatal(err)
			}
			if after.Status != models.AnsibleJobStatusRunning {
				t.Errorf("artifact read ended job as %s", after.Status)
			}
		})
	}
}

func TestRunnerReadErrors_TofuArtifactInputs(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc := f.blobRouter(t, store)
	run := f.seedRunWithConfig(t, store, []byte("configuration"))
	t.Cleanup(func() {
		f.db.Where("kind = ? AND name = ?", models.APIKeyKindJob, "registry tofu_run "+run.ID).Delete(&models.APIKey{})
	})
	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	for _, table := range []string{"configuration_versions", "state_versions"} {
		t.Run(table, func(t *testing.T) {
			rec := runnerReadFailure(t, f.db, table, 1, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
				return runnerGet(t, r, "job", "/api/v2/runner/jobs/"+run.ID+"/artifacts")
			})
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("artifact read = %d, want 500", rec.Code)
			}
		})
	}
}

func TestRunnerReadErrors_ClonePreservesCause(t *testing.T) {
	f := setupAgentPrepFixture(t)
	h := &RunnerAgentHandler{db: f.db, vcsRegistry: vcs.NewProviderRegistry(nil, nil, nil, nil)}
	for _, cause := range []error{errors.New("database read interrupted"), gorm.ErrRecordNotFound} {
		_, err := h.cloneSourceFor(t.Context(), func(*repository.OrganizationScope) (*models.VCSConnection, error) {
			return nil, fmt.Errorf("looking up VCS: %w", cause)
		}, "fixture/repository", "main")
		if !errors.Is(err, cause) {
			t.Errorf("clone error = %v, want preserved cause %v", err, cause)
		}
	}
}

func TestRunnerReadErrors_WorkItemTargetReads(t *testing.T) {
	f := setupAgentPrepFixture(t)
	if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", f.inventory).Updates(map[string]any{"vcs_connection_id": f.vcsConn, "vcs_repository": "fixture/inventories", "inventory_path": "hosts.yml"}).Error; err != nil {
		t.Fatal(err)
	}
	run := f.seedRun(t, f.runnerA1)
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", run.WorkspaceID).Updates(map[string]any{"vcs_connection_id": f.vcsConn, "vcs_repository": "fixture/configuration"}).Error; err != nil {
		t.Fatal(err)
	}
	h := &RunnerAgentHandler{
		db: f.db, inventoryRepo: repository.NewAnsibleInventoryRepository(f.db),
		vcsRegistry:   vcs.NewProviderRegistry(nil, nil, nil, nil),
		azureOIDCRepo: repository.NewAzureOIDCConfigurationRepository(f.db),
	}
	h.SetWorkItems(ansible.NewWorkItemRuntime(f.db, nil, nil))
	r := f.router(func(g *gin.RouterGroup) { g.GET("/jobs/:id/artifacts", h.GetJobArtifacts) })
	for _, tt := range []struct {
		kind, table string
		occurrence  int
	}{
		{models.WorkItemInventoryFileSync, "ansible_inventories", 1},
		{models.WorkItemInventoryFileSync, "organizations", 2},
		{models.WorkItemInventoryFileSync, "vcs_connections", 1},
		{models.WorkItemInventoryFileSync, "azure_o_id_c_configurations", 1},
		{models.WorkItemConfigurationSnapshot, "runs", 1},
		{models.WorkItemConfigurationSnapshot, "workspaces", 1},
		{models.WorkItemConfigurationSnapshot, "vcs_connections", 1},
	} {
		t.Run(tt.kind+"/"+tt.table, func(t *testing.T) {
			item := &models.WorkItem{
				OrganizationID: f.orgA, Kind: tt.kind,
				InventoryID: &f.inventory, RunID: &run.ID,
				Status: models.WorkItemStatusRunning, AgentPoolID: &f.poolA,
				RunnerID: &f.runnerA1.ID, Attempt: 1,
			}
			if err := f.db.Create(item).Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.db.Where("id = ?", item.ID).Delete(&models.WorkItem{}) })
			rec := runnerReadFailure(t, f.db, tt.table, tt.occurrence, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
				return runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+item.ID+"/artifacts")
			})
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("target read = %d, want 500", rec.Code)
			}
			var after models.WorkItem
			if err := f.db.First(&after, "id = ?", item.ID).Error; err != nil {
				t.Fatal(err)
			}
			if after.Status != models.WorkItemStatusRunning || after.FinishedAt != nil {
				t.Errorf("read failure ended work item as %s", after.Status)
			}
		})
	}
}

func TestRunnerReadErrors_PermanentWorkItemInput(t *testing.T) {
	f := setupAgentPrepFixture(t)
	if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", f.inventory).Update("type", models.InventoryTypeConstructed).Error; err != nil {
		t.Fatal(err)
	}
	h := &RunnerAgentHandler{db: f.db}
	inv := repository.NewAnsibleInventoryRepository(f.db)
	h.SetWorkItems(ansible.NewWorkItemRuntime(f.db, ansible.NewInventoryService(inv, repository.NewOrganizationRepository(f.db)), nil))
	r := f.router(func(g *gin.RouterGroup) { g.GET("/jobs/:id/artifacts", h.GetJobArtifacts) })
	item := &models.WorkItem{
		OrganizationID: f.orgA, Kind: models.WorkItemConstructedRebuild,
		InventoryID: &f.inventory, Status: models.WorkItemStatusRunning,
		AgentPoolID: &f.poolA, RunnerID: &f.runnerA1.ID, Attempt: 1,
	}
	if err := f.db.Create(item).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", item.ID).Delete(&models.WorkItem{}) })
	rec := runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+item.ID+"/artifacts")
	if rec.Code != http.StatusConflict {
		t.Errorf("invalid constructed source = %d, want 409", rec.Code)
	}
	var after models.WorkItem
	if err := f.db.First(&after, "id = ?", item.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Status != models.WorkItemStatusFailed {
		t.Errorf("permanent input left work item %s", after.Status)
	}
}

func TestRunnerReadErrors_PlaybookVCSLookup(t *testing.T) {
	f := setupAgentPrepFixture(t)
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeFresh})
	job := f.seedJob(t, &pb.ID, f.runnerA1)
	r := f.artifactsRouter(newSnapshotStore(), nil)
	rec := runnerReadFailure(t, f.db, "vcs_connections", 2, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
		return runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+job.ID.String()+"/artifacts")
	})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("VCS read = %d, want 500", rec.Code)
	}
}

func TestRunnerReadErrors_StartExecutionLookup(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _ := f.attemptRouter()
	job := f.seedJob(t, nil, nil)
	if err := f.db.Model(job).Update("queued_at", time.Now()).Error; err != nil {
		t.Fatal(err)
	}
	rec := runnerReadFailure(t, f.db, "runner_job_executions", 1, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
		return runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+job.ID.String()+"/start", runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String()})
	})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("execution lookup = %d, want 500", rec.Code)
	}
	t.Cleanup(func() { f.db.Where("job_id = ?", job.ID).Delete(&models.RunnerJobExecution{}) })
}

func TestRunnerReadErrors_TofuVCSLookup(t *testing.T) {
	f := setupAgentPrepFixture(t)
	run := f.seedRun(t, f.runnerA1)
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", run.WorkspaceID).Updates(map[string]any{"vcs_connection_id": f.vcsConn, "vcs_repository": "fixture/configuration"}).Error; err != nil {
		t.Fatal(err)
	}
	h := &RunnerAgentHandler{db: f.db, vcsRegistry: vcs.NewProviderRegistry(nil, nil, nil, nil)}
	r := f.router(func(g *gin.RouterGroup) { g.GET("/jobs/:id/artifacts", h.GetJobArtifacts) })
	rec := runnerReadFailure(t, f.db, "vcs_connections", 1, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
		return runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+run.ID+"/artifacts")
	})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("VCS read = %d, want 500", rec.Code)
	}
}

func TestRunnerReadErrors_TokenTemplateLookup(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _ := f.jobDataRouter(t)
	pb := f.seedPlaybook(t, playbookSpec{noVCS: true})
	template := seedTemplate(t, f, "read-error-"+uuid.NewString(), pb.ID)
	for _, occurrence := range []int{2, 3} {
		t.Run(fmt.Sprint(occurrence), func(t *testing.T) {
			job := f.seedJob(t, &pb.ID, f.runnerA1)
			if err := f.db.Model(job).Update("template_id", template.ID).Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				f.db.Where("kind = ? AND name = ?", models.APIKeyKindJob, "job ansible_job "+job.ID.String()+" attempt 1").Delete(&models.APIKey{})
			})
			rec := runnerReadFailure(t, f.db, "ansible_job_templates", occurrence, errors.New("database read interrupted"), func() *httptest.ResponseRecorder {
				return runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+job.ID.String()+"/token", nil)
			})
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("template read = %d, want 500", rec.Code)
			}
			if got := f.jobTokenRows(t, models.JobTypeAnsibleJob, job.ID.String()); got != 0 {
				t.Errorf("template read minted %d tokens", got)
			}
		})
	}
}
