// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type startRouteCase struct {
	name, kind, phase, runType string
	operation                  models.RunOperation
	status                     models.RunStatus
}

var startRouteCases = []startRouteCase{
	{name: "ansible", kind: "ansible"},
	{name: "work item", kind: "work_item"},
	{name: "plan", kind: "tofu", phase: "plan", runType: "plan", operation: models.RunOperationPlanAndApply, status: models.RunStatusPending},
	{name: "plan only", kind: "tofu", phase: "plan", runType: "plan", operation: models.RunOperationPlanOnly, status: models.RunStatusPending},
	{name: "apply", kind: "tofu", phase: "apply", runType: "apply", operation: models.RunOperationPlanAndApply, status: models.RunStatusApplying},
	{name: "destroy plan", kind: "tofu", phase: "plan", runType: "plan-destroy", operation: models.RunOperationDestroy, status: models.RunStatusPending},
	{name: "destroy apply", kind: "tofu", phase: "apply", runType: "apply-destroy", operation: models.RunOperationDestroy, status: models.RunStatusApplying},
}

type claimRouteFixture struct {
	*agentPrepFixture
	router         *gin.Engine
	handler        *RunnerAgentHandler
	keys           *apikey.Service
	token          string
	beforeComplete func(*gin.Context)
}

// setupClaimRouteFixture uses stored bearer keys through the production authentication middleware.
func setupClaimRouteFixture(t *testing.T) *claimRouteFixture {
	t.Helper()
	f := setupAgentPrepFixture(t)
	user := &models.User{ID: uuid.New(), ZitadelSubject: "claim-auth-" + uuid.NewString(), Email: uuid.NewString() + "@example.invalid"}
	if err := f.db.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", user.ID).Delete(&models.User{}) })
	f.runnerA1.Capabilities = models.RunnerLabels{runnercontract.CapabilityJobToken}
	if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA1.ID).Update("capabilities", f.runnerA1.Capabilities).Error; err != nil {
		t.Fatal(err)
	}
	keys := apikey.NewService(repository.NewAPIKeyRepository(f.db), repository.NewOrganizationRepository(f.db), repository.NewProjectRepository(f.db), repository.NewTeamRepository(f.db))
	key, raw, err := keys.CreateRunnerToken(user.ID, f.runnerA1.ID, f.orgA, f.poolA, "claim-auth-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("kind = ? AND organization_id = ?", models.APIKeyKindJob, f.orgA).Delete(&models.APIKey{})
		f.db.Where("id = ?", key.ID).Delete(&models.APIKey{})
	})
	cs, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	h := &RunnerAgentHandler{
		db: f.db, runnerRepo: repository.NewRunnerRepository(f.db),
		jobExecRepo: repository.NewRunnerJobExecutionRepository(f.db), apiKeyService: keys,
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db), playbookRepo: repository.NewAnsiblePlaybookRepository(f.db),
		inventoryRepo: repository.NewAnsibleInventoryRepository(f.db), credentialRepo: repository.NewAnsibleCredentialRepository(f.db),
		ansibleConfigRepo: repository.NewAnsibleConfigRepository(f.db), cryptoService: cs,
		storageClient: newSnapshotStore(), vcsRegistry: vcs.NewProviderRegistry(nil, nil, nil, nil),
		workItems: ansible.NewWorkItemRuntime(f.db, nil, nil),
	}
	fixture := &claimRouteFixture{agentPrepFixture: f, handler: h, keys: keys, token: raw}
	authService := auth.NewService(repository.NewUserRepository(f.db))
	authService.SetAPIKeyService(keys)
	router := gin.New()
	fixture.router = router
	router.Use(middleware.AuthMiddleware(authService))
	group := router.Group("/api/v2/runner", middleware.RunnerAuth(repository.NewRunnerRepository(f.db), nil))
	group.POST("/jobs/:id/start", middleware.RequireRunnerToken(), h.JobStart)
	group.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
	group.POST("/heartbeat", middleware.RequireRunnerToken(), h.Heartbeat)
	group.GET("/jobs/:id/status", h.GetJobStatus)
	group.POST("/jobs/:id/complete", func(c *gin.Context) {
		if fixture.beforeComplete != nil {
			fixture.beforeComplete(c)
		}
		h.JobComplete(c)
	})
	return fixture
}

func (f *claimRouteFixture) do(t *testing.T, token, method, path string, body any, extraHeaders ...map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequestWithContext(t.Context(), method, "/api/v2/runner"+path, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	for _, headers := range extraHeaders {
		for name, value := range headers {
			req.Header.Set(name, value)
		}
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func (f *claimRouteFixture) seedStart(t *testing.T, cfg startRouteCase) (id, table string) {
	t.Helper()
	now := time.Now()
	switch cfg.kind {
	case "ansible":
		job := f.seedJob(t, nil, nil)
		if err := f.db.Model(job).Update("queued_at", now).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.db.Where("job_id = ?", job.ID).Delete(&models.RunnerJobExecution{}) })
		return job.ID.String(), "ansible_jobs"
	case "work_item":
		if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", f.inventory).Update("type", models.InventoryTypeConstructed).Error; err != nil {
			t.Fatal(err)
		}
		item := &models.WorkItem{OrganizationID: f.orgA, AgentPoolID: &f.poolA, InventoryID: &f.inventory, Kind: models.WorkItemConstructedRebuild, Status: models.WorkItemStatusPending, QueuedAt: &now}
		if err := f.db.Create(item).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			f.db.Where("id = ?", item.ID).Delete(&models.WorkItem{})
			f.db.Where("inventory_id = ?", f.inventory).Delete(&models.AnsibleInventorySync{})
		})
		return item.ID, "work_items"
	default:
		run := f.seedRun(t, f.runnerA1)
		if err := f.db.Model(run).Updates(map[string]any{"status": cfg.status, "operation": cfg.operation, "runner_id": nil, "attempt": 0}).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.db.Where("workspace_id = ?", run.WorkspaceID).Delete(&models.StateLock{}) })
		return run.ID, "runs"
	}
}

func (f *claimRouteFixture) expected(cfg startRouteCase) runnercontract.JobStartRequest {
	return runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String(), Attempt: 1, Phase: cfg.phase, RunType: cfg.runType}
}

func (f *claimRouteFixture) claimDirect(t *testing.T, cfg startRouteCase, id string) {
	t.Helper()
	expected := f.expected(cfg)
	var err error
	switch cfg.kind {
	case "ansible":
		_, _, err = repository.NewAnsibleJobRepository(f.db).ClaimAttempt(t.Context(), uuid.MustParse(id), f.runnerA1.ID, expected)
	case "work_item":
		_, _, err = repository.NewWorkItemRepository(f.db).ClaimAttempt(t.Context(), id, f.runnerA1.ID, expected)
	default:
		_, _, err = repository.NewRunRepository(f.db).ClaimAttempt(t.Context(), id, f.runnerA1.ID, expected)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunnerStartRecovery_ReplayedAcknowledgement(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, _ := f.seedStart(t, cfg)
			for attempt := range 2 {
				rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", f.expected(cfg))
				if rec.Code != http.StatusOK {
					t.Errorf("start request %d = HTTP %d, want 200", attempt, rec.Code)
					continue
				}
				var response struct {
					Meta runnercontract.JobStartResponse `json:"meta"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if response.Meta.Status != "started" || response.Meta.Attempt != 1 || response.Meta.Phase != cfg.phase || response.Meta.RunType != cfg.runType {
					t.Errorf("start acknowledgement %d = %+v", attempt, response.Meta)
				}
			}
		})
	}
}

func TestRunnerStartRecovery_FixedLauncherRequiresIdentity(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table := f.seedStart(t, cfg)
			if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA1.ID).Update("capabilities", models.RunnerLabels{runnercontract.CapabilityJobToken, runnercontract.CapabilityClaimRecovery}).Error; err != nil {
				t.Fatal(err)
			}
			rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String()})
			if rec.Code != http.StatusBadRequest {
				t.Errorf("fixed launcher without expected identity = HTTP %d, want 400", rec.Code)
			}
			var stored struct{ Attempt int }
			if err := f.db.Table(table).Select("attempt").Where("id = ?", id).Take(&stored).Error; err != nil {
				t.Fatal(err)
			}
			if stored.Attempt != 0 {
				t.Errorf("invalid start consumed attempt %d", stored.Attempt)
			}
		})
	}
}

func TestRunnerStartRecovery_FixedTokenRequiresOriginalIdentity(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, _ := f.seedStart(t, cfg)
			f.claimDirect(t, cfg, id)
			rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/token", nil)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("fixed claim with empty token request = HTTP %d, want 400", rec.Code)
			}
			var count int64
			if err := f.db.Model(&models.APIKey{}).Where("kind = ? AND organization_id = ?", models.APIKeyKindJob, f.orgA).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Errorf("invalid token request minted %d keys", count)
			}
		})
	}
}

func TestRunnerStartRecovery_HeartbeatIncludesActiveClaim(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, _ := f.seedStart(t, cfg)
			f.claimDirect(t, cfg, id)
			rec := f.do(t, f.token, http.MethodPost, "/heartbeat", runnercontract.HeartbeatRequest{RunnerID: f.runnerA1.ID.String(), Status: "busy", CurrentJobs: 1})
			if rec.Code != http.StatusOK {
				t.Fatalf("heartbeat = HTTP %d", rec.Code)
			}
			var response runnercontract.HeartbeatResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if len(response.ActiveClaims) != 1 {
				t.Fatalf("active claim count = %d, want 1", len(response.ActiveClaims))
			}
			claim := response.ActiveClaims[0]
			if claim.JobID != id || claim.Attempt != 1 || claim.Phase != cfg.phase || claim.RunType != cfg.runType || claim.TimeoutSeconds <= 0 {
				t.Errorf("active claim = %+v", claim)
			}
		})
	}
}

func TestRunnerStartRecovery_LegacyRequests(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, _ := f.seedStart(t, cfg)
			legacy := runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String()}
			if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", legacy); rec.Code != http.StatusOK {
				t.Fatalf("legacy start = HTTP %d", rec.Code)
			}
			rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/token", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("legacy empty token request = HTTP %d", rec.Code)
			}
			var token runnercontract.JobToken
			if err := json.Unmarshal(rec.Body.Bytes(), &token); err != nil {
				t.Fatal(err)
			}
			if token.Token == "" || token.Attempt != 1 || token.JobID != id {
				t.Fatal("legacy token response has incomplete claim identity")
			}
			if status := f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/status", nil); status.Code != http.StatusOK {
				t.Errorf("legacy job token status = HTTP %d", status.Code)
			}
		})
	}
}

func TestRunnerStartRecovery_ReplayKeepsIssuedToken(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, _ := f.seedStart(t, cfg)
			expected := f.expected(cfg)
			if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", expected); rec.Code != http.StatusOK {
				t.Fatalf("first start = HTTP %d", rec.Code)
			}
			rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/token", runnercontract.JobTokenRequest{Attempt: 1, Phase: cfg.phase, RunType: cfg.runType})
			if rec.Code != http.StatusOK {
				t.Fatalf("bound token request = HTTP %d", rec.Code)
			}
			var token runnercontract.JobToken
			if err := json.Unmarshal(rec.Body.Bytes(), &token); err != nil {
				t.Fatal(err)
			}
			if token.Token == "" || token.Attempt != 1 || token.Phase != cfg.phase || token.RunType != cfg.runType {
				t.Error("token response does not identify the original executable claim")
			}
			if replay := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", expected); replay.Code != http.StatusOK {
				t.Errorf("start replay = HTTP %d", replay.Code)
			}
			if status := f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/status", nil); status.Code != http.StatusOK {
				t.Errorf("issued token after start replay = HTTP %d", status.Code)
			}
		})
	}
}

type claimRouteState struct {
	Attempt   int
	Status    string
	Owner     string
	Recovery  bool
	UpdatedAt time.Time
}

func (f *claimRouteFixture) state(t *testing.T, table, id string) claimRouteState {
	t.Helper()
	var result claimRouteState
	if err := f.db.Table(table).Select("attempt, status, COALESCE(runner_id::text, '') AS owner, claim_recovery AS recovery, updated_at").Where("id = ?", id).Take(&result).Error; err != nil {
		t.Fatal(err)
	}
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result
}

func TestRunnerStartRecovery_StartEffectsRollback(t *testing.T) {
	for _, scenario := range []struct {
		caseIndex int
		table     string
	}{
		{0, "runner_job_executions"},
		{1, "ansible_inventory_syncs"},
		{2, "state_locks"},
		{4, "state_locks"},
		{5, "state_locks"},
		{6, "state_locks"},
	} {
		cfg := startRouteCases[scenario.caseIndex]
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table := f.seedStart(t, cfg)
			before := f.state(t, table, id)
			var inventory models.AnsibleInventory
			if err := f.db.First(&inventory, "id = ?", f.inventory).Error; err != nil {
				t.Fatal(err)
			}
			injected := errors.New("later claim effect failed")
			callback := "claim-effect-" + uuid.NewString()
			seen := false
			if err := f.db.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
				if tx.Statement.Table == scenario.table {
					seen = true
					_ = tx.AddError(injected)
				}
			}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := f.db.Callback().Create().Remove(callback); err != nil {
					t.Error(err)
				}
			}()
			rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", f.expected(cfg))
			if !seen {
				t.Fatalf("injected %s write was never reached", scenario.table)
			}
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("failed claim effect = HTTP %d, want 500", rec.Code)
			}
			if after := f.state(t, table, id); before != after {
				t.Errorf("failed claim effect changed state: before %+v, after %+v", before, after)
			}
			if cfg.kind == "work_item" {
				var after models.AnsibleInventory
				if err := f.db.First(&after, "id = ?", inventory.ID).Error; err != nil {
					t.Fatal(err)
				}
				if after.LastSyncStatus != inventory.LastSyncStatus {
					t.Errorf("failed work-item claim changed target status from %q to %q", inventory.LastSyncStatus, after.LastSyncStatus)
				}
			}
		})
	}
}

func TestRunnerStartRecovery_PlacementFailureRollsBack(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table := f.seedStart(t, cfg)
			before := f.state(t, table, id)
			callback := "claim-placement-" + uuid.NewString()
			seen := false
			if err := f.db.Callback().Update().Before("gorm:update").Register(callback, func(tx *gorm.DB) {
				columns, ok := tx.Statement.Dest.(map[string]any)
				if tx.Statement.Table == table && ok {
					if _, placement := columns["placement_driver"]; placement {
						seen = true
						_ = tx.AddError(errors.New("placement persistence failed"))
					}
				}
			}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := f.db.Callback().Update().Remove(callback); err != nil {
					t.Error(err)
				}
			}()
			expected := f.expected(cfg)
			expected.Placement = &runnercontract.Placement{Driver: "container", PlacementID: "claim-fixture"}
			rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", expected)
			if !seen {
				t.Fatal("placement persistence was never reached")
			}
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("failed placement persistence = HTTP %d, want 500", rec.Code)
			}
			if after := f.state(t, table, id); before != after {
				t.Errorf("failed placement persistence changed claim: before %+v, after %+v", before, after)
			}
		})
	}
}

func TestRunnerStartRecovery_FixedClaimRequiresIdentityAfterCapabilityChange(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table := f.seedStart(t, cfg)
			f.claimDirect(t, cfg, id)
			before := f.state(t, table, id)
			legacy := runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String()}
			rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", legacy)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("fixed claim without expected identity = HTTP %d, want 400", rec.Code)
			}
			if after := f.state(t, table, id); before != after {
				t.Errorf("missing identity changed fixed claim: before %+v, after %+v", before, after)
			}
		})
	}
}

func TestRunnerStartRecovery_FreshAttemptRebindsExecution(t *testing.T) {
	f := setupClaimRouteFixture(t)
	cfg := startRouteCases[0]
	id, table := f.seedStart(t, cfg)
	prior := time.Now().Add(-time.Hour)
	if err := f.db.Table(table).Where("id = ?", id).Updates(map[string]any{"attempt": 1, "started_at": prior}).Error; err != nil {
		t.Fatal(err)
	}
	execution := &models.RunnerJobExecution{
		RunnerID: f.runnerA2.ID, JobType: models.JobTypeAnsibleJob, JobID: uuid.MustParse(id),
		Status: models.JobExecutionStatusFailed, StartedAt: &prior, FinishedAt: &prior, ErrorMessage: "previous attempt failed",
	}
	if err := f.db.Create(execution).Error; err != nil {
		t.Fatal(err)
	}
	expected := f.expected(cfg)
	expected.Attempt = 2
	if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", expected); rec.Code != http.StatusOK {
		t.Fatalf("fresh attempt = HTTP %d", rec.Code)
	}
	var current models.RunnerJobExecution
	if err := f.db.First(&current, "id = ?", execution.ID).Error; err != nil {
		t.Fatal(err)
	}
	if current.RunnerID != f.runnerA1.ID || current.Status != models.JobExecutionStatusRunning || current.FinishedAt != nil || current.ErrorMessage != "" || current.StartedAt == nil || !current.StartedAt.After(prior) {
		t.Errorf("fresh attempt retained previous execution identity or outcome: runner=%s status=%s finished=%v error=%q", current.RunnerID, current.Status, current.FinishedAt, current.ErrorMessage)
	}
	updatedAt := current.UpdatedAt.UTC()
	if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", expected); rec.Code != http.StatusOK {
		t.Errorf("fresh attempt replay = HTTP %d", rec.Code)
	}
	if err := f.db.First(&current, "id = ?", execution.ID).Error; err != nil {
		t.Fatal(err)
	}
	if current.UpdatedAt.UTC() != updatedAt {
		t.Error("claim replay rewrote its execution record")
	}
}

func TestRunnerStartRecovery_UnconfiguredJobServices(t *testing.T) {
	for _, cfg := range startRouteCases[:2] {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table := f.seedStart(t, cfg)
			before := f.state(t, table, id)
			want := http.StatusInternalServerError
			if cfg.kind == "work_item" {
				f.handler.workItems = nil
				want = http.StatusNotFound
			} else {
				f.handler.ansibleJobRepo = nil
			}
			rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", f.expected(cfg))
			if rec.Code != want {
				t.Errorf("unconfigured job service = HTTP %d, want %d", rec.Code, want)
			}
			if after := f.state(t, table, id); before != after {
				t.Errorf("unconfigured job service changed claim: before %+v, after %+v", before, after)
			}
		})
	}
}

func TestRunnerStartRecovery_RefusesInvalidTokenIdentity(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, _ := f.seedStart(t, cfg)
			f.claimDirect(t, cfg, id)
			cases := []struct {
				name string
				body runnercontract.JobTokenRequest
				want int
			}{
				{"stale", runnercontract.JobTokenRequest{Attempt: 2, Phase: cfg.phase, RunType: cfg.runType}, http.StatusConflict},
				{"partial", runnercontract.JobTokenRequest{Phase: "plan"}, http.StatusBadRequest},
			}
			if cfg.kind == "tofu" {
				cases = append(cases, struct {
					name string
					body runnercontract.JobTokenRequest
					want int
				}{"wrong type", runnercontract.JobTokenRequest{Attempt: 1, Phase: cfg.phase, RunType: "unknown"}, http.StatusConflict})
			}
			for _, scenario := range cases {
				rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/token", scenario.body)
				if rec.Code != scenario.want {
					t.Errorf("%s token identity = HTTP %d, want %d", scenario.name, rec.Code, scenario.want)
				}
			}
			var count int64
			if err := f.db.Model(&models.APIKey{}).Where("kind = ? AND organization_id = ?", models.APIKeyKindJob, f.orgA).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Errorf("invalid token identities minted %d keys", count)
			}
		})
	}
}

func TestRunnerStartRecovery_LegacyReservationCannotMintAnActiveToken(t *testing.T) {
	f := setupClaimRouteFixture(t)
	cfg := startRouteCases[4]
	id, _ := f.seedStart(t, cfg)
	f.claimDirect(t, cfg, id)
	if err := f.db.Model(&models.Run{}).Where("id = ?", id).Update("claim_recovery", false).Error; err != nil {
		t.Fatal(err)
	}
	runs := repository.NewRunRepository(f.db)
	if err := runs.ClearDispatch(id); err != nil {
		t.Fatal(err)
	}
	reserved, err := runs.ReserveForRunner(f.runnerA1.ID, f.poolA, 1)
	if err != nil || len(reserved) != 1 {
		t.Fatalf("reserve previously released apply: count=%d error=%v", len(reserved), err)
	}
	for _, body := range []any{nil, runnercontract.JobTokenRequest{Attempt: 1, Phase: cfg.phase, RunType: cfg.runType}} {
		rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/token", body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("legacy reservation token request = HTTP %d, want 403", rec.Code)
		}
	}
	var count int64
	if err := f.db.Model(&models.APIKey{}).Where("kind = ? AND organization_id = ?", models.APIKeyKindJob, f.orgA).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("unstarted reservation minted %d tokens", count)
	}
}

func TestRunnerStartRecovery_HeartbeatDistinguishesEmptyAndUnavailable(t *testing.T) {
	t.Run("complete empty", func(t *testing.T) {
		f := setupClaimRouteFixture(t)
		rec := f.do(t, f.token, http.MethodPost, "/heartbeat", runnercontract.HeartbeatRequest{RunnerID: f.runnerA1.ID.String(), Status: "online"})
		if rec.Code != http.StatusOK {
			t.Fatalf("empty heartbeat = HTTP %d", rec.Code)
		}
		var response runnercontract.HeartbeatResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.ActiveClaims == nil || len(response.ActiveClaims) != 0 {
			t.Error("successful empty inventory must return a nonnil empty list")
		}
	})
	t.Run("later kind unavailable", func(t *testing.T) {
		f := setupClaimRouteFixture(t)
		id, _ := f.seedStart(t, startRouteCases[0])
		f.claimDirect(t, startRouteCases[0], id)
		prior := time.Now().Add(-time.Hour)
		if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA1.ID).Update("last_heartbeat_at", prior).Error; err != nil {
			t.Fatal(err)
		}
		callback := "claim-inventory-" + uuid.NewString()
		seen := false
		if err := f.db.Callback().Query().Before("gorm:query").Register(callback, func(tx *gorm.DB) {
			if _, rows := tx.Statement.Dest.(*[]models.WorkItem); rows && tx.Statement.Table == "work_items" {
				seen = true
				_ = tx.AddError(errors.New("work-item inventory unavailable"))
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := f.db.Callback().Query().Remove(callback); err != nil {
				t.Error(err)
			}
		}()
		rec := f.do(t, f.token, http.MethodPost, "/heartbeat", runnercontract.HeartbeatRequest{RunnerID: f.runnerA1.ID.String(), Status: "busy", CurrentJobs: 1})
		if rec.Code != http.StatusOK {
			t.Fatalf("heartbeat during inventory failure = HTTP %d", rec.Code)
		}
		if !seen {
			t.Fatal("complete active inventory never read the work-item surface")
		}
		var response runnercontract.HeartbeatResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.ActiveClaims != nil {
			t.Error("failed inventory must return unavailable instead of a partial or empty success")
		}
		var runner models.Runner
		if err := f.db.First(&runner, "id = ?", f.runnerA1.ID).Error; err != nil {
			t.Fatal(err)
		}
		if runner.LastHeartbeatAt == nil || !runner.LastHeartbeatAt.After(prior) {
			t.Error("inventory failure prevented heartbeat progress")
		}
	})
}

func TestRunnerStartRecovery_OffersNormalizeLegacyCounterBeforeReply(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table := f.seedStart(t, cfg)
			prior := time.Now().Add(-time.Hour)
			columns := map[string]any{"started_at": prior}
			if cfg.kind == "tofu" {
				columns["claimed_phase"] = "plan"
				if cfg.phase == "apply" {
					columns["plan_completed_at"] = prior
				}
				if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA1.ID).Update("tofu_version", "1.9.0").Error; err != nil {
					t.Fatal(err)
				}
			}
			if cfg.kind == "work_item" {
				if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA1.ID).Update("capabilities", models.RunnerLabels{runnercontract.CapabilityJobToken, runnercontract.CapabilityWorkItems}).Error; err != nil {
					t.Fatal(err)
				}
			}
			if err := f.db.Table(table).Where("id = ?", id).Updates(columns).Error; err != nil {
				t.Fatal(err)
			}
			rec := f.do(t, f.token, http.MethodPost, "/heartbeat", runnercontract.HeartbeatRequest{RunnerID: f.runnerA1.ID.String(), Status: "online", AvailableCapacity: 1})
			if rec.Code != http.StatusOK {
				t.Fatalf("offer heartbeat = HTTP %d", rec.Code)
			}
			var response runnercontract.HeartbeatResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if len(response.PendingJobs) != 1 {
				t.Fatalf("offer count = %d, want 1", len(response.PendingJobs))
			}
			offer := response.PendingJobs[0]
			if offer.JobID != id || offer.Attempt != 2 || offer.Phase != cfg.phase || offer.RunType != cfg.runType {
				t.Errorf("legacy next offer = %+v", offer)
			}
			if stored := f.state(t, table, id); stored.Attempt != 1 {
				t.Errorf("counter stored before offer = %d, want 1", stored.Attempt)
			}
		})
	}
}

func TestRunnerStartRecovery_CanceledHeartbeatStopsWaitingForOfferLock(t *testing.T) {
	f := setupClaimRouteFixture(t)
	id, table := f.seedStart(t, startRouteCases[0])
	if err := f.db.Table(table).Where("id = ?", id).Update("runner_id", f.runnerA1.ID).Error; err != nil {
		t.Fatal(err)
	}
	hold := f.db.Begin()
	if hold.Error != nil {
		t.Fatal(hold.Error)
	}
	defer hold.Rollback()
	var job models.AnsibleJob
	if err := hold.Clauses(clause.Locking{Strength: "UPDATE"}).First(&job, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	callback := "claim-offer-wait-" + uuid.NewString()
	lockReached := make(chan struct{})
	var signal sync.Once
	if err := f.db.Callback().Query().Before("gorm:query").Register(callback, func(tx *gorm.DB) {
		if _, locked := tx.Statement.Clauses["FOR"]; locked && tx.Statement.Table == table {
			signal.Do(func() { close(lockReached) })
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.db.Callback().Query().Remove(callback); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	body, err := json.Marshal(runnercontract.HeartbeatRequest{RunnerID: f.runnerA1.ID.String(), Status: "online", AvailableCapacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v2/runner/heartbeat", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		f.router.ServeHTTP(rec, req)
		close(done)
	}()
	select {
	case <-lockReached:
	case <-done:
		t.Error("heartbeat returned before reaching the row-locked offer preparation")
	case <-time.After(10 * time.Second):
		t.Error("heartbeat never reached the row-locked offer preparation")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("canceled heartbeat kept waiting for a locked offer")
		if err := hold.Rollback().Error; err != nil {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("heartbeat remained stuck after releasing its owned test lock")
		}
	}
	if stored := f.state(t, table, id); stored.Attempt != 0 {
		t.Errorf("canceled offer request advanced the claim to %d", stored.Attempt)
	}
}

func (f *claimRouteFixture) startupFailure(cfg startRouteCase) runnercontract.JobCompleteRequest {
	return runnercontract.JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Attempt: 1, Phase: cfg.phase, Status: "failed", ExitCode: 2, ErrorMessage: "startup abandoned"}
}

func TestRunnerStartRecovery_PreStartAbandonmentFencesLateStart(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table := f.seedStart(t, cfg)
			rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/complete", f.startupFailure(cfg))
			if rec.Code != http.StatusOK {
				t.Fatalf("pre-start abandonment = HTTP %d, want 200", rec.Code)
			}
			stored := f.state(t, table, id)
			wantStatus := "failed"
			if cfg.kind == "tofu" {
				wantStatus = string(models.RunStatusErrored)
			}
			if stored.Attempt != 1 || stored.Status != wantStatus || !stored.Recovery {
				t.Errorf("abandoned candidate = %+v", stored)
			}
			late := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", f.expected(cfg))
			if late.Code != http.StatusConflict {
				t.Errorf("delayed start after abandonment = HTTP %d, want 409", late.Code)
			}
			if after := f.state(t, table, id); stored != after {
				t.Errorf("delayed start changed abandoned claim: before %+v, after %+v", stored, after)
			}
		})
	}
}

func TestRunnerStartRecovery_AbandonMatchingActiveClaimRevokesItsToken(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, _ := f.seedStart(t, cfg)
			if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", f.expected(cfg)); rec.Code != http.StatusOK {
				t.Fatalf("start = HTTP %d", rec.Code)
			}
			rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/token", runnercontract.JobTokenRequest{Attempt: 1, Phase: cfg.phase, RunType: cfg.runType})
			if rec.Code != http.StatusOK {
				t.Fatalf("mint = HTTP %d", rec.Code)
			}
			var token runnercontract.JobToken
			if err := json.Unmarshal(rec.Body.Bytes(), &token); err != nil {
				t.Fatal(err)
			}
			if abandoned := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/complete", f.startupFailure(cfg)); abandoned.Code != http.StatusOK {
				t.Fatalf("matching active abandonment = HTTP %d, want 200", abandoned.Code)
			}
			status := f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/status", nil)
			code, _ := runnercontract.DecodeError(status.Body.Bytes())
			if status.Code != http.StatusForbidden || code != runnercontract.ErrorCodeJobTokenRevoked {
				t.Errorf("abandoned claim token = HTTP %d code %q", status.Code, code)
			}
		})
	}
}

func TestRunnerStartRecovery_StartupReportRequiresBoundFailure(t *testing.T) {
	for _, cfg := range startRouteCases[:3] {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table := f.seedStart(t, cfg)
			before := f.state(t, table, id)
			for _, scenario := range []struct {
				name string
				edit func(*runnercontract.JobCompleteRequest)
			}{
				{"unbound", func(req *runnercontract.JobCompleteRequest) { req.Attempt = 0 }},
				{"successful", func(req *runnercontract.JobCompleteRequest) { req.Status = "completed" }},
				{"output", func(req *runnercontract.JobCompleteRequest) { req.Output = "untrusted outcome" }},
				{"result", func(req *runnercontract.JobCompleteRequest) { req.WorkResult = &runnercontract.WorkResult{} }},
				{"promotion", func(req *runnercontract.JobCompleteRequest) { req.CacheManifest = &runnercontract.CacheManifest{} }},
				{"plan counts", func(req *runnercontract.JobCompleteRequest) { req.ResourceAdditions = 1 }},
			} {
				req := f.startupFailure(cfg)
				scenario.edit(&req)
				rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/complete", req)
				if rec.Code != http.StatusBadRequest {
					t.Errorf("%s runner-key report = HTTP %d, want 400", scenario.name, rec.Code)
				}
				if after := f.state(t, table, id); before != after {
					t.Errorf("%s report changed candidate: before %+v, after %+v", scenario.name, before, after)
				}
			}
		})
	}
}

func TestRunnerStartRecovery_AbandonmentSQLFailureRollsBack(t *testing.T) {
	for _, scenario := range []struct {
		caseIndex int
		table     string
	}{
		{0, "ansible_jobs"},
		{0, "runner_job_executions"},
		{1, "ansible_inventories"},
		{1, "ansible_inventory_syncs"},
		{1, "work_items"},
		{2, "runs"},
		{0, "runners"},
	} {
		cfg := startRouteCases[scenario.caseIndex]
		t.Run(cfg.name+"/"+scenario.table, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table := f.seedStart(t, cfg)
			before := f.state(t, table, id)
			callback := "abandonment-" + uuid.NewString()
			seen := false
			if err := f.db.Callback().Update().Before("gorm:update").Register(callback, func(tx *gorm.DB) {
				columns, ok := tx.Statement.Dest.(map[string]any)
				status, hasStatus := columns["status"]
				failed := hasStatus && (status == models.AnsibleJobStatusFailed || status == models.JobExecutionStatusFailed || status == models.RunStatusErrored || status == models.WorkItemStatusFailed || status == models.InventorySyncStatusFailed)
				inventoryFailure := columns["last_sync_error"] == "startup abandoned"
				if tx.Statement.Table == scenario.table && ok && (failed || inventoryFailure || scenario.table == "runners") {
					seen = true
					_ = tx.AddError(errors.New("injected abandonment outcome failure"))
				}
			}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := f.db.Callback().Update().Remove(callback); err != nil {
					t.Error(err)
				}
			}()
			rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/complete", f.startupFailure(cfg))
			if !seen {
				t.Fatalf("injected %s failure was never reached", scenario.table)
			}
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("failed abandonment SQL = HTTP %d, want 500", rec.Code)
			}
			if after := f.state(t, table, id); before != after {
				t.Errorf("abandonment failure changed claim: before %+v, after %+v", before, after)
			}
		})
	}
}

func TestRunnerStartRecovery_AbandonmentRefusesStaleOrForeignCandidates(t *testing.T) {
	for _, cfg := range startRouteCases {
		for _, scenario := range []string{"stale", "foreign reservation", "foreign pool", "wrong runner", "terminal replay"} {
			t.Run(cfg.name+"/"+scenario, func(t *testing.T) {
				f := setupClaimRouteFixture(t)
				id, table := f.seedStart(t, cfg)
				req := f.startupFailure(cfg)
				want := http.StatusForbidden
				switch scenario {
				case "stale":
					req.Attempt = 2
					want = http.StatusConflict
				case "foreign reservation":
					if err := f.db.Table(table).Where("id = ?", id).Update("runner_id", f.runnerA2.ID).Error; err != nil {
						t.Fatal(err)
					}
				case "foreign pool":
					if err := f.db.Table(table).Where("id = ?", id).Update("agent_pool_id", f.runnerB1.PoolID()).Error; err != nil {
						t.Fatal(err)
					}
				case "wrong runner":
					req.RunnerID = f.runnerA2.ID.String()
				case "terminal replay":
					first := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/complete", req)
					if first.Code != http.StatusOK {
						t.Fatalf("initial abandonment = HTTP %d", first.Code)
					}
					req.ErrorMessage = "later report must not replace first outcome"
					want = http.StatusConflict
				}
				before := f.state(t, table, id)
				rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/complete", req)
				if rec.Code != want {
					t.Errorf("abandonment = HTTP %d, want %d", rec.Code, want)
				}
				if want == http.StatusConflict {
					if code, _ := runnercontract.DecodeError(rec.Body.Bytes()); code != runnercontract.ErrorCodeJobTerminal {
						t.Errorf("settled candidate code = %q", code)
					}
				}
				if after := f.state(t, table, id); before != after {
					t.Errorf("refused abandonment changed claim: before %+v, after %+v", before, after)
				}
			})
		}
	}
}

func TestRunnerStartRecovery_ConcurrentStartAndAbandonmentSettleOnce(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table := f.seedStart(t, cfg)
			ready := make(chan struct{})
			results := make(chan int, 8)
			var workers sync.WaitGroup
			for i := range 8 {
				workers.Go(func() {
					<-ready
					route := "/jobs/" + id + "/start"
					var body any = f.expected(cfg)
					if i%2 == 0 {
						route = "/jobs/" + id + "/complete"
						body = f.startupFailure(cfg)
					}
					rec := f.do(t, f.token, http.MethodPost, route, body)
					if rec.Code != http.StatusOK && rec.Code != http.StatusConflict {
						t.Errorf("concurrent request = HTTP %d", rec.Code)
					}
					if i%2 == 0 {
						results <- rec.Code
					}
				})
			}
			close(ready)
			workers.Wait()
			close(results)
			winners := 0
			for status := range results {
				if status == http.StatusOK {
					winners++
				}
			}
			if winners != 1 {
				t.Errorf("committed failed-start outcomes = %d, want one", winners)
			}
			stored := f.state(t, table, id)
			wantStatus := "failed"
			if cfg.kind == "tofu" {
				wantStatus = string(models.RunStatusErrored)
			}
			if stored.Attempt != 1 || stored.Status != wantStatus {
				t.Errorf("concurrent outcome = %+v", stored)
			}
			if cfg.kind == "work_item" {
				var histories int64
				if err := f.db.Model(&models.AnsibleInventorySync{}).Where("inventory_id = ?", f.inventory).Count(&histories).Error; err != nil {
					t.Fatal(err)
				}
				if histories != 1 {
					t.Errorf("concurrent history rows = %d, want one", histories)
				}
			}
		})
	}
}
