// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/executor"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/storage"
	"gorm.io/gorm"
)

// completionCommitPool fails the final commit after exercising the ordinary SQL
// writes. Its rollback leaves the same claim available to the real retry.
type completionCommitPool struct {
	gorm.ConnPool
	seen *bool
}

func (p completionCommitPool) BeginTx(ctx context.Context, options *sql.TxOptions) (gorm.ConnPool, error) {
	tx, err := p.ConnPool.(gorm.TxBeginner).BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &completionCommitTx{ConnPool: tx, seen: p.seen}, nil
}

type completionCommitTx struct {
	gorm.ConnPool
	seen *bool
}

func (tx completionCommitTx) Commit() error {
	*tx.seen = true
	if err := tx.ConnPool.(gorm.TxCommitter).Rollback(); err != nil {
		return err
	}
	return errors.New("injected final completion commit failure")
}

func (tx completionCommitTx) Rollback() error {
	return tx.ConnPool.(gorm.TxCommitter).Rollback()
}

func (f *claimRouteFixture) startCompletion(t *testing.T, cfg startRouteCase) (string, string, runnercontract.JobToken) {
	t.Helper()
	id, table := f.seedStart(t, cfg)
	t.Cleanup(func() { f.db.Where("organization_id = ?", f.orgA).Delete(&models.CachePromotion{}) })
	if cfg.kind == "work_item" {
		t.Cleanup(func() {
			if err := f.db.Exec("DELETE FROM ansible_inventory_host_groups WHERE ansible_inventory_host_id IN (SELECT id FROM ansible_inventory_hosts WHERE inventory_id = ?)", f.inventory).Error; err != nil {
				t.Error(err)
			}
			if err := f.db.Where("inventory_id = ?", f.inventory).Delete(&models.AnsibleInventoryHost{}).Error; err != nil {
				t.Error(err)
			}
			if err := f.db.Where("inventory_id = ?", f.inventory).Delete(&models.AnsibleInventoryGroup{}).Error; err != nil {
				t.Error(err)
			}
		})
	}
	if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", f.expected(cfg)); rec.Code != http.StatusOK {
		t.Fatalf("start = HTTP %d", rec.Code)
	}
	rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/token", runnercontract.JobTokenRequest{
		Attempt: 1, Phase: cfg.phase, RunType: cfg.runType,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("token = HTTP %d", rec.Code)
	}
	var token runnercontract.JobToken
	if err := json.Unmarshal(rec.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	if token.Token == "" {
		t.Fatal("empty job token")
	}
	return id, table, token
}

func (f *claimRouteFixture) completionSnapshot(t *testing.T, table, id string) string {
	t.Helper()
	var result string
	// Table comes only from seedStart's fixed model mapping. The owned graph is
	// compared independently of authentication's last-used bookkeeping.
	query := `SELECT jsonb_build_object(
		'job', (SELECT to_jsonb(j) FROM ` + table + ` j WHERE id::text = ?),
		'execution', (SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM runner_job_executions e WHERE job_id::text = ?),
		'events', (SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM ansible_job_events e WHERE job_id::text = ?),
		'inventory', (SELECT to_jsonb(i) FROM ansible_inventories i WHERE id = ?),
		'history', (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM ansible_inventory_syncs s WHERE inventory_id = ?),
		'hosts', (SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM ansible_inventory_hosts h WHERE inventory_id = ?),
		'groups', (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM ansible_inventory_groups g WHERE inventory_id = ?),
		'memberships', (SELECT jsonb_agg(to_jsonb(m) ORDER BY ansible_inventory_host_id, ansible_inventory_group_id) FROM ansible_inventory_host_groups m WHERE ansible_inventory_host_id IN (SELECT id FROM ansible_inventory_hosts WHERE inventory_id = ?)),
		'runner', (SELECT to_jsonb(r) FROM runners r WHERE id = ?),
		'promotions', (SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM cache_promotions p WHERE job_id = ?),
		'keys', (SELECT jsonb_agg(jsonb_build_object('id', id, 'expires_at', expires_at) ORDER BY id) FROM api_keys WHERE kind = 'job' AND organization_id = ?),
		'locks', (SELECT jsonb_agg(to_jsonb(l) ORDER BY id) FROM state_locks l WHERE locked_by = ?)
	)::text`
	if err := f.db.Raw(query, id, id, id, f.inventory, f.inventory, f.inventory, f.inventory, f.inventory, f.runnerA1.ID, id, f.orgA, id).Scan(&result).Error; err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRunnerCompletion_SQLFailureRollsBack(t *testing.T) {
	for _, scenario := range []struct {
		name, table, operation string
		caseIndex              int
		canceled, manifest     bool
	}{
		{name: "ansible outcome", table: "ansible_jobs", caseIndex: 0},
		{name: "ansible execution", table: "runner_job_executions", caseIndex: 0},
		{name: "ansible cleanup", table: "api_keys", caseIndex: 0},
		{name: "work item target", table: "ansible_inventories", caseIndex: 1},
		{name: "work item history", table: "ansible_inventory_syncs", caseIndex: 1},
		{name: "work item finish", table: "work_items", caseIndex: 1},
		{name: "work item cleanup", table: "api_keys", caseIndex: 1},
		{name: "plan outcome", table: "runs", caseIndex: 2},
		{name: "plan cleanup", table: "api_keys", caseIndex: 2},
		{name: "apply outcome", table: "runs", caseIndex: 4},
		{name: "apply cleanup", table: "api_keys", caseIndex: 4},
		{name: "runner state", table: "runners", caseIndex: 0},
		{name: "registry credentials", table: "api_keys", caseIndex: 0, operation: "delete"},
		{name: "workspace lock", table: "state_locks", caseIndex: 4, operation: "delete"},
		{name: "cancel event", table: "ansible_job_events", caseIndex: 0, operation: "create", canceled: true},
		{name: "canceled apply outcome", table: "runs", caseIndex: 4, canceled: true},
		{name: "canceled apply cleanup", table: "api_keys", caseIndex: 4, canceled: true},
		{name: "cache promotion", table: "cache_promotions", caseIndex: 0, operation: "create", manifest: true},
		{name: "cache lookup", table: "cache_entries", caseIndex: 0, operation: "query", manifest: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			cfg := startRouteCases[scenario.caseIndex]
			f := setupClaimRouteFixture(t)
			id, table, token := f.startCompletion(t, cfg)
			kind := models.JobTypeAnsibleJob
			if cfg.kind == "work_item" {
				kind = models.JobTypeWorkItem
			}
			if cfg.kind == "tofu" {
				kind = models.JobTypeTofuRun
			}
			if _, err := f.keys.CreateJobRegistryToken(f.orgA, f.poolA, kind, id, time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if scenario.canceled {
				if cfg.kind == "tofu" {
					f.cancelAsTheAPIDoes(t, id)
				} else if err := f.db.Table(table).Where("id = ?", id).Updates(map[string]any{"status": models.AnsibleJobStatusCanceled, "finished_at": time.Now()}).Error; err != nil {
					t.Fatal(err)
				}
			}
			before := f.completionSnapshot(t, table, id)
			name := "completion-write-" + uuid.NewString()
			seen := false
			operation := scenario.operation
			if operation == "" {
				operation = "update"
			}
			callback := f.db.Callback().Update()
			switch operation {
			case "create":
				callback = f.db.Callback().Create()
			case "delete":
				callback = f.db.Callback().Delete()
			case "query":
				callback = f.db.Callback().Query()
			}
			if err := callback.Before("gorm:"+operation).Register(name, func(tx *gorm.DB) {
				if tx.Statement.Table == "api_keys" && operation == "update" {
					columns, ok := tx.Statement.Dest.(map[string]any)
					if _, expiration := columns["expires_at"]; !ok || !expiration {
						return
					}
				}
				if tx.Statement.Table == scenario.table {
					seen = true
					_ = tx.AddError(errors.New("injected completion write failure"))
				}
			}); err != nil {
				t.Fatal(err)
			}
			body := runnercontract.JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Status: "failed", ErrorMessage: "engine outcome", Attempt: 1, Phase: cfg.phase}
			if scenario.manifest {
				body.Status = "completed"
				body.CacheManifest = &runnercontract.CacheManifest{Entries: []runnercontract.CacheEntry{{Kind: runnercontract.CacheKindCollection, Name: "example.tools", Version: "1.2.3"}}}
			}
			rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body)
			if err := callback.Remove(name); err != nil {
				t.Fatal(err)
			}
			if !seen {
				t.Fatalf("completion did not reach %s write", scenario.table)
			}
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("failed completion write = HTTP %d, want 500", rec.Code)
			}
			if after := f.completionSnapshot(t, table, id); before != after {
				t.Error("failed completion changed its SQL outcome or cleanup graph")
			}
		})
	}
}

func TestRunnerCompletion_FirstOutcomeSurvivesLostResponse(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table, token := f.startCompletion(t, cfg)
			body := runnercontract.JobCompleteRequest{
				RunnerID: f.runnerA1.ID.String(), Status: "failed", ErrorMessage: "first outcome", Attempt: 1, Phase: cfg.phase,
			}
			if rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body); rec.Code != http.StatusOK {
				t.Fatalf("first report = HTTP %d", rec.Code)
			}
			before := f.completionSnapshot(t, table, id)
			body.Status, body.ErrorMessage = "completed", "competing outcome"
			rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body)
			if rec.Code != http.StatusForbidden {
				t.Errorf("lost-response replay = HTTP %d, want revoked token 403", rec.Code)
			}
			if after := f.completionSnapshot(t, table, id); before != after {
				t.Error("replay replaced the first committed outcome")
			}
			if state := f.state(t, table, id); cfg.kind == "ansible" && state.Status != string(models.AnsibleJobStatusFailed) {
				t.Errorf("first Ansible outcome = %s", state.Status)
			}
		})
	}
}

func TestRunnerCompletion_CommitFailureRetainsRetryableClaim(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table, token := f.startCompletion(t, cfg)
			before := f.completionSnapshot(t, table, id)
			original := f.handler.db
			scoped := original.Session(&gorm.Session{NewDB: true, Context: t.Context()})
			seen := false
			scoped.Statement.ConnPool = &completionCommitPool{ConnPool: original.Statement.ConnPool, seen: &seen}
			f.handler.db = scoped
			body := runnercontract.JobCompleteRequest{
				RunnerID: f.runnerA1.ID.String(), Status: "failed", ErrorMessage: "engine outcome", Attempt: 1, Phase: cfg.phase,
			}
			rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body)
			f.handler.db = original
			if !seen {
				t.Error("completion did not reach the outer transaction commit")
			}
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("failed commit = HTTP %d, want 500", rec.Code)
			}
			if after := f.completionSnapshot(t, table, id); before != after {
				t.Error("failed commit left partial SQL effects")
			}
			if retry := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body); retry.Code != http.StatusOK {
				t.Errorf("report retry after failed commit = HTTP %d", retry.Code)
			}
		})
	}
}

func TestRunnerCompletion_AuthenticatedPlanReplayPreservesNextState(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		autoApply bool
		postPlan  bool
		want      models.RunStatus
	}{
		{name: "waiting for confirmation", want: models.RunStatusPlanned},
		{name: "auto apply", autoApply: true, want: models.RunStatusApplying},
		{name: "post plan task", postPlan: true, want: models.RunStatusPostPlanRunning},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			cfg := startRouteCases[2]
			f := setupClaimRouteFixture(t)
			id, table, token := f.startCompletion(t, cfg)
			if err := f.db.Model(&models.Run{}).Where("id = ?", id).Update("auto_apply", scenario.autoApply).Error; err != nil {
				t.Fatal(err)
			}
			if scenario.postPlan {
				stage := &models.TaskStage{RunID: id, Stage: models.TaskStagePostPlan}
				if err := f.db.Create(stage).Error; err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { f.db.Where("id = ?", stage.ID).Delete(&models.TaskStage{}) })
			}
			authenticated := make(chan struct{})
			resume := make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(resume) }) }
			t.Cleanup(release)
			f.beforeComplete = func(c *gin.Context) {
				if c.GetHeader("X-Test-Delayed-Completion") == "yes" {
					close(authenticated)
					<-resume
				}
			}
			body := runnercontract.JobCompleteRequest{
				RunnerID: f.runnerA1.ID.String(), Status: "completed", Attempt: 1, Phase: "plan", HasChanges: true, ResourceAdditions: 1,
				CacheManifest: &runnercontract.CacheManifest{Entries: []runnercontract.CacheEntry{{Kind: runnercontract.CacheKindCollection, Name: "example.plan", Version: "1.2.3"}}},
			}
			delayed := make(chan *httptest.ResponseRecorder, 1)
			joined := false
			defer func() {
				release()
				if !joined {
					select {
					case <-delayed:
					case <-time.After(10 * time.Second):
						t.Error("delayed report did not finish before owned fixture cleanup")
					}
				}
			}()
			go func() {
				delayed <- f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body, map[string]string{"X-Test-Delayed-Completion": "yes"})
			}()
			select {
			case <-authenticated:
			case <-time.After(10 * time.Second):
				t.Fatal("delayed report did not complete real authentication")
			}
			if rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body); rec.Code != http.StatusOK {
				t.Fatalf("winning plan completion = HTTP %d", rec.Code)
			}
			if state := f.state(t, table, id); state.Status != string(scenario.want) {
				t.Fatalf("plan completion state = %s, want %s", state.Status, scenario.want)
			}
			if scenario.autoApply {
				start := runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String(), Attempt: 2, Phase: "apply", RunType: "apply"}
				if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", start); rec.Code != http.StatusOK {
					t.Fatalf("next apply before old plan replay = HTTP %d", rec.Code)
				}
				if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/token", runnercontract.JobTokenRequest{Attempt: 2, Phase: "apply", RunType: "apply"}); rec.Code != http.StatusOK {
					t.Fatalf("next apply token before old plan replay = HTTP %d", rec.Code)
				}
			}
			before := f.completionSnapshot(t, table, id)
			for _, unbound := range []runnercontract.JobCompleteRequest{
				{RunnerID: f.runnerA1.ID.String(), Status: "completed"},
				{RunnerID: f.runnerA1.ID.String(), Status: "failed"},
				{RunnerID: f.runnerA1.ID.String(), Status: "failed", Attempt: 1},
			} {
				if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/complete", unbound); rec.Code != http.StatusBadRequest {
					t.Errorf("phase-omitted runner-key report after plan = HTTP %d, want 400", rec.Code)
				}
				if after := f.completionSnapshot(t, table, id); before != after {
					t.Error("phase-omitted runner-key report changed the later state or SQL cleanup")
				}
			}
			release()
			select {
			case rec := <-delayed:
				joined = true
				terminal := bytes.Contains(rec.Body.Bytes(), []byte(runnercontract.ErrorCodeJobTerminal)) || bytes.Contains(rec.Body.Bytes(), []byte(runnercontract.ErrorCodeJobTokenRevoked))
				if rec.Code != http.StatusForbidden || !terminal {
					t.Errorf("already authenticated plan replay = HTTP %d, want a coded terminal 403", rec.Code)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("delayed replay did not finish")
			}
			if after := f.completionSnapshot(t, table, id); before != after {
				t.Error("authenticated plan replay changed the later state or SQL cleanup")
			}
		})
	}
}

func TestRunnerCompletion_WorkItemSuccessDatabaseFailureIsRetryable(t *testing.T) {
	for _, scenario := range []struct {
		name, table, operation, column string
	}{
		{name: "host", table: "ansible_inventory_hosts", operation: "create"},
		{name: "group", table: "ansible_inventory_groups", operation: "create"},
		{name: "membership", table: "ansible_inventory_host_groups", operation: "raw"},
		{name: "target", table: "ansible_inventories", operation: "update"},
		{name: "history", table: "ansible_inventory_syncs", operation: "update"},
		{name: "commit", table: "work_items", operation: "update", column: "commit"},
		{name: "outcome", table: "work_items", operation: "update", column: "status"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table, token := f.startCompletion(t, startRouteCases[1])
			before := f.completionSnapshot(t, table, id)
			name := "successful-work-completion-" + uuid.NewString()
			processor := f.db.Callback().Update()
			if scenario.operation == "create" {
				processor = f.db.Callback().Create()
			}
			if scenario.operation == "raw" {
				processor = f.db.Callback().Raw()
			}
			seen := false
			if err := processor.Before("gorm:"+scenario.operation).Register(name, func(tx *gorm.DB) {
				matches := tx.Statement.Table == scenario.table
				if scenario.operation == "raw" {
					matches = strings.Contains(tx.Statement.SQL.String(), "INSERT INTO "+scenario.table)
				}
				if !matches {
					return
				}
				if scenario.column != "" {
					columns, ok := tx.Statement.Dest.(map[string]any)
					if _, selected := columns[scenario.column]; !ok || !selected {
						return
					}
				}
				seen = true
				_ = tx.AddError(errors.New("injected successful work-item persistence failure"))
			}); err != nil {
				t.Fatal(err)
			}
			body := runnercontract.JobCompleteRequest{
				RunnerID: f.runnerA1.ID.String(), Attempt: 1, Status: "completed",
				WorkResult: &runnercontract.WorkResult{Commit: "verified-revision", Inventory: json.RawMessage(`{"fleet":{"hosts":["one"]}}`)},
			}
			rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body)
			if err := processor.Remove(name); err != nil {
				t.Fatal(err)
			}
			if !seen {
				t.Fatalf("completion did not reach the %s persistence fault", scenario.name)
			}
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("database error in successful work = HTTP %d, want 500", rec.Code)
			}
			if after := f.completionSnapshot(t, table, id); before != after {
				t.Error("successful work's database failure left partial inventory, history or cleanup")
			}
			if rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body); rec.Code != http.StatusOK {
				t.Errorf("same outcome retry after database recovery = HTTP %d", rec.Code)
			}
		})
	}
}

func TestRunnerCompletion_ConcurrentAuthenticatedReportsCommitOneOutcome(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table, token := f.startCompletion(t, cfg)
			const count = 8
			ready := make(chan struct{}, count)
			resume := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(resume) }) }
			f.beforeComplete = func(c *gin.Context) {
				ready <- struct{}{}
				select {
				case <-resume:
				case <-c.Request.Context().Done():
				}
			}
			type outcome struct {
				index int
				rec   *httptest.ResponseRecorder
			}
			results := make(chan outcome, count)
			var workers sync.WaitGroup
			defer func() { release(); workers.Wait() }()
			for index := range count {
				workers.Go(func() {
					body := runnercontract.JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Attempt: 1, Phase: cfg.phase, Status: "failed", ErrorMessage: fmt.Sprintf("outcome-%d", index)}
					results <- outcome{index: index, rec: f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body)}
				})
			}
			for range count {
				select {
				case <-ready:
				case <-time.After(10 * time.Second):
					t.Fatal("concurrent reports did not finish real authentication")
				}
			}
			release()
			winners, winningIndex := 0, -1
			for range count {
				result := <-results
				if result.rec.Code == http.StatusOK {
					winners++
					winningIndex = result.index
					continue
				}
				if result.rec.Code != http.StatusForbidden || !bytes.Contains(result.rec.Body.Bytes(), []byte(runnercontract.ErrorCodeJobTerminal)) {
					t.Errorf("losing authenticated report = HTTP %d without its terminal disposition", result.rec.Code)
				}
			}
			if winners != 1 {
				t.Fatalf("concurrent reports produced %d committed acknowledgements, want 1", winners)
			}
			var message string
			if err := f.db.Table(table).Select("error_message").Where("id = ?", id).Scan(&message).Error; err != nil {
				t.Fatal(err)
			}
			if message != fmt.Sprintf("outcome-%d", winningIndex) {
				t.Error("stored outcome differs from the one acknowledged winner")
			}
		})
	}
}

type completionLogStore struct {
	storage.Client
	beforePut func(context.Context, string) error
}

func (s completionLogStore) Put(ctx context.Context, key string, data []byte) error {
	if s.beforePut != nil {
		if err := s.beforePut(ctx, key); err != nil {
			return err
		}
	}
	return s.Client.Put(ctx, key, data)
}

func TestRunnerCompletion_DelayedPlanFinalizationPreservesNextApply(t *testing.T) {
	f := setupClaimRouteFixture(t)
	id, _, token := f.startCompletion(t, startRouteCases[2])
	if err := f.db.Model(&models.Run{}).Where("id = ?", id).Update("auto_apply", true).Error; err != nil {
		t.Fatal(err)
	}
	store := newSnapshotStore()
	planKey, applyKey := "runs/"+id+"/logs/plan.log", "runs/"+id+"/logs/apply.log"
	if err := store.Put(t.Context(), planKey, []byte("plan output\n")); err != nil {
		t.Fatal(err)
	}
	applyOutput := []byte("next apply is still writing\n")
	if err := store.Put(t.Context(), applyKey, applyOutput); err != nil {
		t.Fatal(err)
	}
	finalizing, resume := make(chan struct{}), make(chan struct{})
	var releaseOnce, enteredOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(resume) }) }
	f.handler.storageClient = completionLogStore{Client: store, beforePut: func(ctx context.Context, key string) error {
		if key == planKey {
			enteredOnce.Do(func() { close(finalizing) })
			select {
			case <-resume:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}}
	result := make(chan *httptest.ResponseRecorder, 1)
	joined := false
	defer func() {
		release()
		if !joined {
			<-result
		}
	}()
	go func() {
		result <- f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", runnercontract.JobCompleteRequest{
			RunnerID: f.runnerA1.ID.String(), Attempt: 1, Phase: "plan", Status: "completed", HasChanges: true, ResourceAdditions: 1,
		})
	}()
	select {
	case <-finalizing:
	case <-time.After(10 * time.Second):
		t.Fatal("plan completion did not reach its delayed external finalization")
	}
	start := runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String(), Attempt: 2, Phase: "apply", RunType: "apply"}
	if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", start); rec.Code != http.StatusOK {
		t.Fatalf("next apply while plan log is delayed = HTTP %d", rec.Code)
	}
	rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/token", runnercontract.JobTokenRequest{Attempt: 2, Phase: "apply", RunType: "apply"})
	if rec.Code != http.StatusOK {
		t.Fatalf("next apply token = HTTP %d", rec.Code)
	}
	var applyToken runnercontract.JobToken
	if err := json.Unmarshal(rec.Body.Bytes(), &applyToken); err != nil {
		t.Fatal(err)
	}
	var lock models.StateLock
	if err := f.db.First(&lock, "lock_id = ?", repository.RunStateLockID(id)).Error; err != nil {
		t.Fatal(err)
	}
	release()
	if rec := <-result; rec.Code != http.StatusOK {
		t.Errorf("winning plan completion = HTTP %d", rec.Code)
	}
	joined = true
	if rec := f.do(t, applyToken.Token, http.MethodGet, "/jobs/"+id+"/status", nil); rec.Code != http.StatusOK {
		t.Errorf("next apply credentials after delayed plan finalization = HTTP %d", rec.Code)
	}
	var kept models.StateLock
	if err := f.db.First(&kept, "id = ?", lock.ID).Error; err != nil {
		t.Errorf("delayed plan finalization removed the next apply lock: %v", err)
	}
	if actual, err := store.Get(t.Context(), applyKey); err != nil || !bytes.Equal(actual, applyOutput) {
		t.Error("plan completion changed or finalized the next apply log")
	}
}

func TestRunnerCompletion_ExternalLogFailurePreservesCommittedOutcome(t *testing.T) {
	for _, cfg := range []startRouteCase{startRouteCases[2], startRouteCases[4]} {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table, token := f.startCompletion(t, cfg)
			store := newSnapshotStore()
			if err := store.Put(t.Context(), "runs/"+id+"/logs/"+cfg.phase+".log", []byte("successful user work\n")); err != nil {
				t.Fatal(err)
			}
			writes := 0
			f.handler.storageClient = completionLogStore{Client: store, beforePut: func(context.Context, string) error {
				writes++
				return errors.New("external log store unavailable")
			}}
			rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", runnercontract.JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Attempt: 1, Phase: cfg.phase, Status: "completed", HasChanges: true, ResourceAdditions: 1})
			if rec.Code != http.StatusOK || writes == 0 {
				t.Fatalf("post-commit failed log write = HTTP %d, writes %d", rec.Code, writes)
			}
			want := models.RunStatusPlanned
			if cfg.phase == "apply" {
				want = models.RunStatusApplied
			}
			if state := f.state(t, table, id); state.Status != string(want) {
				t.Errorf("log-store failure changed the committed outcome to %s", state.Status)
			}
		})
	}
}

func TestRunnerCompletion_FailedSQLLeavesExternalLogsUntouched(t *testing.T) {
	f := setupClaimRouteFixture(t)
	cfg := startRouteCases[2]
	id, table, token := f.startCompletion(t, cfg)
	store := newSnapshotStore()
	key := "runs/" + id + "/logs/plan.log"
	output := []byte("the executor's final output\n")
	if err := store.Put(t.Context(), key, output); err != nil {
		t.Fatal(err)
	}
	f.handler.storageClient = store
	before := f.completionSnapshot(t, table, id)
	name := "completion-log-boundary-" + uuid.NewString()
	if err := f.db.Callback().Update().Before("gorm:update").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table == "runs" {
			_ = tx.AddError(errors.New("outcome write failed before commit"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", runnercontract.JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Attempt: 1, Phase: "plan", Status: "completed"})
	if err := f.db.Callback().Update().Remove(name); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("uncommitted outcome = HTTP %d", rec.Code)
	}
	if after := f.completionSnapshot(t, table, id); before != after {
		t.Error("uncommitted completion changed its SQL graph")
	}
	if actual, err := store.Get(t.Context(), key); err != nil || !bytes.Equal(actual, output) {
		t.Error("failed SQL completion finalized or changed its external log")
	}
}

func TestRunnerCompletion_CanceledFinalReportPreservesCancellation(t *testing.T) {
	for _, cfg := range []startRouteCase{startRouteCases[0], startRouteCases[2], startRouteCases[4]} {
		for _, reported := range []string{"completed", "failed", "canceled"} {
			t.Run(cfg.name+"/"+reported, func(t *testing.T) {
				f := setupClaimRouteFixture(t)
				id, table, token := f.startCompletion(t, cfg)
				want := string(models.AnsibleJobStatusCanceled)
				store := newSnapshotStore()
				f.handler.storageClient = store
				key := "runs/" + id + "/logs/" + cfg.phase + ".log"
				if cfg.kind == "tofu" {
					f.cancelAsTheAPIDoes(t, id)
					want = string(models.RunStatusCancelled)
					if err := store.Put(t.Context(), key, []byte("Interrupt received.\n")); err != nil {
						t.Fatal(err)
					}
				} else if err := f.db.Table(table).Where("id = ?", id).Updates(map[string]any{"status": models.AnsibleJobStatusCanceled, "finished_at": time.Now()}).Error; err != nil {
					t.Fatal(err)
				}
				body := runnercontract.JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Attempt: 1, Phase: cfg.phase, Status: reported}
				if rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body); rec.Code != http.StatusOK {
					t.Fatalf("matching canceled final report = HTTP %d", rec.Code)
				}
				if state := f.state(t, table, id); state.Status != want {
					t.Errorf("executor report replaced cancellation with %s", state.Status)
				}
				before := f.completionSnapshot(t, table, id)
				if rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body); rec.Code != http.StatusForbidden {
					t.Errorf("replayed canceled report = HTTP %d", rec.Code)
				}
				if after := f.completionSnapshot(t, table, id); before != after {
					t.Error("canceled report replay changed the winner's SQL effects")
				}
				if cfg.kind == "tofu" {
					data, err := store.Get(t.Context(), key)
					if err != nil || !bytes.Contains(data, []byte("Interrupt received.")) || bytes.Count(data, []byte(cancelMarker)) != 1 {
						t.Error("canceled final report lost its interrupt output or exactly-once cancel marker")
					}
				} else {
					var count int64
					if err := f.db.Model(&models.AnsibleJobEvent{}).Where("job_id = ? AND stdout = ?", id, jobCancelMarker).Count(&count).Error; err != nil {
						t.Fatal(err)
					}
					if count != 1 {
						t.Errorf("canceled job has %d cancel events, want 1", count)
					}
				}
			})
		}
	}
}

func TestRunnerCompletion_ConcurrentDifferentClaimsReleaseRunnerCapacity(t *testing.T) {
	f := setupClaimRouteFixture(t)
	if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA1.ID).Update("max_concurrent_jobs", 2).Error; err != nil {
		t.Fatal(err)
	}
	first, _, _ := f.startCompletion(t, startRouteCases[0])
	second, _, _ := f.startCompletion(t, startRouteCases[1])
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	left := f.db.WithContext(ctx).Begin()
	if left.Error != nil {
		t.Fatal(left.Error)
	}
	defer left.Rollback()
	right := f.db.WithContext(ctx).Begin()
	if right.Error != nil {
		t.Fatal(right.Error)
	}
	defer right.Rollback()
	if err := left.Model(&models.AnsibleJob{}).Where("id = ?", first).Update("status", models.AnsibleJobStatusFailed).Error; err != nil {
		t.Fatal(err)
	}
	if err := right.Model(&models.WorkItem{}).Where("id = ?", second).Update("status", models.WorkItemStatusFailed).Error; err != nil {
		t.Fatal(err)
	}
	if err := updateRunnerAfterClaim(left, f.runnerA1.ID); err != nil {
		t.Fatal(err)
	}
	// The first transaction now holds the runner row. The second must acquire
	// that row before taking the count used by its final status update.
	boundary := make(chan struct{}, 2)
	name := "completion-capacity-" + uuid.NewString()
	if err := f.db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
		if _, locked := tx.Statement.Clauses["FOR"]; locked && tx.Statement.Table == "runners" {
			boundary <- struct{}{}
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.db.Callback().Query().Remove(name) }()
	if err := f.db.Callback().Row().After("gorm:row").Register(name, func(tx *gorm.DB) {
		sql := tx.Statement.SQL.String()
		if strings.Contains(sql, "FROM ansible_jobs") && strings.Contains(sql, "FROM work_items") {
			boundary <- struct{}{}
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.db.Callback().Row().Remove(name) }()
	done := make(chan struct{})
	var outcome error
	go func() {
		outcome = updateRunnerAfterClaim(right, f.runnerA1.ID)
		close(done)
	}()
	defer func() {
		_ = left.Rollback()
		<-done
		_ = right.Rollback()
	}()
	select {
	case <-boundary:
	case <-ctx.Done():
		t.Fatal("second completion did not reach its runner lock or counter read")
	}
	if err := left.Commit().Error; err != nil {
		t.Fatal(err)
	}
	<-done
	if outcome != nil {
		t.Fatal(outcome)
	}
	if err := right.Commit().Error; err != nil {
		t.Fatal(err)
	}
	var runner models.Runner
	if err := f.db.First(&runner, "id = ?", f.runnerA1.ID).Error; err != nil {
		t.Fatal(err)
	}
	if runner.Status != models.RunnerStatusOnline {
		t.Errorf("all claims finished but runner status is %s, want online", runner.Status)
	}
}

func TestRunnerCompletion_LegacyExecutionOutcomeIsNotReplaced(t *testing.T) {
	f := setupClaimRouteFixture(t)
	id, table, token := f.startCompletion(t, startRouteCases[0])
	// An older nontransactional completion could store the execution outcome
	// before failing to update the parent. Its terminal status still fences replay.
	if err := f.db.Model(&models.RunnerJobExecution{}).Where("job_id = ?", id).
		Updates(map[string]any{"status": models.JobExecutionStatusFailed, "finished_at": nil, "error_message": "first persisted outcome"}).Error; err != nil {
		t.Fatal(err)
	}
	before := f.completionSnapshot(t, table, id)
	rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", runnercontract.JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Attempt: 1, Status: "completed"})
	if rec.Code != http.StatusForbidden || !bytes.Contains(rec.Body.Bytes(), []byte(runnercontract.ErrorCodeJobTerminal)) {
		t.Errorf("legacy terminal execution replay = HTTP %d, want 403/job-terminal", rec.Code)
	}
	if after := f.completionSnapshot(t, table, id); before != after {
		t.Error("replay replaced the earlier persisted execution outcome")
	}
}

func TestRunnerCompletion_SuccessPreservesOriginalOperation(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table, token := f.startCompletion(t, cfg)
			// Earlier executors omit completion phase. Their immutable token attempt
			// still identifies the captured phase while that claim remains active.
			body := runnercontract.JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Status: "completed", HasChanges: true, ResourceAdditions: 1}
			want := string(models.AnsibleJobStatusSuccessful)
			if cfg.kind == "work_item" {
				body.WorkResult = &runnercontract.WorkResult{Inventory: json.RawMessage(`{}`), Commit: "verified-revision"}
				want = models.WorkItemStatusCompleted
			}
			if cfg.kind == "tofu" {
				want = string(models.RunStatusPlanned)
				if cfg.phase == "apply" {
					want = string(models.RunStatusApplied)
				}
				if cfg.operation == models.RunOperationPlanOnly {
					want = string(models.RunStatusPlannedAndFinished)
				}
			}
			if rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", body); rec.Code != http.StatusOK {
				t.Fatalf("original operation completion = HTTP %d", rec.Code)
			}
			if state := f.state(t, table, id); state.Status != want || state.Attempt != 1 {
				t.Errorf("successful completion state = %+v, want %s/original attempt1", state, want)
			}
			if cfg.kind == "tofu" {
				var run models.Run
				if err := f.db.First(&run, "id = ?", id).Error; err != nil {
					t.Fatal(err)
				}
				if run.ClaimedPhase != cfg.phase || run.ClaimedRunType != cfg.runType || run.DispatchedAt != nil {
					t.Error("completion changed the original executable identity or retained its consumed dispatch")
				}
			}
		})
	}
}

// The gateway discards an already committed response before any headers reach the normal
// client. Its retry goes through stored bearer authentication and observes the revoked token.
func TestRunnerCompletion_NormalClientRetiresAfterLostCommittedResponse(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table, token := f.startCompletion(t, cfg)
			committed := make(chan int, 1)
			resume := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(resume) }) }
			defer release()
			var attempts atomic.Int64
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if attempts.Add(1) == 1 {
					rec := httptest.NewRecorder()
					f.router.ServeHTTP(rec, r)
					committed <- rec.Code
					<-resume
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = connection.Close()
					return
				}
				f.router.ServeHTTP(w, r)
			}))
			defer func() {
				release()
				gateway.Close()
			}()
			client := executor.NewClient(gateway.URL, token.Token, f.runnerA1.ID.String())
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			completed := make(chan error, 1)
			go func() {
				completed <- client.Complete(ctx, id, runnercontract.JobCompleteRequest{
					Status: "failed", ErrorMessage: "first committed outcome", Attempt: 1, Phase: cfg.phase,
				})
			}()
			select {
			case code := <-committed:
				if code != http.StatusOK {
					t.Errorf("committed handler response = %d, want 200", code)
				}
			case <-ctx.Done():
				t.Fatal("completion did not reach the real handler")
			}
			before := f.completionSnapshot(t, table, id)
			release()
			err := <-completed
			var status *executor.StatusError
			if !errors.As(err, &status) || status.Code != http.StatusForbidden || status.ErrorCode != runnercontract.ErrorCodeJobTokenRevoked {
				t.Fatalf("lost-response retry = %v, want authenticated revoked-token refusal", err)
			}
			if client.ExitCode("failed") != executor.ExitStopped || attempts.Load() != 2 {
				t.Errorf("exit %d after %d attempts, want stopped after the retry", client.ExitCode("failed"), attempts.Load())
			}
			if after := f.completionSnapshot(t, table, id); before != after {
				t.Error("retry changed the first committed outcome or cleanup graph")
			}
		})
	}
}

func TestRunnerCompletion_NormalClientRetiresWhenRevokedBeforeDelivery(t *testing.T) {
	for _, cfg := range startRouteCases {
		t.Run(cfg.name, func(t *testing.T) {
			f := setupClaimRouteFixture(t)
			id, table, token := f.startCompletion(t, cfg)
			kind := models.JobTypeTofuRun
			if cfg.kind == "ansible" {
				kind = models.JobTypeAnsibleJob
			}
			if cfg.kind == "work_item" {
				kind = models.JobTypeWorkItem
			}
			if err := f.keys.RevokeJobTokens(kind, id); err != nil {
				t.Fatal(err)
			}
			before := f.completionSnapshot(t, table, id)
			server := httptest.NewServer(f.router)
			defer server.Close()
			client := executor.NewClient(server.URL, token.Token, f.runnerA1.ID.String())
			err := client.Complete(t.Context(), id, runnercontract.JobCompleteRequest{Status: "failed", Attempt: 1, Phase: cfg.phase})
			var status *executor.StatusError
			if !errors.As(err, &status) || status.ErrorCode != runnercontract.ErrorCodeJobTokenRevoked || client.ExitCode("failed") != executor.ExitStopped {
				t.Fatalf("revoked-before-delivery error %v, exit %d, want revoked stop", err, client.ExitCode("failed"))
			}
			if after := f.completionSnapshot(t, table, id); before != after {
				t.Error("revocation before delivery fabricated a stored outcome")
			}
		})
	}
}
