// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package runner

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
)

type monitorCleanupRevoker struct {
	service *apikey.Service
	before  func()
}

func (r *monitorCleanupRevoker) RevokeJobTokens(kind models.JobType, jobID string) error {
	r.before()
	return r.service.RevokeJobTokens(kind, jobID)
}

func (r *monitorCleanupRevoker) RevokeJobTokensInTransaction(tx *gorm.DB, kind models.JobType, jobID string) error {
	r.before()
	return apikey.NewService(repository.NewAPIKeyRepository(tx), nil, nil, nil).RevokeJobTokens(kind, jobID)
}

type monitorCleanupFixture struct {
	db        *gorm.DB
	org       *models.Organization
	oldRunner *models.Runner
	newRunner *models.Runner
	run       *models.Run
	service   *apikey.Service
	monitor   *MonitorService
	now       time.Time
}

func newMonitorCleanupFixture(t *testing.T) *monitorCleanupFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dsn, &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	create := func(value any) {
		t.Helper()
		if err := db.Create(value).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := db.Delete(value).Error; err != nil {
				t.Error(err)
			}
		})
	}
	suffix := uuid.NewString()[:8]
	org := &models.Organization{ID: uuid.New(), Name: "monitor-cleanup-" + suffix}
	create(org)
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: org.ID, Name: "monitor-cleanup-" + suffix}
	create(pool)
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "monitor-cleanup-" + suffix}
	create(project)
	workspace := &models.Workspace{ProjectID: project.ID, Name: "monitor-cleanup-" + suffix, AgentPoolID: &pool.ID, ExecutionMode: "agent"}
	create(workspace)
	now := time.Now()
	stale := now.Add(-10 * time.Minute)
	oldRunner := &models.Runner{ID: uuid.New(), Name: "old-" + suffix, OrganizationID: &org.ID, AgentPoolID: &pool.ID, Status: models.RunnerStatusBusy, LastHeartbeatAt: &stale}
	create(oldRunner)
	newRunner := &models.Runner{ID: uuid.New(), Name: "new-" + suffix, OrganizationID: &org.ID, AgentPoolID: &pool.ID, Status: models.RunnerStatusOnline, LastHeartbeatAt: &now, Capabilities: models.RunnerLabels{runnercontract.CapabilityClaimRecovery}}
	create(newRunner)
	run := &models.Run{WorkspaceID: workspace.ID, AgentPoolID: &pool.ID, RunnerID: &oldRunner.ID, Status: models.RunStatusPlanning, Operation: models.RunOperationPlanAndApply, Attempt: 1, PhaseAttempt: 1, ClaimedPhase: "plan", ClaimedRunType: "plan", ClaimRecovery: true, StartedAt: &now, DispatchedAt: &now}
	create(run)

	service := apikey.NewService(repository.NewAPIKeyRepository(db), nil, nil, nil)
	monitor := NewMonitorService(repository.NewRunnerRepository(db))
	fixture := &monitorCleanupFixture{db: db, org: org, oldRunner: oldRunner, newRunner: newRunner, run: run, service: service, monitor: monitor, now: now}
	monitor.now = func() time.Time { return fixture.now }
	monitor.healthySince, monitor.lastHealthy = now.Add(-RecoveryGrace), now
	monitor.SetLostLauncherHandling(repository.NewRunRepository(db), service)
	return fixture
}

func TestMonitorRecovery_OldCleanupCannotRevokeANewClaim(t *testing.T) {
	f := newMonitorCleanupFixture(t)
	claim := func(ctx context.Context) (*models.Run, bool, error) {
		return repository.NewRunRepository(f.db).ClaimAttempt(ctx, f.run.ID, f.newRunner.ID, runnercontract.JobStartRequest{RunnerID: f.newRunner.ID.String(), Attempt: 2, Phase: "plan", RunType: "plan"})
	}
	mint := func() *models.APIKey {
		t.Helper()
		key, _, err := f.service.CreateJobToken(f.org.ID, f.run.AgentPoolID, apikey.JobPrincipal{Kind: models.JobTypeTofuRun, JobID: f.run.ID, RunnerID: f.newRunner.ID, Attempt: 2}, f.now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := f.db.Delete(&models.APIKey{}, "id = ?", key.ID).Error; err != nil {
				t.Error(err)
			}
		})
		return key
	}
	var nextKey *models.APIKey
	var earlyClaim bool
	revoker := &monitorCleanupRevoker{service: f.service, before: func() {
		ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
		defer cancel()
		_, created, err := claim(ctx)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return
		}
		if err != nil || !created {
			t.Fatalf("claim during old cleanup = created %v, error %v", created, err)
		}
		earlyClaim = true
		nextKey = mint()
	}}
	f.monitor.SetLostLauncherHandling(repository.NewRunRepository(f.db), revoker)
	f.monitor.markStaleRunners(t.Context())
	if earlyClaim {
		t.Error("a later claim committed before the old monitor's credential cleanup")
	}
	if nextKey == nil {
		if _, created, err := claim(t.Context()); err != nil || !created {
			t.Fatalf("claim after old cleanup = created %v, error %v", created, err)
		}
		nextKey = mint()
	}
	var stored models.APIKey
	if err := f.db.First(&stored, "id = ?", nextKey.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.ExpiresAt == nil || !stored.ExpiresAt.After(time.Now()) {
		t.Error("the old monitor revoked the later claim's token")
	}
}

func TestMonitorRecovery_SettlementFailureRollsBackAllSQL(t *testing.T) {
	for _, scenario := range []string{"revocation error", "successful late cleanup"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMonitorCleanupFixture(t)
			key, _, err := f.service.CreateJobToken(f.org.ID, f.run.AgentPoolID, apikey.JobPrincipal{Kind: models.JobTypeTofuRun, JobID: f.run.ID, RunnerID: f.oldRunner.ID, Attempt: 1}, f.now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := f.db.Delete(&models.APIKey{}, "id = ?", key.ID).Error; err != nil {
					t.Error(err)
				}
			})
			if _, err := f.service.CreateJobRegistryToken(f.org.ID, *f.run.AgentPoolID, models.JobTypeTofuRun, f.run.ID, f.now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			registryScope := "%job-registry:tofu_run:" + f.run.ID + "%"
			t.Cleanup(func() {
				if err := f.db.Where("organization_id = ? AND scopes::text LIKE ?", f.org.ID, registryScope).Delete(&models.APIKey{}).Error; err != nil {
					t.Error(err)
				}
			})
			lock := &models.StateLock{WorkspaceID: f.run.WorkspaceID, LockID: repository.RunStateLockID(f.run.ID), Operation: "plan", LockedBy: &f.run.ID, ExpiresAt: f.now.Add(time.Hour)}
			if err := f.db.Create(lock).Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := f.db.Delete(&models.StateLock{}, "id = ?", lock.ID).Error; err != nil {
					t.Error(err)
				}
			})
			injected := false
			if err := f.db.Callback().Update().After("gorm:update").Register("monitor:cleanup_fault", func(tx *gorm.DB) {
				if tx.Statement.Table != "api_keys" {
					return
				}
				injected = true
				if scenario == "revocation error" {
					_ = tx.AddError(errors.New("credential update unavailable"))
				} else {
					f.now = f.now.Add(monitorBudget + time.Second)
				}
			}); err != nil {
				t.Fatal(err)
			}
			f.monitor.markStaleRunners(t.Context())
			if !injected || !f.monitor.uncertain {
				t.Fatal("cleanup failure did not leave the monitor uncertain")
			}
			var run models.Run
			if err := f.db.First(&run, "id = ?", f.run.ID).Error; err != nil {
				t.Fatal(err)
			}
			if run.Status != models.RunStatusPlanning || run.RunnerID == nil || *run.RunnerID != f.oldRunner.ID || run.Attempt != 1 || run.DispatchedAt == nil {
				t.Error("interrupted cleanup committed its redispatch")
			}
			var runner models.Runner
			if err := f.db.First(&runner, "id = ?", f.oldRunner.ID).Error; err != nil {
				t.Fatal(err)
			}
			if runner.Status != models.RunnerStatusBusy {
				t.Error("interrupted cleanup committed its offline marker")
			}
			var locks, registryKeys int64
			if err := f.db.Model(&models.StateLock{}).Where("id = ?", lock.ID).Count(&locks).Error; err != nil {
				t.Fatal(err)
			}
			if err := f.db.Model(&models.APIKey{}).Where("organization_id = ? AND scopes::text LIKE ?", f.org.ID, registryScope).Count(&registryKeys).Error; err != nil {
				t.Fatal(err)
			}
			var stored models.APIKey
			if err := f.db.First(&stored, "id = ?", key.ID).Error; err != nil {
				t.Fatal(err)
			}
			if locks != 1 || registryKeys != 1 || stored.ExpiresAt == nil || !stored.ExpiresAt.After(time.Now()) {
				t.Error("interrupted cleanup released state or revoked credentials")
			}
		})
	}
}
