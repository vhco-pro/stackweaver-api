// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package runner

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/dbtest/testschema"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// A monitor that just started cannot treat the platform outage as launcher silence.
func TestMonitorRecovery_StartupGracePreservesAnExistingLauncher(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dsn, &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := testschema.Ensure(db); err != nil {
		t.Fatal(err)
	}
	sfx := uuid.NewString()[:8]
	runner := func(name string, silentFor time.Duration) *models.Runner {
		beat := time.Now().Add(-silentFor)
		r := &models.Runner{ID: uuid.New(), Name: name + "-" + sfx, Kind: models.RunnerKindHosted, HostedGroup: "monitor-" + sfx, Status: models.RunnerStatusBusy, LastHeartbeatAt: &beat}
		if err := db.Create(r).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Delete(&models.Runner{}, "id = ?", r.ID) })
		return r
	}
	// Held for the full wait, then a few seconds of claims on a loaded host.
	claiming := runner("claiming", OfflineAfter/2+15*time.Second)
	gone := runner("gone", OfflineAfter+30*time.Second)

	NewMonitorService(repository.NewRunnerRepository(db)).markStaleRunners(t.Context())

	var c, g models.Runner
	db.First(&c, "id = ?", claiming.ID)
	db.First(&g, "id = ?", gone.ID)
	if c.Status == models.RunnerStatusOffline {
		t.Errorf("a launcher silent for %s, inside its heartbeat gap, was marked offline", OfflineAfter/2+15*time.Second)
	}
	if g.Status != models.RunnerStatusBusy {
		t.Errorf("fresh monitor settled an existing launcher before recovery grace: %s", g.Status)
	}
}

type monitorRecoveryFixture struct {
	db      *gorm.DB
	runner  *models.Runner
	monitor *MonitorService
	now     time.Time
}

func newMonitorRecoveryFixture(t *testing.T) *monitorRecoveryFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dsn, &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := testschema.Ensure(db); err != nil {
		t.Fatal(err)
	}
	f := &monitorRecoveryFixture{db: db, now: time.Now()}
	stale := f.now.Add(-10 * time.Minute)
	f.runner = &models.Runner{ID: uuid.New(), Name: "monitor-recovery-" + uuid.NewString(), Kind: models.RunnerKindHosted, HostedGroup: "monitor-recovery-" + uuid.NewString(), Status: models.RunnerStatusBusy, LastHeartbeatAt: &stale}
	if err := db.Create(f.runner).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&models.Runner{}, "id = ?", f.runner.ID).Error; err != nil {
			t.Error(err)
		}
	})
	f.monitor = NewMonitorService(repository.NewRunnerRepository(db))
	f.monitor.now = func() time.Time { return f.now }
	f.monitor.healthySince, f.monitor.lastHealthy = f.now, f.now
	return f
}

func (f *monitorRecoveryFixture) tick(t *testing.T, elapsed time.Duration) {
	t.Helper()
	f.now = f.now.Add(elapsed)
	f.monitor.markStaleRunners(t.Context())
}

func (f *monitorRecoveryFixture) assertStatus(t *testing.T, want models.RunnerStatus) {
	t.Helper()
	var runner models.Runner
	if err := f.db.First(&runner, "id = ?", f.runner.ID).Error; err != nil {
		t.Fatal(err)
	}
	if runner.Status != want {
		t.Fatalf("runner status = %s, want %s", runner.Status, want)
	}
}

func (f *monitorRecoveryFixture) finishRecovery(t *testing.T) {
	t.Helper()
	// A healthy observation starts grace, and observations continue while it elapses.
	recovered := f.monitor.healthySince
	if f.monitor.uncertain {
		recovered = f.now.Add(30 * time.Second)
	}
	f.tick(t, 30*time.Second)
	if !f.monitor.healthySince.Equal(recovered) {
		t.Fatalf("recovery grace started at %s, want %s", f.monitor.healthySince, recovered)
	}
	for f.now.Before(recovered.Add(RecoveryGrace)) {
		f.assertStatus(t, models.RunnerStatusBusy)
		f.tick(t, 30*time.Second)
	}
	f.assertStatus(t, models.RunnerStatusOffline)
}

func TestMonitorRecovery_HealthyTicksEventuallySettleASilentLauncher(t *testing.T) {
	f := newMonitorRecoveryFixture(t)
	for range 4 {
		f.tick(t, 30*time.Second)
		f.assertStatus(t, models.RunnerStatusBusy)
	}
	f.tick(t, 30*time.Second)
	f.assertStatus(t, models.RunnerStatusOffline)
}

func TestMonitorRecovery_UncertainObservationsRestartGrace(t *testing.T) {
	for _, scenario := range []string{"database error", "successful late observation", "missed interval", "canceled observation", "successful late mutation"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMonitorRecoveryFixture(t)
			f.monitor.healthySince = f.now.Add(-RecoveryGrace)
			fault := true
			if err := f.db.Callback().Raw().Before("gorm:raw").Register("monitor:health_fault", func(tx *gorm.DB) {
				if !fault || strings.TrimSpace(tx.Statement.SQL.String()) != "SELECT 1" {
					return
				}
				deadline, bounded := tx.Statement.Context.Deadline()
				if !bounded || time.Until(deadline) > monitorBudget {
					t.Error("database observation has no five-second context bound")
				}
				switch scenario {
				case "database error":
					_ = tx.AddError(errors.New("database unavailable"))
				case "successful late observation":
					f.now = f.now.Add(monitorBudget + time.Second)
				}
			}); err != nil {
				t.Fatal(err)
			}
			if err := f.db.Callback().Update().Before("gorm:update").Register("monitor:mutation_fault", func(tx *gorm.DB) {
				if !fault || scenario != "successful late mutation" || tx.Statement.Table != "runners" {
					return
				}
				deadline, bounded := tx.Statement.Context.Deadline()
				if !bounded || time.Until(deadline) > monitorBudget {
					t.Error("database mutation has no five-second context bound")
				}
				var timeout string
				if err := tx.Session(&gorm.Session{NewDB: true}).Raw("SELECT current_setting('statement_timeout')").Scan(&timeout).Error; err != nil {
					t.Error(err)
				}
				if timeout != "5s" {
					t.Errorf("mutation statement timeout = %q, want 5s", timeout)
				}
				f.now = f.now.Add(monitorBudget + time.Second)
			}); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missed interval":
				f.tick(t, f.monitor.interval+monitorBudget+time.Second)
			case "canceled observation":
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				f.monitor.markStaleRunners(ctx)
			default:
				f.tick(t, 30*time.Second)
			}
			f.assertStatus(t, models.RunnerStatusBusy)
			fault = false
			f.finishRecovery(t)
		})
	}
}

func TestMonitorRecovery_RepeatedOutagesRestartTheFullGrace(t *testing.T) {
	f := newMonitorRecoveryFixture(t)
	f.monitor.healthySince = f.now.Add(-RecoveryGrace)
	unavailable := true
	if err := f.db.Callback().Raw().Before("gorm:raw").Register("monitor:repeated_outage", func(tx *gorm.DB) {
		if unavailable && strings.TrimSpace(tx.Statement.SQL.String()) == "SELECT 1" {
			_ = tx.AddError(errors.New("database unavailable"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	f.tick(t, 30*time.Second)
	unavailable = false
	for range 4 {
		f.tick(t, 30*time.Second)
		f.assertStatus(t, models.RunnerStatusBusy)
	}
	unavailable = true
	f.tick(t, 30*time.Second)
	unavailable = false
	f.finishRecovery(t)
}

func TestMonitorRecovery_ReplicaStartupKeepsItsOwnGrace(t *testing.T) {
	f := newMonitorRecoveryFixture(t)
	f.monitor.healthySince = f.now.Add(-RecoveryGrace)
	replica := NewMonitorService(repository.NewRunnerRepository(f.db))
	replica.now = func() time.Time { return f.now }
	replica.healthySince, replica.lastHealthy = f.now, f.now
	f.now = f.now.Add(30 * time.Second)
	replica.markStaleRunners(t.Context())
	f.assertStatus(t, models.RunnerStatusBusy)
	// A replica with a continuous healthy history still settles an actually silent launcher.
	f.monitor.markStaleRunners(t.Context())
	f.assertStatus(t, models.RunnerStatusOffline)
}

func TestMonitorRecovery_ReplicasRecoverAtTheirOwnFirstHealthyObservation(t *testing.T) {
	f := newMonitorRecoveryFixture(t)
	f.monitor.healthySince = f.now.Add(-RecoveryGrace)
	replica := NewMonitorService(repository.NewRunnerRepository(f.db))
	replica.now = func() time.Time { return f.now }
	replica.healthySince, replica.lastHealthy = f.monitor.healthySince, f.now
	unavailable := true
	if err := f.db.Callback().Raw().Before("gorm:raw").Register("monitor:replica_outage", func(tx *gorm.DB) {
		if unavailable && strings.TrimSpace(tx.Statement.SQL.String()) == "SELECT 1" {
			_ = tx.AddError(errors.New("database unavailable to both replicas"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	f.tick(t, 30*time.Second)
	replica.markStaleRunners(t.Context())
	f.assertStatus(t, models.RunnerStatusBusy)
	unavailable = false
	f.tick(t, 30*time.Second)
	firstRecovery := f.now
	// The second replica observes recovery one tick later.
	for range 4 {
		f.tick(t, 30*time.Second)
		replica.markStaleRunners(t.Context())
		f.assertStatus(t, models.RunnerStatusBusy)
	}
	if !f.monitor.healthySince.Equal(firstRecovery) || !replica.healthySince.Equal(firstRecovery.Add(30*time.Second)) {
		t.Fatal("replicas did not retain their independent recovery observations")
	}
	f.now = f.now.Add(30 * time.Second)
	replica.markStaleRunners(t.Context())
	f.assertStatus(t, models.RunnerStatusBusy)
	f.monitor.markStaleRunners(t.Context())
	f.assertStatus(t, models.RunnerStatusOffline)
}

func TestMonitorRecovery_OrdinaryTickJitterDoesNotRestartGrace(t *testing.T) {
	f := newMonitorRecoveryFixture(t)
	started := f.monitor.healthySince
	for range 4 {
		f.tick(t, 31*time.Second)
		f.assertStatus(t, models.RunnerStatusBusy)
	}
	f.tick(t, 31*time.Second)
	f.assertStatus(t, models.RunnerStatusOffline)
	if !f.monitor.healthySince.Equal(started) {
		t.Fatal("ordinary one-second tick jitter restarted recovery grace")
	}
}

func TestMonitorRecovery_BlockedHealthObservationIsBounded(t *testing.T) {
	f := newMonitorRecoveryFixture(t)
	f.monitor.healthySince = f.now.Add(-RecoveryGrace)
	pool, err := f.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(1)
	connection, err := pool.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	started := time.Now()
	f.monitor.markStaleRunners(t.Context())
	if elapsed := time.Since(started); elapsed < monitorBudget || elapsed > monitorBudget+2*time.Second {
		t.Errorf("blocked health observation elapsed %s, want five-second bound", elapsed)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	f.assertStatus(t, models.RunnerStatusBusy)
	f.finishRecovery(t)
}

func TestMonitorRecovery_BlockedMutationCannotResumeAfterRecovery(t *testing.T) {
	f := newMonitorRecoveryFixture(t)
	f.monitor.healthySince = f.now.Add(-RecoveryGrace)
	tx := f.db.WithContext(t.Context()).Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	defer func() { _ = tx.Rollback().Error }()
	if err := tx.Exec("SELECT id FROM runners WHERE id = ? FOR UPDATE", f.runner.ID).Error; err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	f.monitor.markStaleRunners(t.Context())
	if elapsed := time.Since(started); elapsed < monitorBudget-time.Second || elapsed > monitorBudget+2*time.Second {
		t.Errorf("blocked mutation elapsed %s, want five-second bound", elapsed)
	}
	if err := tx.Rollback().Error; err != nil {
		t.Fatal(err)
	}
	f.assertStatus(t, models.RunnerStatusBusy)
	f.finishRecovery(t)
}
