// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package runner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// MonitorService handles background tasks for runner management
type MonitorService struct {
	runnerRepo *repository.RunnerRepository
	// runRepo releases the state locks and revokes the job tokens of a lost launcher's work
	// (SetLostLauncherHandling); without them that work is only released, not settled.
	runRepo   *repository.RunRepository
	revoker   JobTokenRevoker
	interval  time.Duration
	threshold time.Duration
	stopCh    chan struct{}
	now       func() time.Time
	// Healthy observations continue during startup and recovery grace.
	healthySince time.Time
	lastHealthy  time.Time
	uncertain    bool
}

// JobTokenRevoker revokes every job token of a job (apikey.Service.RevokeJobTokens).
type JobTokenRevoker interface {
	RevokeJobTokens(kind models.JobType, jobID string) error
}

// SetLostLauncherHandling enables the lost-launcher outcome (#933, decision 16): the monitor then
// re-dispatches the plans and fails the applies and jobs of runners gone offline, releasing their
// state locks and revoking their job tokens.
func (s *MonitorService) SetLostLauncherHandling(runRepo *repository.RunRepository, revoker JobTokenRevoker) {
	s.runRepo, s.revoker = runRepo, revoker
}

// OfflineAfter is how long a runner may go without a heartbeat before it is marked offline, which
// settles its started work as lost (decision 16). It spans several heartbeats: the API holds one
// for up to handlers.DefaultLongPollMax (25 seconds), and after an answer with offers the launcher
// claims and places each before it polls again, so a live launcher's last heartbeat is routinely
// more than 25 seconds old. A threshold inside that gap marked live launchers lost under load,
// re-dispatching their plans as second attempts and failing their applies (#933, AC17).
const OfflineAfter = 90 * time.Second

// RecoveryGrace lets an existing launcher finish a stranded heartbeat and its longest retry.
const RecoveryGrace = OfflineAfter + time.Minute

const monitorBudget = 5 * time.Second

// NewMonitorService creates a new runner monitor service
func NewMonitorService(runnerRepo *repository.RunnerRepository) *MonitorService {
	now := time.Now()
	return &MonitorService{
		runnerRepo:   runnerRepo,
		interval:     30 * time.Second,
		threshold:    OfflineAfter,
		stopCh:       make(chan struct{}),
		now:          time.Now,
		healthySince: now,
		lastHealthy:  now,
	}
}

// Start begins the background monitoring loop
func (s *MonitorService) Start(ctx context.Context) {
	logger.Info("Starting runner monitor service")

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Runner monitor service stopped (context cancelled)")
			return
		case <-s.stopCh:
			logger.Info("Runner monitor service stopped")
			return
		case <-ticker.C:
			s.markStaleRunners(ctx)
		}
	}
}

// Stop stops the monitoring loop
func (s *MonitorService) Stop() {
	close(s.stopCh)
}

// markStaleRunners observes database health before one bounded, atomic mutation cycle.
func (s *MonitorService) markStaleRunners(ctx context.Context) {
	started := s.now()
	if started.Sub(s.lastHealthy) > s.interval+monitorBudget {
		s.uncertain = true
	}
	healthCtx, cancel := context.WithTimeout(ctx, monitorBudget)
	err := s.runnerRepo.DB().WithContext(healthCtx).Exec("SELECT 1").Error
	err = errors.Join(err, s.budgetError(healthCtx, started))
	cancel()
	if err != nil {
		s.uncertain = true
		logger.Warnf("Observing runner monitor database health: %v", err)
		return
	}
	observed := s.now()
	if s.uncertain {
		s.healthySince, s.uncertain = observed, false
	}
	s.lastHealthy = observed
	if observed.Before(s.healthySince.Add(RecoveryGrace)) {
		return
	}
	cycleCtx, cancel := context.WithTimeout(ctx, monitorBudget)
	defer cancel()
	var marked, ansibleReservations, runReservations, workReservations int64
	var lost repository.LostLauncherOutcome
	err = s.runnerRepo.DB().WithContext(cycleCtx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL statement_timeout = '5s'").Error; err != nil {
			return err
		}
		runners := repository.NewRunnerRepository(tx)
		var err error
		if marked, err = runners.MarkOfflineBefore(observed.Add(-s.threshold)); err != nil {
			return err
		}
		if err := s.budgetError(cycleCtx, observed); err != nil {
			return err
		}
		if ansibleReservations, err = runners.ReleaseStaleAnsibleReservations(); err != nil {
			return err
		}
		if err := s.budgetError(cycleCtx, observed); err != nil {
			return err
		}
		if runReservations, err = runners.ReleaseStaleRunReservations(); err != nil {
			return err
		}
		if err := s.budgetError(cycleCtx, observed); err != nil {
			return err
		}
		if workReservations, err = runners.ReleaseStaleWorkItemReservations(); err != nil {
			return err
		}
		if err := s.budgetError(cycleCtx, observed); err != nil {
			return err
		}
		lost, err = s.settleLostWork(cycleCtx, tx, observed)
		return errors.Join(err, s.budgetError(cycleCtx, observed))
	})
	if err != nil {
		s.uncertain = true
		logger.Warnf("Settling a runner monitor cycle: %v", err)
		return
	}
	if marked > 0 {
		logger.Infof("Marked %d runner(s) as offline (no heartbeat for %v)", marked, s.threshold)
	}
	if ansibleReservations+runReservations+workReservations > 0 {
		logger.Infof("Released stranded reservations: %d Ansible job(s), %d run(s), %d work item(s)", ansibleReservations, runReservations, workReservations)
	}
	if len(lost.RedispatchedRuns)+len(lost.FailedRuns)+len(lost.FailedJobs)+len(lost.RedispatchedWorkItems) > 0 {
		logger.Infof("Lost launchers: %d plan(s) and %d sync(s) re-dispatched, %d apply(s) and %d job(s) ended",
			len(lost.RedispatchedRuns), len(lost.RedispatchedWorkItems), len(lost.FailedRuns), len(lost.FailedJobs))
	}
}

func (s *MonitorService) budgetError(ctx context.Context, started time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.now().Sub(started) >= monitorBudget {
		return context.DeadlineExceeded
	}
	return nil
}

// settleLostWork applies the lost-launcher outcome to started work (#933, decision 16, AC9): a
// plan re-dispatches as a new attempt, an apply and an Ansible job end with "runner lost", and the
// state lock and the job tokens of each are released, so an orphan that outlives its launcher can
// neither complete nor upload state for work now settled or running elsewhere.
func (s *MonitorService) settleLostWork(ctx context.Context, tx *gorm.DB, started time.Time) (repository.LostLauncherOutcome, error) {
	if s.runRepo == nil || s.revoker == nil {
		return repository.LostLauncherOutcome{}, nil
	}
	out, err := repository.NewRunnerRepository(tx).ApplyLostLauncherOutcome()
	if err != nil {
		return out, err
	}
	if err := s.budgetError(ctx, started); err != nil {
		return out, err
	}
	revoke := s.revoker.RevokeJobTokens
	if transactional, ok := s.revoker.(interface {
		RevokeJobTokensInTransaction(*gorm.DB, models.JobType, string) error
	}); ok {
		revoke = func(kind models.JobType, jobID string) error {
			return transactional.RevokeJobTokensInTransaction(tx, kind, jobID)
		}
	}
	runRepo := repository.NewRunRepository(tx)
	for _, runs := range [][]repository.LostRun{out.RedispatchedRuns, out.FailedRuns} {
		for _, r := range runs {
			if err := runRepo.ReleaseStateLock(r.WorkspaceID, r.ID); err != nil {
				return out, fmt.Errorf("releasing the state lock of lost run %s: %w", r.ID, err)
			}
			if err := s.budgetError(ctx, started); err != nil {
				return out, err
			}
			if err := revoke(models.JobTypeTofuRun, r.ID); err != nil {
				return out, fmt.Errorf("revoking the job tokens of lost run %s: %w", r.ID, err)
			}
			if err := s.budgetError(ctx, started); err != nil {
				return out, err
			}
		}
	}
	for _, id := range out.FailedJobs {
		if err := revoke(models.JobTypeAnsibleJob, id.String()); err != nil {
			return out, fmt.Errorf("revoking the job tokens of lost job %s: %w", id, err)
		}
		if err := s.budgetError(ctx, started); err != nil {
			return out, err
		}
	}
	for _, id := range out.RedispatchedWorkItems {
		if err := revoke(models.JobTypeWorkItem, id); err != nil {
			return out, fmt.Errorf("revoking the job tokens of lost work item %s: %w", id, err)
		}
		if err := s.budgetError(ctx, started); err != nil {
			return out, err
		}
	}
	return out, nil
}
