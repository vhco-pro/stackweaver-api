// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package runner

import (
	"context"
	"time"

	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
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

// NewMonitorService creates a new runner monitor service
func NewMonitorService(runnerRepo *repository.RunnerRepository) *MonitorService {
	return &MonitorService{
		runnerRepo: runnerRepo,
		interval:   30 * time.Second, // Check every 30 seconds
		threshold:  OfflineAfter,
		stopCh:     make(chan struct{}),
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
			s.markStaleRunners()
		}
	}
}

// Stop stops the monitoring loop
func (s *MonitorService) Stop() {
	close(s.stopCh)
}

// markStaleRunners marks runners as offline if they haven't sent a heartbeat
func (s *MonitorService) markStaleRunners() {
	count, err := s.runnerRepo.MarkOfflineIfStale(s.threshold)
	if err != nil {
		logger.Warnf("Failed to mark stale runners: %v", err)
		return
	}
	if count > 0 {
		logger.Infof("Marked %d runner(s) as offline (no heartbeat for %v)", count, s.threshold)
	}
	// Free any ansible jobs reserved by runners that just went offline so they
	// can be picked up elsewhere rather than stranded.
	if released, err := s.runnerRepo.ReleaseStaleAnsibleReservations(); err != nil {
		logger.Warnf("Failed to release stale ansible reservations: %v", err)
	} else if released > 0 {
		logger.Infof("Released %d stranded ansible job reservation(s)", released)
	}
	if released, err := s.runnerRepo.ReleaseStaleRunReservations(); err != nil {
		logger.Warnf("Failed to release stale run reservations: %v", err)
	} else if released > 0 {
		logger.Infof("Released %d stranded run reservation(s)", released)
	}
	if released, err := s.runnerRepo.ReleaseStaleWorkItemReservations(); err != nil {
		logger.Warnf("Failed to release stale work item reservations: %v", err)
	} else if released > 0 {
		logger.Infof("Released %d stranded work item reservation(s)", released)
	}
	s.settleLostWork()
}

// settleLostWork applies the lost-launcher outcome to started work (#933, decision 16, AC9): a
// plan re-dispatches as a new attempt, an apply and an Ansible job end with "runner lost", and the
// state lock and the job tokens of each are released, so an orphan that outlives its launcher can
// neither complete nor upload state for work now settled or running elsewhere.
func (s *MonitorService) settleLostWork() {
	if s.runRepo == nil || s.revoker == nil {
		return
	}
	out, err := s.runnerRepo.ApplyLostLauncherOutcome()
	if err != nil {
		logger.Warnf("Failed to settle the work of lost launchers: %v", err)
		return
	}
	for _, runs := range [][]repository.LostRun{out.RedispatchedRuns, out.FailedRuns} {
		for _, r := range runs {
			if err := s.runRepo.ReleaseStateLock(r.WorkspaceID, r.ID); err != nil {
				logger.Warnf("Releasing the state lock of lost run %s: %v", r.ID, err)
			}
			if err := s.revoker.RevokeJobTokens(models.JobTypeTofuRun, r.ID); err != nil {
				logger.Warnf("Revoking the job tokens of lost run %s: %v", r.ID, err)
			}
		}
	}
	for _, id := range out.FailedJobs {
		if err := s.revoker.RevokeJobTokens(models.JobTypeAnsibleJob, id.String()); err != nil {
			logger.Warnf("Revoking the job tokens of lost job %s: %v", id, err)
		}
	}
	for _, id := range out.RedispatchedWorkItems {
		if err := s.revoker.RevokeJobTokens(models.JobTypeWorkItem, id); err != nil {
			logger.Warnf("Revoking the job tokens of lost work item %s: %v", id, err)
		}
	}
	if n := len(out.RedispatchedRuns) + len(out.FailedRuns) + len(out.FailedJobs) + len(out.RedispatchedWorkItems); n > 0 {
		logger.Infof("Lost launchers: %d plan(s) and %d sync(s) re-dispatched, %d apply(s) and %d job(s) ended",
			len(out.RedispatchedRuns), len(out.RedispatchedWorkItems), len(out.FailedRuns), len(out.FailedJobs))
	}
}
