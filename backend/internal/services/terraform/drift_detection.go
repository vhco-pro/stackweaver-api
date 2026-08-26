// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/robfig/cron/v3"
)

// DriftDetectionService handles scheduled drift detection runs
type DriftDetectionService struct {
	workspaceRepo     *repository.WorkspaceRepository
	runRepo           *repository.RunRepository
	configVersionRepo *repository.ConfigurationVersionRepository

	cronParser    cron.Parser
	mu            sync.RWMutex
	running       bool
	stopCh        chan struct{}
	ticker        *time.Ticker
	checkInterval time.Duration
}

// NewDriftDetectionService creates a new drift detection service
func NewDriftDetectionService(
	workspaceRepo *repository.WorkspaceRepository,
	runRepo *repository.RunRepository,
	configVersionRepo *repository.ConfigurationVersionRepository,
) *DriftDetectionService {
	return &DriftDetectionService{
		workspaceRepo:     workspaceRepo,
		runRepo:           runRepo,
		configVersionRepo: configVersionRepo,
		cronParser:        cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow),
		checkInterval:     1 * time.Minute, // Check every minute
	}
}

// Start starts the drift detection background worker
func (s *DriftDetectionService) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return
	}

	s.running = true
	s.stopCh = make(chan struct{})
	s.ticker = time.NewTicker(s.checkInterval)

	go s.run()
	logger.Info("Drift detection service started")
}

// Stop stops the drift detection background worker
func (s *DriftDetectionService) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopCh)
	s.ticker.Stop()
	s.running = false
	logger.Info("Drift detection service stopped")
}

// run is the main scheduler loop
func (s *DriftDetectionService) run() {
	// Process any due drift checks on startup
	s.processDueDriftChecks()

	for {
		select {
		case <-s.stopCh:
			return
		case <-s.ticker.C:
			s.processDueDriftChecks()
		}
	}
}

// defaultAssessmentSchedule paces workspaces that were pulled into drift detection through the
// assessments flags (workspace assessments_enabled / org assessments_enforced) without a drift
// schedule of their own. Daily, matching TFE's roughly-every-24h assessment cadence. Never
// persisted onto the workspace row - it only feeds the in-loop due calculation.
const defaultAssessmentSchedule = "0 3 * * *"

// processDueDriftChecks finds and executes all due drift detection checks
func (s *DriftDetectionService) processDueDriftChecks() {
	ctx := context.Background()

	// Get all workspaces with drift detection enabled
	workspaces, err := s.workspaceRepo.ListWithDriftDetectionEnabled()
	if err != nil {
		logger.Infof("Error listing workspaces with drift detection: %v", err)
		return
	}

	// tfe_organization assessments_enforced + workspace assessments_enabled: assessments ARE
	// drift detection - fold the assessment set into the same loop, with a default daily
	// schedule when a workspace carries none of its own.
	assessed := map[string]bool{}
	if assessedWorkspaces, err := s.workspaceRepo.ListAssessmentWorkspaces(); err != nil {
		logger.Infof("Error listing assessment workspaces: %v", err)
	} else {
		seen := make(map[string]bool, len(workspaces))
		for i := range workspaces {
			seen[workspaces[i].ID] = true
		}
		for i := range assessedWorkspaces {
			assessed[assessedWorkspaces[i].ID] = true
			if !seen[assessedWorkspaces[i].ID] {
				workspaces = append(workspaces, assessedWorkspaces[i])
			}
		}
	}

	now := time.Now()

	for _, workspace := range workspaces {
		schedule := workspace.DriftDetectionSchedule
		if schedule == "" {
			// Skip if no schedule configured - unless the workspace is assessment-driven, which
			// falls back to the default daily cadence.
			if !assessed[workspace.ID] {
				continue
			}
			schedule = defaultAssessmentSchedule
		}

		// Calculate next run time if not set
		if workspace.NextDriftCheckAt == nil {
			nextRun, err := s.calculateNextRun(schedule, workspace.DriftDetectionTimezone, now)
			if err != nil {
				logger.Infof("Error calculating next run for workspace %s: %v", workspace.ID, err)
				continue
			}
			workspace.NextDriftCheckAt = &nextRun
			if err := s.workspaceRepo.Update(&workspace); err != nil {
				logger.Infof("Error updating next drift check for workspace %s: %v", workspace.ID, err)
			}
			continue
		}

		// Check if drift check is due
		if workspace.NextDriftCheckAt.After(now) {
			continue
		}

		// Execute the drift check
		if err := s.executeDriftCheck(ctx, &workspace); err != nil {
			logger.Infof("Error executing drift check for workspace %s: %v", workspace.ID, err)
		}

		// Calculate and update next run time
		nextRun, err := s.calculateNextRun(schedule, workspace.DriftDetectionTimezone, now)
		if err != nil {
			logger.Infof("Error calculating next run for workspace %s: %v", workspace.ID, err)
			continue
		}
		workspace.NextDriftCheckAt = &nextRun
		workspace.LastDriftCheckAt = &now
		if err := s.workspaceRepo.Update(&workspace); err != nil {
			logger.Infof("Error updating drift check times for workspace %s: %v", workspace.ID, err)
		}
	}
}

// executeDriftCheck creates a plan-only run to detect drift
func (s *DriftDetectionService) executeDriftCheck(ctx context.Context, workspace *models.Workspace) error {
	logger.Infof("Executing drift check for workspace: %s (%s)", workspace.Name, workspace.ID)

	// Check if workspace is locked (has an active run)
	if workspace.Locked {
		logger.Infof("Workspace %s is locked, skipping drift check", workspace.ID)
		return nil
	}

	// Check if there's already a pending or running plan run
	recentRuns, _, err := s.runRepo.ListByWorkspace(workspace.ID, 5, 0)
	if err == nil {
		for _, run := range recentRuns {
			if (run.Status == models.RunStatusPending ||
				run.Status == models.RunStatusPlanning ||
				run.Status == models.RunStatusRunning) &&
				(run.Operation == models.RunOperationPlanOnly || run.Operation == models.RunOperationPlanAndApply) {
				logger.Infof("Workspace %s already has an active plan run, skipping drift check", workspace.ID)
				return nil
			}
		}
	}

	// Create a plan-only run for drift detection
	// Note: We don't create a configuration version - drift detection runs use the current state
	run := &models.Run{
		WorkspaceID:            workspace.ID,
		ConfigurationVersionID: nil, // Drift detection doesn't use config version
		CreatedBy:              nil, // System-triggered
		Status:                 models.RunStatusPending,
		Operation:              models.RunOperationPlanOnly, // Plan-only run for drift detection
	}

	if err := s.runRepo.Create(run); err != nil {
		return fmt.Errorf("failed to create drift detection run: %w", err)
	}

	logger.Infof("Created drift detection run %s for workspace %s", run.ID, workspace.ID)
	return nil
}

// calculateNextRun calculates the next run time based on cron expression
func (s *DriftDetectionService) calculateNextRun(cronExpr, timezone string, from time.Time) (time.Time, error) {
	// Parse cron expression
	schedule, err := s.cronParser.Parse(cronExpr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid cron expression: %w", err)
	}

	// Load timezone
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}

	// Convert from time to the schedule's timezone
	fromInTz := from.In(loc)

	// Get next run time
	next := schedule.Next(fromInTz)

	// Convert back to UTC for storage
	return next.UTC(), nil
}

// ValidateCronExpression validates a cron expression
func (s *DriftDetectionService) ValidateCronExpression(cronExpression string) error {
	_, err := s.cronParser.Parse(cronExpression)
	return err
}
