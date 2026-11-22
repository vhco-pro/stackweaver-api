// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// failStartedClaim runs only after the same transaction acquired the parent start lock.
func failStartedClaim(tx *gorm.DB, id string, req JobCompleteRequest) (models.JobType, error) {
	now := time.Now()
	switch {
	case isWorkItem(id):
		item, err := repository.NewWorkItemRepository(tx).GetByID(id)
		if err != nil {
			return models.JobTypeWorkItem, err
		}
		_, err = ansible.NewWorkItemRuntime(tx, nil, nil).FinishedContext(tx.Statement.Context, item, models.WorkItemStatusFailed, req.ErrorMessage, nil)
		return models.JobTypeWorkItem, err
	case strings.HasPrefix(id, "run-"):
		var run models.Run
		if err := tx.First(&run, "id = ?", id).Error; err != nil {
			return models.JobTypeTofuRun, err
		}
		if err := tx.Model(&run).Omit(clause.Associations).Updates(map[string]any{
			"status": models.RunStatusErrored, "error_message": req.ErrorMessage, "completed_at": now,
		}).Error; err != nil {
			return models.JobTypeTofuRun, err
		}
		return models.JobTypeTofuRun, repository.NewRunRepository(tx).ReleaseStateLock(run.WorkspaceID, run.ID)
	default:
		jobID, err := uuid.Parse(id)
		if err != nil {
			return models.JobTypeAnsibleJob, errInvalidRunnerJobID
		}
		executions := repository.NewRunnerJobExecutionRepository(tx)
		exec, err := executions.GetByJobID(jobID)
		if err != nil {
			return models.JobTypeAnsibleJob, err
		}
		if err := executions.UpdateStatus(exec.ID, models.JobExecutionStatusFailed, req.ErrorMessage); err != nil {
			return models.JobTypeAnsibleJob, err
		}
		err = tx.Model(&models.AnsibleJob{}).Where("id = ?", jobID).Updates(map[string]any{
			"status": models.AnsibleJobStatusFailed, "finished_at": now, "error_message": req.ErrorMessage,
			"hosts_failed": gorm.Expr("CASE WHEN hosts_failed = 0 AND hosts_unreachable = 0 THEN 1 ELSE hosts_failed END"),
		}).Error
		return models.JobTypeAnsibleJob, err
	}
}

// updateRunnerAfterClaim counts reservations as well as active work across all engines.
// The runner lock makes the subsequent count observe earlier committed outcomes.
// Its conditional update preserves an offline or errored launcher's state.
func updateRunnerAfterClaim(tx *gorm.DB, runnerID uuid.UUID) error {
	var runner models.Runner
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").First(&runner, "id = ?", runnerID).Error; err != nil {
		return err
	}
	var count int64
	if err := tx.Raw(`SELECT
		(SELECT count(*) FROM ansible_jobs WHERE runner_id = ? AND status IN (?, ?)) +
		(SELECT count(*) FROM runs WHERE runner_id = ? AND status IN (?, ?, ?, ?)) +
		(SELECT count(*) FROM work_items WHERE runner_id = ? AND status IN (?, ?))`,
		runnerID, models.AnsibleJobStatusPending, models.AnsibleJobStatusRunning,
		runnerID, models.RunStatusPending, models.RunStatusPrePlanCompleted, models.RunStatusPlanning, models.RunStatusApplying,
		runnerID, models.WorkItemStatusPending, models.WorkItemStatusRunning).Scan(&count).Error; err != nil {
		return err
	}
	status := models.RunnerStatusBusy
	if count == 0 {
		status = models.RunnerStatusOnline
	}
	return tx.Model(&models.Runner{}).Where("id = ? AND status IN ?", runnerID, []models.RunnerStatus{models.RunnerStatusBusy, models.RunnerStatusOnline}).
		Update("status", status).Error
}
