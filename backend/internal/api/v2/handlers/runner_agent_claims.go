// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/settings"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	errInvalidRunnerJobID     = errors.New("invalid runner job ID")
	errUpgradeAdmissionPaused = errors.New("launcher admission paused for upgrade")
)

func (h *RunnerAgentHandler) activeClaims(ctx context.Context, runnerID uuid.UUID) []runnercontract.ActiveClaim {
	if h.db == nil {
		return nil
	}
	claims, err := repository.NewRunnerRepository(h.db).ActiveClaims(ctx, runnerID, settings.DeploymentRunTimeout(os.Getenv), settings.SyncTimeout(os.Getenv))
	if err != nil {
		logger.Warnf("listing active claims for launcher %s failed (%v)", runnerID, err)
		return nil
	}
	return claims
}

// startExpectedClaim commits the claim and its SQL effects before acknowledging startup.
func (h *RunnerAgentHandler) startExpectedClaim(ctx context.Context, id string, runnerID uuid.UUID, req runnercontract.JobStartRequest) (runnercontract.JobStartResponse, error) {
	kind := models.JobTypeAnsibleJob
	var jobID uuid.UUID
	switch {
	case isWorkItem(id):
		kind = models.JobTypeWorkItem
	case strings.HasPrefix(id, "run-"):
		kind = models.JobTypeTofuRun
	default:
		var err error
		jobID, err = uuid.Parse(id)
		if err != nil {
			return runnercontract.JobStartResponse{}, errInvalidRunnerJobID
		}
	}
	if h.db == nil {
		return runnercontract.JobStartResponse{}, errors.New("runner claim storage unavailable")
	}
	if kind == models.JobTypeAnsibleJob && h.ansibleJobRepo == nil {
		return runnercontract.JobStartResponse{}, errors.New("ansible job service unavailable")
	}
	result := runnercontract.JobStartResponse{Status: "started"}
	err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var target any
		var placement models.JobPlacement
		scoped := *h
		scoped.db = tx
		scoped.jobExecRepo = repository.NewRunnerJobExecutionRepository(tx)
		switch kind {
		case models.JobTypeAnsibleJob:
			job, created, err := repository.NewAnsibleJobRepository(tx).ClaimAttempt(ctx, jobID, runnerID, req)
			if err != nil {
				return err
			}
			result.Attempt = job.Attempt
			if !created {
				return nil
			}
			if h.pauseRegistration {
				return errUpgradeAdmissionPaused
			}
			if err := scoped.upsertJobExecution(job, runnerID); err != nil {
				return err
			}
			target, placement = job, job.Placement
		case models.JobTypeWorkItem:
			item, created, err := repository.NewWorkItemRepository(tx).ClaimAttempt(ctx, id, runnerID, req)
			if err != nil {
				return err
			}
			result.Attempt = item.Attempt
			if !created {
				return nil
			}
			if h.pauseRegistration {
				return errUpgradeAdmissionPaused
			}
			if err := ansible.NewWorkItemRuntime(tx, nil, nil).Started(item); err != nil {
				return err
			}
			target, placement = item, item.Placement
		case models.JobTypeTofuRun:
			run, created, err := repository.NewRunRepository(tx).ClaimAttempt(ctx, id, runnerID, req)
			if err != nil {
				return err
			}
			result.Attempt, result.Phase, result.RunType = run.Attempt, run.ClaimedPhase, run.ClaimedRunType
			if !created {
				return nil
			}
			if h.pauseRegistration {
				return errUpgradeAdmissionPaused
			}
			locked, err := scoped.lockWorkspaceForRun(run)
			if err != nil {
				return err
			}
			if !locked {
				return repository.ErrClaimConflict
			}
			target, placement = run, run.Placement
		default:
			return repository.ErrInvalidClaim
		}
		keys := apikey.NewService(repository.NewAPIKeyRepository(tx), nil, nil, nil)
		if err := keys.RevokeJobTokens(kind, id); err != nil {
			return err
		}
		return persistClaimPlacement(tx, target, placement, req.Placement)
	})
	if err != nil {
		return runnercontract.JobStartResponse{}, err
	}
	return result, nil
}

func persistClaimPlacement(tx *gorm.DB, target any, current models.JobPlacement, report *runnercontract.Placement) error {
	if report == nil {
		return nil
	}
	return tx.Model(target).Omit(clause.Associations).Updates(placementColumns(current, report)).Error
}

func placementColumns(current models.JobPlacement, report *runnercontract.Placement) map[string]any {
	current.Merge(report.ToModel())
	return map[string]any{
		"placement_driver": current.Driver, "placement_placement_id": current.PlacementID,
		"placement_image": current.Image, "placement_image_digest": current.ImageDigest,
		"placement_image_level": current.ImageLevel, "placement_node": current.Node,
	}
}

func writeRunnerClaimError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errUpgradeAdmissionPaused):
		jsonapi.WriteCodedError(c, http.StatusServiceUnavailable, "runner-upgrade-admission-paused",
			"Service Unavailable", "New launcher work is paused during this upgrade. Retry after cutover.")
	case errors.Is(err, errInvalidRunnerJobID):
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid job ID")
	case errors.Is(err, repository.ErrInvalidClaim):
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "a complete valid expected claim identity is required")
	case errors.Is(err, repository.ErrClaimForbidden):
		writeRunnerForbidden(c, "this launcher cannot claim the selected job")
	case errors.Is(err, repository.ErrClaimConflict):
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", "the expected claim is no longer eligible")
	default:
		writeRunnerJobReadError(c, err)
	}
}
