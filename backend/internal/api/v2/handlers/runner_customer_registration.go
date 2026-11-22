// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var errJITRegistrationConsumed = errors.New("one-time launcher registration token consumed or expired")

func (h *RunnerAgentHandler) registerCustomerRunner(ctx context.Context, req RegisterRequest, pool *models.AgentPool, registrationKey *models.APIKey, apiKeyUUID, userID uuid.UUID, clientIP string) (*models.Runner, string, bool, error) {
	if h.db == nil {
		return nil, "", false, errors.New("launcher registration storage is unavailable")
	}
	var runner models.Runner
	var raw string
	var created bool
	err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		keys := apikey.NewService(repository.NewAPIKeyRepository(tx), nil, nil, nil)
		if registrationKey != nil && registrationKey.IsJITToken {
			used, err := keys.UseJITToken(registrationKey.ID)
			if err != nil {
				return fmt.Errorf("consuming launcher registration token: %w", err)
			}
			if !used {
				return errJITRegistrationConsumed
			}
		}

		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&runner,
			"organization_id = ? AND name = ?", pool.OrganizationID, req.Name).Error
		created = errors.Is(err, gorm.ErrRecordNotFound)
		if err != nil && !created {
			return err
		}
		now := time.Now()
		poolID := pool.ID
		if created {
			runnerType := runnerTypeFor(req.Engines, req.TofuVersion, req.AnsibleVersion)
			maxJobs := max(req.MaxConcurrentJobs, 1)
			runner = models.Runner{
				OrganizationID:         &pool.OrganizationID,
				AgentPoolID:            &poolID,
				Name:                   req.Name,
				RunnerType:             runnerType,
				Status:                 models.RunnerStatusOnline,
				Hostname:               req.Hostname,
				IPAddress:              clientIP,
				OSType:                 req.OSType,
				OSVersion:              req.OSVersion,
				AgentVersion:           req.AgentVersion,
				TofuVersion:            req.TofuVersion,
				AnsibleVersion:         req.AnsibleVersion,
				AvailableCollections:   models.RunnerCollections(req.AvailableCollections),
				MaxConcurrentJobs:      maxJobs,
				Labels:                 models.RunnerLabels(req.Labels),
				Capabilities:           models.RunnerLabels(req.Capabilities),
				Driver:                 req.Driver,
				NetworkMode:            req.NetworkMode,
				LastHeartbeatAt:        &now,
				RegisteredAt:           now,
				RegisteredWithAPIKeyID: &apiKeyUUID,
			}
			applyLauncherSettings(&runner, req)
			if err := tx.Create(&runner).Error; err != nil {
				return err
			}
		} else {
			runner.Status = models.RunnerStatusOnline
			runner.AgentPoolID = &poolID
			runner.IPAddress = clientIP
			now := time.Now()
			runner.LastHeartbeatAt = &now
			if req.TofuVersion != "" {
				runner.TofuVersion = req.TofuVersion
			}
			if req.AnsibleVersion != "" {
				runner.AnsibleVersion = req.AnsibleVersion
			}
			// Refresh the engine routing from the new launcher's reported capabilities.
			runner.RunnerType = runnerTypeFor(req.Engines, req.TofuVersion, req.AnsibleVersion)
			// The capabilities are the binary's, so a re-registration replaces them.
			runner.Capabilities = models.RunnerLabels(req.Capabilities)
			runner.Driver, runner.NetworkMode = req.Driver, req.NetworkMode
			applyLauncherSettings(&runner, req)
			// A new launcher process under the name is not draining (D11).
			runner.DrainRequestedAt = nil
			runner.RegisteredWithAPIKeyID = &apiKeyUUID
			if err := repository.NewRunnerRepository(tx).Update(&runner); err != nil {
				return err
			}
		}

		if err := keys.DeleteAPIKeysForRunner(runner.ID); err != nil {
			return err
		}
		issuerKey, secret, err := keys.CreateRunnerToken(userID, runner.ID, pool.OrganizationID, pool.ID, "runner-"+runner.Name)
		if err != nil {
			return err
		}
		runner.RunnerAPIKeyID = &issuerKey.ID
		raw = secret
		return tx.Model(&runner).UpdateColumn("runner_api_key_id", issuerKey.ID).Error
	})
	if err != nil {
		return nil, "", false, err
	}
	return &runner, raw, created, nil
}
