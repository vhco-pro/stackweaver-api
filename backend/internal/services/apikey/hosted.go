// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package apikey

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// ScopeHostedRegister is the one scope of the deployment's hosted registration secret: it lets a
// hosted launcher register, and nothing else (#933, D9).
const ScopeHostedRegister = "hosted:register"

// HostedSecretName names the hosted registration secret's key row.
const HostedSecretName = "hosted-registration" //nolint:gosec // G101: the key row's name, not a credential

// minHostedSecretLength refuses a guessable secret.
const minHostedSecretLength = 36

// UpsertHostedSecret makes secret the deployment's hosted registration secret under name, at API
// start (#933, D9, AC69): one ownerless, organization-less key of kind hosted holding only the
// secret's hash, listed nowhere. A changed secret replaces the old row, so the old value is
// refused from that start on. The secret must look like an API token (tfe-, at least 36
// characters), which is what the deployment's generators write.
func (s *Service) UpsertHostedSecret(name, secret string) (*models.APIKey, error) {
	secret = strings.TrimSpace(secret)
	if !strings.HasPrefix(secret, "tfe-") || len(secret) < minHostedSecretLength {
		return nil, errors.New("the hosted registration secret must be a tfe- token of at least 36 characters")
	}
	existing, err := s.apiKeyRepo.GetByKindAndName(models.APIKeyKindHosted, name)
	if err != nil {
		return nil, fmt.Errorf("reading the hosted registration secret: %w", err)
	}
	for _, k := range existing {
		if VerifyKey(secret, k.KeyHash) && len(existing) == 1 {
			return k, nil
		}
	}
	for _, k := range existing {
		if err := s.apiKeyRepo.Delete(k.ID); err != nil {
			return nil, fmt.Errorf("revoking the previous hosted registration secret: %w", err)
		}
	}
	hash, err := HashKey(secret)
	if err != nil {
		return nil, err
	}
	key := &models.APIKey{
		Name: name, Kind: models.APIKeyKindHosted, KeyHash: hash, KeyPrefix: GetKeyPrefix(secret),
		Scopes: models.StringArray{ScopeHostedRegister},
	}
	if err := s.apiKeyRepo.Create(key); err != nil {
		return nil, fmt.Errorf("storing the hosted registration secret: %w", err)
	}
	return key, nil
}

// IsHostedRegistrationKey reports whether key is a hosted registration secret.
func IsHostedRegistrationKey(key *models.APIKey) bool {
	return key != nil && key.Kind == models.APIKeyKindHosted && key.OrganizationID == nil &&
		len(key.Scopes) == 1 && key.Scopes[0] == ScopeHostedRegister
}

// CreateHostedRunnerToken mints the runner token of a hosted runner: kind hosted, ownerless and
// organization-less like the runner itself, scoped to the runner (D9).
func (s *Service) CreateHostedRunnerToken(runnerID uuid.UUID, name string) (*models.APIKey, string, error) {
	key, err := GenerateAPIKey()
	if err != nil {
		return nil, "", fmt.Errorf("generating the hosted launcher token: %w", err)
	}
	hash, err := HashKey(key)
	if err != nil {
		return nil, "", err
	}
	expiresAt := time.Now().Add(RunnerTokenTTL)
	apiKey := &models.APIKey{
		Name: name, Kind: models.APIKeyKindHosted, KeyHash: hash, KeyPrefix: GetKeyPrefix(key),
		Scopes:    models.StringArray{"runner:" + runnerID.String() + ":heartbeat", "runner:" + runnerID.String() + ":jobs"},
		ExpiresAt: &expiresAt,
	}
	if err := s.apiKeyRepo.Create(apiKey); err != nil {
		return nil, "", fmt.Errorf("storing the hosted launcher token: %w", err)
	}
	return apiKey, key, nil
}
