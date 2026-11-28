// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package apikey

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// A job token (#933, D1) is valid for one job and one attempt. It is minted by the API after the
// runner's claim, carries no owner and the job's organization, and is the only credential the
// executor holds. Its scopes name the job, the runner that claimed it and the attempt:
//
//	job:<kind>:<job id>:*
//	job-runner:<runner id>
//	job-attempt:<n>
//
// They are not ScopeChecker scopes: a job token is recognised by its kind (models.APIKeyKindJob) and
// read with ParseJobPrincipal, never by the generic scope machinery.
const (
	jobScopePrefix        = "job:"
	jobRunnerScopePrefix  = "job-runner:"
	jobAttemptScopePrefix = "job-attempt:"
	// A job's registry token carries registry:read and names its job with this prefix.
	jobRegistryScopePrefix = "job-registry:"
	registryReadScope      = "registry:read"
)

// JobTokenGrace is how long a job token outlives the job's timeout, so an executor finishing at the
// deadline can still report its completion.
const JobTokenGrace = 15 * time.Minute

// JobPrincipal is the identity a job token carries.
type JobPrincipal struct {
	Kind     models.JobType
	JobID    string
	RunnerID uuid.UUID
	Attempt  int
}

// jobScopes returns the scopes of a job token for p.
func jobScopes(p JobPrincipal) models.StringArray {
	return models.StringArray{
		jobScopePrefix + string(p.Kind) + ":" + p.JobID + ":*",
		jobRunnerScopePrefix + p.RunnerID.String(),
		jobAttemptScopePrefix + strconv.Itoa(p.Attempt),
	}
}

// ParseJobPrincipal reads the principal of a job token from its scopes. ok is false unless every
// part is present and well formed, so a malformed token authorizes nothing.
func ParseJobPrincipal(scopes []string) (p JobPrincipal, ok bool) {
	var haveJob, haveRunner, haveAttempt bool
	for _, s := range scopes {
		switch {
		case strings.HasPrefix(s, jobRunnerScopePrefix):
			id, err := uuid.Parse(strings.TrimPrefix(s, jobRunnerScopePrefix))
			if err != nil {
				return JobPrincipal{}, false
			}
			p.RunnerID, haveRunner = id, true
		case strings.HasPrefix(s, jobAttemptScopePrefix):
			n, err := strconv.Atoi(strings.TrimPrefix(s, jobAttemptScopePrefix))
			if err != nil || n < 1 {
				return JobPrincipal{}, false
			}
			p.Attempt, haveAttempt = n, true
		case strings.HasPrefix(s, jobScopePrefix):
			parts := strings.Split(strings.TrimPrefix(s, jobScopePrefix), ":")
			if len(parts) != 3 || parts[2] != "*" || parts[1] == "" {
				return JobPrincipal{}, false
			}
			kind := models.JobType(parts[0])
			if kind != models.JobTypeTofuRun && kind != models.JobTypeAnsibleJob && kind != models.JobTypeWorkItem {
				return JobPrincipal{}, false
			}
			p.Kind, p.JobID, haveJob = kind, parts[1], true
		}
	}
	return p, haveJob && haveRunner && haveAttempt
}

// CreateJobToken mints the job token for principal p of a job in orgID, valid until expiresAt.
// The token has no owner and the job kind; the caller has authorized the runner's claim.
//
// poolID is the agent pool of the launcher the token is minted for, nil for a hosted launcher. It
// is stored as the token's AgentPoolID, marking the token as minted for a launcher that passed
// HasJobToken reports whether a job token was ever minted for the job's attempt, expired, revoked or
// live. An attempt that holds one but no identity decision started before decisions were recorded
// (#1113, D3).
func (s *Service) HasJobToken(kind models.JobType, jobID string, attempt int) (bool, error) {
	return s.apiKeyRepo.ExistsByScopes(jobScopePrefix+string(kind)+":"+jobID+":", jobAttemptScopePrefix+strconv.Itoa(attempt))
}

// RunnerAuth as it now works; RunnerAuth refuses a customer job token without it.
func (s *Service) CreateJobToken(orgID uuid.UUID, poolID *uuid.UUID, p JobPrincipal, expiresAt time.Time) (*models.APIKey, string, error) {
	key, err := GenerateAPIKey()
	if err != nil {
		return nil, "", fmt.Errorf("generating job token: %w", err)
	}
	hash, err := HashKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("hashing job token: %w", err)
	}
	apiKey := &models.APIKey{
		Name:           fmt.Sprintf("job %s %s attempt %d", p.Kind, p.JobID, p.Attempt),
		Kind:           models.APIKeyKindJob,
		KeyHash:        hash,
		KeyPrefix:      GetKeyPrefix(key),
		Scopes:         jobScopes(p),
		OrganizationID: &orgID,
		AgentPoolID:    poolID,
		ExpiresAt:      &expiresAt,
	}
	if err := s.apiKeyRepo.Create(apiKey); err != nil {
		return nil, "", fmt.Errorf("storing job token: %w", err)
	}
	return apiKey, key, nil
}

// RevokeJobTokens ends every job token minted for a job, whatever its attempt, and deletes its
// registry token. It is called when the job completes or turns terminal and when it is
// re-dispatched. A job token is expired rather than deleted, so an executor still presenting it is
// answered job-token-revoked and stops (IsRevokedJobToken, AC67, AC72).
func (s *Service) RevokeJobTokens(kind models.JobType, jobID string) error {
	if err := s.apiKeyRepo.ExpireByScopePrefix(jobScopePrefix+string(kind)+":"+jobID+":", time.Now().UTC()); err != nil {
		return fmt.Errorf("revoking job tokens: %w", err)
	}
	return s.RevokeJobRegistryTokens(kind, jobID)
}

// RevokeJobTokensInTransaction binds credential cleanup to the job's settlement transaction.
func (s *Service) RevokeJobTokensInTransaction(tx *gorm.DB, kind models.JobType, jobID string) error {
	scoped := *s
	scoped.apiKeyRepo = repository.NewAPIKeyRepository(tx)
	return scoped.RevokeJobTokens(kind, jobID)
}

// RevokeJobAttemptTokens revokes the job tokens of one attempt of a job, leaving a later attempt's
// tokens valid (#938): a stale request that finishes nothing must not end the current attempt.
func (s *Service) RevokeJobAttemptTokens(kind models.JobType, jobID string, attempt int) error {
	if err := s.apiKeyRepo.ExpireByScopes(jobScopePrefix+string(kind)+":"+jobID+":", jobAttemptScopePrefix+strconv.Itoa(attempt), time.Now().UTC()); err != nil {
		return fmt.Errorf("revoking job tokens of attempt %d: %w", attempt, err)
	}
	return nil
}

// IsRevokedJobToken reports whether key is a job token that no longer verifies: revoked, or past
// the job's own deadline. Either way its executor's job is over for it. It is false for an unknown
// token and for every other kind of key.
func (s *Service) IsRevokedJobToken(key string) bool {
	keys, err := s.apiKeyRepo.GetByPrefix(GetKeyPrefix(key))
	if err != nil {
		return false
	}
	for _, k := range keys {
		if k.Kind == models.APIKeyKindJob && VerifyKey(key, k.KeyHash) {
			return k.ExpiresAt != nil && !k.ExpiresAt.After(time.Now())
		}
	}
	return false
}

// CreateJobRegistryToken mints a job's private-registry token (#933, D2, AC14): an ownerless job
// key with registry:read for orgID, accepted by the registry protocol's read check for that
// organization's private artifacts and by nothing else. It is a separate credential from the job
// token because it is exported into the engine's environment, where the job token never is.
//
// poolID is the job's agent pool (the hosted pool for hosted capacity), stored as the token's
// AgentPoolID: IsJobRegistryTokenFor accepts only a registry token with it, so one minted before
// registry tokens carried their job's pool, which cannot be traced to its launcher, is refused.
func (s *Service) CreateJobRegistryToken(orgID, poolID uuid.UUID, kind models.JobType, jobID string, expiresAt time.Time) (string, error) {
	key, err := GenerateAPIKey()
	if err != nil {
		return "", fmt.Errorf("generating registry token: %w", err)
	}
	hash, err := HashKey(key)
	if err != nil {
		return "", fmt.Errorf("hashing registry token: %w", err)
	}
	apiKey := &models.APIKey{
		Name:           fmt.Sprintf("registry %s %s", kind, jobID),
		Kind:           models.APIKeyKindJob,
		KeyHash:        hash,
		KeyPrefix:      GetKeyPrefix(key),
		Scopes:         models.StringArray{registryReadScope, jobRegistryScopePrefix + string(kind) + ":" + jobID},
		OrganizationID: &orgID,
		AgentPoolID:    &poolID,
		ExpiresAt:      &expiresAt,
	}
	if err := s.apiKeyRepo.Create(apiKey); err != nil {
		return "", fmt.Errorf("storing registry token: %w", err)
	}
	return key, nil
}

// RevokeJobRegistryTokens deletes a job's registry tokens.
func (s *Service) RevokeJobRegistryTokens(kind models.JobType, jobID string) error {
	return s.apiKeyRepo.DeleteByScopePrefix(jobRegistryScopePrefix + string(kind) + ":" + jobID)
}

// IsJobRegistryTokenFor reports whether key is a job's registry token for orgID, minted with its
// job's pool (CreateJobRegistryToken).
func IsJobRegistryTokenFor(key *models.APIKey, orgID uuid.UUID) bool {
	if key == nil || key.Kind != models.APIKeyKindJob || key.OrganizationID == nil || *key.OrganizationID != orgID || key.AgentPoolID == nil {
		return false
	}
	return slices.Contains(key.Scopes, registryReadScope)
}
