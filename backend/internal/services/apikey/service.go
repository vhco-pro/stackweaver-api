// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package apikey

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	apiKeyRepo  *repository.APIKeyRepository
	orgRepo     *repository.OrganizationRepository
	projectRepo *repository.ProjectRepository
	teamRepo    *repository.TeamRepository
}

func NewService(apiKeyRepo *repository.APIKeyRepository, orgRepo *repository.OrganizationRepository, projectRepo *repository.ProjectRepository, teamRepo *repository.TeamRepository) *Service {
	return &Service{
		apiKeyRepo:  apiKeyRepo,
		orgRepo:     orgRepo,
		projectRepo: projectRepo,
		teamRepo:    teamRepo,
	}
}

// GenerateAPIKey generates a new API key string
// Format: tfe-<random_base64> (Terraform Cloud compatible)
func GenerateAPIKey() (string, error) {
	// Generate 32 random bytes (256 bits)
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 URL-safe (no padding) - matching Terraform Cloud format
	keySuffix := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(randomBytes)

	// Format: tfe-<suffix> (Terraform Cloud compatible)
	return fmt.Sprintf("tfe-%s", keySuffix), nil
}

// HashKey hashes an API key using bcrypt
func HashKey(key string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash API key: %w", err)
	}
	return string(hash), nil
}

// VerifyKey verifies an API key against its hash
func VerifyKey(key, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(key))
	return err == nil
}

// GetKeyPrefix extracts the first 12 characters of a key for display
// Format: tfe-<first 8 chars of suffix>
func GetKeyPrefix(key string) string {
	// Key format is "tfe-<suffix>"
	// We want to show "tfe-<first 8 chars>"
	if len(key) <= 12 {
		return key
	}
	// Show first 12 characters (tfe- + first 8 chars of suffix)
	return key[:12]
}

// CreateAPIKey creates a new API key for a user.
//
// Every API key MUST be bound to exactly one organization (single-org token
// invariant). A key with no scopes, or whose scopes do not resolve to an
// organization, is rejected — there is no instance-wide token for non-admins.
func (s *Service) CreateAPIKey(userID uuid.UUID, name string, scopes []string, expiresAt *time.Time) (*models.APIKey, string, error) {
	// Reject empty/nil scopes outright. Under the single-org token model an
	// empty scope means "deny", not "full access" — the caller must declare a
	// scope that binds the key to an organization.
	if len(scopes) == 0 {
		return nil, "", fmt.Errorf("API key must declare at least one scope bound to an organization")
	}

	// Generate the API key
	key, err := GenerateAPIKey()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate API key: %w", err)
	}

	// Hash the key
	keyHash, err := HashKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash API key: %w", err)
	}

	// Validate and parse scopes
	parsedScopes, err := ParseScopes(scopes)
	if err != nil {
		return nil, "", fmt.Errorf("invalid scopes: %w", err)
	}

	// Reject wildcard scopes outright. There is no platform-admin concept yet,
	// so a `*` scope (or a `*` permission such as `org:<id>:*`) would grant
	// unbounded access and defeat the single-org token model. Wildcard creation
	// is re-enabled for platform admins only once #132 lands.
	for _, scope := range parsedScopes {
		if scope.Type == "*" || scope.Permission == "*" {
			return nil, "", fmt.Errorf("wildcard scopes are not permitted")
		}
	}

	// Validate organization, project, and team access
	var orgID *uuid.UUID
	var projectID *uuid.UUID
	var teamID *uuid.UUID

	for _, scope := range parsedScopes {
		if scope.Type == "team" && scope.ResourceID != nil {
			// Validate that the team exists
			team, err := s.teamRepo.GetByID(*scope.ResourceID)
			if err != nil {
				return nil, "", fmt.Errorf("team not found: %w", err)
			}

			// Check if user has access to the team's organization (team-based)
			inOrg, err := s.orgRepo.UserInOrg(userID, team.OrganizationID)
			if err != nil || !inOrg {
				return nil, "", fmt.Errorf("user is not a member of the team's organization")
			}

			// If multiple team scopes, they must all be for the same team
			if teamID != nil && *teamID != *scope.ResourceID {
				return nil, "", fmt.Errorf("API key cannot be scoped to multiple teams")
			}
			teamID = scope.ResourceID

			// If team is scoped, set org ID from team
			if orgID == nil {
				orgID = &team.OrganizationID
			} else if *orgID != team.OrganizationID {
				return nil, "", fmt.Errorf("team does not belong to the specified organization")
			}
		}

		if scope.Type == "org" && scope.ResourceID != nil {
			// Validate that the organization exists and user is a member
			org, err := s.orgRepo.GetByID(*scope.ResourceID)
			if err != nil {
				return nil, "", fmt.Errorf("organization not found: %w", err)
			}

			// Check if user has access to the organization (team-based)
			inOrg, err := s.orgRepo.UserInOrg(userID, *scope.ResourceID)
			if err != nil || !inOrg {
				return nil, "", fmt.Errorf("user is not a member of organization %s", scope.ResourceID.String())
			}
			_ = org // org exists

			// If multiple org scopes, they must all be for the same org
			if orgID != nil && *orgID != *scope.ResourceID {
				return nil, "", fmt.Errorf("API key cannot be scoped to multiple organizations")
			}
			orgID = scope.ResourceID
		}

		if scope.Type == "project" && scope.ResourceID != nil {
			// Validate that the project exists
			project, err := s.projectRepo.GetByID(*scope.ResourceID)
			if err != nil {
				return nil, "", fmt.Errorf("project not found: %w", err)
			}

			// Check if user has access to the project's organization (team-based)
			inOrg, err := s.orgRepo.UserInOrg(userID, project.OrganizationID)
			if err != nil || !inOrg {
				return nil, "", fmt.Errorf("user is not a member of the project's organization")
			}

			// If multiple project scopes, they must all be for the same project
			if projectID != nil && *projectID != *scope.ResourceID {
				return nil, "", fmt.Errorf("API key cannot be scoped to multiple projects")
			}
			projectID = scope.ResourceID

			// If project is scoped, set org ID from project
			if orgID == nil {
				orgID = &project.OrganizationID
			} else if *orgID != project.OrganizationID {
				return nil, "", fmt.Errorf("project does not belong to the specified organization")
			}
		}
	}

	// Enforce the single-org token invariant: the scopes must resolve to exactly
	// one organization. A key that binds to no org (e.g. only legacy/user/wildcard
	// scopes) is rejected — there is no instance-wide token for non-admins.
	if orgID == nil {
		return nil, "", fmt.Errorf("API key must be scoped to exactly one organization (use an org, project, or team scope)")
	}

	// Create the API key record
	apiKey := &models.APIKey{
		UserID:         userID,
		Name:           name,
		Kind:           models.APIKeyKindOrg,
		KeyHash:        keyHash,
		KeyPrefix:      GetKeyPrefix(key),
		Scopes:         models.StringArray(scopes),
		OrganizationID: orgID,
		ProjectID:      projectID,
		ExpiresAt:      expiresAt,
	}

	if err := s.apiKeyRepo.Create(apiKey); err != nil {
		return nil, "", fmt.Errorf("failed to create API key: %w", err)
	}

	// Return the API key (plaintext) and the record
	// The plaintext key is only shown once during creation
	return apiKey, key, nil
}

// CreateUserToken creates a user-bound (acts-as-user) token — the personal
// access / `terraform login` token. Unlike an org-bound API key it is NOT
// pinned to a single organization: it is authorized by the owning user's
// organization memberships at the request boundary. It therefore carries no
// scopes and a nil OrganizationID.
//
// This is the unified successor to the legacy `tfe_tokens` table: user tokens
// are now kind="user" rows in api_keys so there is a single token subsystem.
func (s *Service) CreateUserToken(userID uuid.UUID, name string, expiresAt *time.Time) (*models.APIKey, string, error) {
	key, err := GenerateAPIKey()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate user token: %w", err)
	}

	keyHash, err := HashKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash user token: %w", err)
	}

	apiKey := &models.APIKey{
		UserID:    userID,
		Name:      name,
		Kind:      models.APIKeyKindUser,
		KeyHash:   keyHash,
		KeyPrefix: GetKeyPrefix(key),
		Scopes:    models.StringArray{},
		ExpiresAt: expiresAt,
	}

	if err := s.apiKeyRepo.Create(apiKey); err != nil {
		return nil, "", fmt.Errorf("failed to create user token: %w", err)
	}

	return apiKey, key, nil
}

// CreateRunnerToken mints a runner-scoped automation token bound to a single
// runner and its organization. It is the credential a self-hosted runner uses
// to authenticate on the /runner/* control plane after registration; the runner
// id is recoverable from the token's scopes (see ScopeChecker.GetScopedRunners).
//
// Unlike CreateAPIKey it does NOT require the user to be an org member and does
// not go through the generic single-org scope validation: a runner is a machine
// identity minted by an already-authorized registration (the caller presented an
// org-scoped key carrying runner:register). The token is org-bound so every
// downstream authorization check can compare the runner's org to the target job.
func (s *Service) CreateRunnerToken(userID, runnerID, orgID uuid.UUID, name string) (*models.APIKey, string, error) {
	key, err := GenerateAPIKey()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate runner token: %w", err)
	}

	keyHash, err := HashKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash runner token: %w", err)
	}

	// Explicit per-permission runner scopes (no wildcards — those are rejected by
	// the scope validator). GetScopedRunners keys off the "runner" scope type, so
	// any of these lets the runner-auth middleware recover this runner's id.
	scopes := models.StringArray{
		"runner:" + runnerID.String() + ":heartbeat",
		"runner:" + runnerID.String() + ":jobs",
	}

	apiKey := &models.APIKey{
		UserID:         userID,
		Name:           name,
		Kind:           models.APIKeyKindOrg,
		KeyHash:        keyHash,
		KeyPrefix:      GetKeyPrefix(key),
		Scopes:         scopes,
		OrganizationID: &orgID,
	}

	if err := s.apiKeyRepo.Create(apiKey); err != nil {
		return nil, "", fmt.Errorf("failed to create runner token: %w", err)
	}

	return apiKey, key, nil
}

// DeleteAPIKeysForRunner removes every token minted for a runner (by its
// runner:<id>:* scopes). Called when a runner is deregistered/deleted so its
// credentials cannot outlive it.
func (s *Service) DeleteAPIKeysForRunner(runnerID uuid.UUID) error {
	return s.apiKeyRepo.DeleteByScopePrefix("runner:" + runnerID.String() + ":")
}

// ListAPIKeys lists a user's org-bound automation keys (kind="org").
// User-bound tokens are listed separately via ListUserTokens.
func (s *Service) ListAPIKeys(userID uuid.UUID) ([]*models.APIKey, error) {
	return s.apiKeyRepo.GetByUserIDAndKind(userID, models.APIKeyKindOrg)
}

// ListUserTokens lists a user's user-bound (acts-as-user) tokens (kind="user").
func (s *Service) ListUserTokens(userID uuid.UUID) ([]*models.APIKey, error) {
	return s.apiKeyRepo.GetByUserIDAndKind(userID, models.APIKeyKindUser)
}

// GetAPIKey gets a single API key by ID (for the owner)
func (s *Service) GetAPIKey(id uuid.UUID, userID uuid.UUID) (*models.APIKey, error) {
	apiKey, err := s.apiKeyRepo.GetByID(id)
	if err != nil {
		return nil, err
	}

	// Verify ownership
	if apiKey.UserID != userID {
		return nil, fmt.Errorf("API key not found")
	}

	return apiKey, nil
}

// DeleteAPIKey deletes an API key
func (s *Service) DeleteAPIKey(id uuid.UUID, userID uuid.UUID) error {
	// Verify ownership
	apiKey, err := s.apiKeyRepo.GetByID(id)
	if err != nil {
		return err
	}

	if apiKey.UserID != userID {
		return fmt.Errorf("API key not found")
	}

	return s.apiKeyRepo.Delete(id)
}

// VerifyAPIKey verifies an API key and returns the associated API key record
// Uses the key prefix for fast lookup, then verifies with bcrypt
func (s *Service) VerifyAPIKey(key string) (*models.APIKey, error) {
	// Extract prefix for fast lookup
	keyPrefix := GetKeyPrefix(key)

	// Get API keys with matching prefix (much faster than checking all keys)
	apiKeys, err := s.apiKeyRepo.GetByPrefix(keyPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup API keys: %w", err)
	}

	// Verify each key with matching prefix
	for _, apiKey := range apiKeys {
		// Verify the full key against the hash
		if VerifyKey(key, apiKey.KeyHash) {
			// Check if expired
			if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
				return nil, fmt.Errorf("API key has expired")
			}
			return apiKey, nil
		}
	}

	return nil, fmt.Errorf("invalid API key")
}

// UpdateLastUsed updates the last used timestamp for an API key
func (s *Service) UpdateLastUsed(id uuid.UUID) error {
	return s.apiKeyRepo.UpdateLastUsed(id)
}

// CheckPermission checks if an API key has permission for a specific resource
// Returns true if the key has the requested permission
func (s *Service) CheckPermission(apiKey *models.APIKey, resourceType string, resourceID *uuid.UUID, permission string) (bool, error) {
	checker, err := NewScopeChecker(apiKey.Scopes)
	if err != nil {
		return false, fmt.Errorf("failed to parse scopes: %w", err)
	}

	// Check if key is scoped to a specific organization/project
	if apiKey.OrganizationID != nil {
		// If resource is organization-scoped, verify it matches
		if resourceType == "org" && resourceID != nil {
			if *apiKey.OrganizationID != *resourceID {
				return false, nil
			}
		}
		// If resource is project-scoped, verify it belongs to the org
		if resourceType == "project" && resourceID != nil {
			project, err := s.projectRepo.GetByID(*resourceID)
			if err != nil {
				return false, nil
			}
			if project.OrganizationID != *apiKey.OrganizationID {
				return false, nil
			}
		}
	}

	if apiKey.ProjectID != nil {
		// If resource is project-scoped, verify it matches
		if resourceType == "project" && resourceID != nil {
			if *apiKey.ProjectID != *resourceID {
				return false, nil
			}
		}
	}

	return checker.HasPermission(resourceType, resourceID, permission), nil
}

// CheckOrgPermission checks if an API key has permission for an organization
func (s *Service) CheckOrgPermission(apiKey *models.APIKey, orgID uuid.UUID, permission string) (bool, error) {
	return s.CheckPermission(apiKey, "org", &orgID, permission)
}

// CheckProjectPermission checks if an API key has permission for a project
func (s *Service) CheckProjectPermission(apiKey *models.APIKey, projectID uuid.UUID, permission string) (bool, error) {
	return s.CheckPermission(apiKey, "project", &projectID, permission)
}

// CheckUserPermission checks if an API key has permission for user operations
func (s *Service) CheckUserPermission(apiKey *models.APIKey, permission string) (bool, error) {
	return s.CheckPermission(apiKey, "user", nil, permission)
}

// GetScopeChecker returns a scope checker for an API key
func (s *Service) GetScopeChecker(apiKey *models.APIKey) (*ScopeChecker, error) {
	return NewScopeChecker(apiKey.Scopes)
}
