// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
)

// BrowserIdentity is who a verified browser sign-in names, read from its ID token.
type BrowserIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	GivenName     string
	FamilyName    string
	Picture       string
}

// errNoVerifier means Zitadel verification is not initialized, so a sign-in cannot be checked.
var errNoVerifier = errors.New("zitadel verification is not initialized")

// ssoGroups reads the normalized sso_groups claim the complement-token action puts in the access
// token.
func ssoGroups(claimsMap map[string]any) []string {
	raw, ok := claimsMap["sso_groups"].([]any)
	if !ok {
		return nil
	}
	var groups []string
	for _, g := range raw {
		if s, ok := g.(string); ok && s != "" {
			groups = append(groups, s)
		}
	}
	return groups
}

// ProvisionBrowserUser turns a verified browser sign-in into the platform user. It refuses an
// account whose email is not verified (ErrEmailNotVerified), verifies the access token received at
// sign-in (signature, issuer, audience) so its sso_groups claim can be trusted, provisions the user,
// and syncs SSO-driven team membership. The access token is used only here and never stored.
func (s *Service) ProvisionBrowserUser(ctx context.Context, id BrowserIdentity, accessToken string) (*models.User, error) {
	if !id.EmailVerified {
		return nil, ErrEmailNotVerified
	}
	if s.verifier == nil {
		return nil, errNoVerifier
	}
	_, claimsMap, err := s.verifier.VerifyToken(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("verifying the sign-in access token: %w", err)
	}

	name := id.Name
	if name == "" {
		name = id.Email
	}
	user, err := s.userRepo.GetOrCreateByZitadelSubject(id.Subject, id.Email, name)
	if err != nil {
		return nil, fmt.Errorf("getting or creating the user for %q: %w", id.Subject, err)
	}

	// The seeder sees exactly what this sign-in established. A seeder failure does not block
	// sign-in, as a team sync failure does not.
	if s.adminSeeder != nil {
		if err := s.adminSeeder.ApplyDeclared(ctx, user, id); err != nil {
			logger.Errorf("auth: applying the declared platform administrators to user %s: %v", user.ID, err)
		}
	}

	if s.teamSyncer != nil && s.teamSyncer.IsEnabled() {
		if groups := ssoGroups(claimsMap); len(groups) > 0 {
			if err := s.teamSyncer.SyncUserTeams(ctx, user.ID, groups); err != nil {
				// Team sync never blocks sign-in, as on the token path.
				logger.Errorf("auth: team sync at sign-in failed for user %s: %v", user.ID, err)
			}
		}
	}
	return user, nil
}
