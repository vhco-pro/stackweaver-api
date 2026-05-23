// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// F-reg-1 + F-reg-2 — TFE token + API key auth regression.
//
// Plan contract (docs/internal/plans/features/custom-login-ui-plan.md):
//   F-reg-1: TFE token auth still works
//   F-reg-2: API key auth still works
//
// The custom-login-ui rollout added /auth/* proxy routes but did NOT
// touch the /api/v2/* auth middleware or the `Service.GetUserFromToken`
// routing logic. These tests pin the contract so a future regression
// (e.g. a refactor that swaps the prefix check, removes the API key
// fallback, or changes the user-lookup chain) is caught at unit-test
// time rather than discovered when terraform-provider-tfe stops
// authenticating.
//
// # Why mocks instead of a real Postgres
//
// The auth service's lookup interfaces (`TFETokenLookup`, `UserLookup`,
// `APIKeyVerifier`) are narrow — exactly the methods `GetUserFromToken`
// calls. Mocks here exercise the SAME code path the production
// service runs, just with deterministic repos. A DB integration test
// would also exercise gorm + bcrypt, but those layers have their own
// upstream test coverage; what's load-bearing for auth-routing is
// the prefix check, the fallback chain, and the user-id lookup.
//
// # What's NOT covered here (and where it lives)
//
// - JWT verification: `ZitadelVerifier` lives in `verifier.go`, gets
//   integration coverage from every E2E spec (auth-setup mints a real
//   Zitadel JWT, every UI spec uses it).
// - bcrypt-of-API-key: covered in `services/apikey/service_test.go`
//   when that lands; for now exercised end-to-end whenever an API key
//   is created and consumed in the dev stack.
// - Middleware HTTP wiring (Authorization header parsing, gin
//   context, etc): covered by `Service.AuthenticateMiddleware`'s
//   shape — these unit tests exercise the underlying lookup. A
//   middleware-level test would add value but isn't required for
//   the F-reg-1/2 contract.

// --- Mocks ---

type mockTFETokenRepo struct {
	getByTokenFn      func(string) (*models.TFEToken, error)
	updateLastUsedFn  func(uuid.UUID) error
	getByTokenCalls   []string
	updateLastUsedIDs []uuid.UUID
}

func (m *mockTFETokenRepo) GetByToken(token string) (*models.TFEToken, error) {
	m.getByTokenCalls = append(m.getByTokenCalls, token)
	if m.getByTokenFn != nil {
		return m.getByTokenFn(token)
	}
	return nil, errors.New("not found")
}

func (m *mockTFETokenRepo) UpdateLastUsed(id uuid.UUID) error {
	m.updateLastUsedIDs = append(m.updateLastUsedIDs, id)
	if m.updateLastUsedFn != nil {
		return m.updateLastUsedFn(id)
	}
	return nil
}

type mockUserRepo struct {
	getByIDFn     func(uuid.UUID) (*models.User, error)
	getOrCreateFn func(string, string, string) (*models.User, error)
	getByIDCalls  []uuid.UUID
}

func (m *mockUserRepo) GetByID(id uuid.UUID) (*models.User, error) {
	m.getByIDCalls = append(m.getByIDCalls, id)
	if m.getByIDFn != nil {
		return m.getByIDFn(id)
	}
	return nil, errors.New("user not found")
}

func (m *mockUserRepo) GetOrCreateByZitadelSubject(subject, email, name string) (*models.User, error) {
	if m.getOrCreateFn != nil {
		return m.getOrCreateFn(subject, email, name)
	}
	return nil, errors.New("not implemented")
}

type mockAPIKeyService struct {
	verifyFn         func(string) (*models.APIKey, error)
	updateLastUsedFn func(uuid.UUID) error
	verifyCalls      []string
	updateCalls      []uuid.UUID
}

func (m *mockAPIKeyService) VerifyAPIKey(key string) (*models.APIKey, error) {
	m.verifyCalls = append(m.verifyCalls, key)
	if m.verifyFn != nil {
		return m.verifyFn(key)
	}
	return nil, errors.New("invalid api key")
}

func (m *mockAPIKeyService) UpdateLastUsed(id uuid.UUID) error {
	m.updateCalls = append(m.updateCalls, id)
	if m.updateLastUsedFn != nil {
		return m.updateLastUsedFn(id)
	}
	return nil
}

// --- F-reg-1: TFE token auth ---

func TestGetUserFromToken_TFETokenSucceeds(t *testing.T) {
	userID := uuid.New()
	tokenID := uuid.New()
	wantUser := &models.User{ID: userID, Email: "tfe-user@example.com", Name: "TFE User"}

	const validTFEToken = "tfe-validtoken123" //nolint:gosec // test fixture, not a real credential
	tfeRepo := &mockTFETokenRepo{
		getByTokenFn: func(token string) (*models.TFEToken, error) {
			if token != validTFEToken {
				return nil, errors.New("not found")
			}
			return &models.TFEToken{ID: tokenID, UserID: userID, Token: "hashed"}, nil
		},
	}
	userRepo := &mockUserRepo{
		getByIDFn: func(id uuid.UUID) (*models.User, error) {
			if id != userID {
				return nil, errors.New("user not found")
			}
			return wantUser, nil
		},
	}

	svc := NewServiceWithLookups(userRepo, tfeRepo)

	got, err := svc.GetUserFromToken(validTFEToken)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if got.ID != wantUser.ID {
		t.Errorf("returned user id: want %s, got %s", wantUser.ID, got.ID)
	}
	if got.Email != wantUser.Email {
		t.Errorf("returned user email: want %s, got %s", wantUser.Email, got.Email)
	}

	// Lookup fired exactly once with the full token.
	if len(tfeRepo.getByTokenCalls) != 1 || tfeRepo.getByTokenCalls[0] != validTFEToken {
		t.Errorf("GetByToken call log: %v", tfeRepo.getByTokenCalls)
	}
	// UpdateLastUsed bumped the matched token's id (best-effort, not
	// blocking on success — but the bookkeeping must fire).
	if len(tfeRepo.updateLastUsedIDs) != 1 || tfeRepo.updateLastUsedIDs[0] != tokenID {
		t.Errorf("UpdateLastUsed call log: %v", tfeRepo.updateLastUsedIDs)
	}
}

func TestGetUserFromToken_TFETokenLookupFailsFallsThroughToAPIKey(t *testing.T) {
	userID := uuid.New()
	apiKeyID := uuid.New()
	wantUser := &models.User{ID: userID, Email: "apikey-user@example.com"}

	tfeRepo := &mockTFETokenRepo{
		// TFE lookup fails — must not return a user.
		getByTokenFn: func(string) (*models.TFEToken, error) {
			return nil, errors.New("token not found")
		},
	}
	apiKey := &mockAPIKeyService{
		verifyFn: func(key string) (*models.APIKey, error) {
			if key != "tfe-apikeytoken456" {
				return nil, errors.New("invalid api key")
			}
			return &models.APIKey{ID: apiKeyID, UserID: userID}, nil
		},
	}
	userRepo := &mockUserRepo{
		getByIDFn: func(id uuid.UUID) (*models.User, error) {
			if id != userID {
				return nil, errors.New("user not found")
			}
			return wantUser, nil
		},
	}

	svc := NewServiceWithLookups(userRepo, tfeRepo)
	svc.SetAPIKeyService(apiKey)

	got, err := svc.GetUserFromToken("tfe-apikeytoken456")
	if err != nil {
		t.Fatalf("expected fallback to API key to succeed, got error: %v", err)
	}
	if got.ID != wantUser.ID {
		t.Errorf("returned user id: want %s, got %s", wantUser.ID, got.ID)
	}
	// TFE lookup happened first.
	if len(tfeRepo.getByTokenCalls) != 1 {
		t.Errorf("TFE GetByToken should have been tried first; got calls: %v", tfeRepo.getByTokenCalls)
	}
	// API key fallback fired.
	if len(apiKey.verifyCalls) != 1 || apiKey.verifyCalls[0] != "tfe-apikeytoken456" {
		t.Errorf("API key fallback didn't fire; calls: %v", apiKey.verifyCalls)
	}
	if len(apiKey.updateCalls) != 1 || apiKey.updateCalls[0] != apiKeyID {
		t.Errorf("UpdateLastUsed on API key didn't fire: %v", apiKey.updateCalls)
	}
}

func TestGetUserFromToken_TFEPrefixButUnknownUser(t *testing.T) {
	// TFE lookup matches the token but the linked user is gone (e.g.
	// orphaned token after a user delete). Service must NOT return a
	// nil-user with nil-error — the contract is "either valid user
	// or error". Today the loop just falls through to JWT, which
	// without a verifier returns "authentication service not
	// initialized". That's the regression-pinning value here: the
	// "broken token" case never silently succeeds.
	tokenID := uuid.New()
	missingUserID := uuid.New()

	tfeRepo := &mockTFETokenRepo{
		getByTokenFn: func(string) (*models.TFEToken, error) {
			return &models.TFEToken{ID: tokenID, UserID: missingUserID}, nil
		},
	}
	userRepo := &mockUserRepo{
		// User lookup fails — this is the orphaned-token case.
		getByIDFn: func(uuid.UUID) (*models.User, error) {
			return nil, errors.New("user not found")
		},
	}

	svc := NewServiceWithLookups(userRepo, tfeRepo)

	got, err := svc.GetUserFromToken("tfe-orphaned789")
	if err == nil {
		t.Fatalf("orphaned-token case must return an error, got user: %+v", got)
	}
	if got != nil {
		t.Errorf("orphaned-token case must return a nil user, got: %+v", got)
	}
}

func TestGetUserFromToken_NonTFEPrefixSkipsTFEAndAPIKey(t *testing.T) {
	// Token without the `tfe-` prefix must NOT touch the TFE / API
	// key lookup paths. Without a JWT verifier set, the call falls
	// through to the "authentication service not initialized" error.
	// What matters is that the lookups didn't fire — a regression
	// where the prefix check was inverted would call them.
	tfeRepo := &mockTFETokenRepo{}
	apiKey := &mockAPIKeyService{}
	userRepo := &mockUserRepo{}

	svc := NewServiceWithLookups(userRepo, tfeRepo)
	svc.SetAPIKeyService(apiKey)

	_, err := svc.GetUserFromToken("eyJhbGciOi...not-a-tfe-token")
	if err == nil {
		t.Fatal("non-tfe token without JWT verifier must return an error")
	}
	if len(tfeRepo.getByTokenCalls) != 0 {
		t.Errorf("non-tfe token must NOT trigger TFE lookup; got calls: %v", tfeRepo.getByTokenCalls)
	}
	if len(apiKey.verifyCalls) != 0 {
		t.Errorf("non-tfe token must NOT trigger API key lookup; got calls: %v", apiKey.verifyCalls)
	}
}

// --- F-reg-2: API key auth (when no TFE token matches) ---

func TestGetUserFromToken_APIKeyFallbackWithoutAPIKeyServiceFailsCleanly(t *testing.T) {
	// `tfe-` prefix, TFE lookup fails, AND no APIKeyService set
	// (older deployments before the API key feature landed). Must
	// fall through cleanly without panicking on a nil pointer.
	tfeRepo := &mockTFETokenRepo{
		getByTokenFn: func(string) (*models.TFEToken, error) {
			return nil, errors.New("not found")
		},
	}
	userRepo := &mockUserRepo{}

	svc := NewServiceWithLookups(userRepo, tfeRepo)
	// Deliberately do NOT call SetAPIKeyService — apiKeyService stays nil.

	_, err := svc.GetUserFromToken("tfe-something")
	if err == nil {
		t.Fatal("missing API key service AND failing TFE lookup must error, not silently succeed")
	}
}

func TestGetUserFromToken_APIKeyValidButOrphanedUser(t *testing.T) {
	// API key matches but the linked user is gone. Same shape as the
	// TFE orphaned-token case — service must NOT return a nil-user
	// with nil-error.
	apiKeyID := uuid.New()
	missingUserID := uuid.New()

	tfeRepo := &mockTFETokenRepo{
		getByTokenFn: func(string) (*models.TFEToken, error) {
			return nil, errors.New("not a tfe token")
		},
	}
	apiKey := &mockAPIKeyService{
		verifyFn: func(string) (*models.APIKey, error) {
			return &models.APIKey{ID: apiKeyID, UserID: missingUserID}, nil
		},
	}
	userRepo := &mockUserRepo{
		getByIDFn: func(uuid.UUID) (*models.User, error) {
			return nil, errors.New("user not found")
		},
	}

	svc := NewServiceWithLookups(userRepo, tfeRepo)
	svc.SetAPIKeyService(apiKey)

	got, err := svc.GetUserFromToken("tfe-validkey-orphanuser")
	if err == nil {
		t.Fatalf("orphaned-API-key case must return an error, got user: %+v", got)
	}
	if got != nil {
		t.Errorf("orphaned-API-key case must return a nil user, got: %+v", got)
	}
}
