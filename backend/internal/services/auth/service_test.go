// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// Programmatic-token auth regression.
//
// Plan contract (docs/internal/plans/security/api-key-org-scoping-enforcement-plan.md):
// all programmatic tokens — org-bound automation keys and user-bound
// (`terraform login`) tokens — are now `tfe-`-prefixed api_keys. The
// legacy separate `tfe_tokens` table was retired, so `GetUserFromToken`
// resolves a `tfe-`-prefixed token through a single api-key lookup.
//
// These tests pin that routing contract so a future refactor (swapping
// the prefix check, dropping the api-key lookup, or changing the
// user-lookup chain) is caught at unit-test time rather than when
// terraform-provider-tfe stops authenticating.
//
// # Why mocks instead of a real Postgres
//
// The auth service's lookup interfaces (`UserLookup`, `APIKeyVerifier`)
// are narrow — exactly the methods `GetUserFromToken` calls. Mocks here
// exercise the SAME code path the production service runs, just with
// deterministic repos. bcrypt-of-API-key and gorm have their own
// upstream coverage.
//
// # What's NOT covered here (and where it lives)
//
//   - JWT verification: `ZitadelVerifier` lives in `verifier.go`, gets
//     integration coverage from every E2E spec.
//   - api-key creation/scoping: `services/apikey/service_test.go`.

// --- Mocks ---

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

// --- Programmatic-token (api-key) auth ---

func TestGetUserFromToken_APIKeyTokenSucceeds(t *testing.T) {
	userID := uuid.New()
	apiKeyID := uuid.New()
	wantUser := &models.User{ID: userID, Email: "apikey-user@example.com", Name: "API User"}

	const validToken = "tfe-validtoken123" //nolint:gosec // test fixture, not a real credential
	apiKey := &mockAPIKeyService{
		verifyFn: func(key string) (*models.APIKey, error) {
			if key != validToken {
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

	svc := NewServiceWithLookups(userRepo)
	svc.SetAPIKeyService(apiKey)

	got, err := svc.GetUserFromToken(validToken)
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
	if len(apiKey.verifyCalls) != 1 || apiKey.verifyCalls[0] != validToken {
		t.Errorf("VerifyAPIKey call log: %v", apiKey.verifyCalls)
	}
	// UpdateLastUsed bumped the matched key's id.
	if len(apiKey.updateCalls) != 1 || apiKey.updateCalls[0] != apiKeyID {
		t.Errorf("UpdateLastUsed call log: %v", apiKey.updateCalls)
	}
}

func TestGetUserFromToken_NonTFEPrefixSkipsAPIKey(t *testing.T) {
	// Token without the `tfe-` prefix must NOT touch the api-key
	// lookup path. Without a JWT verifier set, the call falls through
	// to the "authentication service not initialized" error. What
	// matters is that the api-key lookup didn't fire — a regression
	// where the prefix check was inverted would call it.
	apiKey := &mockAPIKeyService{}
	userRepo := &mockUserRepo{}

	svc := NewServiceWithLookups(userRepo)
	svc.SetAPIKeyService(apiKey)

	_, err := svc.GetUserFromToken("eyJhbGciOi...not-a-tfe-token")
	if err == nil {
		t.Fatal("non-tfe token without JWT verifier must return an error")
	}
	if len(apiKey.verifyCalls) != 0 {
		t.Errorf("non-tfe token must NOT trigger api-key lookup; got calls: %v", apiKey.verifyCalls)
	}
}

func TestGetUserFromToken_APIKeyMissingServiceFailsCleanly(t *testing.T) {
	// `tfe-` prefix but no APIKeyService set must fall through cleanly
	// without panicking on a nil pointer.
	userRepo := &mockUserRepo{}

	svc := NewServiceWithLookups(userRepo)
	// Deliberately do NOT call SetAPIKeyService — apiKeyService stays nil.

	_, err := svc.GetUserFromToken("tfe-something")
	if err == nil {
		t.Fatal("missing api-key service must error, not silently succeed")
	}
}

func TestGetUserFromToken_UnknownTFETokenIsTerminal(t *testing.T) {
	// #503: a `tfe-` token that fails api-key lookup must be rejected
	// outright, NOT handed to JWT verification. With no verifier set,
	// the legacy fallthrough returned "authentication service not
	// initialized" — the truthful invalid-token error proves the prefix
	// is authoritative.
	apiKey := &mockAPIKeyService{} // every lookup fails

	svc := NewServiceWithLookups(&mockUserRepo{})
	svc.SetAPIKeyService(apiKey)

	_, err := svc.GetUserFromToken("tfe-revoked-or-unknown")
	if err == nil || !strings.Contains(err.Error(), "invalid or revoked API token") {
		t.Fatalf("want terminal invalid-or-revoked error, got: %v", err)
	}
	if len(apiKey.verifyCalls) != 1 {
		t.Errorf("VerifyAPIKey call log: %v", apiKey.verifyCalls)
	}
}

func TestGetUserFromToken_APIKeyValidButOrphanedUser(t *testing.T) {
	// API key matches but the linked user is gone (e.g. orphaned key
	// after a user delete). Service must NOT return a nil-user with
	// nil-error — the contract is "either valid user or error".
	apiKeyID := uuid.New()
	missingUserID := uuid.New()

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

	svc := NewServiceWithLookups(userRepo)
	svc.SetAPIKeyService(apiKey)

	got, err := svc.GetUserFromToken("tfe-validkey-orphanuser")
	if err == nil {
		t.Fatalf("orphaned-key case must return an error, got user: %+v", got)
	}
	if got != nil {
		t.Errorf("orphaned-key case must return a nil user, got: %+v", got)
	}
}

// --- Org-resolution wall inputs (Phase 2 step 1) ---
//
// `AuthenticateMiddleware` must publish the token's *kind* (and, for an
// org-bound token, its bound org id) into the gin context so the
// downstream org-resolution wall can authorize the target org against
// the token. These tests pin that the two kinds are stamped correctly:
// an org-bound key sets `token_kind="org"` + `token_org_id`; a
// user-bound key sets `token_kind="user"` and NO `token_org_id`.

func runMiddlewareWithAPIKey(t *testing.T, apiKey *models.APIKey, user *models.User) map[string]any {
	t.Helper()
	gin.SetMode(gin.TestMode)

	apiKeySvc := &mockAPIKeyService{
		verifyFn: func(string) (*models.APIKey, error) { return apiKey, nil },
	}
	userRepo := &mockUserRepo{
		getByIDFn: func(uuid.UUID) (*models.User, error) { return user, nil },
	}
	svc := NewServiceWithLookups(userRepo)
	svc.SetAPIKeyService(apiKeySvc)

	captured := map[string]any{}
	r := gin.New()
	r.Use(svc.AuthenticateMiddleware())
	r.GET("/probe", func(c *gin.Context) {
		for _, k := range []string{"token_kind", "token_org_id", "auth_method"} {
			if v, ok := c.Get(k); ok {
				captured[k] = v
			}
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer tfe-probe-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("middleware rejected the request: status %d", w.Code)
	}
	return captured
}

func TestAuthenticateMiddleware_OrgBoundTokenSetsBoundOrg(t *testing.T) {
	userID := uuid.New()
	orgID := uuid.New()
	apiKey := &models.APIKey{
		ID:             uuid.New(),
		UserID:         userID,
		Kind:           models.APIKeyKindOrg,
		OrganizationID: &orgID,
	}
	user := &models.User{ID: userID, Email: "org@example.com", Name: "Org User"}

	got := runMiddlewareWithAPIKey(t, apiKey, user)

	if got["auth_method"] != "api_key" {
		t.Errorf("auth_method: want api_key, got %v", got["auth_method"])
	}
	if got["token_kind"] != models.APIKeyKindOrg {
		t.Errorf("token_kind: want %q, got %v", models.APIKeyKindOrg, got["token_kind"])
	}
	gotOrg, ok := got["token_org_id"].(uuid.UUID)
	if !ok {
		t.Fatalf("token_org_id missing or wrong type: %#v", got["token_org_id"])
	}
	if gotOrg != orgID {
		t.Errorf("token_org_id: want %s, got %s", orgID, gotOrg)
	}
}

// runMiddlewareExpectingRejection drives AuthenticateMiddleware with the
// given mocks and bearer token, asserting the request never reaches the
// handler. Returns the response for status/body assertions.
func runMiddlewareExpectingRejection(t *testing.T, apiKeySvc *mockAPIKeyService, userRepo *mockUserRepo, token string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)

	svc := NewServiceWithLookups(userRepo)
	svc.SetAPIKeyService(apiKeySvc)

	r := gin.New()
	r.Use(svc.AuthenticateMiddleware())
	handlerReached := false
	r.GET("/probe", func(c *gin.Context) {
		handlerReached = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if handlerReached {
		t.Fatal("request must not reach the handler")
	}
	return w
}

func TestAuthenticateMiddleware_UnknownTFETokenIsTerminal(t *testing.T) {
	// #503: a `tfe-` token that fails api-key lookup must 401 outright,
	// NOT fall through to JWT verification. With no verifier set, the
	// legacy fallthrough produced a 500 ("authentication service not
	// initialized"), so the 401 + truthful detail proves the prefix is
	// authoritative. Applies equally to a valid JWT wearing a `tfe-`
	// prefix — the declared kind wins.
	apiKeySvc := &mockAPIKeyService{} // every lookup fails

	w := runMiddlewareExpectingRejection(t, apiKeySvc, &mockUserRepo{}, "tfe-revoked-or-unknown")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: want 401, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid or revoked API token") {
		t.Errorf("body must carry the truthful detail, got: %s", w.Body.String())
	}
	if len(apiKeySvc.verifyCalls) != 1 {
		t.Errorf("VerifyAPIKey call log: %v", apiKeySvc.verifyCalls)
	}
}

func TestAuthenticateMiddleware_OrphanedAPIKeyIsTerminal(t *testing.T) {
	// A key that verifies but whose user row is gone must also 401 at
	// the api-key layer rather than fall through to JWT verification.
	apiKeySvc := &mockAPIKeyService{
		verifyFn: func(string) (*models.APIKey, error) {
			return &models.APIKey{ID: uuid.New(), UserID: uuid.New()}, nil
		},
	}
	userRepo := &mockUserRepo{
		getByIDFn: func(uuid.UUID) (*models.User, error) {
			return nil, errors.New("user not found")
		},
	}

	w := runMiddlewareExpectingRejection(t, apiKeySvc, userRepo, "tfe-orphaned-key")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: want 401, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid or revoked API token") {
		t.Errorf("body must carry the truthful detail, got: %s", w.Body.String())
	}
}

func TestAuthenticateMiddleware_UserBoundTokenSetsNoOrg(t *testing.T) {
	userID := uuid.New()
	apiKey := &models.APIKey{
		ID:             uuid.New(),
		UserID:         userID,
		Kind:           models.APIKeyKindUser,
		OrganizationID: nil,
	}
	user := &models.User{ID: userID, Email: "user@example.com", Name: "PAT User"}

	got := runMiddlewareWithAPIKey(t, apiKey, user)

	if got["token_kind"] != models.APIKeyKindUser {
		t.Errorf("token_kind: want %q, got %v", models.APIKeyKindUser, got["token_kind"])
	}
	if _, present := got["token_org_id"]; present {
		t.Errorf("user-bound token must NOT set token_org_id, got %v", got["token_org_id"])
	}
}
