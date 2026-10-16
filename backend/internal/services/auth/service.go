// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/logtoken"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// shortTokenID returns a 16-hex-char SHA-256 prefix of the token, suitable
// for opaque correlation in debug logs without revealing token bytes.
// Round 25 hardening (item 16): the previous implementation logged the
// first 10 raw chars of the token at Debug, leaking enough entropy to
// be useful in a log-correlation attack on TFE-style tokens. SHA-256 is
// one-way; the hex prefix is enough to match an audit-log record back to
// a Debug breadcrumb but cannot be back-walked to the source token.
func shortTokenID(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:16]
}

// APIKeyVerifier interface for API key verification
type APIKeyVerifier interface {
	VerifyAPIKey(key string) (*models.APIKey, error)
	UpdateLastUsed(id uuid.UUID) error
	// IsTeamMember reports whether a user belongs to a team, which decides whether a key
	// scoped to that team acts as it.
	IsTeamMember(teamID, userID uuid.UUID) (bool, error)
	// ActiveAPIKey returns the key with this id while it exists and has not expired.
	ActiveAPIKey(id uuid.UUID) (*models.APIKey, error)
}

// TeamSyncer interface for automatic team assignment based on SSO group claims
type TeamSyncer interface {
	IsEnabled() bool
	SyncUserTeams(ctx context.Context, userID uuid.UUID, ssoGroups []string) error
}

// UserLookup is the subset of `repository.UserRepository` the auth
// service depends on. Defined as an interface so unit tests can pass
// a mock without a live database. The concrete repo satisfies it
// implicitly.
type UserLookup interface {
	GetByID(id uuid.UUID) (*models.User, error)
	GetOrCreateByZitadelSubject(subject, email, name string) (*models.User, error)
}

type Service struct {
	userRepo      UserLookup
	apiKeyService APIKeyVerifier
	teamSyncer    TeamSyncer
	verifier      *ZitadelVerifier
	issuer        string
	clientID      string
	verified      verifiedCache
}

// ErrEmailNotVerified means the account has an email address Zitadel has not verified. Such an
// account does not reach the platform (#829 D5): it gets no users row and claims no invitation.
var ErrEmailNotVerified = errors.New("the account's email address is not verified")

// ErrIdentityUnavailable means Zitadel could not be asked about the account, and there is no
// recent verified result to fall back on. The request fails closed.
var ErrIdentityUnavailable = errors.New("the identity provider could not be reached")

// verifiedCache remembers subjects Zitadel recently reported as verified, until their token
// expires (#829 Q14), so a brief Zitadel outage does not cut off users who were already in.
type verifiedCache struct {
	mu    sync.Mutex
	until map[string]time.Time
}

const verifiedCacheMax = 10000

func (v *verifiedCache) mark(subject string, until time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.until == nil || len(v.until) >= verifiedCacheMax {
		v.until = make(map[string]time.Time) // bounded: start over rather than grow without limit
	}
	v.until[subject] = until
}

func (v *verifiedCache) has(subject string, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return now.Before(v.until[subject])
}

// userFromJWT is the one place a verified JWT becomes a platform user, used by
// Authenticate (#829 D5). It refuses an account whose email is
// unverified before any users row is written, so an invitation placeholder for that address stays
// unclaimed until the person verifies. Accounts without an email (machine users) are not subject
// to the check: they cannot self-register or claim an invitation. When Zitadel cannot be reached,
// a subject verified within its token's lifetime proceeds and any other fails closed.
func (s *Service) userFromJWT(ctx context.Context, claims *oidc.AccessTokenClaims, claimsMap map[string]interface{}, tokenString string) (*models.User, *UserInfo, error) {
	info, err := ExtractUserInfo(ctx, claims, claimsMap, s.issuer, tokenString, s.verifier.httpClient, s.verifier.internalAddr, s.verifier.hostOverride)
	switch {
	case err != nil:
		if !s.verified.has(claims.Subject, time.Now()) {
			return nil, nil, fmt.Errorf("%w: %w", ErrIdentityUnavailable, err)
		}
		logger.Warnf("auth: %v; using the cached verified state for %s", err, claims.Subject)
		info = &UserInfo{Subject: claims.Subject, ID: claims.Subject}
	case info.Email != "" && !info.EmailVerified:
		return nil, info, ErrEmailNotVerified
	case info.Email != "":
		s.verified.mark(claims.Subject, claims.GetExpiration())
	}

	user, err := s.userRepo.GetOrCreateByZitadelSubject(info.Subject, info.Email, info.Name)
	if err != nil {
		return nil, info, fmt.Errorf("getting or creating the user for %q: %w", info.Subject, err)
	}
	return user, info, nil
}

// NewService constructs the auth service with the production repos.
// The signature accepts the concrete `*repository.UserRepository` so
// production callers stay simple - Go's structural typing means the
// concrete repo satisfies the `UserLookup` interface automatically.
func NewService(userRepo *repository.UserRepository) *Service {
	return &Service{
		userRepo: userRepo,
	}
}

// NewServiceWithLookups is the test-friendly constructor - accepts
// the lookup interface directly so unit tests can pass a mock
// without depending on the concrete repo type or a live database.
// Production callers should keep using `NewService`.
func NewServiceWithLookups(userRepo UserLookup) *Service {
	return &Service{
		userRepo: userRepo,
	}
}

// SetAPIKeyService sets the API key service for authentication
func (s *Service) SetAPIKeyService(apiKeyService APIKeyVerifier) {
	s.apiKeyService = apiKeyService
}

// SetTeamSyncer sets the team sync service for automatic SSO team assignment
func (s *Service) SetTeamSyncer(syncer TeamSyncer) {
	s.teamSyncer = syncer
}

// InitializeZitadel initializes the Zitadel verifier with configuration.
// internalAddr (e.g. "localhost:8080") is used to fetch JWKS keys internally
// when the issuer is an external domain, avoiding public internet round-trips.
func (s *Service) InitializeZitadel(issuer, clientID, clientSecret, internalAddr string) error {
	verifier, err := NewZitadelVerifier(issuer, clientID, clientSecret, internalAddr)
	if err != nil {
		return fmt.Errorf("failed to create Zitadel verifier: %w", err)
	}
	s.verifier = verifier
	s.issuer = issuer
	s.clientID = clientID
	return nil
}

// RegisterAudience adds a client_id the Zitadel verifier will accept in an access token's
// `aud` (AUD-012). Register both the API and the frontend PKCE client so real user tokens
// (issued to the frontend client) are accepted while tokens for other clients are rejected.
func (s *Service) RegisterAudience(clientID string) {
	if s.verifier != nil {
		s.verifier.AcceptAudience(clientID)
	}
}

func (s *Service) GetUserFromContext(c *gin.Context) (*models.User, error) {
	userID, exists := c.Get("user_id")
	if !exists {
		return nil, errors.New("user not authenticated")
	}

	id, ok := userID.(uuid.UUID)
	if !ok {
		return nil, errors.New("invalid user ID in context")
	}

	user, err := s.userRepo.GetByID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// AuthError is an authentication failure and the response it calls for.
type AuthError struct {
	Status int
	Title  string
	Detail string
}

func (e *AuthError) Error() string { return e.Detail }

// Authenticate verifies a credential, a `tfe-` API token or a Zitadel JWT, and establishes the
// caller on the request: the user, and for an API token its kind, its organization and the
// subject it is judged as (rbac.Subject). Every place that accepts a credential, whether from the
// Authorization header or elsewhere, goes through it, so a token is the same token wherever it
// arrives. It sets nothing on failure and returns an *AuthError.
func (s *Service) Authenticate(c *gin.Context, tokenString string) error {
	logger.Debugf("auth: received token (id: %s) for %s %s", shortTokenID(tokenString), c.Request.Method, c.Request.URL.Path)

	// Programmatic tokens carry the "tfe-" prefix (Terraform Cloud compatible). Both org-bound and
	// user-bound tokens are api_keys, so a single api-key lookup resolves them.
	if strings.HasPrefix(tokenString, "tfe-") {
		return s.authenticateAPIKey(c, tokenString)
	}

	// Try JWT token (Zitadel)
	if s.verifier == nil {
		return &AuthError{http.StatusInternalServerError, "Internal Server Error", "authentication service not initialized"}
	}
	claims, claimsMap, err := s.verifier.VerifyToken(c.Request.Context(), tokenString)
	if err != nil {
		// Log the actual error for debugging (but don't expose it to client for security)
		logger.Warnf("auth: token verification failed: %v", err)
		return &AuthError{http.StatusUnauthorized, "Unauthorized", "invalid token"}
	}

	user, userInfo, err := s.userFromJWT(c.Request.Context(), claims, claimsMap, tokenString)
	switch {
	case errors.Is(err, ErrEmailNotVerified):
		return &AuthError{http.StatusForbidden, "Forbidden", "verify your email address to continue"}
	case errors.Is(err, ErrIdentityUnavailable):
		logger.Warnf("auth: %v", err)
		return &AuthError{http.StatusServiceUnavailable, "Service Unavailable", "the identity provider could not be reached; try again shortly"}
	case err != nil:
		logger.Errorf("auth: %v", err)
		return &AuthError{http.StatusInternalServerError, "Internal Server Error", "failed to get or create user"}
	}
	logger.Infof("Auth: Subject=%s Email=%s Groups=%v", userInfo.Subject, userInfo.Email, userInfo.Groups)

	// Store local user UUID in context (not Zitadel subject)
	c.Set("user_id", user.ID)
	c.Set("user_email", user.Email)
	c.Set("user_name", user.Name)
	c.Set("user_subject", userInfo.Subject)
	c.Set("token_claims", claims)
	c.Set("auth_method", "jwt")

	// Store SSO groups in context for downstream team sync
	if len(userInfo.Groups) > 0 {
		c.Set("sso_groups", userInfo.Groups)

		// Trigger automatic team sync based on SSO group claims
		if s.teamSyncer != nil && s.teamSyncer.IsEnabled() {
			if err := s.teamSyncer.SyncUserTeams(c.Request.Context(), user.ID, userInfo.Groups); err != nil {
				logger.Errorf("TeamSync failed for user %s: %v", user.ID, err)
				// Don't block authentication on team sync failure
			}
		}
	}
	return nil
}

func (s *Service) authenticateAPIKey(c *gin.Context, tokenString string) error {
	// The "tfe-" prefix is authoritative (#503): an API token is never a JWT, so a lookup miss is
	// terminal. Falling through to JWT verification surfaced revoked/unknown keys as "token is not
	// a JWT (got opaque token)" - misdirecting operators toward Zitadel configuration instead of
	// the token's lifecycle.
	rejected := &AuthError{http.StatusUnauthorized, "Unauthorized", "invalid or revoked API token"}
	if s.apiKeyService == nil {
		return rejected
	}
	apiKey, err := s.apiKeyService.VerifyAPIKey(tokenString)
	if err != nil || apiKey == nil {
		logger.Warnf("auth: api token rejected: unknown or revoked (id: %s)", shortTokenID(tokenString))
		return rejected
	}
	return s.establishAPIKey(c, apiKey)
}

// establishAPIKey establishes a verified API key as the request's caller: its user, its kind, its
// organization and the subject it is judged as.
func (s *Service) establishAPIKey(c *gin.Context, apiKey *models.APIKey) error {
	rejected := &AuthError{http.StatusUnauthorized, "Unauthorized", "invalid or revoked API token"}
	user, err := s.userRepo.GetByID(apiKey.UserID)
	if err != nil {
		return rejected
	}
	// The subject is resolved before anything is set, so a failure leaves the request untouched.
	subj, scoped, err := rbac.SubjectForAPIKey(apiKey, s.apiKeyService.IsTeamMember)
	if err != nil {
		logger.Errorf("auth: resolving the scope of api token %s: %v", apiKey.ID, err)
		return &AuthError{http.StatusInternalServerError, "Internal Server Error", "failed to resolve the token's scope"}
	}
	_ = s.apiKeyService.UpdateLastUsed(apiKey.ID)

	c.Set("user_id", user.ID)
	c.Set("user_email", user.Email)
	c.Set("user_name", user.Name)
	c.Set("auth_method", "api_key")
	// Store API key details for runner registration and scope checks
	c.Set("api_key_id", apiKey.ID)
	c.Set("api_key_scopes", []string(apiKey.Scopes))
	c.Set("api_key", apiKey)
	// Org-resolution wall inputs: the token's kind drives how the target org is authorized. An
	// org-bound token also carries its bound org id; a user-bound token carries none (authorized
	// by the user's memberships at the wall instead).
	c.Set("token_kind", apiKey.Kind)
	if apiKey.OrganizationID != nil {
		c.Set("token_org_id", *apiKey.OrganizationID)
	}
	// A token scoped to a team or a project is judged as that team or project by every permission
	// check, not as its owner, whose id stays in user_id for attribution only. See rbac.Subject.
	if scoped {
		c.Request = c.Request.WithContext(rbac.WithSubject(c.Request.Context(), subj))
	}
	return nil
}

// authenticateLogToken establishes the credential a run-bound log token was minted for, as it
// stands now: the API key while it exists and has not expired, judged with its current scope and
// subject, or the session's user while the user exists. The token itself grants nothing, so a
// revoked key reads no more logs, and the org wall and the run's authorization judge the
// credential exactly as they would judge it in the Authorization header.
func (s *Service) authenticateLogToken(c *gin.Context, cred logtoken.Credential) error {
	rejected := &AuthError{http.StatusUnauthorized, "Unauthorized", "invalid or revoked log token"}
	if cred.APIKeyID != uuid.Nil {
		if s.apiKeyService == nil {
			return rejected
		}
		apiKey, err := s.apiKeyService.ActiveAPIKey(cred.APIKeyID)
		if err != nil || apiKey == nil {
			return rejected
		}
		if err := s.establishAPIKey(c, apiKey); err != nil {
			return rejected
		}
		return nil
	}
	user, err := s.userRepo.GetByID(cred.UserID)
	if err != nil {
		return rejected
	}
	c.Set("user_id", user.ID)
	c.Set("user_email", user.Email)
	c.Set("user_name", user.Name)
	c.Set("auth_method", "log_token")
	return nil
}

// runIDFromLogPath returns the run id of a run log route.
func runIDFromLogPath(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/api/v2/runs/"), "/")
	return parts[0]
}

// isRunLogPath reports whether path is one of the run log routes, which also accept a credential
// in ?token= (the TFE log-read-url the Terraform CLI fetches without its Authorization header).
func isRunLogPath(path string) bool {
	if !strings.HasPrefix(path, "/api/v2/runs/") {
		return false
	}
	return strings.HasSuffix(path, "/logs") || strings.HasSuffix(path, "/logs/plan") || strings.HasSuffix(path, "/logs/apply")
}

func (s *Service) AuthenticateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip authentication for OPTIONS requests (CORS preflight)
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		// TFE-compatible: the run log routes also take a credential in ?token=, either a credential
		// itself or the run-bound log token of a log-read-url. Both are authenticated here exactly as
		// a header credential is, so the org wall and every permission check judge them the same
		// way; a log token re-establishes the credential it was minted for, as that credential
		// stands now.
		if isRunLogPath(c.Request.URL.Path) && c.Query("token") != "" {
			tokenFromQuery := c.Query("token")
			err := s.Authenticate(c, tokenFromQuery)
			if err != nil {
				if cred, ok := logtoken.Verify(tokenFromQuery, runIDFromLogPath(c.Request.URL.Path)); ok {
					err = s.authenticateLogToken(c, cred)
				}
			}
			if err == nil {
				c.Next()
				return
			}
			if c.GetHeader("Authorization") == "" {
				var authErr *AuthError
				if !errors.As(err, &authErr) {
					authErr = &AuthError{http.StatusUnauthorized, "Unauthorized", "invalid token"}
				}
				jsonapi.WriteError(c, authErr.Status, authErr.Title, authErr.Detail)
				c.Abort()
				return
			}
		}

		// Extract token from Authorization header (standard TFE authentication)
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.Debugf("auth: missing authorization header for path: %s", c.Request.URL.Path)
			jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "missing authorization header")
			c.Abort()
			return
		}

		// Check for Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "invalid authorization header format")
			c.Abort()
			return
		}

		if err := s.Authenticate(c, parts[1]); err != nil {
			var authErr *AuthError
			if !errors.As(err, &authErr) {
				authErr = &AuthError{http.StatusUnauthorized, "Unauthorized", "invalid token"}
			}
			jsonapi.WriteError(c, authErr.Status, authErr.Title, authErr.Detail)
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *Service) GetUserID(ctx context.Context) (uuid.UUID, error) {
	// Try to get from gin context if available
	if c, ok := ctx.(*gin.Context); ok {
		userID, exists := c.Get("user_id")
		if exists {
			if idStr, ok := userID.(string); ok {
				// Try to parse as UUID
				if id, err := uuid.Parse(idStr); err == nil {
					return id, nil
				}
				// If not a UUID, return error
				return uuid.Nil, fmt.Errorf("user_id is not a valid UUID: %s", idStr)
			}
		}
	}
	return uuid.Nil, errors.New("user not authenticated")
}

// GetUserSubject returns the Zitadel subject (user ID) from context
func (s *Service) GetUserSubject(c *gin.Context) (string, error) {
	subject, exists := c.Get("user_subject")
	if !exists {
		return "", errors.New("user not authenticated")
	}
	subjectStr, ok := subject.(string)
	if !ok {
		return "", errors.New("invalid subject type")
	}
	return subjectStr, nil
}

// GetTokenClaims returns the token claims from context
func (s *Service) GetTokenClaims(c *gin.Context) (*oidc.AccessTokenClaims, error) {
	claims, exists := c.Get("token_claims")
	if !exists {
		return nil, errors.New("token claims not found")
	}
	tokenClaims, ok := claims.(*oidc.AccessTokenClaims)
	if !ok {
		return nil, errors.New("invalid token claims type")
	}
	return tokenClaims, nil
}

// FetchUserInfoPicture calls the OIDC UserInfo endpoint and returns the picture URL.
// Returns empty string if the user has no avatar or the call fails.
// Only works for JWT auth (requires a valid access token).
func (s *Service) FetchUserInfoPicture(ctx context.Context, c *gin.Context) string {
	// Only fetch for JWT auth - API key / TFE token don't work with Zitadel UserInfo
	authMethod, _ := c.Get("auth_method")
	if authMethod != "jwt" {
		return ""
	}

	// Extract Bearer token from Authorization header
	authHeader := c.GetHeader("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}
	tokenString := parts[1]

	if s.verifier == nil || s.issuer == "" {
		return ""
	}

	userInfoData, err := fetchUserInfoFromEndpoint(ctx, s.issuer, tokenString, s.verifier.httpClient, s.verifier.internalAddr, s.verifier.hostOverride)
	if err != nil {
		logger.Warnf("auth: %v", err)
		return ""
	}

	if picture, ok := userInfoData["picture"].(string); ok {
		return picture
	}
	return ""
}
