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

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/logtoken"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
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

// PlatformAdminSeeder applies the deployment's declared platform administrators to a user at
// sign-in (#132, D2). It is handed the user row and the identity the sign-in verified, so it
// matches on the email the identity provider verified now and never on the stored column.
// Declared here, where it is used: the implementation lives in the platformadmin package, which
// imports this one.
type PlatformAdminSeeder interface {
	ApplyDeclared(ctx context.Context, user *models.User, id BrowserIdentity) error
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
	adminSeeder   PlatformAdminSeeder
	verifier      *ZitadelVerifier
	issuer        string
	clientID      string
	sessions      *Sessions
	sessionCheck  func(*http.Request) error
}

// CodeAuthenticationRequired is the JSON:API error `code` of a 401 that means the browser has no
// usable session. The SPA signs out on it, and only on it, so a 401 passed through from another
// service does not end the user's session.
const CodeAuthenticationRequired = "authentication-required"

// CodeEmailNotVerified is the JSON:API error `code` of the 403 a sign-in gets for an account whose
// email address is not verified, so the SPA can tell it from any other refusal.
const CodeEmailNotVerified = "email-not-verified"

// SetSessionRequestCheck sets the CSRF defence every cookie-authenticated request must pass (the
// custom header and the origin allowlist; see middleware.OriginPolicy.CheckBrowserRequest). The
// cookie is sent by the browser on its own, so without a check it would be accepted from any
// page; with none set, the cookie credential is refused.
func (s *Service) SetSessionRequestCheck(check func(*http.Request) error) {
	s.sessionCheck = check
}

// SetBrowserSessions enables the session-cookie credential: a request with no Authorization
// header is authenticated by its __Host-sw_session cookie.
func (s *Service) SetBrowserSessions(ss *Sessions) {
	s.sessions = ss
}

// ErrEmailNotVerified means the account has an email address Zitadel has not verified. Such an
// account does not reach the platform (#829 D5): it gets no users row and claims no invitation.
var ErrEmailNotVerified = errors.New("the account's email address is not verified")

// NewService constructs the auth service with the production repos.
// The signature accepts the concrete `*repository.UserRepository` so
// production callers stay simple - Go's structural typing means the
// concrete repo satisfies the `UserLookup` interface automatically.
func NewService(userRepo *repository.UserRepository) *Service {
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

// SetPlatformAdminSeeder sets the service that applies the declared platform administrators at
// sign-in.
func (s *Service) SetPlatformAdminSeeder(seeder PlatformAdminSeeder) {
	s.adminSeeder = seeder
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
// `aud` (AUD-012). The access token verified at sign-in is issued to the BFF client, so that
// client is registered; tokens for other clients are rejected.
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
	// Code is the JSON:API error code, set where a client must act on the refusal.
	Code string
}

func (e *AuthError) Error() string { return e.Detail }

// Authenticate verifies a `tfe-` API token and establishes the caller on the request: the user, and for an API token its kind, its organization and the
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

	// Any other value is refused. A Zitadel access token is not a credential for the API: the
	// browser authenticates with its session cookie (backend-for-frontend-session-plan.md, AC32).
	return &AuthError{Status: http.StatusUnauthorized, Title: "Unauthorized", Detail: "invalid token"}
}

func (s *Service) authenticateAPIKey(c *gin.Context, tokenString string) error {
	// The "tfe-" prefix is authoritative (#503): an API token is never a JWT, so a lookup miss is
	// terminal. Falling through to JWT verification surfaced revoked/unknown keys as "token is not
	// a JWT (got opaque token)" - misdirecting operators toward Zitadel configuration instead of
	// the token's lifecycle.
	rejected := &AuthError{Status: http.StatusUnauthorized, Title: "Unauthorized", Detail: "invalid or revoked API token"}
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
	rejected := &AuthError{Status: http.StatusUnauthorized, Title: "Unauthorized", Detail: "invalid or revoked API token"}
	user, err := s.userRepo.GetByID(apiKey.UserID)
	if err != nil {
		return rejected
	}
	// The subject is resolved before anything is set, so a failure leaves the request untouched.
	subj, scoped, err := rbac.SubjectForAPIKey(apiKey, s.apiKeyService.IsTeamMember)
	if err != nil {
		logger.Errorf("auth: resolving the scope of api token %s: %v", apiKey.ID, err)
		return &AuthError{Status: http.StatusInternalServerError, Title: "Internal Server Error", Detail: "failed to resolve the token's scope"}
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
// subject, or the user of the browser session that minted it while that session is live. The token itself grants nothing, so a
// revoked key reads no more logs, and the org wall and the run's authorization judge the
// credential exactly as they would judge it in the Authorization header.
func (s *Service) authenticateLogToken(c *gin.Context, cred logtoken.Credential) error {
	rejected := &AuthError{Status: http.StatusUnauthorized, Title: "Unauthorized", Detail: "invalid or revoked log token"}
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
	if cred.BrowserSessionID == uuid.Nil || s.sessions == nil {
		return rejected
	}
	session, err := s.sessions.ResolveID(c.Request.Context(), cred.BrowserSessionID)
	if err != nil {
		return rejected
	}
	user, err := s.userRepo.GetByID(session.UserID)
	if err != nil {
		return rejected
	}
	c.Set("user_id", user.ID)
	c.Set("user_email", user.Email)
	c.Set("user_name", user.Name)
	c.Set("auth_method", "log_token")
	return nil
}

// authenticateSession establishes the user of the request's browser session: the
// __Host-sw_session cookie, looked up by its hash and checked against Zitadel when a check is due.
// The request is an interactive user's, so it carries no token kind and the org wall judges it by
// the user's memberships. It sets nothing on failure.
func (s *Service) authenticateSession(c *gin.Context) error {
	required := func(detail string) error {
		return &AuthError{Status: http.StatusUnauthorized, Title: "Unauthorized", Detail: detail, Code: CodeAuthenticationRequired}
	}
	raw, err := c.Cookie(SessionCookieName)
	if err != nil || raw == "" {
		logger.Debugf("auth: no credential for path: %s", c.Request.URL.Path)
		return required("not signed in")
	}
	if s.sessions == nil {
		return required("not signed in")
	}
	// The CSRF defence comes before the lookup, so a forged request costs no database read and
	// triggers no liveness check.
	if s.sessionCheck == nil {
		return &AuthError{Status: http.StatusForbidden, Title: "Forbidden", Detail: "browser sessions are not accepted here"}
	}
	if err := s.sessionCheck(c.Request); err != nil {
		logger.Warnf("auth: refusing a session request to %s %s: %v", c.Request.Method, c.Request.URL.Path, err)
		return &AuthError{Status: http.StatusForbidden, Title: "Forbidden", Detail: err.Error()}
	}
	session, err := s.sessions.Resolve(c.Request.Context(), raw)
	switch {
	case errors.Is(err, ErrSessionNotFound):
		return required("not signed in")
	case errors.Is(err, ErrSessionExpired):
		return required("the session has expired; sign in again")
	case errors.Is(err, ErrSessionEnded):
		return required("the session has ended; sign in again")
	case err != nil:
		logger.Errorf("auth: %v", err)
		return &AuthError{Status: http.StatusInternalServerError, Title: "Internal Server Error", Detail: "failed to look up the session"}
	}
	user, err := s.userRepo.GetByID(session.UserID)
	if err != nil {
		return required("not signed in")
	}

	c.Set("user_id", user.ID)
	c.Set("user_email", user.Email)
	c.Set("user_name", user.Name)
	c.Set("user_subject", session.ZitadelSubject)
	c.Set("auth_method", "session")
	c.Set(BrowserSessionContextKey, session)

	// A state-changing request is the person acting, so it counts as activity; a GET does not,
	// so background polling cannot keep a forgotten tab signed in.
	if m := c.Request.Method; m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions {
		if err := s.sessions.Touch(session); err != nil {
			logger.Warnf("auth: %v", err)
		}
	}
	return nil
}

// BrowserSessionContextKey holds the *models.BrowserSession of a cookie-authenticated request.
const BrowserSessionContextKey = "browser_session"

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
					authErr = &AuthError{Status: http.StatusUnauthorized, Title: "Unauthorized", Detail: "invalid token"}
				}
				jsonapi.WriteError(c, authErr.Status, authErr.Title, authErr.Detail)
				c.Abort()
				return
			}
		}

		// Extract token from Authorization header (standard TFE authentication)
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// A request with no Authorization header is the browser's: its credential is the session
			// cookie, and with none it has no credential at all. Both refusals carry the code the
			// SPA signs out on. A request that does carry a header is judged by that header alone,
			// so a valid cookie never rescues an invalid bearer token.
			if err := s.authenticateSession(c); err != nil {
				var authErr *AuthError
				if !errors.As(err, &authErr) {
					authErr = &AuthError{Status: http.StatusUnauthorized, Title: "Unauthorized", Detail: "not signed in"}
				}
				jsonapi.WriteCodedError(c, authErr.Status, authErr.Code, authErr.Title, authErr.Detail)
				c.Abort()
				return
			}
			c.Next()
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
				authErr = &AuthError{Status: http.StatusUnauthorized, Title: "Unauthorized", Detail: "invalid token"}
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

// SessionPicture is the signed-in browser user's avatar, read from the session record (set at
// sign-in and refreshed by the liveness check). Other callers have none.
func (s *Service) SessionPicture(c *gin.Context) string {
	if session, ok := c.Get(BrowserSessionContextKey); ok {
		if bs, ok := session.(*models.BrowserSession); ok {
			return bs.Picture
		}
	}
	return ""
}
