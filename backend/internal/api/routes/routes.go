// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package routes

import (
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/handlers"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	v2handlers "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers"
	v2routes "github.com/michielvha/stackweaver/backend/internal/api/v2/routes"
	"github.com/michielvha/stackweaver/backend/internal/services/activity"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/profile"
	"github.com/michielvha/stackweaver/backend/internal/services/sessions"
	"github.com/michielvha/stackweaver/backend/internal/services/totp"
	"github.com/michielvha/stackweaver/core/queue"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"gorm.io/gorm"
)

func SetupRoutes(
	db *gorm.DB,
	authService *auth.Service,
	totpService *totp.Service,
	profileService *profile.Service,
	sessionsService *sessions.Service,
	apiKeyService *apikey.Service,
	githubAppManager *vcs.GitHubAppManager,
	authProxy *v2handlers.AuthProxy,
) *gin.Engine {
	r := gin.Default()

	// Round 25c Finding C-3 (CRITICAL): lock down trusted proxies.
	// Gin's default trusts all proxies, so any peer can spoof the
	// client IP via X-Forwarded-For. Combined with the per-IP rate
	// limiter (and per-IP decoy keying) this neutralises every per-
	// IP cap and lets an attacker mint unbounded fresh limiter
	// buckets for memory exhaustion. Operators behind a reverse
	// proxy/k8s ingress set TRUSTED_PROXIES (comma-separated CIDRs);
	// when unset we trust no proxies and `c.ClientIP()` falls back
	// to the direct connection address.
	if trusted := os.Getenv("TRUSTED_PROXIES"); trusted != "" {
		proxies := []string{}
		for p := range strings.SplitSeq(trusted, ",") {
			if p = strings.TrimSpace(p); p != "" {
				proxies = append(proxies, p)
			}
		}
		_ = r.SetTrustedProxies(proxies)
	} else {
		_ = r.SetTrustedProxies(nil)
	}

	// Middleware
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.NewIPRateLimiter(100, 200).Middleware())

	// Health check (supports both GET and HEAD for healthchecks)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.HEAD("/health", func(c *gin.Context) {
		c.Status(200)
	})

	// Terraform Service Discovery (public endpoint - no auth required)
	// GET /.well-known/terraform.json
	r.GET("/.well-known/terraform.json", v2handlers.HandleServiceDiscovery)

	// ==========================================
	// Terraform CLI login (login.v1) — OAuth2 authorization-code + PKCE.
	// Registered on the ROOT router (not the /api/v2 group) so it bypasses the
	// org-resolution wall: the flow is org-agnostic and mints a user-bound
	// token. MintCode is Bearer-authed (the SPA session); Token is public (the
	// CLI has no session yet — PKCE + the one-time code are the authentication).
	// ==========================================
	setupOAuthLoginRoutes(r, authService, apiKeyService)

	// ==========================================
	// Webhook Routes (no auth - uses signature validation)
	// ==========================================
	webhookSecret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	playbookRepo := repository.NewAnsiblePlaybookRepository(db)
	vcsRepo := repository.NewVCSConnectionRepository(db)
	githubWebhookHandler := handlers.NewGitHubWebhookHandler(playbookRepo, vcsRepo, nil, webhookSecret)

	webhooks := r.Group("/api/v2/webhooks")
	{
		webhooks.POST("/github", githubWebhookHandler.HandleWebhook)
	}

	// ==========================================
	// Auth Proxy Routes (unauthenticated — login flow, /auth/* at root per DR-5)
	// These routes proxy requests to Zitadel for the custom login UI.
	// NOT under /api/v2/* — responses use Zitadel's v2 API shape, not JSON:API.
	// ==========================================
	if authProxy != nil {
		setupAuthProxyRoutes(r, authProxy)
	}

	// Setup v2 API routes
	v2routes.SetupV2Routes(r, db, authService, githubAppManager)

	// API v1
	v1 := r.Group("/api/v1")
	v1.Use(middleware.AuthMiddleware(authService))

	// Settings endpoints (v2)
	settings := r.Group("/api/v2/settings")
	settings.Use(middleware.AuthMiddleware(authService))
	{
		// 2FA Settings (only if TOTP service is available)
		if totpService != nil {
			totpHandler := handlers.NewTOTPHandler(totpService, authService)
			twoFA := settings.Group("/2fa")
			{
				twoFA.GET("/status", totpHandler.GetTOTPStatus)
				twoFA.POST("/start", totpHandler.StartTOTPRegistration)
				twoFA.POST("/verify", totpHandler.VerifyTOTP)
				twoFA.DELETE("", totpHandler.RemoveTOTP)
			}
			settings.POST("/password", totpHandler.ChangePassword)
			settings.GET("/mfa-devices", totpHandler.ListMFADevices)
		}

		// Profile Settings
		userRepo := repository.NewUserRepository(db)
		profileHandler := handlers.NewProfileHandler(profileService, authService, userRepo)
		settings.GET("/profile", profileHandler.GetProfile)
		settings.PATCH("/profile", profileHandler.UpdateProfile)

		// Sessions Settings (only if sessions service is available)
		if sessionsService != nil {
			sessionsHandler := handlers.NewSessionsHandler(sessionsService, authService)
			settings.GET("/sessions", sessionsHandler.ListSessions)
			settings.DELETE("/sessions/:sessionId", sessionsHandler.RevokeSession)
		}

		// API Keys Settings
		if apiKeyService != nil {
			auditLogRepo := repository.NewAuditLogRepository(db)
			activityService := activity.NewService(auditLogRepo)
			apiKeyHandler := handlers.NewAPIKeyHandler(apiKeyService, authService, activityService)
			settings.GET("/api-keys", apiKeyHandler.ListAPIKeys)
			settings.POST("/api-keys", apiKeyHandler.CreateAPIKey)
			settings.DELETE("/api-keys/:id", apiKeyHandler.DeleteAPIKey)
		}
	}

	return r
}

// setupOAuthLoginRoutes wires the Terraform CLI login.v1 endpoints. It opens a
// dedicated Redis connection for the short-lived one-time authorization-code
// store. If Redis is unavailable the feature is disabled (discovery still
// advertises login.v1, but no exchange endpoint is registered) rather than
// blocking startup — mirroring how log streaming degrades.
func setupOAuthLoginRoutes(r *gin.Engine, authService *auth.Service, apiKeyService *apikey.Service) {
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		host = "localhost"
	}
	port := 6379
	if portStr := os.Getenv("REDIS_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	password := os.Getenv("REDIS_PASSWORD")

	redisQueue, err := queue.NewRedisQueue(host, port, password, 0)
	if err != nil {
		logger.Warnf("Failed to initialize Redis for terraform login (login.v1): %v (CLI login will be disabled)", err)
		return
	}

	oauthHandler := v2handlers.NewOAuthLoginHandler(apiKeyService, authService, redisQueue.Client())

	// MintCode requires the SPA Bearer session; Token is public (PKCE + code).
	r.POST("/api/v2/oauth/authorize", middleware.AuthMiddleware(authService), oauthHandler.MintCode)
	r.POST("/api/v2/oauth/token", oauthHandler.Token)
}

// setupAuthProxyRoutes registers all /auth/* routes for the custom login UI proxy.
// These routes are unauthenticated (the user hasn't logged in yet) and proxy
// requests to Zitadel using the service account PAT (server-side only).
// CSRF protection is applied to mutating methods via Origin/Referer validation.
func setupAuthProxyRoutes(r *gin.Engine, proxy *v2handlers.AuthProxy) {
	// Auth-specific rate limiter: stricter than the global one (10 req/s, burst 20)
	authRateLimiter := middleware.NewIPRateLimiter(10, 20)

	// CSRF protection on mutating methods
	// Allowed origins match the CORS middleware (localhost variants + CORS_EXTRA_ORIGINS)
	allowedOrigins := []string{
		"http://localhost:5173",
		"http://localhost:3000",
		"http://localhost:5174",
		"http://127.0.0.1:5173",
		"http://127.0.0.1:3000",
		"http://127.0.0.1:5174",
	}
	if extra := os.Getenv("CORS_EXTRA_ORIGINS"); extra != "" {
		for o := range strings.SplitSeq(extra, ",") {
			if o = strings.TrimSpace(o); o != "" {
				allowedOrigins = append(allowedOrigins, o)
			}
		}
	}

	auth := r.Group("/auth")
	auth.Use(middleware.SecurityHeaders())
	// Round 25c Finding C-2 (CRITICAL): cap request bodies on the
	// unauth /auth/* surface. Every legitimate auth body is small
	// (loginName, password, TOTP, passkey assertion); 64KiB is
	// generous enough that no real flow trips it but tight enough
	// to bound memory under flood.
	auth.Use(middleware.MaxBodyBytes(64 * 1024))
	auth.Use(authRateLimiter.Middleware())
	auth.Use(middleware.CSRFProtection(allowedOrigins))
	{
		// OIDC proxy endpoints (A2)
		oidc := auth.Group("/oidc")
		{
			oidc.GET("/authorize", proxy.Authorize)
			oidc.POST("/token", proxy.TokenExchange)
			oidc.GET("/keys", proxy.JWKSProxy)
			oidc.GET("/userinfo", proxy.UserinfoProxy)
			oidc.POST("/end-session", proxy.EndSession)
			oidc.GET("/end-session", proxy.EndSession) // OIDC RP-Initiated Logout uses GET
			oidc.GET("/discovery", proxy.OIDCDiscovery)
		}

		// Auth request endpoints (A3)
		oidc.GET("/auth-requests/:id", proxy.GetAuthRequest)
		auth.POST("/oidc/finalize", proxy.FinalizeAuthRequest)

		// Session API proxy (A4)
		auth.POST("/sessions", proxy.CreateSession)
		auth.PATCH("/sessions/:id", proxy.UpdateSession)
		auth.GET("/sessions/:id", proxy.GetSession)
		auth.DELETE("/sessions/:id", proxy.DeleteSession)
		auth.POST("/sessions/search", proxy.SearchSessions)

		// IdP proxy (A5)
		idp := auth.Group("/idp")
		{
			idp.POST("/start", proxy.StartIdP)
			idp.POST("/complete/:intentId", proxy.CompleteIdP)
			idp.GET("/providers", proxy.ListIdpProviders)
		}

		// User management proxy (A6)
		users := auth.Group("/users")
		{
			users.POST("", proxy.CreateUser)
			users.GET("/:id", proxy.GetUserByID)
			users.POST("/:id/password-reset", proxy.PasswordReset)
			users.POST("/:id/password", proxy.ChangePassword)
			users.POST("/:id/totp", proxy.RegisterTOTP)
			users.POST("/:id/totp/verify", proxy.VerifyTOTP)
			users.POST("/:id/passkeys", proxy.RegisterPasskey)
			users.POST("/:id/passkeys/:pkId", proxy.VerifyPasskey)
			users.POST("/:id/u2f", proxy.RegisterU2F)
			users.POST("/:id/u2f/:u2fId", proxy.VerifyU2F)
			users.POST("/:id/otp-email", proxy.EnableOTPEmail)
			users.POST("/:id/otp-sms", proxy.EnableOTPSMS)
			users.POST("/:id/email", proxy.VerifyEmail)
			users.GET("/:id/authentication_methods", proxy.ListAuthMethods)
		}

		// Settings proxy (A7)
		settings := auth.Group("/settings")
		{
			settings.GET("/login", proxy.GetLoginSettings)
			settings.GET("/password-complexity", proxy.GetPasswordComplexity)
			settings.GET("/branding", proxy.GetBrandingSettings)
			settings.GET("/password-expiry", proxy.GetPasswordExpiry)
			settings.GET("/lockout", proxy.GetLockoutSettings)
			settings.GET("/legal", proxy.GetLegalSettings)
			settings.GET("/security", proxy.GetSecuritySettings)
		}

		// Org discovery (A7.1, AC-36) — maps an email domain to its org so the
		// SPA can scope subsequent auth when allowDomainDiscovery is enabled.
		auth.GET("/orgs/by-domain", proxy.LookupOrgByDomain)

		// Round 27 Wave 15 — runtime probe of auth-proxy config state
		// (backchannel binding, production_mode). Lets the E2E suite
		// assert R24-8 without scraping container logs.
		auth.GET("/health/auth-proxy", proxy.HealthAuthProxy)

		// Testing hook (A14) — only registered in builds with the `e2e` tag.
		// Production binaries get a no-op implementation (see testing_noop.go).
		registerTestingRoutes(auth, authRateLimiter, proxy)
	}
}
