// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/redis/go-redis/v9"
)

// OAuth login (login.v1) — implements the `terraform login <host>` flow.
//
// Terraform discovers `login.v1` via /.well-known/terraform.json, opens the
// system browser at the SPA `authz` page (/oauth/authorize), and binds a
// loopback listener. The SPA — using the authenticated in-browser session —
// calls MintCode (POST /api/v2/oauth/authorize, Bearer) to obtain a one-time
// authorization code, then redirects the browser to Terraform's loopback
// `redirect_uri`. Terraform then exchanges that code at the public Token
// endpoint (POST /api/v2/oauth/token) using PKCE, receiving a TFE-style API
// token.
//
// PKCE (S256) binds the browser-issued code to the CLI process that started
// the flow, so an intercepted code is useless without the matching verifier.
const (
	// oauthClientID is the client identifier advertised in discovery. Terraform
	// echoes it back; we reject anything else.
	oauthClientID = "terraform-cli"

	// oauthLoopbackMinPort / oauthLoopbackMaxPort bound the loopback redirect
	// ports advertised in discovery ("ports": [10000, 10010]).
	oauthLoopbackMinPort = 10000
	oauthLoopbackMaxPort = 10010

	// oauthCodeTTL is how long a minted authorization code stays valid before
	// it must be exchanged. Short by design — the CLI exchanges immediately.
	oauthCodeTTL = 60 * time.Second

	// oauthCodeKeyPrefix namespaces authorization codes in Redis.
	oauthCodeKeyPrefix = "oauth:authcode:"

	// oauthTokenName is the description applied to tokens minted via CLI login.
	oauthTokenName = "terraform login"
)

// OAuthLoginHandler serves the login.v1 endpoints.
type OAuthLoginHandler struct {
	apiKeyService *apikey.Service
	authService   *auth.Service
	redis         *redis.Client
}

// NewOAuthLoginHandler constructs the handler. `redisClient` backs the
// short-lived one-time authorization-code store.
func NewOAuthLoginHandler(apiKeyService *apikey.Service, authService *auth.Service, redisClient *redis.Client) *OAuthLoginHandler {
	return &OAuthLoginHandler{
		apiKeyService: apiKeyService,
		authService:   authService,
		redis:         redisClient,
	}
}

// storedAuthCode is the JSON payload persisted under oauth:authcode:<code>.
type storedAuthCode struct {
	UserID        string `json:"user_id"`
	CodeChallenge string `json:"code_challenge"`
	RedirectURI   string `json:"redirect_uri"`
	ClientID      string `json:"client_id"`
}

// mintCodeRequest is the JSON body the SPA sends to MintCode.
type mintCodeRequest struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	State               string `json:"state"`
}

// MintCode handles POST /api/v2/oauth/authorize.
//
// Authenticated (Bearer) — registered on the root router with an explicit
// AuthMiddleware so it bypasses the org-resolution wall (the flow is
// org-agnostic; the resulting token is user-bound). Validates the PKCE
// challenge and loopback redirect, mints a single-use code bound to the
// caller's user, stores it in Redis with a short TTL, and returns it.
func (h *OAuthLoginHandler) MintCode(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "User not authenticated"}},
		})
		return
	}

	var req mintCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid request body"}},
		})
		return
	}

	if req.ClientID != oauthClientID {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Unsupported client_id"}},
		})
		return
	}

	if req.CodeChallengeMethod != "S256" || req.CodeChallenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "code_challenge_method must be S256 with a non-empty code_challenge"}},
		})
		return
	}

	if !validLoopbackRedirect(req.RedirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "redirect_uri must be a loopback address on an advertised port"}},
		})
		return
	}

	code, err := generateAuthCode()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to generate authorization code"}},
		})
		return
	}

	payload, err := json.Marshal(storedAuthCode{
		UserID:        user.ID.String(),
		CodeChallenge: req.CodeChallenge,
		RedirectURI:   req.RedirectURI,
		ClientID:      req.ClientID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to encode authorization code"}},
		})
		return
	}

	if err := h.redis.Set(c.Request.Context(), oauthCodeKeyPrefix+code, payload, oauthCodeTTL).Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to persist authorization code"}},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": code, "state": req.State})
}

// Token handles POST /api/v2/oauth/token.
//
// Public (no Bearer) — the CLI has no session yet. Authentication is provided
// by the one-time code plus the PKCE verifier. Errors use the RFC 6749 OAuth
// shape (`{"error": "..."}`). On success returns a TFE-style API token.
func (h *OAuthLoginHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	code := c.PostForm("code")
	verifier := c.PostForm("code_verifier")
	redirectURI := c.PostForm("redirect_uri")

	if grantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}
	if code == "" || verifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// GetDel atomically consumes the code so it can never be replayed.
	raw, err := h.redis.GetDel(c.Request.Context(), oauthCodeKeyPrefix+code).Result()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	var stored storedAuthCode
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	if redirectURI != stored.RedirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	if !verifyPKCE(verifier, stored.CodeChallenge) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	userID, err := uuid.Parse(stored.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	_, tokenString, err := h.apiKeyService.CreateUserToken(userID, oauthTokenName, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": tokenString,
		"token_type":   "bearer",
	})
}

// validLoopbackRedirect reports whether raw is an http loopback URL on an
// advertised port. Terraform binds 127.0.0.1/localhost on one of the ports
// from discovery; restricting to those prevents the minted code being
// redirected to an attacker-controlled host.
func validLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	if host := u.Hostname(); host != "localhost" && host != "127.0.0.1" {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return false
	}
	return port >= oauthLoopbackMinPort && port <= oauthLoopbackMaxPort
}

// verifyPKCE reports whether the S256 transform of verifier equals challenge.
// Comparison is constant-time to avoid leaking the challenge via timing.
func verifyPKCE(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// generateAuthCode returns a 256-bit cryptographically random, URL-safe code.
func generateAuthCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
