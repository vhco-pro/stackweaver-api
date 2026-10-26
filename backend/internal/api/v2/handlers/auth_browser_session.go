// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/models"
)

// sessionCookieName carries the browser's session identifier; see auth.SessionCookieName.
const sessionCookieName = auth.SessionCookieName

// sessionResourceType is the JSON:API type of a browser session.
const sessionResourceType = "sessions"

// tokenExchangeTimeout bounds the code exchange with Zitadel.
const tokenExchangeTimeout = 10 * time.Second

// browserSignIn turns a verified sign-in into the platform user. *auth.Service satisfies it.
type browserSignIn interface {
	ProvisionBrowserUser(ctx context.Context, id auth.BrowserIdentity, accessToken string) (*models.User, error)
}

var _ browserSignIn = (*auth.Service)(nil)

// createSessionRequest is the JSON:API document the SPA's callback page posts: the code and state
// Zitadel sent back.
type createSessionRequest struct {
	Data *struct {
		Type       string `json:"type"`
		Attributes struct {
			Code  string `json:"code" binding:"required"`
			State string `json:"state" binding:"required"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

// PrimaryType reports data.type and whether data was sent (jsonapi.TypedDocument).
func (r *createSessionRequest) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
}

// SessionAttributes is what the SPA learns about the signed-in user. It carries no credential.
type SessionAttributes struct {
	Email      string    `json:"email"`
	Name       string    `json:"name"`
	GivenName  string    `json:"given-name"`
	FamilyName string    `json:"family-name"`
	Picture    string    `json:"picture"`
	ExpiresAt  time.Time `json:"expires-at"`
}

func sessionResource(s *models.BrowserSession) jsonapi.Resource[SessionAttributes] {
	return jsonapi.Resource[SessionAttributes]{
		ID:   s.ID.String(),
		Type: sessionResourceType,
		Attributes: SessionAttributes{
			Email:      s.Email,
			Name:       s.Name,
			GivenName:  s.GivenName,
			FamilyName: s.FamilyName,
			Picture:    s.Picture,
			ExpiresAt:  s.AbsoluteExpiresAt,
		},
	}
}

// setSessionCookie sets the browser's session cookie. It is persistent for maxAge seconds (the
// absolute limit); the server-side limits end the session.
func setSessionCookie(c *gin.Context, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// browserSessionsConfigured reports whether the proxy can create and read browser sessions.
func (p *AuthProxy) browserSessionsConfigured() bool {
	return p.browserSignInConfigured() && p.config.BrowserSessions != nil && p.config.SignIn != nil
}

// CreateBrowserSession handles POST /auth/session: it redeems the code from the sign-in redirect
// as the confidential BFF client, verifies the ID token, provisions the user, and starts a server-
// side session whose only trace in the browser is the httpOnly session cookie. No OAuth token is
// stored or returned.
func (p *AuthProxy) CreateBrowserSession(c *gin.Context) {
	if !p.browserSessionsConfigured() {
		jsonapi.WriteError(c, http.StatusServiceUnavailable, "Service Unavailable", "browser sign-in is not configured")
		return
	}
	var req createSessionRequest
	if !jsonapi.BindDocument(c, &req, sessionResourceType) {
		return
	}

	tx, err := p.takeLoginTransaction(c, req.Data.Attributes.State)
	if errors.Is(err, errLoginTransactionRefused) {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "the sign-in expired or was started in another browser; sign in again")
		return
	}
	if err != nil {
		logger.Errorf("auth proxy: %v", err)
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "could not complete sign-in")
		return
	}

	ctx := c.Request.Context()
	idToken, accessToken, err := p.exchangeCode(ctx, req.Data.Attributes.Code, tx.CodeVerifier)
	if err != nil {
		p.warnf("auth proxy: code exchange failed: %v", err)
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "the sign-in could not be completed; sign in again")
		return
	}
	claims, err := p.verifyIDToken(ctx, idToken, tx.Nonce)
	if err == nil {
		err = checkMaxAge(claims, tx.MaxAgeSeconds, time.Now())
	}
	if err != nil {
		p.warnf("auth proxy: ID token refused at sign-in: %v", err)
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "the sign-in could not be completed; sign in again")
		return
	}

	user, err := p.config.SignIn.ProvisionBrowserUser(ctx, auth.BrowserIdentity{
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		GivenName:     claims.GivenName,
		FamilyName:    claims.FamilyName,
		Picture:       claims.Picture,
	}, accessToken)
	if errors.Is(err, auth.ErrEmailNotVerified) {
		jsonapi.WriteCodedError(c, http.StatusForbidden, auth.CodeEmailNotVerified, "Forbidden", auth.ErrEmailNotVerified.Error())
		return
	}
	if err != nil {
		logger.Errorf("auth proxy: provisioning the signed-in user: %v", err)
		jsonapi.WriteError(c, http.StatusBadGateway, "Bad Gateway", "could not complete sign-in")
		return
	}

	// The cookie this browser held before, if any: replaced below once the new session exists.
	previous, _ := c.Cookie(sessionCookieName)
	raw, session, err := p.config.BrowserSessions.Start(&models.BrowserSession{
		UserID:         user.ID,
		ZitadelSubject: claims.Subject,
		ZitadelSID:     claims.SID,
		OrganizationID: claims.OrganizationID,
		Email:          claims.Email,
		Name:           claims.Name,
		GivenName:      claims.GivenName,
		FamilyName:     claims.FamilyName,
		Picture:        claims.Picture,
		UserAgent:      c.Request.UserAgent(),
		ClientIP:       c.ClientIP(),
	})
	if err != nil {
		logger.Errorf("auth proxy: %v", err)
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "could not complete sign-in")
		return
	}
	// Signing in again, as the same person or another, replaces the browser's session rather than
	// keeping the old one alongside it.
	p.config.BrowserSessions.Supersede(ctx, previous, session.ZitadelSID)
	setSessionCookie(c, raw, int(p.config.BrowserSessions.Limits().Absolute.Seconds()))
	c.Header("Cache-Control", "no-store")
	jsonapi.WriteDocument(c, http.StatusCreated, sessionResource(session))
}

// sessionRefused reports whether err is a definite answer that the browser has no usable session,
// as opposed to a failure to find out.
func sessionRefused(err error) bool {
	return errors.Is(err, auth.ErrSessionNotFound) || errors.Is(err, auth.ErrSessionExpired) || errors.Is(err, auth.ErrSessionEnded)
}

// writeSessionLookupError answers a failed session lookup: the coded 401 the SPA signs out on when
// there is no session, or a 503 it retries when the store could not be read, so a database blip
// does not sign anyone out.
func writeSessionLookupError(c *gin.Context, err error) {
	if sessionRefused(err) {
		jsonapi.WriteCodedError(c, http.StatusUnauthorized, auth.CodeAuthenticationRequired, "Unauthorized", "not signed in")
		return
	}
	logger.Errorf("auth proxy: looking up the browser session: %v", err)
	jsonapi.WriteError(c, http.StatusServiceUnavailable, "Service Unavailable", "could not check the session; try again")
}

// GetBrowserSession handles GET /auth/session: the signed-in user's profile, or 401.
func (p *AuthProxy) GetBrowserSession(c *gin.Context) {
	if p.config.BrowserSessions == nil {
		jsonapi.WriteError(c, http.StatusServiceUnavailable, "Service Unavailable", "browser sign-in is not configured")
		return
	}
	raw, _ := c.Cookie(sessionCookieName)
	session, err := p.config.BrowserSessions.Resolve(c.Request.Context(), raw)
	if err != nil {
		writeSessionLookupError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	jsonapi.WriteDocument(c, http.StatusOK, sessionResource(session))
}

// EndBrowserSession handles POST /auth/session/end, sign-out as a top-level form POST from a trusted
// origin (middleware.RequireBrowserNavigation). It ends the session and its Zitadel session, clears
// the cookie, and sends the browser through Zitadel's end_session as the BFF client, which lands it
// on the login UI's logout page.
func (p *AuthProxy) EndBrowserSession(c *gin.Context) {
	if p.config.BrowserSessions == nil {
		jsonapi.WriteError(c, http.StatusServiceUnavailable, "Service Unavailable", "browser sign-in is not configured")
		return
	}
	raw, _ := c.Cookie(sessionCookieName)
	// Lookup answers an expired session too, which is still worth ending properly. A sign-out that
	// could not find out about the session, or could not delete it, says so and keeps the cookie:
	// clearing the cookie while the row lives on would leave a copy of the cookie still working.
	session, err := p.config.BrowserSessions.Lookup(raw)
	if err != nil && !sessionRefused(err) {
		logger.Errorf("auth proxy: signing out: %v", err)
		jsonapi.WriteError(c, http.StatusServiceUnavailable, "Service Unavailable", "could not sign out; try again")
		return
	}
	if session != nil {
		if err := p.config.BrowserSessions.SignOut(c.Request.Context(), session); err != nil {
			logger.Errorf("auth proxy: signing out: %v", err)
			jsonapi.WriteError(c, http.StatusServiceUnavailable, "Service Unavailable", "could not sign out; try again")
			return
		}
	}
	setSessionCookie(c, "", -1)
	c.Header("Cache-Control", "no-store")
	// 303, so the browser follows the end_session hop with a GET whatever method signed out.
	c.Redirect(http.StatusSeeOther, p.signOutRedirect(c))
}

// signOutRedirect runs the end_session hop as the BFF client and returns where Zitadel sends the
// browser, when that is a host the proxy trusts, or else the app itself.
func (p *AuthProxy) signOutRedirect(c *gin.Context) string {
	postLogout := "/"
	if u, err := url.Parse(p.signInRedirectURI()); err == nil && u.Scheme != "" && u.Host != "" {
		postLogout = u.Scheme + "://" + u.Host
	}
	form := url.Values{"client_id": {p.config.BFFClientID}, "post_logout_redirect_uri": {postLogout}}
	_, _, location, err := p.endSessionAtZitadel(c.Request.Context(), form)
	switch {
	case err != nil:
		logger.Warnf("auth proxy: the end_session hop at sign-out failed: %v", err)
	case location != "" && p.allowPostLogoutRedirect(location):
		return location
	case location != "":
		logger.Warnf("auth proxy: refusing post-logout redirect to disallowed host (%q)", location)
	}
	return postLogout
}

// TouchBrowserSession handles POST /auth/session/touch: the SPA reports that the person used the
// keyboard, mouse or touch, which extends the session's idle limit.
func (p *AuthProxy) TouchBrowserSession(c *gin.Context) {
	if p.config.BrowserSessions == nil {
		jsonapi.WriteError(c, http.StatusServiceUnavailable, "Service Unavailable", "browser sign-in is not configured")
		return
	}
	raw, _ := c.Cookie(sessionCookieName)
	session, err := p.config.BrowserSessions.Resolve(c.Request.Context(), raw)
	if err != nil {
		writeSessionLookupError(c, err)
		return
	}
	if err := p.config.BrowserSessions.Touch(session); err != nil {
		logger.Errorf("auth proxy: %v", err)
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to record activity")
		return
	}
	c.Status(http.StatusNoContent)
	c.Writer.WriteHeaderNow()
}

// maxAgeSkew is the clock difference tolerated between Zitadel and the API when holding auth_time
// to max_age.
const maxAgeSkew = time.Minute

// checkMaxAge holds an ID token to the max_age its sign-in asked for (OIDC Core 3.1.2.1 and
// 3.1.3.7 step 11): the person must have authenticated within that many seconds, so auth_time is
// required. A sign-in that asked for none passes.
func checkMaxAge(claims *idTokenClaims, maxAge *int, now time.Time) error {
	if maxAge == nil {
		return nil
	}
	if claims.AuthTime == 0 {
		return errors.New("the ID token has no auth_time, and the sign-in asked for max_age")
	}
	if now.Sub(time.Unix(claims.AuthTime, 0)) > time.Duration(*maxAge)*time.Second+maxAgeSkew {
		return fmt.Errorf("the person authenticated longer ago than the max_age of %ds", *maxAge)
	}
	return nil
}

// exchangeCode redeems an authorization code at Zitadel's token endpoint as the confidential BFF
// client (HTTP Basic, RFC 6749 section 2.3.1) and returns the ID and access tokens.
func (p *AuthProxy) exchangeCode(ctx context.Context, code, verifier string) (idToken, accessToken string, err error) {
	ctx, cancel := context.WithTimeout(ctx, tokenExchangeTimeout)
	defer cancel()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.signInRedirectURI()},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.zitadelURL("/oauth/v2/token"), strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("building the token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(p.config.BFFClientID), url.QueryEscape(p.config.BFFClientSecret))
	for k, v := range p.parsedHeaders() {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("exchanging the code: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", fmt.Errorf("reading the token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("exchanging the code: Zitadel answered %d", resp.StatusCode)
	}
	var tokens struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil {
		return "", "", fmt.Errorf("decoding the token response: %w", err)
	}
	if tokens.IDToken == "" || tokens.AccessToken == "" {
		return "", "", errors.New("the token response lacks an ID or access token")
	}
	return tokens.IDToken, tokens.AccessToken, nil
}

// idTokenClaims is the part of a Zitadel ID token the sign-in reads. With ID-token userinfo
// assertion enabled on the BFF client, the profile and email claims are in it.
type idTokenClaims struct {
	Issuer         string          `json:"iss"`
	Audience       json.RawMessage `json:"aud"`
	Subject        string          `json:"sub"`
	SID            string          `json:"sid"`
	Nonce          string          `json:"nonce"`
	Expiry         int64           `json:"exp"`
	AuthTime       int64           `json:"auth_time"`
	Email          string          `json:"email"`
	EmailVerified  bool            `json:"email_verified"`
	Name           string          `json:"name"`
	GivenName      string          `json:"given_name"`
	FamilyName     string          `json:"family_name"`
	Picture        string          `json:"picture"`
	OrganizationID string          `json:"urn:zitadel:iam:user:resourceowner:id"`
}

// verifyIDToken checks an ID token's signature against Zitadel's published keys, its issuer, that
// its audience names the BFF client, that it has not expired, and that its nonce is the one the
// sign-in sent. It also requires the subject and the Zitadel session id.
func (p *AuthProxy) verifyIDToken(ctx context.Context, raw, nonce string) (*idTokenClaims, error) {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256})
	if err != nil {
		return nil, fmt.Errorf("parsing the ID token: %w", err)
	}
	payload, err := p.getBackchannelVerifier().verifySignature(ctx, jws)
	if err != nil {
		return nil, fmt.Errorf("verifying the ID token signature: %w", err)
	}
	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decoding the ID token: %w", err)
	}
	if canonicalIssuer(claims.Issuer) != canonicalIssuer(p.config.ZitadelIssuer) {
		return nil, fmt.Errorf("unexpected issuer %q", claims.Issuer)
	}
	audiences, err := parseAudienceClaim(claims.Audience)
	if err != nil || !slices.Contains(audiences, p.config.BFFClientID) {
		return nil, errors.New("the ID token is not for the BFF client")
	}
	if time.Now().Unix() >= claims.Expiry {
		return nil, errors.New("the ID token has expired")
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("the ID token nonce does not match the sign-in")
	}
	if claims.Subject == "" || claims.SID == "" {
		return nil, errors.New("the ID token names no subject or session")
	}
	return &claims, nil
}
