// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// Backend-for-frontend sign-in: the API runs the OAuth authorization-code flow itself, as a
// confidential client, so the browser never holds an OAuth token. Its only credential after
// sign-in is the session cookie. See docs/internal/plans/security/backend-for-frontend-session-plan.md.

const (
	// loginBindingCookiePrefix names the cookies that bind a login transaction to the browser
	// that started it, one per sign-in (see loginBindingCookieName). The __Host- prefix makes
	// browsers require Secure, Path=/ and no Domain.
	loginBindingCookiePrefix = "__Host-sw_login_"

	// loginTransactionTTL bounds a sign-in from the authorize request to the redemption of its
	// code, and is the binding cookie's lifetime.
	loginTransactionTTL = 10 * time.Minute

	// randomTokenBytes is the size of every random value the sign-in mints: state, nonce, PKCE
	// verifier and browser binding.
	randomTokenBytes = 32
)

// errLoginTransactionRefused means a code cannot be redeemed: no transaction for its state, an
// expired one, one already redeemed, or one another browser started. Callers answer it the same
// way whatever the reason.
var errLoginTransactionRefused = errors.New("login transaction refused")

// loginTransactionStore keeps login transactions between the authorize request and the
// redemption of its code. *repository.BrowserSessionRepository satisfies it.
type loginTransactionStore interface {
	CreateLoginTransaction(tx *models.LoginTransaction) error
	TakeLoginTransaction(state string, now time.Time) (*models.LoginTransaction, error)
}

var _ loginTransactionStore = (*repository.BrowserSessionRepository)(nil)

// randomURLToken returns randomTokenBytes from crypto/rand, base64url without padding.
func randomURLToken() (string, error) {
	b := make([]byte, randomTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceChallenge is the S256 code challenge for a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// bffScope builds the scope the BFF requests: the identity scopes plus the user's organization
// (so the ID token names it), keeping only organization scopes from the caller. offline_access is
// never requested, so Zitadel never issues a refresh token.
func bffScope(callerScope string) string {
	scopes := []string{"openid", "profile", "email", "urn:zitadel:iam:user:resourceowner"}
	for s := range strings.FieldsSeq(callerScope) {
		if !strings.HasPrefix(s, "urn:zitadel:iam:org:") {
			continue
		}
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	return strings.Join(scopes, " ")
}

// signInRedirectURI is where Zitadel sends the browser back after sign-in: the configured
// redirect, or the SPA's callback page under its public URL. It must be registered on the BFF
// client, which zitadel-init does.
func (p *AuthProxy) signInRedirectURI() string {
	if p.config.DefaultRedirectURI != "" {
		return p.config.DefaultRedirectURI
	}
	if p.config.PublicFrontendURL != "" {
		return strings.TrimRight(p.config.PublicFrontendURL, "/") + "/auth/callback"
	}
	return ""
}

// browserSignInConfigured reports whether the proxy can run the BFF sign-in.
func (p *AuthProxy) browserSignInConfigured() bool {
	return p.config.BFFClientID != "" && p.config.LoginTransactions != nil && p.signInRedirectURI() != ""
}

// loginBindingCookieName is the binding cookie of the sign-in with this state. Each sign-in has its
// own, so several tabs of one browser starting sign-in at the same moment, none of them yet holding
// a cookie, cannot overwrite each other's binding. The name is derived from the state and so says
// nothing the state does not; the value is the secret.
func loginBindingCookieName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return loginBindingCookiePrefix + hex.EncodeToString(sum[:8])
}

// setLoginBindingCookie issues a sign-in's binding cookie for the ten minutes its transaction
// lives, or, with maxAge -1, clears it.
func setLoginBindingCookie(c *gin.Context, state, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     loginBindingCookieName(state),
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// takeLoginTransaction redeems the transaction for state: it must exist, be unexpired, not be
// redeemed already, and have been started by this browser (its binding cookie). A take is final
// even when refused, so a code cannot be retried with another binding.
func (p *AuthProxy) takeLoginTransaction(c *gin.Context, state string) (*models.LoginTransaction, error) {
	if state == "" {
		return nil, errLoginTransactionRefused
	}
	binding, err := c.Cookie(loginBindingCookieName(state))
	if err != nil || binding == "" {
		return nil, errLoginTransactionRefused
	}
	// The cookie has done its work whatever the outcome: the take below is final.
	setLoginBindingCookie(c, state, "", -1)
	tx, err := p.config.LoginTransactions.TakeLoginTransaction(state, time.Now())
	if errors.Is(err, repository.ErrLoginTransactionNotFound) {
		return nil, errLoginTransactionRefused
	}
	if err != nil {
		return nil, fmt.Errorf("taking login transaction: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(tx.BrowserBinding), []byte(binding)) != 1 {
		return nil, errLoginTransactionRefused
	}
	return tx, nil
}
