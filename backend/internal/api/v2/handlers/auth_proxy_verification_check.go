// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// A user with no authentication method (an invited user, or one an administrator created
// without a password) has no current password and no reset code, so the first password is set
// on a different proof: an email verification this browser completed moments ago. This is the
// rule Zitadel's own login applies (its verification check cookie): a password may be set
// without a code only for a user who has no authentication method, and only after a
// verification the server checked itself, recorded in a short-lived cookie that is signed with
// a server secret and names the user, so it cannot be forged, moved to another user, or used
// after it expires.

// VerificationCheckCookieName is the cookie that records a completed email verification.
const VerificationCheckCookieName = "sw_verification_check"

// verificationCheckTTL is how long a verification lets the browser set a first password.
const verificationCheckTTL = 5 * time.Minute

const verificationCheckHMACDomain = "stackweaver-verification-check-v1:"

// verificationCheckPath scopes the cookie to the user endpoints that read it.
const verificationCheckPath = "/auth/users"

func (p *AuthProxy) verificationCheckTag(userID string, expires int64) string {
	mac := hmac.New(sha256.New, p.decoySecret)
	mac.Write([]byte(verificationCheckHMACDomain))
	mac.Write([]byte(userID + "." + strconv.FormatInt(expires, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verificationCheckValue is the cookie value recording a verification of userID that is good
// until expires: `<tag>.<user id>.<expiry unix seconds>`.
func (p *AuthProxy) verificationCheckValue(userID string, expires time.Time) string {
	exp := expires.Unix()
	return p.verificationCheckTag(userID, exp) + "." + userID + "." + strconv.FormatInt(exp, 10)
}

// hasVerificationCheck reports whether the request carries an unexpired verification check
// for userID that this server signed.
func (p *AuthProxy) hasVerificationCheck(c *gin.Context, userID string) bool {
	raw, err := c.Cookie(VerificationCheckCookieName)
	if err != nil || raw == "" {
		return false
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[1] != userID {
		return false
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return false
	}
	return hmac.Equal([]byte(parts[0]), []byte(p.verificationCheckTag(userID, exp)))
}

func (p *AuthProxy) setVerificationCheckCookie(c *gin.Context, userID string) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(VerificationCheckCookieName, p.verificationCheckValue(userID, time.Now().Add(verificationCheckTTL)),
		int(verificationCheckTTL.Seconds()), verificationCheckPath, "", p.config.IsProduction || requestIsHTTPS(c), true)
}

func (p *AuthProxy) clearVerificationCheckCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(VerificationCheckCookieName, "", -1, verificationCheckPath, "", p.config.IsProduction || requestIsHTTPS(c), true)
}

// userHasNoAuthMethods reports whether Zitadel confirms the user exists and has no
// authentication method at all: no password, passkey, identity provider link or other factor.
// Any failure to confirm counts as false.
func (p *AuthProxy) userHasNoAuthMethods(ctx context.Context, userID string) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body, status, err := p.proxyJSON(ctx, http.MethodGet, "/v2/users/"+userID+"/authentication_methods", nil)
	if err != nil || status != http.StatusOK {
		return false
	}
	var methods struct {
		AuthMethodTypes *[]string `json:"authMethodTypes"`
	}
	if err := json.Unmarshal(body, &methods); err != nil {
		return false
	}
	return methods.AuthMethodTypes == nil || len(*methods.AuthMethodTypes) == 0
}

// passwordChangeCarriesNoProof reports whether a SetPassword body names neither a current
// password nor a verification code (absent, null or empty all count as not named).
func passwordChangeCarriesNoProof(body map[string]any) bool {
	for _, key := range []string{"currentPassword", "verificationCode"} {
		if v, present := body[key]; present && v != nil && v != "" {
			return false
		}
	}
	return true
}

// firstAuthenticatorProof reports whether the request may set up the user's first
// authentication method without a session: it carries a fresh verification check for this user,
// and Zitadel confirms the user has no authentication method. The cookie is checked first, so a
// request without one costs no call to Zitadel.
func (p *AuthProxy) firstAuthenticatorProof(c *gin.Context, userID string) bool {
	return p.hasVerificationCheck(c, userID) && p.userHasNoAuthMethods(c.Request.Context(), userID)
}

// setFirstPassword sets the first password of a user who has no authentication method, on the
// proof of a fresh verification check for that user. It reports whether it handled the
// request; when it did not, the caller refuses the request as having no proof.
func (p *AuthProxy) setFirstPassword(c *gin.Context, userID string, reqBody map[string]any) bool {
	if !passwordChangeCarriesNoProof(reqBody) || !p.firstAuthenticatorProof(c, userID) {
		return false
	}
	// Only the new password is forwarded: nothing else in the caller's body reaches the call
	// the service token authorises.
	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPost, "/v2/users/"+userID+"/password",
		map[string]any{"newPassword": reqBody["newPassword"]})
	if err != nil {
		respondError(c, http.StatusBadGateway, "failed to change password")
		return true
	}
	if statusCode == http.StatusOK {
		p.clearVerificationCheckCookie(c)
	}
	c.Data(statusCode, "application/json", respBody)
	return true
}

// firstPasskey forwards one step of a user's first passkey registration, on the same proof as a
// first password, and reports whether it did. Registering a passkey otherwise needs a session
// that has proven a credential, which a user with no authentication method cannot have. Only the
// fields the step takes are forwarded. A completed registration spends the verification check.
func (p *AuthProxy) firstPasskey(c *gin.Context, userID, zitadelPath string, fields []string, completes bool) bool {
	if !p.firstAuthenticatorProof(c, userID) {
		return false
	}
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return true
	}
	forward := map[string]any{}
	for _, f := range fields {
		if v, ok := body[f]; ok {
			forward[f] = v
		}
	}
	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPost, zitadelPath, forward)
	if err != nil {
		respondError(c, http.StatusBadGateway, "failed to complete request with identity provider")
		return true
	}
	if completes && statusCode == http.StatusOK {
		p.clearVerificationCheckCookie(c)
	}
	c.Data(statusCode, "application/json", respBody)
	return true
}

// withAuthenticatorSetupRequired adds `"authenticatorSetupRequired": true` to a JSON object
// answer, which tells the login to send the user to set up a first authentication method.
func withAuthenticatorSetupRequired(body []byte) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return body
	}
	obj["authenticatorSetupRequired"] = json.RawMessage("true")
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}
