// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

// finalizeCheckTimeout bounds the Zitadel reads that decide whether a session may finalize.
const finalizeCheckTimeout = 10 * time.Second

// Second-factor authentication method types, as Zitadel's ListAuthenticationMethodTypes names
// them. Password and passkey are primary credentials and are not in this set.
var secondFactorMethods = map[string]bool{
	"AUTHENTICATION_METHOD_TYPE_TOTP":      true,
	"AUTHENTICATION_METHOD_TYPE_OTP_EMAIL": true,
	"AUTHENTICATION_METHOD_TYPE_OTP_SMS":   true,
	"AUTHENTICATION_METHOD_TYPE_U2F":       true,
}

// finalizeSession is the part of Zitadel's GET /v2/sessions/{id} the finalize check reads.
type finalizeSession struct {
	Factors        sessionFactors `json:"factors"`
	ExpirationDate string         `json:"expirationDate"`
}

// sessionMayFinalize reports whether a session has authenticated its user well enough to
// finish a sign-in, following the rule of Zitadel's own login UI (isSessionValid):
//
//   - the session names a user and has not expired;
//   - it has verified a primary credential: a password, a user-verified passkey, or an identity
//     provider;
//   - when the user has a second factor enrolled (TOTP, one-time code by email or SMS, or a
//     security key), one of those enrolled kinds is verified, unless the primary credential was
//     a passkey, which is multi-factor by itself;
//   - when nothing is enrolled but the login policy forces MFA (for every sign-in, or for local
//     ones and the user signed in with a password), some second factor is verified.
//
// It fails closed: if any of the reads fails, the session may not finalize. A refusal comes with
// the reason, for the log.
func (p *AuthProxy) sessionMayFinalize(ctx context.Context, sessionID string) (bool, string) {
	if sessionID == "" {
		return false, "no session id"
	}
	ctx, cancel := context.WithTimeout(ctx, finalizeCheckTimeout)
	defer cancel()

	session, ok := p.fetchFinalizeSession(ctx, sessionID)
	if !ok {
		return false, "reading the session failed"
	}
	f := session.Factors
	if f.User.VerifiedAt == "" || f.User.ID == "" {
		return false, "the session names no user"
	}
	if sessionExpired(session.ExpirationDate) {
		return false, "the session has expired"
	}
	passkey := f.WebAuthN.VerifiedAt != "" && f.WebAuthN.UserVerified
	if f.Password.VerifiedAt == "" && f.Intent.VerifiedAt == "" && !passkey {
		return false, "no primary credential verified"
	}
	if passkey {
		return true, ""
	}

	enrolled, ok := p.enrolledSecondFactors(ctx, f.User.ID)
	if !ok {
		return false, "reading the user's authentication methods failed"
	}
	if len(enrolled) > 0 {
		if (enrolled["AUTHENTICATION_METHOD_TYPE_TOTP"] && f.TOTP.VerifiedAt != "") ||
			(enrolled["AUTHENTICATION_METHOD_TYPE_OTP_EMAIL"] && f.OTPEmail.VerifiedAt != "") ||
			(enrolled["AUTHENTICATION_METHOD_TYPE_OTP_SMS"] && f.OTPSMS.VerifiedAt != "") ||
			(enrolled["AUTHENTICATION_METHOD_TYPE_U2F"] && f.WebAuthN.VerifiedAt != "") {
			return true, ""
		}
		return false, "an enrolled second factor is not verified"
	}

	forceMfa, forceMfaLocalOnly, ok := p.mfaPolicy(ctx, f.User.OrganizationID)
	if !ok {
		return false, "reading the login policy failed"
	}
	mfaRequired := forceMfa || (forceMfaLocalOnly && f.Intent.VerifiedAt == "" && f.Password.VerifiedAt != "")
	if !mfaRequired {
		return true, ""
	}
	if f.TOTP.VerifiedAt != "" || f.OTPEmail.VerifiedAt != "" || f.OTPSMS.VerifiedAt != "" || f.WebAuthN.VerifiedAt != "" {
		return true, ""
	}
	return false, "the login policy requires a second factor"
}

func (p *AuthProxy) fetchFinalizeSession(ctx context.Context, sessionID string) (finalizeSession, bool) {
	body, status, err := p.proxyJSON(ctx, http.MethodGet, "/v2/sessions/"+url.PathEscape(sessionID), nil)
	if err != nil || status != http.StatusOK {
		return finalizeSession{}, false
	}
	var parsed struct {
		Session finalizeSession `json:"session"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return finalizeSession{}, false
	}
	return parsed.Session, true
}

// enrolledSecondFactors returns the second-factor method types the user has enrolled.
func (p *AuthProxy) enrolledSecondFactors(ctx context.Context, userID string) (map[string]bool, bool) {
	body, status, err := p.proxyJSON(ctx, http.MethodGet, "/v2/users/"+url.PathEscape(userID)+"/authentication_methods", nil)
	if err != nil || status != http.StatusOK {
		return nil, false
	}
	var parsed struct {
		AuthMethodTypes []string `json:"authMethodTypes"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, false
	}
	enrolled := map[string]bool{}
	for _, m := range parsed.AuthMethodTypes {
		if secondFactorMethods[m] {
			enrolled[m] = true
		}
	}
	return enrolled, true
}

// mfaPolicy reads the login policy that applies to the user's organization.
func (p *AuthProxy) mfaPolicy(ctx context.Context, orgID string) (forceMfa, forceMfaLocalOnly, ok bool) {
	path := "/v2/settings/login"
	if orgID != "" {
		path += "?" + url.Values{"ctx.orgId": {orgID}}.Encode()
	}
	body, status, err := p.proxyJSON(ctx, http.MethodGet, path, nil)
	if err != nil || status != http.StatusOK {
		return false, false, false
	}
	var parsed struct {
		Settings struct {
			ForceMfa          bool `json:"forceMfa"`
			ForceMfaLocalOnly bool `json:"forceMfaLocalOnly"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false, false, false
	}
	return parsed.Settings.ForceMfa, parsed.Settings.ForceMfaLocalOnly, true
}

// sessionExpired reports whether a session's expirationDate has passed. An absent or unparseable
// date means the session has no expiry set.
func sessionExpired(expirationDate string) bool {
	if expirationDate == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, expirationDate)
	if err != nil {
		return false
	}
	return !t.After(time.Now())
}
