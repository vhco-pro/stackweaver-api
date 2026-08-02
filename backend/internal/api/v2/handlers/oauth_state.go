// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// AUD-155: the Azure DevOps OAuth `state` parameter carried a uuid nonce that was generated at
// initiate time but never persisted or validated on callback — the callback trusted whatever
// `state` the redirect delivered, so an attacker could craft a state pointing to any organization
// (CSRF / connection fixation). The flow is stateless (no session store is wired for it), so
// instead of persisting the nonce we sign the state with the deployment's ENCRYPTION_KEY: the
// callback recomputes the HMAC and rejects any state it did not mint. This makes the state
// unforgeable and, via the embedded expiry, replay-bounded — mirroring the AUD-045 log-token model.

const oauthStateTTL = 15 * time.Minute

// oauthStateSecret is the HMAC key for signed OAuth state, set once at startup from ENCRYPTION_KEY.
var oauthStateSecret []byte

// SetOAuthStateSecret installs the signing key (the resolved ENCRYPTION_KEY). When empty, state
// verification fails closed (every callback is rejected) rather than silently trusting an
// unsigned state.
func SetOAuthStateSecret(key []byte) { oauthStateSecret = key }

// mintOAuthState wraps the business payload (e.g. "org|adoOrg|return|nonce") in a signed,
// expiring envelope safe to pass through an OAuth redirect. Returns "" when signing is disabled.
func mintOAuthState(payload string) string {
	if len(oauthStateSecret) == 0 {
		return ""
	}
	body := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		strconv.FormatInt(time.Now().Add(oauthStateTTL).Unix(), 10)
	return body + "." + signOAuthState(body)
}

// verifyOAuthState returns the original payload when state is a valid, unexpired, correctly-signed
// envelope minted by this deployment; otherwise ok is false. Fails closed when no secret is set.
func verifyOAuthState(state string) (string, bool) {
	if len(oauthStateSecret) == 0 {
		return "", false
	}
	body, sig, ok := cutLast(state, ".")
	if !ok {
		return "", false
	}
	if !hmac.Equal([]byte(sig), []byte(signOAuthState(body))) {
		return "", false
	}
	b64, expStr, ok := strings.Cut(body, ".")
	if !ok {
		return "", false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return "", false
	}
	return string(payload), true
}

func signOAuthState(body string) string {
	mac := hmac.New(sha256.New, oauthStateSecret)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// cutLast splits s on the final occurrence of sep (the signature is appended last, and the body
// itself contains a sep between the payload and the expiry).
func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}
