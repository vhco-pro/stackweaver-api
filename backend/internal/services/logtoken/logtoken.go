// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package logtoken mints and verifies the run-bound token in a run's log-read-url.
//
// The token is short-lived, HMAC-signed and bound to one run, so a leaked URL reads only that run's
// logs. It names the credential that minted it, an API key or a browser session, and grants nothing
// itself: each read re-establishes that credential and authorizes it as of that moment, so a
// revoked key, an ended browser session, or a team that has lost access to the run stops reading
// at once.
//
// The lifetime is an hour. Terraform Enterprise's archivist log URLs live longer, and go-tfe's log
// reader does not rely on either: it authenticates its polls with its Authorization header and
// replaces the URL's query string, token included, on every request.
package logtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TTL is how long a minted token stays valid.
const TTL = time.Hour

// Credential is what minted a log token: an API key, or a browser session. Exactly one of the two
// is set.
type Credential struct {
	APIKeyID         uuid.UUID
	BrowserSessionID uuid.UUID
}

// secret is the HMAC key, set once at startup.
var secret []byte

// SetSecret installs the signing key (the resolved ENCRYPTION_KEY). When empty, tokens are neither
// minted nor accepted, and a log-read-url carries none.
func SetSecret(key []byte) { secret = key }

// Mint returns a token for reading runID's logs as cred, or "" when signing is disabled or cred
// names nothing.
func Mint(runID string, cred Credential) string {
	if len(secret) == 0 {
		return ""
	}
	var kind, id string
	switch {
	case cred.APIKeyID != uuid.Nil:
		kind, id = "k", cred.APIKeyID.String()
	case cred.BrowserSessionID != uuid.Nil:
		kind, id = "s", cred.BrowserSessionID.String()
	default:
		return ""
	}
	payload := fmt.Sprintf("%s:%s:%s:%d", runID, kind, id, time.Now().Add(TTL).Unix())
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sign(payload)
}

// Verify checks that token is a valid, unexpired, correctly signed token for runID and returns the
// credential it was minted for. The credential still has to be authorized for the read.
func Verify(token, runID string) (Credential, bool) {
	if len(secret) == 0 {
		return Credential{}, false
	}
	b64, sig, ok := strings.Cut(token, ".")
	if !ok {
		return Credential{}, false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return Credential{}, false
	}
	payload := string(payloadBytes)
	if !hmac.Equal([]byte(sig), []byte(sign(payload))) {
		return Credential{}, false
	}
	parts := strings.Split(payload, ":")
	if len(parts) != 4 || parts[0] != runID {
		return Credential{}, false
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return Credential{}, false
	}
	id, err := uuid.Parse(parts[2])
	if err != nil || id == uuid.Nil {
		return Credential{}, false
	}
	switch parts[1] {
	case "k":
		return Credential{APIKeyID: id}, true
	case "s":
		return Credential{BrowserSessionID: id}, true
	default:
		return Credential{}, false
	}
}

func sign(payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
