// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// buildLogReadURL builds the absolute log-read-url for a run, appending extraQuery (e.g.
// "phase=apply") and a run-scoped log token minted for the current user (AUD-045). When no scoped
// token can be minted, the URL is returned without one and the CLI falls back to its Authorization
// header.
func buildLogReadURL(c *gin.Context, scheme, host, runID, extraQuery string) string {
	base := fmt.Sprintf("%s://%s/api/v2/runs/%s/logs", scheme, host, runID)
	var params []string
	if extraQuery != "" {
		params = append(params, extraQuery)
	}
	if uidVal, ok := c.Get("user_id"); ok {
		if uid, ok := uidVal.(uuid.UUID); ok {
			if tok := mintLogToken(runID, uid); tok != "" {
				params = append(params, "token="+tok)
			}
		}
	}
	if len(params) > 0 {
		return base + "?" + strings.Join(params, "&")
	}
	return base
}

// AUD-045: the run response used to embed the caller's full, long-lived bearer token in the
// `log-read-url` query string, leaking it into proxy/access logs and browser history. Instead we
// mint a short-TTL token that is HMAC-bound to a single run ID, so even if it leaks it only grants
// read access to that one run's logs for a short window. The signing key is the deployment's
// ENCRYPTION_KEY, which is stable across restarts (tokens minted before a restart still verify).

const logTokenTTL = time.Hour

// logTokenSecret is the HMAC key for run-scoped log tokens, set once at startup.
var logTokenSecret []byte

// SetLogTokenSecret installs the signing key (the resolved ENCRYPTION_KEY). When empty, scoped log
// tokens are disabled and the log-read-url is emitted without a token (the CLI then authenticates
// with its Authorization header).
func SetLogTokenSecret(key []byte) { logTokenSecret = key }

// mintLogToken returns a run-scoped, expiring token, or "" if signing is disabled.
func mintLogToken(runID string, userID uuid.UUID) string {
	if len(logTokenSecret) == 0 {
		return ""
	}
	payload := fmt.Sprintf("%s:%s:%d", runID, userID.String(), time.Now().Add(logTokenTTL).Unix())
	sig := signLogPayload(payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

// verifyLogToken checks that token is a valid, unexpired, correctly-signed token for runID and
// returns the user it was minted for.
func verifyLogToken(token, runID string) (uuid.UUID, bool) {
	if len(logTokenSecret) == 0 {
		return uuid.Nil, false
	}
	b64, sig, ok := strings.Cut(token, ".")
	if !ok {
		return uuid.Nil, false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return uuid.Nil, false
	}
	payload := string(payloadBytes)
	if !hmac.Equal([]byte(sig), []byte(signLogPayload(payload))) {
		return uuid.Nil, false
	}
	parts := strings.Split(payload, ":")
	if len(parts) != 3 || parts[0] != runID {
		return uuid.Nil, false
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return uuid.Nil, false
	}
	uid, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil, false
	}
	return uid, true
}

func signLogPayload(payload string) string {
	mac := hmac.New(sha256.New, logTokenSecret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
