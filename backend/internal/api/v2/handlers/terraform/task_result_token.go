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
)

// Run-task access tokens (the `access_token` in the webhook payload). Same stateless HMAC design as
// log tokens (AUD-045): payload `task-result:<taskrs-id>:<run-id>:<exp>` signed with the resolved
// ENCRYPTION_KEY — no DB row, survives restarts, and even if it leaks it only authorizes ONE task
// result's callback plus that run's plan-json/config-version downloads for its lifetime.
//
// TTL = the 60-minute hard execution cap: a service that has not called back within the cap has
// timed out anyway (the orchestrator sweep errors its result), so a longer-lived token would only
// widen the leak window.

const taskResultTokenTTL = time.Hour

// taskTokenSecret is the HMAC key, set once at startup (the resolved ENCRYPTION_KEY).
var taskTokenSecret []byte

// SetTaskTokenSecret installs the signing key. When empty, run-task webhooks cannot be delivered
// with working callbacks (the orchestrator logs and skips minting).
func SetTaskTokenSecret(key []byte) { taskTokenSecret = key }

// MintTaskResultToken returns the access token for one task result of one run, or "" if signing is
// disabled. Exported: the orchestrator mints these when firing stage webhooks.
func MintTaskResultToken(taskResultID, runID string) string {
	if len(taskTokenSecret) == 0 {
		return ""
	}
	payload := fmt.Sprintf("task-result:%s:%s:%d", taskResultID, runID, time.Now().Add(taskResultTokenTTL).Unix())
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + signTaskTokenPayload(payload)
}

// verifyTaskResultToken checks signature + expiry and returns the task-result and run ids the token
// was minted for. Callers must additionally match those ids against the resource being accessed.
func verifyTaskResultToken(token string) (taskResultID, runID string, ok bool) {
	if len(taskTokenSecret) == 0 {
		return "", "", false
	}
	b64, sig, found := strings.Cut(token, ".")
	if !found {
		return "", "", false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return "", "", false
	}
	payload := string(payloadBytes)
	if !hmac.Equal([]byte(sig), []byte(signTaskTokenPayload(payload))) {
		return "", "", false
	}
	parts := strings.Split(payload, ":")
	if len(parts) != 4 || parts[0] != "task-result" {
		return "", "", false
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func signTaskTokenPayload(payload string) string {
	mac := hmac.New(sha256.New, taskTokenSecret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// taskTokenFromAuthHeader extracts a bearer task token from an Authorization header, returning ""
// when the header is absent or not a task token (letting callers fall through to normal auth).
func taskTokenFromAuthHeader(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	tok := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	// Task tokens are base64url(payload).sig where the payload starts with "task-result:".
	b64, _, found := strings.Cut(tok, ".")
	if !found {
		return ""
	}
	if raw, err := base64.RawURLEncoding.DecodeString(b64); err != nil || !strings.HasPrefix(string(raw), "task-result:") {
		return ""
	}
	return tok
}
