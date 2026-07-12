// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-041 Zitadel webhook replay protection. verifySignature authenticated the HMAC but
// never checked the signed timestamp for freshness, so a captured valid idp-sync /
// complement-token request could be replayed indefinitely to re-drive sso_groups/RBAC.
// These are plain unit tests (no build tag — they run in CI).

package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// signZitadel builds a valid "t=<ts>,v1=<hmac>" header for the given body/key/timestamp.
func signZitadel(body, key string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = fmt.Fprintf(mac, "%d.%s", ts, body)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

func TestVerifySignature_TimestampFreshness(t *testing.T) {
	const key = "test-signing-key"
	const body = `{"aggregateID":"123","sso_groups":["admins"]}`
	now := time.Now().Unix()

	t.Run("fresh signed request is accepted", func(t *testing.T) {
		if !verifySignature(signZitadel(body, key, now), body, key, false) {
			t.Fatal("a correctly-signed, current request must be accepted")
		}
	})

	t.Run("replayed old request is rejected", func(t *testing.T) {
		stale := now - int64((10 * time.Minute).Seconds()) // 10 min old, valid HMAC
		if verifySignature(signZitadel(body, key, stale), body, key, false) {
			t.Fatal("a validly-signed but stale request must be rejected (replay) — AUD-041")
		}
	})

	t.Run("future timestamp beyond tolerance is rejected", func(t *testing.T) {
		future := now + int64((10 * time.Minute).Seconds())
		if verifySignature(signZitadel(body, key, future), body, key, false) {
			t.Fatal("a request timestamped far in the future must be rejected")
		}
	})

	t.Run("within-tolerance skew is accepted", func(t *testing.T) {
		recent := now - int64((2 * time.Minute).Seconds())
		if !verifySignature(signZitadel(body, key, recent), body, key, false) {
			t.Fatal("a request within the ±5m tolerance must be accepted")
		}
	})

	t.Run("non-numeric timestamp is rejected", func(t *testing.T) {
		// Valid HMAC over a non-numeric timestamp string — signature passes, freshness must not.
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte("notanumber." + body))
		hdr := "t=notanumber,v1=" + hex.EncodeToString(mac.Sum(nil))
		if verifySignature(hdr, body, key, false) {
			t.Fatal("an unparseable timestamp must be rejected")
		}
	})
}
