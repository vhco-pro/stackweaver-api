// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
)

// AUD-155: the ADO OAuth state must be unforgeable and expiring. These tests pin that a
// correctly-minted state round-trips, and that a forged, tampered, expired, or unsigned state is
// rejected - the CSRF property the callback relies on.
func TestOAuthState(t *testing.T) {
	SetOAuthStateSecret([]byte("test-oauth-state-secret-32bytes!"))
	t.Cleanup(func() { SetOAuthStateSecret(nil) })

	payload := "acme|acme-ado|%2Fsettings|550e8400-e29b-41d4-a716-446655440000"

	t.Run("valid round-trip", func(t *testing.T) {
		state := mintOAuthState(stateAzureDevOpsInstall, payload)
		if state == "" {
			t.Fatal("mintOAuthState returned empty")
		}
		got, ok := verifyOAuthState(stateAzureDevOpsInstall, state)
		if !ok || got != payload {
			t.Fatalf("verify = (%q, %v), want (%q, true)", got, ok, payload)
		}
	})

	t.Run("forged state (attacker crafts unsigned state for a victim org)", func(t *testing.T) {
		forged := "victim-org|attacker-ado|%2F|" + "00000000-0000-0000-0000-000000000000"
		if _, ok := verifyOAuthState(stateAzureDevOpsInstall, forged); ok {
			t.Fatal("forged unsigned state accepted")
		}
	})

	t.Run("tampered payload after signing", func(t *testing.T) {
		state := mintOAuthState(stateAzureDevOpsInstall, payload)
		// swap the org in the signed base64 body; the HMAC no longer matches.
		body, sig, _ := strings.Cut(state, ".")
		b64, expStr, _ := strings.Cut(body, ".")
		raw, _ := base64.RawURLEncoding.DecodeString(b64)
		evil := base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(raw), "acme|", "victim|", 1)))
		tampered := evil + "." + expStr + "." + sig
		if _, ok := verifyOAuthState(stateAzureDevOpsInstall, tampered); ok {
			t.Fatal("tampered state accepted")
		}
	})

	t.Run("expired state", func(t *testing.T) {
		// hand-build an envelope with a past expiry, signed correctly.
		body := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
			strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)
		expired := body + "." + signOAuthState(stateAzureDevOpsInstall, body)
		if _, ok := verifyOAuthState(stateAzureDevOpsInstall, expired); ok {
			t.Fatal("expired state accepted")
		}
	})

	t.Run("a state issued for one flow is refused by the other", func(t *testing.T) {
		for _, tc := range []struct{ issued, presented oauthStatePurpose }{
			{stateAzureDevOpsInstall, stateGitHubAppInstall},
			{stateGitHubAppInstall, stateAzureDevOpsInstall},
			{stateGitHubAppInstall, stateGitHubAppAuthorize},
			{stateGitHubAppAuthorize, stateGitHubAppInstall},
			{stateGitHubAppAuthorize, stateAzureDevOpsInstall},
		} {
			state := mintOAuthState(tc.issued, payload)
			if _, ok := verifyOAuthState(tc.presented, state); ok {
				t.Errorf("a state issued for %s was accepted for %s", tc.issued, tc.presented)
			}
			if _, ok := verifyOAuthState(tc.issued, state); !ok {
				t.Errorf("a state issued for %s was refused for %s", tc.issued, tc.issued)
			}
		}
	})

	t.Run("fails closed with no secret", func(t *testing.T) {
		state := mintOAuthState(stateAzureDevOpsInstall, payload)
		SetOAuthStateSecret(nil)
		if _, ok := verifyOAuthState(stateAzureDevOpsInstall, state); ok {
			t.Fatal("state verified with no secret set")
		}
		if s := mintOAuthState(stateAzureDevOpsInstall, payload); s != "" {
			t.Fatal("mintOAuthState returned non-empty with no secret")
		}
	})
}
