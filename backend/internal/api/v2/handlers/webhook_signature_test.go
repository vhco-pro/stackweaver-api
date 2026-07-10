// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-002 regression tests for GitHub webhook signature verification. Pure — no DB, no build
// tag — so they run in CI's plain `go test`.

package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

func githubSign(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// TestValidGitHubSignature locks in the HMAC compare: only a signature computed with the exact
// secret over the exact body passes; wrong secret, tampered body, missing/short prefix all fail.
func TestValidGitHubSignature(t *testing.T) {
	payload := []byte(`{"ref":"refs/heads/main","after":"abc"}`)
	const secret = "topsecret"

	if !validGitHubSignature(payload, githubSign(payload, secret), secret) {
		t.Error("valid signature rejected")
	}
	if validGitHubSignature(payload, githubSign(payload, "wrong"), secret) {
		t.Error("signature made with the wrong secret accepted")
	}
	if validGitHubSignature([]byte(`{"ref":"refs/heads/evil"}`), githubSign(payload, secret), secret) {
		t.Error("signature over a different body accepted (tamper)")
	}
	if validGitHubSignature(payload, hex.EncodeToString([]byte("nope")), secret) {
		t.Error("signature without the sha256= prefix accepted")
	}
	if validGitHubSignature(payload, "", secret) {
		t.Error("empty signature accepted")
	}
}

// TestVerifyGitHubWebhook is the AUD-002 endpoint gate: the webhook handler must reject an
// unsigned, wrongly-signed, or (fail-closed) unconfigured delivery with 401, and only accept a
// correctly-signed one. Before the fix the verification was commented out and every delivery was
// accepted — an unauthenticated attacker could forge push events and trigger plan-and-apply runs.
func TestVerifyGitHubWebhook(t *testing.T) {
	gin.SetMode(gin.TestMode)
	payload := []byte(`{"ref":"refs/heads/main"}`)

	newHandler := func(secret string) *VCSAppInstallationHandlerV2 {
		t.Setenv("GITHUB_WEBHOOK_SECRET", secret)
		mgr, err := vcs.NewGitHubAppManager() // APP_ID unset -> disabled manager, but carries the secret
		if err != nil {
			t.Fatalf("NewGitHubAppManager: %v", err)
		}
		return &VCSAppInstallationHandlerV2{githubAppManager: mgr}
	}

	cases := []struct {
		name      string
		secret    string
		signature string // "" means no header; "AUTO" means a valid signature for `secret`
		want      bool
	}{
		{"valid signature", "topsecret", "AUTO", true},
		{"wrong signature", "topsecret", githubSign(payload, "attacker"), false},
		{"missing signature header", "topsecret", "", false},
		{"secret unset -> fail closed", "", "AUTO-EMPTY", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler(tc.secret)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v2/vcs-connections/github/webhook", http.NoBody)
			switch tc.signature {
			case "AUTO":
				c.Request.Header.Set("X-Hub-Signature-256", githubSign(payload, tc.secret))
			case "AUTO-EMPTY":
				// even a validly-computed signature must be rejected when no secret is configured
				c.Request.Header.Set("X-Hub-Signature-256", githubSign(payload, "topsecret"))
			case "":
				// no header
			default:
				c.Request.Header.Set("X-Hub-Signature-256", tc.signature)
			}

			got := h.verifyGitHubWebhook(c, payload)
			if got != tc.want {
				t.Fatalf("verifyGitHubWebhook = %v, want %v (status %d)", got, tc.want, w.Code)
			}
			if !tc.want && w.Code != http.StatusUnauthorized {
				t.Errorf("rejected delivery should be 401, got %d", w.Code)
			}
		})
	}
}
