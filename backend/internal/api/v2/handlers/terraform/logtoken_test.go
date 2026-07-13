// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestLogToken_MintVerify(t *testing.T) {
	SetLogTokenSecret([]byte("test-secret-key-32-bytes-long!!!"))
	t.Cleanup(func() { SetLogTokenSecret(nil) })

	runID := "run-abc123"
	uid := uuid.New()

	tok := mintLogToken(runID, uid)
	if tok == "" {
		t.Fatal("mintLogToken returned empty")
	}

	// Valid token for the right run verifies and returns the minted user.
	got, ok := verifyLogToken(tok, runID)
	if !ok || got != uid {
		t.Fatalf("verify valid token: ok=%v got=%v want %v", ok, got, uid)
	}

	// Wrong run ID is rejected (the token is run-scoped).
	if _, ok := verifyLogToken(tok, "run-other"); ok {
		t.Error("token verified for the wrong run ID")
	}

	// Tampered signature is rejected.
	if _, ok := verifyLogToken(tok+"x", runID); ok {
		t.Error("tampered token verified")
	}

	// Tampered payload is rejected.
	b64, sig, _ := strings.Cut(tok, ".")
	_ = b64
	if _, ok := verifyLogToken("YWFhYQ."+sig, runID); ok {
		t.Error("token with swapped payload verified")
	}

	// Garbage is rejected.
	if _, ok := verifyLogToken("not-a-token", runID); ok {
		t.Error("garbage token verified")
	}
}

func TestLogToken_DisabledWhenNoSecret(t *testing.T) {
	SetLogTokenSecret(nil)
	if tok := mintLogToken("run-x", uuid.New()); tok != "" {
		t.Errorf("mint with no secret should return empty, got %q", tok)
	}
	if _, ok := verifyLogToken("anything", "run-x"); ok {
		t.Error("verify with no secret should fail")
	}
}
