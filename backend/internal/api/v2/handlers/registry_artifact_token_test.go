// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import "testing"

func TestArtifactToken_MintVerify(t *testing.T) {
	SetArtifactTokenSecret([]byte("test-secret-key-32-bytes-long!!!"))
	t.Cleanup(func() { SetArtifactTokenSecret(nil) })

	scope := artifactScope("dev-test", "swinstall", "1.0.0")
	tok := mintArtifactToken(scope)
	if tok == "" {
		t.Fatal("mintArtifactToken returned empty with a secret set")
	}

	if !verifyArtifactToken(tok, scope) {
		t.Error("valid token for its own scope must verify")
	}
	// A token for one version must not work for another (scope binding).
	if verifyArtifactToken(tok, artifactScope("dev-test", "swinstall", "2.0.0")) {
		t.Error("token verified for a different version scope")
	}
	if verifyArtifactToken(tok, artifactScope("other", "swinstall", "1.0.0")) {
		t.Error("token verified for a different namespace scope")
	}
	// Tampered signature is rejected.
	if verifyArtifactToken(tok+"x", scope) {
		t.Error("tampered token verified")
	}
	// Garbage is rejected.
	if verifyArtifactToken("not-a-token", scope) {
		t.Error("malformed token verified")
	}
}

func TestArtifactToken_DisabledWhenNoSecret(t *testing.T) {
	SetArtifactTokenSecret(nil)
	scope := artifactScope("dev-test", "swinstall", "1.0.0")
	if got := mintArtifactToken(scope); got != "" {
		t.Errorf("mintArtifactToken = %q, want empty when signing disabled", got)
	}
	if verifyArtifactToken("anything", scope) {
		t.Error("verifyArtifactToken must fail closed when signing disabled")
	}
}
