// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package encryptionkey resolves the application's AES-256 encryption key from
// its configured secret, applying a single fail-loud policy across every binary
// (api, runner, ansible-runner). It refuses a missing or insecure key instead of
// silently falling back to a publicly known zero key (audit AUD-013).
package encryptionkey

import (
	"os"

	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/crypto"
)

// Resolve derives the 32-byte AES-256 key from raw (already resolved from the
// appropriate env var by the caller). On a missing, too-short, or all-zero key
// it terminates the process with a remediation message — unless DEV_INSECURE_KEY=1
// is set, the explicit local-development escape hatch, in which case it logs a
// loud warning and returns an insecure all-zero key.
func Resolve(raw string) []byte {
	key, err := crypto.DeriveKey(raw)
	if err == nil {
		return key
	}
	if os.Getenv("DEV_INSECURE_KEY") == "1" {
		logger.Warnf("DEV_INSECURE_KEY=1: encryption key %v — falling back to an INSECURE all-zero key. NEVER set this outside local development.", err)
		return make([]byte, 32)
	}
	logger.Fatalf("encryption key invalid: %v. Set ENCRYPTION_KEY (or ANSIBLE_ENCRYPTION_KEY) to a 32-byte key — generate one with `openssl rand -hex 32` — or set DEV_INSECURE_KEY=1 for LOCAL DEVELOPMENT ONLY.", err)
	return nil // unreachable: logger.Fatalf exits
}
