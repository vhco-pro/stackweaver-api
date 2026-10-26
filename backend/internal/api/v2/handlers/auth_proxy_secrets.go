// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"crypto/hkdf"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"fmt"
)

// HKDF labels for the keys the auth proxy derives from ENCRYPTION_KEY. Each use has its own
// label, so no derived key equals another or ENCRYPTION_KEY itself.
const (
	decoyKeyLabel         = "stackweaver-auth-proxy-decoy-ids-v1"
	sessionCookieKeyLabel = "stackweaver-auth-proxy-session-cookie-v1"
)

// proxySecrets returns the decoy-id key and the session-cookie key.
//
// An explicit DecoySecret (STACKWEAVER_DECOY_SECRET) keys both, as it always has. Otherwise both
// are derived from the install's ENCRYPTION_KEY, which every API replica shares, so cookies verify
// on any replica and after a restart, and decoy ids are stable across replicas. Without either,
// each process draws its own random keys (tests and zero-config single-process runs). The all-zero
// key DEV_INSECURE_KEY=1 hands out counts as no key: anyone can compute what it derives, and a
// login UI cookie signed with a known key can be forged.
func proxySecrets(config AuthProxyConfig) (decoy, cookie []byte) {
	if len(config.DecoySecret) > 0 {
		return config.DecoySecret, config.DecoySecret
	}
	if len(config.EncryptionKey) > 0 && !allZero(config.EncryptionKey) {
		return deriveProxyKey(config.EncryptionKey, decoyKeyLabel), deriveProxyKey(config.EncryptionKey, sessionCookieKeyLabel)
	}
	return randomProxyKey(), randomProxyKey()
}

func deriveProxyKey(encryptionKey []byte, label string) []byte {
	key, err := hkdf.Key(sha256.New, encryptionKey, nil, label, 32)
	if err != nil {
		// hkdf.Key fails only for an output longer than 255 hash blocks; 32 bytes cannot.
		panic(fmt.Sprintf("auth proxy: deriving %s: %v", label, err))
	}
	return key
}

func randomProxyKey() []byte {
	key := make([]byte, 32)
	if _, err := cryptorand.Read(key); err != nil {
		panic(fmt.Sprintf("auth proxy: generating a random key: %v", err))
	}
	return key
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
