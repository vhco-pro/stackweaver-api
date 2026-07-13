// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package registry

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// GPGService validates GPG public keys and verifies detached signatures for the
// provider registry's trust plane. All crypto is performed in-process with
// github.com/ProtonMail/go-crypto (the maintained OpenPGP fork): it never shells
// out to the gpg binary and, deliberately, never signs on a publisher's behalf —
// publishers sign SHA256SUMS offline and the server only verifies (AUD-106).
type GPGService struct{}

// NewGPGService creates a new GPG service.
func NewGPGService() *GPGService {
	return &GPGService{}
}

// ParseGPGKey validates an ASCII-armored GPG public key and returns its 16-character
// (64-bit) long key ID in uppercase hex — the identifier the Terraform registry protocol
// keys signature verification on. It performs a structured OpenPGP parse and rejects
// anything that is not a single, well-formed public key. There are deliberately no regex
// fallbacks and no shelling out to the gpg binary, so arbitrary text can never be accepted
// as a trust anchor (AUD-122). The complete public key is retained in ASCIIArmor, from
// which the full fingerprint is always recoverable for signature verification.
func (s *GPGService) ParseGPGKey(asciiArmor string) (keyID string, err error) {
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(asciiArmor))
	if err != nil {
		return "", fmt.Errorf("failed to parse GPG public key: %w", err)
	}
	if len(entities) != 1 {
		return "", fmt.Errorf("expected exactly one public key, got %d", len(entities))
	}
	primary := entities[0].PrimaryKey
	if primary == nil {
		return "", fmt.Errorf("GPG key has no primary public key")
	}
	return strings.ToUpper(primary.KeyIdString()), nil
}

// VerifyDetachedSignature verifies that signature is a valid OpenPGP detached signature
// over signed, produced by the private half of the key whose public half is publicKeyASCII.
// The keyring is built from ONLY that one key, so a signature made by any other key is
// rejected — the registry can therefore vouch that a published SHA256SUMS was signed by the
// exact GPG key registered to the org (AUD-106). Both binary and ASCII-armored detached
// signatures are accepted; SHA256SUMS.sig is conventionally a binary detached signature.
func (s *GPGService) VerifyDetachedSignature(publicKeyASCII string, signed, signature []byte) error {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(publicKeyASCII))
	if err != nil {
		return fmt.Errorf("failed to parse signing public key: %w", err)
	}
	check := openpgp.CheckDetachedSignature
	if bytes.Contains(signature, []byte("-----BEGIN PGP SIGNATURE-----")) {
		check = openpgp.CheckArmoredDetachedSignature
	}
	if _, err := check(keyring, bytes.NewReader(signed), bytes.NewReader(signature), nil); err != nil {
		return fmt.Errorf("SHA256SUMS signature verification failed: %w", err)
	}
	return nil
}

// ExtractKeyIDFromASCII extracts the key ID from an ASCII-armored GPG public key
func ExtractKeyIDFromASCII(asciiArmor string) (string, error) {
	service := NewGPGService()
	return service.ParseGPGKey(asciiArmor)
}
