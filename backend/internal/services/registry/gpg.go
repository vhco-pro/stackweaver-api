// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package registry

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/michielvha/logger"
)

// GPGService handles GPG key operations and signing
type GPGService struct {
	// GPG binary path (defaults to "gpg" in PATH)
	gpgPath string
}

// NewGPGService creates a new GPG service
func NewGPGService() *GPGService {
	return &GPGService{
		gpgPath: "gpg",
	}
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

// SignBinary signs a binary file using GPG and returns the signature
// This uses the system GPG binary to sign files
func (s *GPGService) SignBinary(keyID string, binaryReader io.Reader) (signature []byte, err error) {
	// Read binary content
	binaryData, err := io.ReadAll(binaryReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read binary: %w", err)
	}

	// Use GPG binary to sign
	// Note: This requires GPG to be installed and the key to be imported
	cmd := exec.Command(s.gpgPath, "--armor", "--detach-sign", "--local-user", keyID, "--output", "-") //nolint:gosec,noctx // intentional: executing gpg command, no context needed
	cmd.Stdin = bytes.NewReader(binaryData)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("GPG signing failed: %w, stderr: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// VerifySignature verifies a GPG signature against a binary using system GPG
func (s *GPGService) VerifySignature(publicKeyASCII string, binaryData []byte, signature []byte) error {
	// Create temporary files for binary and signature
	binaryFile, err := os.CreateTemp("", "gpg-verify-binary-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		if err := os.Remove(binaryFile.Name()); err != nil { //nolint:gosec // G703: removing temp file we just created
			logger.Warnf("Failed to remove temp file %s: %v", binaryFile.Name(), err)
		}
	}()
	defer func() {
		if err := binaryFile.Close(); err != nil {
			logger.Warnf("Failed to close binary file: %v", err)
		}
	}()

	sigFile, err := os.CreateTemp("", "gpg-verify-sig-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		if err := os.Remove(sigFile.Name()); err != nil { //nolint:gosec // G703: sigFile.Name() is from os.CreateTemp, not user input
			logger.Warnf("Failed to remove temp file %s: %v", sigFile.Name(), err)
		}
	}()
	defer func() {
		if err := sigFile.Close(); err != nil {
			logger.Warnf("Failed to close sig file: %v", err)
		}
	}()

	// Write binary and signature to temp files
	if _, err := binaryFile.Write(binaryData); err != nil {
		return fmt.Errorf("failed to write binary: %w", err)
	}
	if err := binaryFile.Close(); err != nil {
		return fmt.Errorf("failed to close binary file: %w", err)
	}

	if _, err := sigFile.Write(signature); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}
	if err := sigFile.Close(); err != nil {
		return fmt.Errorf("failed to close sig file: %w", err)
	}

	// Import public key temporarily
	// Ignore import errors - key might already be imported
	importCmd := exec.Command(s.gpgPath, "--import", "--no-tty", "--batch") //nolint:gosec,noctx // intentional: executing gpg command, no context needed
	importCmd.Stdin = strings.NewReader(publicKeyASCII)
	_ = importCmd.Run()

	// Verify signature
	verifyCmd := exec.Command(s.gpgPath, "--verify", "--no-tty", sigFile.Name(), binaryFile.Name()) //nolint:gosec,noctx // intentional: executing gpg command, no context needed
	var stderr bytes.Buffer
	verifyCmd.Stderr = &stderr

	if err := verifyCmd.Run(); err != nil {
		return fmt.Errorf("signature verification failed: %w, output: %s", err, stderr.String())
	}

	return nil
}

// ExtractKeyIDFromASCII extracts the key ID from an ASCII-armored GPG public key
func ExtractKeyIDFromASCII(asciiArmor string) (string, error) {
	service := NewGPGService()
	return service.ParseGPGKey(asciiArmor)
}
