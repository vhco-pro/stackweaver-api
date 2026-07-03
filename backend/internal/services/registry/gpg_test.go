// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package registry

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// gpgHomeWithKey creates an isolated GNUPGHOME, generates a throwaway RSA signing key
// (no passphrase), and returns the home dir, the key's short id, and its ASCII-armored
// public key. It skips the test if gpg is unavailable. The isolated home keeps the
// throwaway key out of the developer's real keyring and is removed on cleanup.
func gpgHomeWithKey(t *testing.T) (home, keyID, publicKey string) {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg binary not available - skipping GPG runtime test")
	}

	home = t.TempDir()
	env := append(os.Environ(), "GNUPGHOME="+home)

	// Batch key generation — RSA, no passphrase, so SignBinary can use the secret key.
	batch := `%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: Stackweaver Compat Test
Name-Email: compat-test@stackweaver.local
Expire-Date: 0
%commit
`
	gen := exec.Command("gpg", "--batch", "--gen-key") //nolint:gosec,noctx // test-only: generating a throwaway key in an isolated GNUPGHOME
	gen.Env = env
	gen.Stdin = strings.NewReader(batch)
	var genErr bytes.Buffer
	gen.Stderr = &genErr
	if err := gen.Run(); err != nil {
		t.Skipf("gpg key generation failed (%v): %s", err, genErr.String())
	}

	// Short key id (last 8 hex of the fingerprint) via colon output.
	list := exec.Command("gpg", "--list-keys", "--with-colons") //nolint:gosec,noctx // test-only: reads the isolated keyring
	list.Env = env
	var listOut bytes.Buffer
	list.Stdout = &listOut
	if err := list.Run(); err != nil {
		t.Fatalf("gpg --list-keys: %v", err)
	}
	var fpr string
	for line := range strings.SplitSeq(listOut.String(), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 10 {
				fpr = parts[9]
				break
			}
		}
	}
	if len(fpr) < 8 {
		t.Fatalf("could not parse fingerprint from: %s", listOut.String())
	}
	keyID = fpr[len(fpr)-8:]

	// Export the ASCII-armored public key.
	exp := exec.Command("gpg", "--armor", "--export", fpr) //nolint:gosec,noctx // test-only: fpr comes from gpg's own output, not user input
	exp.Env = env
	var expOut bytes.Buffer
	exp.Stdout = &expOut
	if err := exp.Run(); err != nil {
		t.Fatalf("gpg --export: %v", err)
	}
	publicKey = expOut.String()
	return home, keyID, publicKey
}

// TestGPGService_SignAndVerify proves the runtime behaviour the tfe_registry_gpg_key
// resource exists to enable: a signature produced by the private half of an uploaded key
// verifies against the public key, and a tampered payload is rejected. This is the
// signature-use loop registry provider binaries rely on, exercised without a full
// provider publish.
func TestGPGService_SignAndVerify(t *testing.T) {
	home, keyID, publicKey := gpgHomeWithKey(t)

	// GPGService shells out to `gpg`; point it at the isolated keyring for this test.
	t.Setenv("GNUPGHOME", home)

	svc := NewGPGService()

	// Sanity: the service extracts the same short key id from the exported armor.
	parsed, err := svc.ParseGPGKey(publicKey)
	if err != nil {
		t.Fatalf("ParseGPGKey: %v", err)
	}
	if !strings.EqualFold(parsed, keyID) {
		t.Errorf("ParseGPGKey = %q, want %q", parsed, keyID)
	}

	binary := []byte("stackweaver-provider-binary-payload-v1")
	sig, err := svc.SignBinary(keyID, bytes.NewReader(binary))
	if err != nil {
		t.Fatalf("SignBinary: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("SignBinary produced an empty signature")
	}

	// Good signature verifies.
	if err := svc.VerifySignature(publicKey, binary, sig); err != nil {
		t.Errorf("VerifySignature rejected a valid signature: %v", err)
	}

	// Tampered payload is rejected.
	tampered := []byte("stackweaver-provider-binary-payload-v1-TAMPERED")
	if err := svc.VerifySignature(publicKey, tampered, sig); err == nil {
		t.Error("VerifySignature accepted a signature over a tampered payload")
	}
}
