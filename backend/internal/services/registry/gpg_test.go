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
	if len(fpr) < 16 {
		t.Fatalf("could not parse fingerprint from: %s", listOut.String())
	}
	keyID = fpr[len(fpr)-16:] // 16-char long key id — what ParseGPGKey returns

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

// aud122FixtureArmor is a real RSA-2048 public key exported with `gpg --armor --export`.
// Its 40-char fingerprint is 95AE57C99F86E3B15BACBE7F1B2AEEE4F44A48E5, so the 16-char
// long key id ParseGPGKey must return is 1B2AEEE4F44A48E5. Embedding it keeps the
// structured-parse assertions runnable in CI's plain `go test` (no gpg binary needed).
const (
	aud122FixtureArmor = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGpQVAcBCAC1/kCHS4mMXY+Kys/WrrUn0SO+xlUepuG07znv/62qU4imdNM1
LQON0SBa3gcaENKnva/As4Rcn3aHjywrOgzF5ktaib33/iHqsuoWTYmCJgOsUx83
DyRO8Mu2udGuN5OyW8MY3QCfZarqsfxrGkmMJP+Ma0ee8cGfkHOL5CsxGEfeyXL3
gmz97ZE1Yp4fBddywlblnR8KOp7NURVcbSldJU0Z1cWqsvJ3YvVfZx6qn0zQykzy
UB2ufbTTFPI9Cu2bwemw7Mzuv2Z7nkHqmAOEb9KkhK/9Zd/KDJtsi27QS+AUMFrS
W7WbdXugPCB8DZ2+UVPdsnwcyY4EYF9qyZXbABEBAAG0NVN0YWNrd2VhdmVyIEFV
RDEyMiBGaXh0dXJlIDxhdWQxMjJAc3RhY2t3ZWF2ZXIubG9jYWw+iQFSBBMBCgA8
FiEEla5XyZ+G47FbrL5/Gyru5PRKSOUFAmpQVAcDGy8EBQsJCAcCAiICBhUKCQgL
AgQWAgMBAh4HAheAAAoJEBsq7uT0SkjlDJUH/2xG8GVoN9rQ9nsKKKff7hkz3hss
aewWg6wUcKbQcMQh89HqDvhJsQiFQ/NSWOHon11yOsZK8GKSUN3db0ok8BXNIX7I
bnXNP/SsCvTCSeilGB6xzTVct20Iq3V/7eDrh5oKx5R1BeRvxL1Llw8f5UcqYJi+
V6mRaVdqsdn9t80B+vwBBsDnyCVLEgkWuGkEHV8sZOAJG0VgGIGfeWfHiaK3rtPB
NDAt9uGXIWYAxiRrcz7C1Vjz1MXYhRfF/8g2k/XWn7wJQ3NeUBNwUecit7JZ0AlS
5UqSIwEmiCar/VgdLYwGoKZGmVwmRGSZzyKCHm1asgMeipGdxyKLn+9QU/o=
=UzsX
-----END PGP PUBLIC KEY BLOCK-----`
	aud122FixtureLongKeyID = "1B2AEEE4F44A48E5"
)

// TestParseGPGKey_StructuredParse locks in the AUD-122 fix: ParseGPGKey performs a
// structured OpenPGP parse with no regex fallbacks, so it returns the correct 16-char
// long key id for a real armored key and REJECTS any input that is not a well-formed
// public key. Before the fix the final fallback returned "the first 8-hex-char run found
// anywhere in the text", so garbage was silently accepted as a trust anchor. Pure-Go —
// no gpg binary, runs in CI's plain `go test`.
func TestParseGPGKey_StructuredParse(t *testing.T) {
	svc := NewGPGService()

	got, err := svc.ParseGPGKey(aud122FixtureArmor)
	if err != nil {
		t.Fatalf("ParseGPGKey(valid armored key) errored: %v", err)
	}
	if got != aud122FixtureLongKeyID {
		t.Errorf("ParseGPGKey = %q, want %q (16-char long key id)", got, aud122FixtureLongKeyID)
	}

	// Every one of these was accepted by the old fallback chain (each contains an 8-hex
	// run or looked key-ish); the structured parse must reject them all.
	garbage := map[string]string{
		"empty":                 "",
		"plain text with hex":   "not a key at all DEADBEEF cafe1234 trust me",
		"bare hex fingerprint":  "95AE57C99F86E3B15BACBE7F1B2AEEE4F44A48E5",
		"fake colon pub line":   "pub:u:2048:1:DEADBEEFCAFE1234:...",
		"empty armor block":     "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----",
		"corrupt armor payload": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nZZZZnot-base64-at-all!!DEADBEEF\n=UzsX\n-----END PGP PUBLIC KEY BLOCK-----",
		"truncated armor":       aud122FixtureArmor[:len(aud122FixtureArmor)/2],
	}
	for name, in := range garbage {
		if got, err := svc.ParseGPGKey(in); err == nil {
			t.Errorf("ParseGPGKey(%s) = %q with nil error; want rejection", name, got)
		}
	}
}
