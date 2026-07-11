// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package registry

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// signWithFreshKey simulates a provider publisher: it generates a throwaway OpenPGP
// key entirely in-process (no gpg binary), returns the ASCII-armored public half (what
// gets registered via tfe_registry_gpg_key) and a detached signature over payload. armored
// selects an ASCII-armored detached signature (`gpg --armor --detach-sign`) vs the binary
// form (`gpg --detach-sign`); SHA256SUMS.sig is conventionally binary.
func signWithFreshKey(t *testing.T, payload []byte, armored bool) (publicKeyASCII string, signature []byte) {
	t.Helper()
	entity, err := openpgp.NewEntity("Stackweaver Publisher", "aud106", "publisher@stackweaver.local", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}

	var pub bytes.Buffer
	w, err := armor.Encode(&pub, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if err := entity.Serialize(w); err != nil {
		t.Fatalf("Serialize public key: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close armor: %v", err)
	}

	var sig bytes.Buffer
	if armored {
		err = openpgp.ArmoredDetachSign(&sig, entity, bytes.NewReader(payload), nil)
	} else {
		err = openpgp.DetachSign(&sig, entity, bytes.NewReader(payload), nil)
	}
	if err != nil {
		t.Fatalf("DetachSign: %v", err)
	}
	return pub.String(), sig.Bytes()
}

// TestVerifyDetachedSignature is the AUD-106 trust-check: the registry accepts a
// publisher-produced detached signature over SHA256SUMS only when it was made by the
// exact key registered to the org. It proves a good signature verifies, a tampered
// payload is rejected, a signature made by a DIFFERENT key is rejected (the keyring is
// built from only the registered key), and the armored signature form is accepted too.
// Pure Go — runs in CI's plain `go test`, no gpg binary.
func TestVerifyDetachedSignature(t *testing.T) {
	svc := NewGPGService()
	payload := []byte("f1b2...deadbeef  terraform-provider-test_1.0.0_linux_amd64.zip\n")

	pub, sig := signWithFreshKey(t, payload, false)

	// Good signature verifies.
	if err := svc.VerifyDetachedSignature(pub, payload, sig); err != nil {
		t.Errorf("VerifyDetachedSignature rejected a valid signature: %v", err)
	}

	// Tampered payload is rejected.
	if err := svc.VerifyDetachedSignature(pub, []byte("tampered SHA256SUMS\n"), sig); err == nil {
		t.Error("VerifyDetachedSignature accepted a signature over a tampered payload")
	}

	// A signature made by a key that is NOT the registered one is rejected — the whole
	// point is that verification is pinned to the org's key, not "any valid signature".
	otherPub, otherSig := signWithFreshKey(t, payload, false)
	_ = otherPub
	if err := svc.VerifyDetachedSignature(pub, payload, otherSig); err == nil {
		t.Error("VerifyDetachedSignature accepted a signature made by an unregistered key")
	}

	// The ASCII-armored detached signature form is also accepted.
	pubA, sigA := signWithFreshKey(t, payload, true)
	if err := svc.VerifyDetachedSignature(pubA, payload, sigA); err != nil {
		t.Errorf("VerifyDetachedSignature rejected a valid armored detached signature: %v", err)
	}

	// A malformed public key is a parse error, not a silent pass.
	if err := svc.VerifyDetachedSignature("not a key", payload, sig); err == nil {
		t.Error("VerifyDetachedSignature accepted a malformed public key")
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
