// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package logtoken

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMintVerify_CarriesTheCredential(t *testing.T) {
	SetSecret([]byte("test-secret-key-32-bytes-long!!!"))
	t.Cleanup(func() { SetSecret(nil) })

	runID := "run-abc123"
	for name, cred := range map[string]Credential{
		"api key":         {APIKeyID: uuid.New()},
		"browser session": {BrowserSessionID: uuid.New()},
	} {
		t.Run(name, func(t *testing.T) {
			tok := Mint(runID, cred)
			if tok == "" {
				t.Fatal("Mint returned empty")
			}
			got, ok := Verify(tok, runID)
			if !ok || got != cred {
				t.Fatalf("Verify = %+v, %v; want %+v, true", got, ok, cred)
			}
			// Bound to its run.
			if _, ok := Verify(tok, "run-other"); ok {
				t.Error("a token verified for another run")
			}
			// Tampered signature.
			if _, ok := Verify(tok+"x", runID); ok {
				t.Error("a tampered token verified")
			}
			// Forged payload with the real signature.
			sig := tok[strings.Index(tok, ".")+1:]
			if _, ok := Verify("YWFhYQ."+sig, runID); ok {
				t.Error("a forged payload verified")
			}
		})
	}
	if _, ok := Verify("not-a-token", runID); ok {
		t.Error("garbage verified")
	}
	if tok := Mint(runID, Credential{}); tok != "" {
		t.Error("a token was minted for no credential")
	}
}

func TestMintVerify_DisabledWithoutSecret(t *testing.T) {
	SetSecret(nil)
	if tok := Mint("run-x", Credential{BrowserSessionID: uuid.New()}); tok != "" {
		t.Error("minted a token without a secret")
	}
	if _, ok := Verify("anything", "run-x"); ok {
		t.Error("verified a token without a secret")
	}
}

// A token naming only a user, with no API key or browser session behind it, is refused even when
// correctly signed: nothing could end it before it expires.
func TestVerify_RefusesAUserOnlyToken(t *testing.T) {
	SetSecret([]byte("test-secret-key-32-bytes-long!!!"))
	t.Cleanup(func() { SetSecret(nil) })

	payload := fmt.Sprintf("run-abc:u:%s:%d", uuid.New(), time.Now().Add(TTL).Unix())
	tok := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sign(payload)
	if _, ok := Verify(tok, "run-abc"); ok {
		t.Fatal("a signed user-only token verified")
	}
}
