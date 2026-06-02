// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if !verifyPKCE(verifier, challenge) {
		t.Error("verifyPKCE returned false for a matching verifier/challenge pair")
	}

	if verifyPKCE("wrong-verifier", challenge) {
		t.Error("verifyPKCE returned true for a non-matching verifier")
	}

	if verifyPKCE(verifier, "") {
		t.Error("verifyPKCE returned true for an empty challenge")
	}

	// A plain (non-S256) challenge equal to the verifier must be rejected — we
	// only support S256, so a verifier can never equal its own challenge.
	if verifyPKCE(verifier, verifier) {
		t.Error("verifyPKCE accepted a plain challenge (S256 required)")
	}
}

func TestValidLoopbackRedirect(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want bool
	}{
		{"localhost in range", "http://localhost:10000/login", true},
		{"127.0.0.1 in range", "http://127.0.0.1:10010/login", true},
		{"127.0.0.1 mid range", "http://127.0.0.1:10005/", true},
		{"port below range", "http://127.0.0.1:9999/login", false},
		{"port above range", "http://127.0.0.1:10011/login", false},
		{"no port", "http://127.0.0.1/login", false},
		{"https scheme", "https://127.0.0.1:10000/login", false},
		{"non-loopback host", "http://evil.example.com:10000/login", false},
		{"non-loopback ip", "http://10.0.0.5:10000/login", false},
		{"empty", "", false},
		{"garbage", "://nope", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validLoopbackRedirect(tc.uri); got != tc.want {
				t.Errorf("validLoopbackRedirect(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

func TestGenerateAuthCode(t *testing.T) {
	a, err := generateAuthCode()
	if err != nil {
		t.Fatalf("generateAuthCode error: %v", err)
	}
	b, err := generateAuthCode()
	if err != nil {
		t.Fatalf("generateAuthCode error: %v", err)
	}
	if a == b {
		t.Error("generateAuthCode returned identical codes")
	}
	// 32 random bytes hex-encoded = 64 chars.
	if len(a) != 64 {
		t.Errorf("generateAuthCode length = %d, want 64", len(a))
	}
}

func TestServiceDiscoveryAdvertisesLoginV1(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/.well-known/terraform.json", HandleServiceDiscovery)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/terraform.json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	for _, want := range []string{
		`"login.v1"`,
		`"authz":"/oauth/authorize"`,
		`"token":"/api/v2/oauth/token"`,
		`"client":"terraform-cli"`,
	} {
		if !containsJSON(body, want) {
			t.Errorf("discovery body missing %s; got %s", want, body)
		}
	}
}

// containsJSON checks substring presence ignoring gin's key spacing.
func containsJSON(body, want string) bool {
	return len(body) > 0 && (indexOf(body, want) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
