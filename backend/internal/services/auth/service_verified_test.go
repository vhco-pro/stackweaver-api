// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// #829 D5: an account whose email is not verified does not reach the platform, through either JWT
// path, and a Zitadel outage fails closed except for subjects already known to be verified.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

type staticKeySet struct{ pub *rsa.PublicKey }

func (k staticKeySet) VerifySignature(_ context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	return jws.Verify(k.pub)
}

// verifiedTestRig signs real JWTs, verifies them with a static key set, and answers userinfo with
// whatever the current test sets (status 0 = 503).
type verifiedTestRig struct {
	priv     *rsa.PrivateKey
	svc      *Service
	repo     *mockUserRepo
	lookups  atomic.Int32
	userinfo atomic.Value // string body; "" means the endpoint fails
}

func newVerifiedTestRig(t *testing.T) *verifiedTestRig {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rig := &verifiedTestRig{priv: priv}
	rig.userinfo.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, _ := rig.userinfo.Load().(string)
		if body == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	rig.repo = &mockUserRepo{getOrCreateFn: func(subject, email, _ string) (*models.User, error) {
		rig.lookups.Add(1)
		return &models.User{ID: uuid.New(), ZitadelSubject: subject, Email: email}, nil
	}}
	rig.svc = NewServiceWithLookups(rig.repo)
	rig.svc.issuer = "https://issuer.example"
	rig.svc.verifier = &ZitadelVerifier{
		issuer:       "https://issuer.example",
		keySet:       staticKeySet{pub: &priv.PublicKey},
		httpClient:   srv.Client(),
		internalAddr: strings.TrimPrefix(srv.URL, "http://"),
	}
	return rig
}

func (r *verifiedTestRig) token(t *testing.T, sub string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: r.priv}, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss": "https://issuer.example", "sub": sub, "aud": []string{"frontend"},
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (r *verifiedTestRig) viaMiddleware(t *testing.T, tok string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(r.svc.AuthenticateMiddleware())
	engine.GET("/api/v2/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v2/probe", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w.Code
}

// AC21: an unverified account gets 403 from the middleware and ErrEmailNotVerified from
// GetUserFromToken, and no users row is created (no repository lookup at all).
func TestVerifiedEmailGate_UnverifiedRefusedOnBothPaths(t *testing.T) {
	rig := newVerifiedTestRig(t)
	rig.userinfo.Store(`{"sub":"u-unverified","email":"eve@example.com"}`)
	tok := rig.token(t, "u-unverified")

	if code := rig.viaMiddleware(t, tok); code != http.StatusForbidden {
		t.Errorf("middleware status = %d, want 403", code)
	}
	if _, err := rig.svc.GetUserFromToken(context.Background(), tok); !errors.Is(err, ErrEmailNotVerified) {
		t.Errorf("GetUserFromToken err = %v, want ErrEmailNotVerified", err)
	}
	if n := rig.lookups.Load(); n != 0 {
		t.Errorf("an unverified account must not reach the user repository (%d lookups)", n)
	}
}

// AC14: a verified account reaches the repository with its email, which is where an invitation
// placeholder for that address is claimed.
func TestVerifiedEmailGate_VerifiedReachesRepository(t *testing.T) {
	rig := newVerifiedTestRig(t)
	rig.userinfo.Store(`{"sub":"u-ok","email":"ada@example.com","email_verified":true}`)
	var gotEmail string
	rig.repo.getOrCreateFn = func(subject, email, _ string) (*models.User, error) {
		gotEmail = email
		return &models.User{ID: uuid.New(), ZitadelSubject: subject, Email: email}, nil
	}
	tok := rig.token(t, "u-ok")
	if code := rig.viaMiddleware(t, tok); code != http.StatusOK {
		t.Fatalf("middleware status = %d, want 200", code)
	}
	if gotEmail != "ada@example.com" {
		t.Fatalf("the verified email must reach GetOrCreateByZitadelSubject, got %q", gotEmail)
	}
	if _, err := rig.svc.GetUserFromToken(context.Background(), tok); err != nil {
		t.Fatalf("GetUserFromToken: %v", err)
	}
}

// Machine users have no email at all; they cannot self-register or claim an invitation, so the
// email gate does not apply to them.
func TestVerifiedEmailGate_AccountWithoutEmailIsNotRefused(t *testing.T) {
	rig := newVerifiedTestRig(t)
	rig.userinfo.Store(`{"sub":"machine-1"}`)
	if code := rig.viaMiddleware(t, rig.token(t, "machine-1")); code != http.StatusOK {
		t.Fatalf("an account without an email must not be refused, got %d", code)
	}
}

// AC21 + Q14: when Zitadel cannot be reached, a subject already seen as verified proceeds and any
// other subject gets 503, never 200 and never "verify your email".
func TestVerifiedEmailGate_OutageUsesTheVerifiedCache(t *testing.T) {
	rig := newVerifiedTestRig(t)
	rig.userinfo.Store(`{"sub":"u-known","email":"ada@example.com","email_verified":true}`)
	known := rig.token(t, "u-known")
	if code := rig.viaMiddleware(t, known); code != http.StatusOK {
		t.Fatalf("warm-up request status = %d", code)
	}

	rig.userinfo.Store("") // Zitadel goes away
	if code := rig.viaMiddleware(t, known); code != http.StatusOK {
		t.Errorf("a cached verified subject must proceed during an outage, got %d", code)
	}
	if code := rig.viaMiddleware(t, rig.token(t, "u-stranger")); code != http.StatusServiceUnavailable {
		t.Errorf("an uncached subject must get 503 during an outage, got %d", code)
	}
	if _, err := rig.svc.GetUserFromToken(context.Background(), rig.token(t, "u-stranger")); !errors.Is(err, ErrIdentityUnavailable) {
		t.Errorf("GetUserFromToken err = %v, want ErrIdentityUnavailable", err)
	}
}
