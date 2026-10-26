// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AC32 of backend-for-frontend-session-plan.md: a Zitadel access token is no longer a credential
// for the API. The browser authenticates with its session cookie, and every programmatic caller
// with a `tfe-` token, so a JWT is refused in the Authorization header, as a run-log `?token=`,
// and through Authenticate, which the registry protocol calls.
//
// This file used to pin #829 D5 on the per-request JWT path: an unverified email was refused and a
// Zitadel outage fell back to a cache of verified subjects. That path is gone (owner, 2026-10-23),
// so its tests were rewritten into the refusal below. The email gate now runs once, at sign-in,
// and is pinned by TestProvisionBrowserUser_RefusesUnverifiedEmail; the liveness check re-reads
// email_verified for a live session.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

const bearerTestTFEToken = "tfe-bearer-test-token" //nolint:gosec // test fixture, not a real credential

// bearerTestRig signs real Zitadel-shaped JWTs that its verifier accepts, and holds one valid
// `tfe-` token, so a refusal can only be the API declining the JWT itself.
type bearerTestRig struct {
	priv    *rsa.PrivateKey
	svc     *Service
	user    *models.User
	lookups atomic.Int32
}

func newBearerTestRig(t *testing.T) *bearerTestRig {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rig := &bearerTestRig{priv: priv, user: &models.User{ID: uuid.New(), Email: "ada@example.com"}}
	repo := &mockUserRepo{
		getByIDFn: func(id uuid.UUID) (*models.User, error) {
			if id == rig.user.ID {
				return rig.user, nil
			}
			return nil, errors.New("user not found")
		},
		getOrCreateFn: func(subject, email, _ string) (*models.User, error) {
			rig.lookups.Add(1)
			return &models.User{ID: uuid.New(), ZitadelSubject: subject, Email: email}, nil
		},
	}
	rig.svc = NewServiceWithLookups(repo)
	rig.svc.SetAPIKeyService(&mockAPIKeyService{verifyFn: func(key string) (*models.APIKey, error) {
		if key != bearerTestTFEToken {
			return nil, errors.New("invalid api key")
		}
		return &models.APIKey{ID: uuid.New(), UserID: rig.user.ID, Kind: models.APIKeyKindUser}, nil
	}})
	rig.svc.issuer = "https://issuer.example"
	rig.svc.verifier = &ZitadelVerifier{issuer: "https://issuer.example", keySet: staticKeySet{pub: &priv.PublicKey}}
	rig.svc.verifier.AcceptAudience("bff")
	return rig
}

func (r *bearerTestRig) jwt(t *testing.T) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: r.priv}, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss": "https://issuer.example", "sub": "zitadel-sub", "aud": []string{"bff"},
		"email": "ada@example.com", "email_verified": true,
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

// serve sends the credential through the middleware, in the header or as a run-log ?token=.
func (r *bearerTestRig) serve(t *testing.T, credential string, asQuery bool) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(r.svc.AuthenticateMiddleware())
	engine.GET("/api/v2/runs/:id/logs", func(c *gin.Context) { c.Status(http.StatusOK) })
	target := "/api/v2/runs/run-1/logs"
	if asQuery {
		target += "?token=" + credential
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if !asQuery {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w.Code
}

func TestZitadelAccessTokenIsRefused(t *testing.T) {
	r := newBearerTestRig(t)
	tok := r.jwt(t)

	// The token is genuine: the verifier the API keeps for sign-in accepts it.
	if _, _, err := r.svc.verifier.VerifyToken(context.Background(), tok); err != nil {
		t.Fatalf("the test token does not verify, so its refusal would prove nothing: %v", err)
	}

	if code := r.serve(t, tok, false); code != http.StatusUnauthorized {
		t.Errorf("a Zitadel JWT in the Authorization header answered %d, want 401", code)
	}
	if code := r.serve(t, tok, true); code != http.StatusUnauthorized {
		t.Errorf("a Zitadel JWT as a run-log ?token= answered %d, want 401", code)
	}
	if _, authErr := authenticate(t, r.svc, tok); authErr == nil || authErr.Status != http.StatusUnauthorized {
		t.Errorf("Authenticate (the registry protocol's path) accepted a Zitadel JWT: %v", authErr)
	}
	if n := r.lookups.Load(); n != 0 {
		t.Errorf("a refused JWT provisioned a user %d time(s)", n)
	}
}

func TestTFETokenStillAuthenticatesEverywhere(t *testing.T) {
	r := newBearerTestRig(t)
	if code := r.serve(t, bearerTestTFEToken, false); code != http.StatusOK {
		t.Errorf("a tfe- token in the Authorization header answered %d, want 200", code)
	}
	if code := r.serve(t, bearerTestTFEToken, true); code != http.StatusOK {
		t.Errorf("a tfe- token as a run-log ?token= answered %d, want 200", code)
	}
	if id, authErr := authenticate(t, r.svc, bearerTestTFEToken); authErr != nil || id != r.user.ID {
		t.Errorf("Authenticate (the registry protocol's path) refused a tfe- token: %v", authErr)
	}
}
