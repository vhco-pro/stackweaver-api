// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// signInKeySet verifies with one RSA public key.
type signInKeySet struct{ pub *rsa.PublicKey }

func (k signInKeySet) VerifySignature(_ context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	return jws.Verify(k.pub)
}

type recordingTeamSyncer struct {
	user   uuid.UUID
	groups []string
}

func (r *recordingTeamSyncer) IsEnabled() bool { return true }
func (r *recordingTeamSyncer) SyncUserTeams(_ context.Context, userID uuid.UUID, groups []string) error {
	r.user, r.groups = userID, groups
	return nil
}

type signInRig struct {
	priv   *rsa.PrivateKey
	svc    *Service
	syncer *recordingTeamSyncer
	made   []string // subjects the repository provisioned
}

func newSignInRig(t *testing.T) *signInRig {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rig := &signInRig{priv: priv, syncer: &recordingTeamSyncer{}}
	repo := &mockUserRepo{getOrCreateFn: func(subject, email, _ string) (*models.User, error) {
		rig.made = append(rig.made, subject)
		return &models.User{ID: uuid.New(), ZitadelSubject: subject, Email: email}, nil
	}}
	rig.svc = NewServiceWithLookups(repo)
	rig.svc.verifier = &ZitadelVerifier{issuer: "https://issuer.example", keySet: signInKeySet{pub: &priv.PublicKey}}
	rig.svc.verifier.AcceptAudience("bff-client")
	rig.svc.SetTeamSyncer(rig.syncer)
	return rig
}

func (r *signInRig) accessToken(t *testing.T, aud string, groups []string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: r.priv}, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss": "https://issuer.example", "sub": "user-1", "aud": []string{aud},
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}
	if groups != nil {
		claims["sso_groups"] = groups
	}
	payload, err := json.Marshal(claims)
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

var verifiedIdentity = BrowserIdentity{Subject: "user-1", Email: "ada@example.com", EmailVerified: true, Name: "Ada"}

// A verified sign-in provisions the user and syncs the SSO groups its access token carries.
func TestProvisionBrowserUser_ProvisionsAndSyncsGroups(t *testing.T) {
	rig := newSignInRig(t)
	user, err := rig.svc.ProvisionBrowserUser(context.Background(), verifiedIdentity,
		rig.accessToken(t, "bff-client", []string{"platform-admins", "devs"}))
	if err != nil {
		t.Fatalf("ProvisionBrowserUser: %v", err)
	}
	if !slices.Equal(rig.made, []string{"user-1"}) {
		t.Fatalf("want the user provisioned once, got %v", rig.made)
	}
	if rig.syncer.user != user.ID || !slices.Equal(rig.syncer.groups, []string{"platform-admins", "devs"}) {
		t.Fatalf("SSO groups not synced for the user: %+v", rig.syncer)
	}
}

// An unverified email is refused before anything is provisioned.
func TestProvisionBrowserUser_RefusesUnverifiedEmail(t *testing.T) {
	rig := newSignInRig(t)
	id := verifiedIdentity
	id.EmailVerified = false
	if _, err := rig.svc.ProvisionBrowserUser(context.Background(), id, rig.accessToken(t, "bff-client", nil)); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
	if len(rig.made) != 0 {
		t.Fatalf("an unverified account must not be provisioned")
	}
}

// An access token that does not verify (here: issued for another client) is refused, so an
// unverified sso_groups claim never reaches team sync.
func TestProvisionBrowserUser_RefusesAnUnverifiedAccessToken(t *testing.T) {
	rig := newSignInRig(t)
	if _, err := rig.svc.ProvisionBrowserUser(context.Background(), verifiedIdentity,
		rig.accessToken(t, "some-other-client", []string{"admins"})); err == nil {
		t.Fatalf("an access token for another client must be refused")
	}
	if len(rig.made) != 0 || rig.syncer.groups != nil {
		t.Fatalf("nothing may be provisioned or synced from an unverified token")
	}
}
