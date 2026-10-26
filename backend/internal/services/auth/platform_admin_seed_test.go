// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The sign-in half of the platform administrator's declared list (#132, D2, AC5): every browser
// sign-in hands the seeder the user row and the identity the sign-in verified, so the seeder
// matches on the verified email of that sign-in and never on the stored column. The decision
// itself lives in the platformadmin package and is tested there; these tests hold the auth service
// to what it passes and to failing open on a seeder error, as team sync does.
//
// These tests drove a JWT request through the middleware until the browser moved to the session
// cookie (backend-for-frontend-session-plan.md), which made sign-in the one place a person's
// identity is read. The outage-fallback case went with the per-request JWT path it described: a
// sign-in that cannot reach Zitadel does not complete at all.

package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

type recordingSeeder struct {
	calls []seederCall
	err   error
}

type seederCall struct {
	userID uuid.UUID
	id     BrowserIdentity
}

func (r *recordingSeeder) ApplyDeclared(_ context.Context, user *models.User, id BrowserIdentity) error {
	r.calls = append(r.calls, seederCall{userID: user.ID, id: id})
	return r.err
}

func TestPlatformAdminSeeder_ReceivesTheVerifiedIdentityOfTheSignIn(t *testing.T) {
	rig := newSignInRig(t)
	seeder := &recordingSeeder{}
	rig.svc.SetPlatformAdminSeeder(seeder)
	id := BrowserIdentity{Subject: "user-1", Email: "Admin@Zitadel.localhost", EmailVerified: true}

	user, err := rig.svc.ProvisionBrowserUser(context.Background(), id, rig.accessToken(t, "bff-client", nil))
	if err != nil {
		t.Fatalf("ProvisionBrowserUser: %v", err)
	}
	if len(seeder.calls) != 1 {
		t.Fatalf("seeder called %d times, want 1", len(seeder.calls))
	}
	got := seeder.calls[0]
	if got.userID != user.ID || got.id.Email != "Admin@Zitadel.localhost" || !got.id.EmailVerified {
		t.Errorf("seeder got user %s email %q verified=%v, want the provisioned user and the verified address", got.userID, got.id.Email, got.id.EmailVerified)
	}
}

// An unverified address is refused before the user row is read, so the seeder never sees it.
func TestPlatformAdminSeeder_NotCalledForAnUnverifiedEmail(t *testing.T) {
	rig := newSignInRig(t)
	seeder := &recordingSeeder{}
	rig.svc.SetPlatformAdminSeeder(seeder)
	id := BrowserIdentity{Subject: "user-1", Email: "admin@zitadel.localhost"}

	if _, err := rig.svc.ProvisionBrowserUser(context.Background(), id, rig.accessToken(t, "bff-client", nil)); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
	if len(seeder.calls) != 0 {
		t.Errorf("seeder called %d times for an unverified address, want 0", len(seeder.calls))
	}
}

// A seeder error is logged and does not fail the sign-in, as a team-sync error does not.
func TestPlatformAdminSeeder_ErrorDoesNotFailSignIn(t *testing.T) {
	rig := newSignInRig(t)
	rig.svc.SetPlatformAdminSeeder(&recordingSeeder{err: errors.New("database is read-only")})
	if _, err := rig.svc.ProvisionBrowserUser(context.Background(), verifiedIdentity, rig.accessToken(t, "bff-client", nil)); err != nil {
		t.Fatalf("a seeder error failed the sign-in: %v", err)
	}
}
