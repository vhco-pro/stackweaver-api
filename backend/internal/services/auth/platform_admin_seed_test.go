// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The sign-in half of the platform administrator's declared list (#132, D2, AC5): every JWT
// request hands the seeder the user row and the identity provider's answer for that request, so
// the seeder matches on the verified email of the request and never on the stored column. The
// decision itself lives in the platformadmin package and is tested there; these tests hold the
// auth service to what it passes and to failing open on a seeder error, as team sync does.

package auth

import (
	"context"
	"errors"
	"net/http"
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
	info   UserInfo
}

func (r *recordingSeeder) ApplyDeclared(_ context.Context, user *models.User, info *UserInfo) error {
	r.calls = append(r.calls, seederCall{userID: user.ID, info: *info})
	return r.err
}

func TestPlatformAdminSeeder_ReceivesTheVerifiedIdentityOfTheRequest(t *testing.T) {
	rig := newVerifiedTestRig(t)
	seeder := &recordingSeeder{}
	rig.svc.SetPlatformAdminSeeder(seeder)
	rig.userinfo.Store(`{"sub":"u-admin","email":"Admin@Zitadel.localhost","email_verified":true}`)

	if code := rig.viaMiddleware(t, rig.token(t, "u-admin")); code != http.StatusOK {
		t.Fatalf("middleware status = %d, want 200", code)
	}
	if len(seeder.calls) != 1 {
		t.Fatalf("seeder called %d times, want 1", len(seeder.calls))
	}
	got := seeder.calls[0].info
	if got.Email != "Admin@Zitadel.localhost" || !got.EmailVerified {
		t.Errorf("seeder got email %q verified=%v, want the identity provider's verified address", got.Email, got.EmailVerified)
	}
}

// An unverified address is refused before the user row is read, so the seeder never sees it.
func TestPlatformAdminSeeder_NotCalledForAnUnverifiedEmail(t *testing.T) {
	rig := newVerifiedTestRig(t)
	seeder := &recordingSeeder{}
	rig.svc.SetPlatformAdminSeeder(seeder)
	rig.userinfo.Store(`{"sub":"u-eve","email":"admin@zitadel.localhost"}`)

	if code := rig.viaMiddleware(t, rig.token(t, "u-eve")); code != http.StatusForbidden {
		t.Fatalf("middleware status = %d, want 403", code)
	}
	if len(seeder.calls) != 0 {
		t.Errorf("seeder called %d times for an unverified address, want 0", len(seeder.calls))
	}
}

// During an identity-provider outage the cached verified state lets a known subject through
// with no email at all; the seeder gets exactly that, so it can neither flag nor clear.
func TestPlatformAdminSeeder_OutageFallbackCarriesNoEmail(t *testing.T) {
	rig := newVerifiedTestRig(t)
	seeder := &recordingSeeder{}
	rig.svc.SetPlatformAdminSeeder(seeder)
	rig.userinfo.Store(`{"sub":"u-known","email":"admin@zitadel.localhost","email_verified":true}`)
	tok := rig.token(t, "u-known")
	if code := rig.viaMiddleware(t, tok); code != http.StatusOK {
		t.Fatalf("warm-up status = %d", code)
	}

	rig.userinfo.Store("") // the identity provider goes away
	if code := rig.viaMiddleware(t, tok); code != http.StatusOK {
		t.Fatalf("outage status = %d, want 200 from the cached verified state", code)
	}
	if len(seeder.calls) != 2 {
		t.Fatalf("seeder called %d times, want 2", len(seeder.calls))
	}
	if got := seeder.calls[1].info; got.Email != "" || got.EmailVerified {
		t.Errorf("outage fallback handed the seeder email %q verified=%v, want neither", got.Email, got.EmailVerified)
	}
}

// A seeder error is logged and does not fail authentication, as a team-sync error does not.
func TestPlatformAdminSeeder_ErrorDoesNotFailAuthentication(t *testing.T) {
	rig := newVerifiedTestRig(t)
	rig.svc.SetPlatformAdminSeeder(&recordingSeeder{err: errors.New("database is read-only")})
	rig.userinfo.Store(`{"sub":"u-ok","email":"ada@example.com","email_verified":true}`)
	if code := rig.viaMiddleware(t, rig.token(t, "u-ok")); code != http.StatusOK {
		t.Fatalf("middleware status = %d, want 200 despite the seeder error", code)
	}
}
