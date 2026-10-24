// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The declared list against real Postgres (#132, D2): ApplyDeclared at sign-in flags, promotes
// and clears; Reconcile at startup clears a declared administrator whose address left the list;
// each transition writes its activity row (AC4, AC7, AC11).
//
// The database may be a live one, so every row is the test's own and is deleted by id. Reconcile
// clears every declared row whose email is off the list it is given, so the test always hands it
// the addresses of the declared administrators that already exist, and only its own row can
// change.
//
//	go test -tags integration ./internal/services/platformadmin/ -run TestDeclared

//go:build integration

package platformadmin

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/activity"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

type declaredRig struct {
	db    *gorm.DB
	users *repository.UserRepository
	audit *activity.Service
}

func newDeclaredRig(t *testing.T) *declaredRig {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dsn, nil)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &declaredRig{
		db:    db,
		users: repository.NewUserRepository(db),
		audit: activity.NewService(repository.NewAuditLogRepository(db)),
	}
}

// user creates a user row with the given email and flags and deletes it, and its audit rows, when
// the test ends.
func (r *declaredRig) user(t *testing.T, email string, admin, declared bool) *models.User {
	t.Helper()
	u := &models.User{ID: uuid.New(), ZitadelSubject: "platadm-" + uuid.NewString(), Email: email}
	if err := r.db.Create(u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	if admin || declared {
		if _, err := r.users.SetPlatformAdmin(u.ID, admin, declared); err != nil {
			t.Fatalf("flag user: %v", err)
		}
	}
	t.Cleanup(func() {
		r.db.Where("resource_type = ? AND resource_id = ?", "user", u.ID).Delete(&models.AuditLog{})
		r.db.Where("id = ?", u.ID).Delete(&models.User{})
	})
	return u
}

// service builds the service over the given declared addresses plus every declared administrator
// already in the database other than the test's own rows.
func (r *declaredRig) service(t *testing.T, own []uuid.UUID, emails ...string) *Service {
	t.Helper()
	var others []string
	if err := r.db.Model(&models.User{}).Where("platform_admin_declared AND id NOT IN ?", own).
		Pluck("email", &others).Error; err != nil {
		t.Fatalf("read existing declared administrators: %v", err)
	}
	return NewService(r.users, nil, r.audit, Config{Declared: NewDeclared(append(others, emails...))})
}

func (r *declaredRig) reload(t *testing.T, id uuid.UUID) *models.User {
	t.Helper()
	u, err := r.users.GetByID(id)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	return u
}

func (r *declaredRig) actions(t *testing.T, id uuid.UUID) []models.AuditLog {
	t.Helper()
	var rows []models.AuditLog
	if err := r.db.Where("resource_type = ? AND resource_id = ?", "user", id).Order("created_at").Find(&rows).Error; err != nil {
		t.Fatalf("read audit rows: %v", err)
	}
	return rows
}

func assertFlags(t *testing.T, u *models.User, admin, declared bool) {
	t.Helper()
	if u.PlatformAdmin != admin || u.PlatformAdminDeclared != declared {
		t.Errorf("user %s: platform_admin=%v platform_admin_declared=%v, want %v and %v",
			u.Email, u.PlatformAdmin, u.PlatformAdminDeclared, admin, declared)
	}
}

// assertSystemAction checks the one audit row an automatic transition writes: no organization, no
// acting user, the system as actor, the target and the action.
func assertSystemAction(t *testing.T, rows []models.AuditLog, action string, target uuid.UUID) {
	t.Helper()
	if len(rows) != 1 {
		t.Fatalf("got %d audit rows for the user, want 1 %s", len(rows), action)
	}
	row := rows[0]
	if row.Action != action || row.OrganizationID != nil || row.UserID != nil {
		t.Errorf("audit row = action %q org %v user %v, want %q with no organization and no acting user", row.Action, row.OrganizationID, row.UserID, action)
	}
	if row.ResourceID == nil || *row.ResourceID != target {
		t.Errorf("audit row target = %v, want %s", row.ResourceID, target)
	}
	if row.Details["actor"] != "system" {
		t.Errorf("audit row actor = %v, want system", row.Details["actor"])
	}
}

func verified(email string) *auth.UserInfo {
	return &auth.UserInfo{Email: email, EmailVerified: true}
}

// AC7 + AC11: a verified, listed address is flagged declared at sign-in, matched
// case-insensitively, and the declaration is audited once however many requests repeat it.
func TestDeclared_SignInFlagsAListedAddress(t *testing.T) {
	r := newDeclaredRig(t)
	email := "platadm-" + uuid.NewString()[:8] + "@zitadel.localhost"
	u := r.user(t, email, false, false)
	svc := r.service(t, []uuid.UUID{u.ID}, strings.ToUpper(email))

	for range 3 {
		row := r.reload(t, u.ID)
		if err := svc.ApplyDeclared(t.Context(), row, verified(email)); err != nil {
			t.Fatalf("ApplyDeclared: %v", err)
		}
	}
	assertFlags(t, r.reload(t, u.ID), true, true)
	assertSystemAction(t, r.actions(t, u.ID), ActionDeclared, u.ID)
}

// A granted administrator whose address is on the list is promoted to declared, so the UI shows
// the row read-only.
func TestDeclared_SignInPromotesAGrantedAdministrator(t *testing.T) {
	r := newDeclaredRig(t)
	email := "platadm-" + uuid.NewString()[:8] + "@test.local"
	u := r.user(t, email, true, false)
	svc := r.service(t, []uuid.UUID{u.ID}, email)

	if err := svc.ApplyDeclared(t.Context(), r.reload(t, u.ID), verified(email)); err != nil {
		t.Fatalf("ApplyDeclared: %v", err)
	}
	assertFlags(t, r.reload(t, u.ID), true, true)
	assertSystemAction(t, r.actions(t, u.ID), ActionDeclared, u.ID)
}

// AC5: the match uses the identity provider's verified email of the request only. A stored
// email equal to a declared address flags nothing while the request's address differs, is
// unverified, or is absent (the outage fallback).
func TestDeclared_SignInIgnoresTheStoredColumn(t *testing.T) {
	r := newDeclaredRig(t)
	declared := "platadm-" + uuid.NewString()[:8] + "@zitadel.localhost"
	u := r.user(t, declared, false, false)
	svc := r.service(t, []uuid.UUID{u.ID}, declared)

	for name, info := range map[string]*auth.UserInfo{
		"different verified address":  verified("someone-else-" + uuid.NewString()[:8] + "@test.local"),
		"unverified declared address": {Email: declared, EmailVerified: false},
		"outage fallback":             {Subject: u.ZitadelSubject},
		"no identity":                 nil,
	} {
		if err := svc.ApplyDeclared(t.Context(), r.reload(t, u.ID), info); err != nil {
			t.Fatalf("%s: ApplyDeclared: %v", name, err)
		}
		assertFlags(t, r.reload(t, u.ID), false, false)
	}
	if rows := r.actions(t, u.ID); len(rows) != 0 {
		t.Errorf("got %d audit rows, want none", len(rows))
	}
}

// AC4, sign-in half: a declared administrator whose verified email is no longer on the list loses
// both columns on their next JWT request; a request with no verified email clears nothing.
func TestDeclared_SignInClearsAnAddressOffTheList(t *testing.T) {
	r := newDeclaredRig(t)
	email := "platadm-" + uuid.NewString()[:8] + "@test.local"
	u := r.user(t, email, true, true)
	svc := r.service(t, []uuid.UUID{u.ID}) // the list no longer names the user

	if err := svc.ApplyDeclared(t.Context(), r.reload(t, u.ID), &auth.UserInfo{Subject: u.ZitadelSubject}); err != nil {
		t.Fatalf("ApplyDeclared (outage fallback): %v", err)
	}
	assertFlags(t, r.reload(t, u.ID), true, true)

	if err := svc.ApplyDeclared(t.Context(), r.reload(t, u.ID), verified(email)); err != nil {
		t.Fatalf("ApplyDeclared: %v", err)
	}
	assertFlags(t, r.reload(t, u.ID), false, false)
	assertSystemAction(t, r.actions(t, u.ID), ActionUndeclared, u.ID)
}

// A granted administrator who is not on the list keeps the grant: only declared rows follow the
// list.
func TestDeclared_SignInLeavesAGrantAlone(t *testing.T) {
	r := newDeclaredRig(t)
	email := "platadm-" + uuid.NewString()[:8] + "@test.local"
	u := r.user(t, email, true, false)
	svc := r.service(t, []uuid.UUID{u.ID})

	if err := svc.ApplyDeclared(t.Context(), r.reload(t, u.ID), verified(email)); err != nil {
		t.Fatalf("ApplyDeclared: %v", err)
	}
	assertFlags(t, r.reload(t, u.ID), true, false)
}

// AC4, startup half: Reconcile clears a declared administrator whose address left the list,
// without waiting for them to sign in, and keeps one who is still listed and every grant.
func TestDeclared_ReconcileClearsAddressesOffTheList(t *testing.T) {
	r := newDeclaredRig(t)
	sfx := uuid.NewString()[:8]
	gone := r.user(t, "platadm-gone-"+sfx+"@test.local", true, true)
	kept := r.user(t, "platadm-kept-"+sfx+"@test.local", true, true)
	granted := r.user(t, "platadm-granted-"+sfx+"@test.local", true, false)
	svc := r.service(t, []uuid.UUID{gone.ID, kept.ID, granted.ID}, strings.ToUpper(kept.Email))

	if err := svc.Reconcile(t.Context()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	assertFlags(t, r.reload(t, gone.ID), false, false)
	assertFlags(t, r.reload(t, kept.ID), true, true)
	assertFlags(t, r.reload(t, granted.ID), true, false)
	assertSystemAction(t, r.actions(t, gone.ID), ActionUndeclared, gone.ID)
	if rows := r.actions(t, kept.ID); len(rows) != 0 {
		t.Errorf("the listed administrator got %d audit rows, want none", len(rows))
	}
}
