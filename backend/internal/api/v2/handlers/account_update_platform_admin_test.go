// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AC5 (#132, decision 9): asking for a declared platform administrator's address through
// PATCH /account/update flags nobody. The request leaves the stored email as it was and shows the
// address as unconfirmed-email, and the sign-in requests that follow flag nothing until the
// identity provider reports the address verified.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAccountUpdateDeclaredAddress

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
	"github.com/michielvha/stackweaver/core/models"
)

func TestAccountUpdateDeclaredAddress(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	declaredAddr := "platadm-boot-" + uuid.NewString()[:8] + "@zitadel.localhost"
	admins := f.service(platformadmin.Config{Declared: platformadmin.NewDeclared([]string{declaredAddr})})
	user := f.plain
	original := user.Email

	h := NewAccountHandlerV2(f.authSvc, f.users, nil)
	idp := &fakeProfiles{email: original}
	h.profiles = idp
	router := storedAsSentRouter()
	router.Use(func(c *gin.Context) { c.Set("user_subject", user.ZitadelSubject); c.Next() })
	router.PATCH("/account/update", h.Update)
	body := `{"data":{"type":"users","attributes":{"email":"` + declaredAddr + `"}}}`
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/account/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/vnd.api+json")
	r.Header.Set("X-Test-User", user.ID.String())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("update answered %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var doc struct {
		Data struct {
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Data.Attributes["email"] != original || doc.Data.Attributes["unconfirmed-email"] != declaredAddr {
		t.Errorf("answered email %v and unconfirmed-email %v, want %q and %q",
			doc.Data.Attributes["email"], doc.Data.Attributes["unconfirmed-email"], original, declaredAddr)
	}

	// signIn is what auth.Service.ProvisionBrowserUser does for one browser sign-in: sync the row
	// from the identity the sign-in verified (a verified address only reaches the repository), then
	// apply the declared list to it.
	signIn := func(t *testing.T, info auth.BrowserIdentity) *models.User {
		t.Helper()
		email := ""
		if info.EmailVerified {
			email = info.Email
		}
		u, err := f.users.GetOrCreateByZitadelSubject(user.ZitadelSubject, email, "")
		if err != nil {
			t.Fatalf("GetOrCreateByZitadelSubject: %v", err)
		}
		if err := admins.ApplyDeclared(t.Context(), u, info); err != nil {
			t.Fatalf("ApplyDeclared: %v", err)
		}
		u, err = f.users.GetByID(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	notFlagged := func(t *testing.T, when string, u *models.User) {
		t.Helper()
		if admin, _ := platformadmin.Status(u); admin {
			t.Errorf("%s: the user was flagged a platform administrator", when)
		}
		if u.Email != original {
			t.Errorf("%s: stored email became %q, want %q", when, u.Email, original)
		}
	}

	notFlagged(t, "after the update", signIn(t, auth.BrowserIdentity{Subject: user.ZitadelSubject, Email: original, EmailVerified: true}))
	// While the identity provider holds the address unverified, sign-in is refused before the row
	// is read; the seeder is never even reached with it, and nothing changes.
	notFlagged(t, "with the address pending", signIn(t, auth.BrowserIdentity{Subject: user.ZitadelSubject, Email: declaredAddr}))
	notFlagged(t, "with no email at all", signIn(t, auth.BrowserIdentity{Subject: user.ZitadelSubject}))
}
