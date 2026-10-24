// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAccountUpdateStoredEmail

//go:build integration
// +build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/profile"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// fakeProfiles stands in for the identity provider's copy of the profile.
type fakeProfiles struct {
	email        string
	emailUpdates int
}

func (f *fakeProfiles) GetUserProfile(string) (*profile.UserProfile, error) {
	return &profile.UserProfile{Email: f.email}, nil
}

func (f *fakeProfiles) UpdateUserProfile(_ string, req *profile.UpdateProfileRequest) error {
	if req.Email != "" {
		f.email = req.Email
		f.emailUpdates++
	}
	return nil
}

// TestAccountUpdateStoredEmail pins that an account update never writes the stored email. Only
// the sign-in sync stores an address, and only one the identity provider has verified, because
// invitations, team membership by email and first sign-in all resolve people by that column.
func TestAccountUpdateStoredEmail(t *testing.T) {
	db := setupTestDB(t)
	users := repository.NewUserRepository(db)
	user := createRegistryTestUser(t, db)
	original := user.Email

	patch := func(t *testing.T, h *AccountHandlerV2, email string) (int, map[string]any) {
		t.Helper()
		router := storedAsSentRouter()
		router.Use(func(c *gin.Context) { c.Set("user_subject", user.ZitadelSubject); c.Next() })
		router.PATCH("/account/update", h.Update)
		body := `{"data":{"type":"users","attributes":{"email":"` + email + `"}}}`
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/account/update", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/vnd.api+json")
		r.Header.Set("X-Test-User", user.ID.String())
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, r)
		var doc struct {
			Data struct {
				Attributes map[string]any `json:"attributes"`
			} `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &doc)
		return rec.Code, doc.Data.Attributes
	}
	stored := func(t *testing.T) string {
		t.Helper()
		var u models.User
		if err := db.First(&u, "id = ?", user.ID).Error; err != nil {
			t.Fatalf("reading the user: %v", err)
		}
		return u.Email
	}

	t.Run("without an identity provider a change is refused", func(t *testing.T) {
		h := NewAccountHandlerV2(auth.NewService(users), users, nil)
		if code, _ := patch(t, h, "someone.else@example.com"); code != http.StatusUnprocessableEntity {
			t.Fatalf("a changed email answered %d, want 422", code)
		}
		if got := stored(t); got != original {
			t.Fatalf("stored email became %q, want %q", got, original)
		}
		if code, _ := patch(t, h, strings.ToUpper(original)); code != http.StatusOK {
			t.Fatalf("resending the current email answered %d, want 200", code)
		}
	})

	t.Run("resending the stored address does not reach the identity provider", func(t *testing.T) {
		h := NewAccountHandlerV2(auth.NewService(users), users, nil)
		idp := &fakeProfiles{email: original}
		h.profiles = idp
		if code, _ := patch(t, h, strings.ToUpper(original)); code != http.StatusOK {
			t.Fatalf("update answered %d, want 200", code)
		}
		if idp.emailUpdates != 0 {
			t.Errorf("the identity provider was asked to set the email %d times, want 0", idp.emailUpdates)
		}
	})

	t.Run("with an identity provider the change stays unconfirmed", func(t *testing.T) {
		h := NewAccountHandlerV2(auth.NewService(users), users, nil)
		idp := &fakeProfiles{email: original}
		h.profiles = idp
		code, attrs := patch(t, h, "someone.else@example.com")
		if code != http.StatusOK {
			t.Fatalf("update answered %d, want 200", code)
		}
		if idp.email != "someone.else@example.com" {
			t.Errorf("the identity provider holds %q, want the requested address", idp.email)
		}
		if got := stored(t); got != original {
			t.Errorf("stored email became %q, want %q until the address is verified", got, original)
		}
		if attrs["email"] != original || attrs["unconfirmed-email"] != "someone.else@example.com" {
			t.Errorf("answered email %v and unconfirmed-email %v, want %q and the requested address", attrs["email"], attrs["unconfirmed-email"], original)
		}
	})
}
