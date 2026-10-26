// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The request and response contract of the settings surface #858 converted onto JSON:API (D8,
// AC3). The handlers are mounted without InteractiveOnly, because they are tested here for
// shape, not identity: routes/settings_token_identity_test.go is what proves a token is refused.
// The identity provider behind the two-factor and session handlers is a fake standing in for the
// methods the handlers call; the API keys are real rows in the test database.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/handlers/ -run TestSettingsContract

//go:build integration

package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/sessions"
	"github.com/michielvha/stackweaver/backend/internal/services/totp"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// fakeTwoFactor is the identity provider's side of two-factor and password changes.
type fakeTwoFactor struct {
	enabled  bool
	password string
	// lagging makes the status read trail the write, the way the identity provider's
	// projections do for a moment after a verification.
	lagging bool
}

func (f *fakeTwoFactor) StartTOTPRegistration(string) (*totp.TOTPRegistrationResponse, error) {
	return &totp.TOTPRegistrationResponse{Secret: "JBSWY3DPEHPK3PXP", URL: "otpauth://totp/Stackweaver:contract?secret=JBSWY3DPEHPK3PXP"}, nil
}

func (f *fakeTwoFactor) VerifyTOTP(_, code string) error {
	if code != "123456" {
		return errors.New("code does not match")
	}
	f.enabled = true
	return nil
}

func (f *fakeTwoFactor) RemoveTOTP(string) error { f.enabled = false; return nil }

func (f *fakeTwoFactor) CheckTOTPStatus(string) (bool, error) { return f.enabled && !f.lagging, nil }

func (f *fakeTwoFactor) ChangePassword(_, current, next string) error {
	if current != f.password {
		return errors.New("current password does not match")
	}
	f.password = next
	return nil
}

func (f *fakeTwoFactor) ListMFADevices(string) ([]*totp.MFADevice, error) {
	return []*totp.MFADevice{{ID: "otp-1", Type: "totp", Name: "Authenticator", State: "ready"}}, nil
}

// fakeSessions is the identity provider's side of the session list.
type fakeSessions struct {
	revoked []string
	listErr error
}

func (f *fakeSessions) ListUserSessions(userID string) ([]*sessions.Session, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	return []*sessions.Session{
		{ID: "sess-1", UserID: userID, UserAgent: "Firefox", IPAddress: "192.0.2.1", CreationDate: now, ExpirationDate: now.Add(time.Hour), Factors: []string{"password"}},
		{ID: "sess-2", UserID: userID, UserAgent: "curl", IPAddress: "198.51.100.7", CreationDate: now, ExpirationDate: now.Add(time.Hour), Factors: []string{"password", "otp"}},
	}, nil
}

func (f *fakeSessions) RevokeSession(id string) error {
	f.revoked = append(f.revoked, id)
	return nil
}

// fakeBrowserSessions records which Zitadel sessions' browser sessions were ended.
type fakeBrowserSessions struct{ endedSIDs []string }

func (f *fakeBrowserSessions) DeleteByZitadelSID(sid string) (int64, error) {
	f.endedSIDs = append(f.endedSIDs, sid)
	return 1, nil
}

type settingsFixture struct {
	router   *gin.Engine
	user     *models.User
	orgID    string
	twoFA    *fakeTwoFactor
	sessions *fakeSessions
	browser  *fakeBrowserSessions
}

func setupSettingsContract(t *testing.T) *settingsFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	sfx := uuid.NewString()[:8]
	user := &models.User{ID: uuid.New(), ZitadelSubject: "settings-" + sfx, Email: "settings-" + sfx + "@test.local"}
	org := &models.Organization{ID: uuid.New(), Name: "settings-" + sfx}
	for _, row := range []any{user, org, &models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: user.ID}} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	t.Cleanup(func() {
		db.Where("user_id = ?", user.ID).Delete(&models.APIKey{})
		db.Where("organization_id = ?", org.ID).Delete(&models.OrganizationMember{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
		db.Where("id = ?", user.ID).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	f := &settingsFixture{user: user, orgID: org.ID.String(), twoFA: &fakeTwoFactor{password: "old-password"}, sessions: &fakeSessions{}, browser: &fakeBrowserSessions{}}
	totpHandler := &TOTPHandler{totpService: f.twoFA, authService: authService}
	sessionsHandler := &SessionsHandler{sessionsService: f.sessions, authService: authService, browserSessions: f.browser}
	keys := NewAPIKeyHandler(apikey.NewService(repository.NewAPIKeyRepository(db), orgRepo, repository.NewProjectRepository(db), repository.NewTeamRepository(db)), authService, nil)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", user.ID)
		c.Set("user_subject", user.ZitadelSubject)
		// The caller's browser session, signed in through Zitadel session sess-1.
		c.Set(auth.BrowserSessionContextKey, &models.BrowserSession{ZitadelSID: "sess-1"})
		c.Next()
	})
	// The paths of routes.SetupRoutes' settings group.
	s := r.Group("/api/v2/settings")
	s.GET("/2fa/status", totpHandler.GetTOTPStatus)
	s.POST("/2fa/start", totpHandler.StartTOTPRegistration)
	s.POST("/2fa/verify", totpHandler.VerifyTOTP)
	s.DELETE("/2fa", totpHandler.RemoveTOTP)
	s.POST("/password", totpHandler.ChangePassword)
	s.GET("/mfa-devices", totpHandler.ListMFADevices)
	s.GET("/sessions", sessionsHandler.ListSessions)
	s.DELETE("/sessions/:sessionId", sessionsHandler.RevokeSession)
	s.GET("/api-keys", keys.ListAPIKeys)
	s.POST("/api-keys", keys.CreateAPIKey)
	s.DELETE("/api-keys/:id", keys.DeleteAPIKey)
	f.router = r
	return f
}

type settingsDoc struct {
	Data   json.RawMessage `json:"data"`
	Meta   map[string]any  `json:"meta"`
	Errors []struct {
		Detail string `json:"detail"`
	} `json:"errors"`
}

type settingsResource struct {
	Type          string                     `json:"type"`
	ID            string                     `json:"id"`
	Attributes    map[string]any             `json:"attributes"`
	Relationships map[string]json.RawMessage `json:"relationships"`
}

func (f *settingsFixture) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (f *settingsFixture) doc(t *testing.T, method, path, body string, want int) settingsDoc {
	t.Helper()
	code, raw := f.call(t, method, path, body)
	if code != want {
		t.Fatalf("%s %s: got %d %s, want %d", method, path, code, raw, want)
	}
	var doc settingsDoc
	if want != http.StatusNoContent {
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s %s: not JSON: %v (%s)", method, path, err, raw)
		}
	} else if len(raw) != 0 {
		t.Errorf("%s %s: a 204 carried a body: %s", method, path, raw)
	}
	return doc
}

func (f *settingsFixture) refused(t *testing.T, method, path, body, want string) {
	t.Helper()
	code, raw := f.call(t, method, path, body)
	var doc settingsDoc
	_ = json.Unmarshal(raw, &doc)
	if code != http.StatusBadRequest || len(doc.Errors) != 1 || doc.Errors[0].Detail != want {
		t.Errorf("%s %s with %s: got %d %s\n want 400 with detail %q", method, path, body, code, raw, want)
	}
}

func settingsDocumentRequired(resourceType string) string {
	return `request body must be a JSON:API document: {"data": {"type": "` + resourceType + `", "attributes": {...}}}`
}

func oneSettingsResource(t *testing.T, doc settingsDoc, wantType string) settingsResource {
	t.Helper()
	var res settingsResource
	if err := json.Unmarshal(doc.Data, &res); err != nil || res.Type != wantType || res.ID == "" {
		t.Fatalf("data is not one %s resource: %s", wantType, doc.Data)
	}
	return res
}

func settingsCollection(t *testing.T, doc settingsDoc, wantType string) []settingsResource {
	t.Helper()
	var rows []settingsResource
	if err := json.Unmarshal(doc.Data, &rows); err != nil {
		t.Fatalf("data is not an array: %s", doc.Data)
	}
	for _, r := range rows {
		if r.Type != wantType || r.ID == "" {
			t.Fatalf("data holds %+v, want %s resources", r, wantType)
		}
	}
	p, ok := doc.Meta["pagination"].(map[string]any)
	if !ok || p["total-count"] != float64(len(rows)) {
		t.Errorf("a full collection states total-count %d: %v", len(rows), doc.Meta)
	}
	return rows
}

func TestSettingsContract(t *testing.T) {
	f := setupSettingsContract(t)

	t.Run("two-factor is a resource and its enrolment meta", func(t *testing.T) {
		status := oneSettingsResource(t, f.doc(t, http.MethodGet, "/api/v2/settings/2fa/status", "", http.StatusOK), "two-factor")
		if status.ID != f.user.ID.String() || status.Attributes["enabled"] != false {
			t.Errorf("status: %+v", status)
		}
		start := f.doc(t, http.MethodPost, "/api/v2/settings/2fa/start", "", http.StatusOK)
		if start.Data != nil || start.Meta["secret"] != "JBSWY3DPEHPK3PXP" || !strings.HasPrefix(start.Meta["url"].(string), "otpauth://") {
			t.Errorf("start: data %s, meta %v; want meta alone with secret and url", start.Data, start.Meta)
		}
		f.refused(t, http.MethodPost, "/api/v2/settings/2fa/verify", `{"code":"123456"}`, settingsDocumentRequired("two-factor"))
		f.refused(t, http.MethodPost, "/api/v2/settings/2fa/verify", `{"data":{"type":"users","attributes":{"code":"123456"}}}`, `data.type must be "two-factor" (got "users")`)
		// A successful verification is what enables two-factor, so its answer says enabled even
		// while a status read would still trail it.
		f.twoFA.lagging = true
		verified := oneSettingsResource(t, f.doc(t, http.MethodPost, "/api/v2/settings/2fa/verify", `{"data":{"type":"two-factor","attributes":{"code":"123456"}}}`, http.StatusOK), "two-factor")
		f.twoFA.lagging = false
		if verified.Attributes["enabled"] != true {
			t.Errorf("verify answered %+v, want enabled", verified)
		}
		f.doc(t, http.MethodDelete, "/api/v2/settings/2fa", "", http.StatusNoContent)
		if f.twoFA.enabled {
			t.Error("disable left two-factor enabled")
		}
	})

	t.Run("the password change takes a users document and answers 204", func(t *testing.T) {
		f.refused(t, http.MethodPost, "/api/v2/settings/password", `{"current_password":"old-password","new_password":"n"}`, settingsDocumentRequired("users"))
		code, raw := f.call(t, http.MethodPost, "/api/v2/settings/password", `{"data":{"type":"users","attributes":{"new-password":"next-password"}}}`)
		if code != http.StatusBadRequest || !strings.Contains(string(raw), "CurrentPassword") {
			t.Errorf("a missing current-password: got %d %s, want 400 naming it", code, raw)
		}
		f.doc(t, http.MethodPost, "/api/v2/settings/password", `{"data":{"type":"users","attributes":{"current-password":"old-password","new-password":"next-password"}}}`, http.StatusNoContent)
		if f.twoFA.password != "next-password" {
			t.Error("the password was not changed")
		}
	})

	t.Run("MFA devices and sessions are collections", func(t *testing.T) {
		devices := settingsCollection(t, f.doc(t, http.MethodGet, "/api/v2/settings/mfa-devices", "", http.StatusOK), "mfa-devices")
		if len(devices) != 1 || devices[0].ID != "otp-1" || devices[0].Attributes["device-type"] != "totp" || devices[0].Attributes["state"] != "ready" {
			t.Errorf("devices: %+v", devices)
		}
		list := settingsCollection(t, f.doc(t, http.MethodGet, "/api/v2/settings/sessions", "", http.StatusOK), "sessions")
		if len(list) != 2 || list[0].Attributes["user-agent"] != "Firefox" || list[0].Attributes["ip-address"] != "192.0.2.1" {
			t.Errorf("sessions: %+v", list)
		}
		// The current session is the one the caller's browser session was signed in through (its
		// sid). It was guessed from the caller's IP address before the browser held a session
		// (backend-for-frontend-session-plan.md, AC6), which two browsers behind one address defeat.
		if list[0].Attributes["is-current"] != true || list[1].Attributes["is-current"] != false {
			t.Errorf("is-current: %v, %v; the session the caller signed in through is the current one", list[0].Attributes["is-current"], list[1].Attributes["is-current"])
		}
		f.doc(t, http.MethodDelete, "/api/v2/settings/sessions/sess-2", "", http.StatusNoContent)
		if len(f.sessions.revoked) != 1 || f.sessions.revoked[0] != "sess-2" {
			t.Errorf("revoked %v", f.sessions.revoked)
		}
		// AC6: the browsers signed in through the revoked session are signed out with it.
		if len(f.browser.endedSIDs) != 1 || f.browser.endedSIDs[0] != "sess-2" {
			t.Errorf("browser sessions ended for %v, want [sess-2]", f.browser.endedSIDs)
		}
	})

	t.Run("a revoke whose ownership cannot be confirmed is refused", func(t *testing.T) {
		f.sessions.listErr = errors.New("zitadel unavailable")
		defer func() { f.sessions.listErr = nil }()
		revokedBefore := len(f.sessions.revoked)
		f.doc(t, http.MethodDelete, "/api/v2/settings/sessions/someone-elses", "", http.StatusServiceUnavailable)
		if len(f.sessions.revoked) != revokedBefore {
			t.Errorf("a session was revoked without confirming it belongs to the caller: %v", f.sessions.revoked)
		}
	})

	t.Run("API keys are created from a document, listed and deleted", func(t *testing.T) {
		f.refused(t, http.MethodPost, "/api/v2/settings/api-keys", `{"name":"ci"}`, settingsDocumentRequired("api-keys"))
		f.refused(t, http.MethodPost, "/api/v2/settings/api-keys", `{"data":{"type":"tokens","attributes":{"name":"ci"}}}`, `data.type must be "api-keys" (got "tokens")`)
		created := oneSettingsResource(t, f.doc(t, http.MethodPost, "/api/v2/settings/api-keys",
			`{"data":{"type":"api-keys","attributes":{"name":"contract-ci","scopes":["org:`+f.orgID+`:runner:register"],"expires-at":"2030-01-01T00:00:00Z"}}}`, http.StatusCreated), "api-keys")
		var org struct {
			Data struct{ Type, ID string } `json:"data"`
		}
		if err := json.Unmarshal(created.Relationships["organization"], &org); err != nil || org.Data.ID != f.orgID {
			t.Errorf("the key's organization relationship: %s", created.Relationships["organization"])
		}
		key, _ := created.Attributes["key"].(string)
		if key == "" || created.Attributes["name"] != "contract-ci" || created.Attributes["key-prefix"] == "" {
			t.Errorf("created %+v, want the key shown once with name and key-prefix", created)
		}
		listed := settingsCollection(t, f.doc(t, http.MethodGet, "/api/v2/settings/api-keys", "", http.StatusOK), "api-keys")
		if len(listed) != 1 || listed[0].ID != created.ID {
			t.Fatalf("listed %+v", listed)
		}
		if _, leaked := listed[0].Attributes["key"]; leaked {
			t.Error("the listing carries the plaintext key")
		}
		f.doc(t, http.MethodDelete, "/api/v2/settings/api-keys/"+created.ID, "", http.StatusNoContent)
		if code, raw := f.call(t, http.MethodDelete, "/api/v2/settings/api-keys/"+created.ID, ""); code != http.StatusNotFound {
			t.Errorf("deleting a missing key: got %d %s, want 404", code, raw)
		}
	})
}
