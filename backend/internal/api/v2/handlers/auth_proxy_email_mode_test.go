// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// #829: in email mode the anonymous code-issuing endpoints must never forward a caller-supplied
// `returnCode` (Zitadel would answer with the code) or `isVerified` (it would pre-verify an
// address nobody proved they own).

package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// captureUpstream records the JSON body of the first request to path.
func captureUpstream(t *testing.T, path, response string) (*httptest.Server, *map[string]any) {
	t.Helper()
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/settings/login":
			_, _ = w.Write([]byte(`{"settings":{"allowRegister":true}}`))
		case r.Method == http.MethodPost && r.URL.Path == path:
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Errorf("decoding forwarded body: %v", err)
			}
			_, _ = w.Write([]byte(response))
		case r.Method == http.MethodGet && r.URL.Path == "/v2/users/123":
			_, _ = w.Write([]byte(`{"user":{"userId":"123","state":"USER_STATE_ACTIVE"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestPasswordReset_EmailModeStripsCallerReturnCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv, got := captureUpstream(t, "/v2/users/42/password_reset", `{"details":{}}`)
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "pat", NotificationMode: NotificationModeEmail})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/42/password-reset", `{"returnCode":{}}`)
	c.Params = gin.Params{{Key: "id", Value: "42"}}
	proxy.PasswordReset(c)

	if *got == nil {
		t.Fatal("password reset was not forwarded")
	}
	if _, ok := (*got)["returnCode"]; ok {
		t.Fatalf("email mode forwarded a caller-supplied returnCode: %v", *got)
	}
}

func TestCreateUser_EmailModeStripsReturnCodeAndIsVerified(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv, got := captureUpstream(t, "/v2/users/human", `{"userId":"123"}`)
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "pat", NotificationMode: NotificationModeEmail})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/human",
		`{"username":"eve","email":{"email":"victim@example.com","returnCode":{},"isVerified":true},"phone":{"phone":"+3200","returnCode":{},"isVerified":true}}`)
	proxy.CreateUser(c)

	if *got == nil {
		t.Fatalf("user create was not forwarded (status %d: %s)", w.Code, w.Body.String())
	}
	// The registration allowlist (#829 AC7) drops `phone` entirely, which is stricter than the
	// original hotfix's stripping; a forwarded email or phone object must still carry neither field.
	if _, ok := (*got)["email"].(map[string]any); !ok {
		t.Fatalf("email object missing from forwarded body: %v", *got)
	}
	for _, key := range []string{"email", "phone"} {
		contact, ok := (*got)[key].(map[string]any)
		if !ok {
			continue
		}
		for _, field := range []string{"returnCode", "isVerified"} {
			if _, present := contact[field]; present {
				t.Errorf("email mode forwarded %s.%s: %v", key, field, contact)
			}
		}
	}
}

// #829 AC7: the anonymous registration endpoint forwards only allowlisted fields, so a caller
// cannot steer where the verification mail's link points, attach identity data, or link an IdP
// identity without a redeemed intent.
func TestCreateUser_ForwardsOnlyAllowlistedFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv, got := captureUpstream(t, "/v2/users/human", `{"userId":"123"}`)
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "pat", NotificationMode: NotificationModeEmail})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/human", `{
		"username": "eve",
		"profile": {"givenName": "Eve", "familyName": "Example", "extra": "x"},
		"email": {"email": "eve@example.com", "sendCode": {"urlTemplate": "https://attacker.example/c?code={{.Code}}"}},
		"password": {"password": "Secret123!", "changeRequired": false},
		"hashedPassword": {"hash": "$2a$10$abc"},
		"totpSecret": "JBSWY3DPEHPK3PXP",
		"metadata": [{"key": "role", "value": "YWRtaW4="}],
		"idpLinks": [{"idpId": "idp-1", "userId": "victim-subject", "userName": "victim"}]
	}`)
	proxy.CreateUser(c)

	if *got == nil {
		t.Fatalf("user create was not forwarded (status %d: %s)", w.Code, w.Body.String())
	}
	for _, key := range []string{"hashedPassword", "totpSecret", "metadata", "idpLinks"} {
		if _, present := (*got)[key]; present {
			t.Errorf("forwarded %s: %v", key, (*got)[key])
		}
	}
	email, _ := (*got)["email"].(map[string]any)
	if email["email"] != "eve@example.com" || len(email) != 1 {
		t.Errorf("email must be forwarded as the address only, got %v", email)
	}
	profile, _ := (*got)["profile"].(map[string]any)
	if profile["givenName"] != "Eve" || profile["familyName"] != "Example" || profile["extra"] != nil {
		t.Errorf("profile must keep given and family name only, got %v", profile)
	}
	password, _ := (*got)["password"].(map[string]any)
	if password["password"] != "Secret123!" {
		t.Errorf("the chosen password must be forwarded, got %v", password)
	}
	if (*got)["username"] != "eve" {
		t.Errorf("username must be forwarded, got %v", (*got)["username"])
	}
}

func TestPasswordReset_EmailModeDropsCallerURLTemplate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv, got := captureUpstream(t, "/v2/users/42/password_reset", `{"details":{}}`)
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "pat", NotificationMode: NotificationModeEmail})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/42/password-reset",
		`{"sendLink":{"notificationType":"NOTIFICATION_TYPE_Email","urlTemplate":"https://attacker.example/reset?code={{.Code}}"}}`)
	c.Params = gin.Params{{Key: "id", Value: "42"}}
	proxy.PasswordReset(c)

	if *got == nil {
		t.Fatal("password reset was not forwarded")
	}
	if len(*got) != 0 {
		t.Fatalf("email mode must forward an empty reset body (Zitadel's own link), got %v", *got)
	}
}

// TestStripReturnCodeFlags pins the session-challenge half of AC7: in email mode the SPA still
// sends `returnCode` on OTP challenges, and the proxy must remove it so Zitadel delivers the code.
func TestStripReturnCodeFlags(t *testing.T) {
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: "http://unused", PAT: "pat", NotificationMode: NotificationModeEmail})
	for _, key := range []string{"otpEmail", "otpSms"} {
		t.Run(key, func(t *testing.T) {
			body := map[string]any{
				"challenges": map[string]any{key: map[string]any{"returnCode": map[string]any{}}},
			}
			proxy.stripReturnCodeFlags(body)
			challenge := body["challenges"].(map[string]any)[key].(map[string]any)
			if _, ok := challenge["returnCode"]; ok {
				t.Fatalf("%s still carries returnCode after stripping: %v", key, challenge)
			}
		})
	}
	t.Run("body without challenges is left alone", func(t *testing.T) {
		body := map[string]any{"checks": map[string]any{}}
		proxy.stripReturnCodeFlags(body)
		if _, ok := body["challenges"]; ok {
			t.Fatal("stripping must not add a challenges object")
		}
	})
}
