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
	for _, key := range []string{"email", "phone"} {
		contact, ok := (*got)[key].(map[string]any)
		if !ok {
			t.Fatalf("%s object missing from forwarded body: %v", key, *got)
		}
		for _, field := range []string{"returnCode", "isVerified"} {
			if _, present := contact[field]; present {
				t.Errorf("email mode forwarded %s.%s: %v", key, field, contact)
			}
		}
	}
}
