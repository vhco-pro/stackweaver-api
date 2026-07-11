// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-120 self-registration policy. CreateUser is on the unauthenticated /auth surface and
// forwards to Zitadel POST /v2/users/human with the admin PAT, so it must honor the login
// policy's allowRegister — otherwise an operator who disabled self-registration is bypassed.

package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCreateUser_RespectsAllowRegister(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newProxy := func(allowRegister bool) (*AuthProxy, *bool) {
		created := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/settings/login"):
				w.WriteHeader(http.StatusOK)
				if allowRegister {
					_, _ = w.Write([]byte(`{"settings":{"allowRegister":true}}`))
				} else {
					_, _ = w.Write([]byte(`{"settings":{"allowRegister":false}}`))
				}
			case r.Method == http.MethodPost && r.URL.Path == "/v2/users/human":
				created = true
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"userId":"123"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		t.Cleanup(srv.Close)
		return NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "test-pat"}), &created
	}

	body := `{"username":"bob","email":{"email":"bob@example.com"}}`

	t.Run("registration disabled -> 403, Zitadel create NOT called", func(t *testing.T) {
		proxy, created := newProxy(false)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/human", body)
		proxy.CreateUser(c)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 when registration disabled, got %d: %s", w.Code, w.Body.String())
		}
		if *created {
			t.Fatal("Zitadel user-create must NOT be called when registration is disabled (AUD-120)")
		}
	})

	t.Run("registration enabled -> forwards to Zitadel", func(t *testing.T) {
		proxy, created := newProxy(true)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/human", body)
		proxy.CreateUser(c)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201 when registration enabled, got %d: %s", w.Code, w.Body.String())
		}
		if !*created {
			t.Fatal("Zitadel user-create must be called when registration is enabled")
		}
	})
}
