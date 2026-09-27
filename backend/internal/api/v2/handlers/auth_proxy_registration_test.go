// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-120 self-registration policy. CreateUser is on the unauthenticated /auth surface and
// forwards to Zitadel POST /v2/users/human with the admin PAT, so it must honor the login
// policy's allowRegister - otherwise an operator who disabled self-registration is bypassed.

package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
			case r.Method == http.MethodGet && r.URL.Path == "/v2/users/123":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"user":{"userId":"123","state":"USER_STATE_ACTIVE"}}`))
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

// CreateUser must not answer until Zitadel's read side reports the new user as
// active. Zitadel projects writes asynchronously, and a client that signs the
// user in straight after creating it otherwise races the projection (a 404 on
// the session check, or Errors.User.NotActive at the token endpoint).
func TestCreateUser_WaitsForUserActive(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name      string
		states    []string // successive read-side answers; "" means 404
		timeout   time.Duration
		wantReads int32
	}{
		{"not found, then initial, then active", []string{"", "USER_STATE_INITIAL", "USER_STATE_ACTIVE"}, 5 * time.Second, 3},
		{"active on first read", []string{"USER_STATE_ACTIVE"}, 5 * time.Second, 1},
		{"never active: gives up and still answers", []string{""}, 200 * time.Millisecond, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reads atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/settings/login"):
					_, _ = w.Write([]byte(`{"settings":{"allowRegister":true}}`))
				case r.Method == http.MethodPost && r.URL.Path == "/v2/users/human":
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"userId":"42"}`))
				case r.Method == http.MethodGet && r.URL.Path == "/v2/users/42":
					n := int(reads.Add(1)) - 1
					state := tt.states[min(n, len(tt.states)-1)]
					if state == "" {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"code":5,"message":"User could not be found"}`))
						return
					}
					_, _ = fmt.Fprintf(w, `{"user":{"userId":"42","state":%q}}`, state)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(srv.Close)
			proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "test-pat"})
			proxy.userReadyTimeout = tt.timeout

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/human", `{"username":"bob"}`)
			proxy.CreateUser(c)

			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201: %s", w.Code, w.Body.String())
			}
			if tt.wantReads > 0 && reads.Load() != tt.wantReads {
				t.Fatalf("read-side lookups = %d, want %d (CreateUser answered before the user was active)", reads.Load(), tt.wantReads)
			}
		})
	}
}
