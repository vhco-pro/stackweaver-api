// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func userInfoServer(t *testing.T, status int, body string, delay time.Duration) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func claimsFor(sub string) *oidc.AccessTokenClaims {
	return &oidc.AccessTokenClaims{TokenClaims: oidc.TokenClaims{Subject: sub}}
}

// #829 D5: the verified-email check needs Zitadel's email_verified, which its userinfo omits when
// false. A userinfo failure is an error, never "unverified" and never "allowed".
func TestExtractUserInfo_EmailVerified(t *testing.T) {
	ctx := context.Background()
	host := func(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "http://") }

	t.Run("userinfo says verified", func(t *testing.T) {
		srv, _ := userInfoServer(t, http.StatusOK, `{"sub":"u1","email":"ada@example.com","email_verified":true}`, 0)
		info, err := ExtractUserInfo(ctx, claimsFor("u1"), map[string]any{"sub": "u1"}, "http://issuer", "tok", srv.Client(), host(srv), "")
		if err != nil || !info.EmailVerified || info.Email != "ada@example.com" {
			t.Fatalf("info=%+v err=%v, want verified ada@example.com", info, err)
		}
	})

	t.Run("claim absent means unverified", func(t *testing.T) {
		srv, _ := userInfoServer(t, http.StatusOK, `{"sub":"u1","email":"ada@example.com"}`, 0)
		info, err := ExtractUserInfo(ctx, claimsFor("u1"), map[string]any{"sub": "u1"}, "http://issuer", "tok", srv.Client(), host(srv), "")
		if err != nil || info.EmailVerified {
			t.Fatalf("info=%+v err=%v, want unverified", info, err)
		}
	})

	t.Run("token carrying email but no email_verified still asks userinfo", func(t *testing.T) {
		srv, calls := userInfoServer(t, http.StatusOK, `{"sub":"u1","email":"ada@example.com","email_verified":true}`, 0)
		info, err := ExtractUserInfo(ctx, claimsFor("u1"), map[string]any{"sub": "u1", "email": "ada@example.com"}, "http://issuer", "tok", srv.Client(), host(srv), "")
		if err != nil || !info.EmailVerified || *calls != 1 {
			t.Fatalf("info=%+v err=%v calls=%d, want verified after one userinfo call", info, err, *calls)
		}
	})

	t.Run("token carrying email_verified needs no userinfo", func(t *testing.T) {
		srv, calls := userInfoServer(t, http.StatusOK, `{}`, 0)
		info, err := ExtractUserInfo(ctx, claimsFor("u1"), map[string]any{"sub": "u1", "email": "a@b.c", "email_verified": true}, "http://issuer", "tok", srv.Client(), host(srv), "")
		if err != nil || !info.EmailVerified || *calls != 0 {
			t.Fatalf("info=%+v err=%v calls=%d", info, err, *calls)
		}
	})

	t.Run("userinfo failure is an error", func(t *testing.T) {
		srv, _ := userInfoServer(t, http.StatusServiceUnavailable, `{}`, 0)
		_, err := ExtractUserInfo(ctx, claimsFor("u1"), map[string]any{"sub": "u1"}, "http://issuer", "tok", srv.Client(), host(srv), "")
		if err == nil || !strings.Contains(err.Error(), "userinfo") {
			t.Fatalf("a failed userinfo call must be an error naming it, got %v", err)
		}
	})

	t.Run("a hung userinfo call times out", func(t *testing.T) {
		old := userInfoTimeout
		userInfoTimeout = 50 * time.Millisecond
		t.Cleanup(func() { userInfoTimeout = old })
		srv, _ := userInfoServer(t, http.StatusOK, `{}`, 500*time.Millisecond)
		start := time.Now()
		_, err := ExtractUserInfo(ctx, claimsFor("u1"), map[string]any{"sub": "u1"}, "http://issuer", "tok", srv.Client(), host(srv), "")
		if err == nil || time.Since(start) > 400*time.Millisecond {
			t.Fatalf("want a timeout error well before the server answers, got err=%v after %s", err, time.Since(start))
		}
	})
}
