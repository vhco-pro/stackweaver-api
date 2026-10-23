// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

// refreshZitadel stands in for the three Zitadel endpoints a refresh touches: the token endpoint,
// the session read and the revocation endpoint. Sessions live in the stand-in, never in a proxy,
// so two proxies over one stand-in see the same state.
type refreshZitadel struct {
	mu sync.Mutex
	// sessionAnswer is the status the session read returns per session id. A missing id answers
	// 404, the way Zitadel does for a deleted session; -1 drops the connection instead.
	sessionAnswer map[string]int
	revokeStatus  int
	// noIDToken makes the token endpoint answer without an id_token.
	noIDToken bool

	issued       int
	sessionReads []string
	revoked      []url.Values
	revokeAuth   []string
}

const refreshSessionID = "sess-alive"

func newRefreshZitadel() *refreshZitadel {
	return &refreshZitadel{sessionAnswer: map[string]int{refreshSessionID: http.StatusOK}, revokeStatus: http.StatusOK}
}

func idTokenFor(sid string) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := enc.EncodeToString([]byte(fmt.Sprintf(`{"sub":"user-1","sid":%q}`, sid)))
	return header + "." + payload + ".signature"
}

func (z *refreshZitadel) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		z.mu.Lock()
		defer z.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/oauth/v2/token":
			_ = r.ParseForm()
			z.issued++
			body := map[string]any{
				"access_token":  fmt.Sprintf("at-%d", z.issued),
				"refresh_token": fmt.Sprintf("rt-%d", z.issued),
				"token_type":    "Bearer",
				"expires_in":    3600,
			}
			if !z.noIDToken {
				body["id_token"] = idTokenFor(refreshSessionID)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/sessions/"):
			sid := strings.TrimPrefix(r.URL.Path, "/v2/sessions/")
			z.sessionReads = append(z.sessionReads, sid)
			status, ok := z.sessionAnswer[sid]
			if !ok {
				status = http.StatusNotFound
			}
			if status == -1 {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{}`)
		case r.Method == http.MethodPost && r.URL.Path == "/oauth/v2/revoke":
			_ = r.ParseForm()
			z.revoked = append(z.revoked, r.PostForm)
			z.revokeAuth = append(z.revokeAuth, r.Header.Get("Authorization"))
			w.WriteHeader(z.revokeStatus)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (z *refreshZitadel) endSession(sid string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	delete(z.sessionAnswer, sid)
}

func (z *refreshZitadel) setSessionAnswer(sid string, status int) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.sessionAnswer[sid] = status
}

// newRefreshProxy builds a proxy over the stand-in whose warnings are collected.
func newRefreshProxy(t *testing.T, srv *httptest.Server) (*AuthProxy, *[]string) {
	t.Helper()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "pat"})
	var warnings []string
	var mu sync.Mutex
	proxy.warnf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}
	return proxy, &warnings
}

func postToken(t *testing.T, proxy *AuthProxy, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/oidc/token", proxy.TokenExchange)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func refreshForm() url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa-client"}, "refresh_token": {"rt-old"}}
}

// AC1, AC2: a refresh for a session that has ended at Zitadel is refused with invalid_grant and no
// tokens, and the refresh token Zitadel just issued is revoked without the proxy's credential.
func TestTokenExchange_RefreshForEndedSessionIsRefused(t *testing.T) {
	z := newRefreshZitadel()
	proxy, _ := newRefreshProxy(t, z.server(t))
	z.endSession(refreshSessionID)

	rec := postToken(t, proxy, refreshForm())

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the answer: %v", err)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
	for _, key := range []string{"access_token", "refresh_token", "id_token"} {
		if _, ok := body[key]; ok {
			t.Errorf("the refused answer carries %s", key)
		}
	}
	if len(z.revoked) != 1 {
		t.Fatalf("revocations = %d, want 1", len(z.revoked))
	}
	if got := z.revoked[0].Get("token"); got != "rt-1" {
		t.Errorf("revoked token = %q, want the newly issued rt-1", got)
	}
	if got := z.revoked[0].Get("client_id"); got != "spa-client" {
		t.Errorf("revoke client_id = %q, want spa-client", got)
	}
	if z.revokeAuth[0] != "" {
		t.Errorf("the revoke call carried an Authorization header; a public client revokes with client_id only")
	}
}

// A refresh answer with no ID token cannot name its session, so it is treated as ended.
func TestTokenExchange_RefreshWithoutIDTokenIsRefused(t *testing.T) {
	z := newRefreshZitadel()
	z.noIDToken = true
	proxy, _ := newRefreshProxy(t, z.server(t))

	rec := postToken(t, proxy, refreshForm())

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("answer = %d %s, want 400 invalid_grant", rec.Code, rec.Body)
	}
}

// AC3: a refresh for a live session passes Zitadel's answer through byte for byte.
func TestTokenExchange_RefreshForLiveSessionPassesThrough(t *testing.T) {
	z := newRefreshZitadel()
	proxy, _ := newRefreshProxy(t, z.server(t))

	rec := postToken(t, proxy, refreshForm())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the answer: %v", err)
	}
	if body["access_token"] != "at-1" || body["refresh_token"] != "rt-1" || body["id_token"] != idTokenFor(refreshSessionID) {
		t.Errorf("answer = %v, want Zitadel's tokens unchanged", body)
	}
	if len(z.sessionReads) != 1 || z.sessionReads[0] != refreshSessionID {
		t.Errorf("session reads = %v, want one read of %s", z.sessionReads, refreshSessionID)
	}
	if len(z.revoked) != 0 {
		t.Errorf("a live session's refresh token was revoked")
	}
}

// AC4: sign-in (the authorization_code grant) makes no session check.
func TestTokenExchange_AuthorizationCodeIsNotChecked(t *testing.T) {
	z := newRefreshZitadel()
	z.endSession(refreshSessionID)
	proxy, _ := newRefreshProxy(t, z.server(t))

	rec := postToken(t, proxy, url.Values{"grant_type": {"authorization_code"}, "client_id": {"spa-client"}, "code": {"c"}, "code_verifier": {"v"}})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body)
	}
	if len(z.sessionReads) != 0 {
		t.Errorf("sign-in read the session %v times; it must not be checked", len(z.sessionReads))
	}
}

// AC5: the answer does not depend on which replica serves the refresh; the record is Zitadel's.
func TestTokenExchange_EndedSessionIsRefusedOnEveryReplica(t *testing.T) {
	z := newRefreshZitadel()
	srv := z.server(t)
	replicaA, _ := newRefreshProxy(t, srv)
	replicaB, _ := newRefreshProxy(t, srv)

	if rec := postToken(t, replicaA, refreshForm()); rec.Code != http.StatusOK {
		t.Fatalf("live refresh on replica A = %d, want 200", rec.Code)
	}
	z.endSession(refreshSessionID)
	for name, proxy := range map[string]*AuthProxy{"A": replicaA, "B": replicaB} {
		if rec := postToken(t, proxy, refreshForm()); rec.Code != http.StatusBadRequest {
			t.Errorf("replica %s answered %d after the session ended, want 400", name, rec.Code)
		}
	}
}

// AC12: when the session read fails with anything but a definite 404, the refresh goes through
// and a warning is logged.
func TestTokenExchange_SessionCheckErrorLetsRefreshThrough(t *testing.T) {
	for name, status := range map[string]int{
		"session read 503":   http.StatusServiceUnavailable,
		"session read 403":   http.StatusForbidden,
		"connection dropped": -1,
	} {
		t.Run(name, func(t *testing.T) {
			z := newRefreshZitadel()
			z.setSessionAnswer(refreshSessionID, status)
			proxy, warnings := newRefreshProxy(t, z.server(t))

			rec := postToken(t, proxy, refreshForm())

			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"refresh_token":"rt-1"`) {
				t.Fatalf("answer = %d %s, want Zitadel's tokens", rec.Code, rec.Body)
			}
			if len(*warnings) == 0 {
				t.Errorf("no warning logged for an unanswered session check")
			}
			for _, w := range *warnings {
				if strings.Contains(w, "rt-1") || strings.Contains(w, "rt-old") || strings.Contains(w, "at-1") {
					t.Errorf("a warning carries a token value: %q", w)
				}
			}
		})
	}
}

// AC13: when Zitadel will not revoke, the refused refresh is still refused and the failure logged.
func TestTokenExchange_FailedRevokeStillRefuses(t *testing.T) {
	z := newRefreshZitadel()
	z.revokeStatus = http.StatusServiceUnavailable
	proxy, warnings := newRefreshProxy(t, z.server(t))
	z.endSession(refreshSessionID)

	rec := postToken(t, proxy, refreshForm())

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("answer = %d %s, want 400 invalid_grant", rec.Code, rec.Body)
	}
	if len(*warnings) == 0 {
		t.Errorf("the failed revocation was not logged")
	}
}

// A refresh Zitadel itself refuses is passed through unchanged, with no session check.
func TestTokenExchange_RefusedRefreshPassesThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/v2/token" {
			t.Errorf("unexpected call to %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"refresh token invalid"}`)
	}))
	t.Cleanup(srv.Close)
	proxy, _ := newRefreshProxy(t, srv)

	rec := postToken(t, proxy, refreshForm())

	if rec.Code != http.StatusBadRequest || rec.Body.String() != `{"error":"invalid_grant","error_description":"refresh token invalid"}` {
		t.Errorf("answer = %d %s, want Zitadel's refusal unchanged", rec.Code, rec.Body)
	}
}
