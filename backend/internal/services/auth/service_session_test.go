// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth/authtest"
	"github.com/michielvha/stackweaver/backend/internal/services/logtoken"
	"github.com/michielvha/stackweaver/core/models"
)

// The cookie branch of AuthenticateMiddleware (backend-for-frontend-session-plan.md, AC13, AC23).

type countingLiveness struct {
	calls int
	err   error
}

func (l *countingLiveness) Check(_ context.Context, _ *models.BrowserSession) error {
	l.calls++
	return l.err
}

type sessionRig struct {
	svc        *Service
	checkErr   error
	checkCalls int
	sessions   *Sessions
	now        time.Time
	user       *models.User
	raw        string
	liveness   *countingLiveness
}

func newSessionRig(t *testing.T) *sessionRig {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := &sessionRig{
		now:      time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC),
		user:     &models.User{ID: uuid.New(), Email: "ada@example.com", Name: "Ada"},
		liveness: &countingLiveness{},
	}
	users := &mockUserRepo{getByIDFn: func(id uuid.UUID) (*models.User, error) {
		if id == r.user.ID {
			return r.user, nil
		}
		return nil, errors.New("user not found")
	}}
	r.svc = NewServiceWithLookups(users)
	r.svc.SetAPIKeyService(&mockAPIKeyService{verifyFn: func(string) (*models.APIKey, error) {
		return nil, errors.New("unknown key")
	}})
	r.sessions = NewSessions(authtest.NewMemSessions(), DefaultSessionLimits, func() time.Time { return r.now })
	r.sessions.SetLiveness(r.liveness)
	r.svc.SetBrowserSessions(r.sessions)
	r.svc.SetSessionRequestCheck(func(*http.Request) error {
		r.checkCalls++
		return r.checkErr
	})

	raw, _, err := r.sessions.Start(&models.BrowserSession{
		UserID: r.user.ID, ZitadelSubject: "zitadel-sub-1", ZitadelSID: "sid-1", Email: r.user.Email, Name: r.user.Name,
	})
	if err != nil {
		t.Fatalf("starting a session: %v", err)
	}
	r.raw = raw
	return r
}

type seen struct {
	reached    bool
	userID     any
	subject    any
	authMethod any
	tokenKind  bool
}

// serve sends one request through the middleware and reports what the handler behind it saw.
func (r *sessionRig) serve(t *testing.T, mutate func(*http.Request)) (*httptest.ResponseRecorder, seen) {
	t.Helper()
	var got seen
	router := gin.New()
	router.Use(r.svc.AuthenticateMiddleware())
	router.GET("/api/v2/thing", func(c *gin.Context) {
		got.reached = true
		got.userID, _ = c.Get("user_id")
		got.subject, _ = c.Get("user_subject")
		got.authMethod, _ = c.Get("auth_method")
		_, got.tokenKind = c.Get("token_kind")
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v2/thing", nil)
	if mutate != nil {
		mutate(req)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w, got
}

func withCookie(value string) func(*http.Request) {
	return func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	}
}

// errorCode is the `code` member of the first error in a JSON:API error document.
func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var doc struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || len(doc.Errors) == 0 {
		t.Fatalf("not a JSON:API error document: %s", w.Body.String())
	}
	return doc.Errors[0].Code
}

func TestAuthenticateMiddleware_SessionCookieEstablishesAnInteractiveUser(t *testing.T) {
	r := newSessionRig(t)
	w, got := r.serve(t, withCookie(r.raw))
	if w.Code != http.StatusOK || !got.reached {
		t.Fatalf("a valid session cookie was refused: %d %s", w.Code, w.Body.String())
	}
	if got.authMethod != "session" {
		t.Errorf("auth_method = %v, want session", got.authMethod)
	}
	if got.userID != r.user.ID {
		t.Errorf("user_id = %v, want %v", got.userID, r.user.ID)
	}
	if got.subject != "zitadel-sub-1" {
		t.Errorf("user_subject = %v, want the session's Zitadel subject", got.subject)
	}
	// The org wall treats a request without a token kind as an interactive user.
	if got.tokenKind {
		t.Error("a cookie-authenticated request carries a token_kind")
	}
}

// AC23: the Authorization header alone decides a request that carries one.
func TestAuthenticateMiddleware_ValidCookieDoesNotRescueAnInvalidBearer(t *testing.T) {
	r := newSessionRig(t)
	w, got := r.serve(t, func(req *http.Request) {
		withCookie(r.raw)(req)
		req.Header.Set("Authorization", "Bearer tfe-not-a-real-token")
	})
	if w.Code != http.StatusUnauthorized || got.reached {
		t.Fatalf("an invalid bearer with a valid cookie answered %d (handler reached: %v)", w.Code, got.reached)
	}
}

// AC23: refused cookies answer 401 with the code the SPA signs out on, and establish nothing.
func TestAuthenticateMiddleware_RefusedCookies(t *testing.T) {
	cases := map[string]func(r *sessionRig) func(*http.Request){
		"no credential at all": func(*sessionRig) func(*http.Request) { return nil },
		"unknown value": func(*sessionRig) func(*http.Request) {
			return withCookie("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		},
		"empty value": func(*sessionRig) func(*http.Request) { return withCookie("") },
		"tampered value": func(r *sessionRig) func(*http.Request) {
			b := []byte(r.raw)
			if b[0] == 'A' {
				b[0] = 'B'
			} else {
				b[0] = 'A'
			}
			return withCookie(string(b))
		},
		"idle limit passed": func(r *sessionRig) func(*http.Request) {
			r.now = r.now.Add(DefaultSessionLimits.Idle)
			return withCookie(r.raw)
		},
		"absolute limit passed": func(r *sessionRig) func(*http.Request) {
			r.now = r.now.Add(DefaultSessionLimits.Absolute)
			return withCookie(r.raw)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := newSessionRig(t)
			w, got := r.serve(t, mutate(r))
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("answered %d, want 401: %s", w.Code, w.Body.String())
			}
			if got.reached {
				t.Fatal("the handler ran for a refused cookie")
			}
			if code := errorCode(t, w); code != CodeAuthenticationRequired {
				t.Errorf("error code = %q, want %q", code, CodeAuthenticationRequired)
			}
		})
	}
}

// AC13: a request whose liveness check is not due makes no call to Zitadel; one that is due does.
func TestAuthenticateMiddleware_LivenessOnlyWhenDue(t *testing.T) {
	r := newSessionRig(t)
	if w, _ := r.serve(t, withCookie(r.raw)); w.Code != http.StatusOK {
		t.Fatalf("answered %d", w.Code)
	}
	if r.liveness.calls != 0 {
		t.Fatalf("a request with no check due made %d liveness call(s)", r.liveness.calls)
	}

	r.now = r.now.Add(DefaultSessionLimits.Liveness)
	if w, _ := r.serve(t, withCookie(r.raw)); w.Code != http.StatusOK {
		t.Fatalf("answered %d with a check due", w.Code)
	}
	if r.liveness.calls != 1 {
		t.Fatalf("a request with a check due made %d liveness call(s), want 1", r.liveness.calls)
	}
}

// A check that finds the session gone at Zitadel refuses the request.
func TestAuthenticateMiddleware_LivenessEndedRefuses(t *testing.T) {
	r := newSessionRig(t)
	r.liveness.err = ErrSessionEnded
	r.now = r.now.Add(DefaultSessionLimits.Liveness)
	w, got := r.serve(t, withCookie(r.raw))
	if w.Code != http.StatusUnauthorized || got.reached {
		t.Fatalf("a session the liveness check ended answered %d (handler reached: %v)", w.Code, got.reached)
	}
	if code := errorCode(t, w); code != CodeAuthenticationRequired {
		t.Errorf("error code = %q, want %q", code, CodeAuthenticationRequired)
	}
}

// The account page's avatar comes from the session record, with no call to Zitadel.
func TestSessionPicture_FromTheSession(t *testing.T) {
	r := newSessionRig(t)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("auth_method", "session")
	c.Set(BrowserSessionContextKey, &models.BrowserSession{Picture: "https://example.com/ada.png"})
	if got := r.svc.SessionPicture(c); got != "https://example.com/ada.png" {
		t.Errorf("picture = %q, want the session's", got)
	}
}

// AC4: a cookie request that fails the browser-request check (the CSRF header and the origin
// allowlist) is refused with 403 and establishes nothing.
func TestAuthenticateMiddleware_SessionRequestFailingTheBrowserCheck(t *testing.T) {
	r := newSessionRig(t)
	r.checkErr = errors.New("missing X-Stackweaver-CSRF")
	w, got := r.serve(t, withCookie(r.raw))
	if w.Code != http.StatusForbidden || got.reached {
		t.Fatalf("answered %d (handler reached: %v), want 403", w.Code, got.reached)
	}
}

// With no browser-request check configured, the cookie credential fails closed.
func TestAuthenticateMiddleware_SessionWithoutABrowserCheckIsRefused(t *testing.T) {
	r := newSessionRig(t)
	r.svc.SetSessionRequestCheck(nil)
	w, got := r.serve(t, withCookie(r.raw))
	if w.Code != http.StatusForbidden || got.reached {
		t.Fatalf("answered %d (handler reached: %v), want 403", w.Code, got.reached)
	}
}

// Bearer requests skip the browser check: a CLI or the provider sends no CSRF header.
func TestAuthenticateMiddleware_BearerRequestsSkipTheBrowserCheck(t *testing.T) {
	r := newSessionRig(t)
	r.checkErr = errors.New("would refuse")
	_, _ = r.serve(t, func(req *http.Request) { req.Header.Set("Authorization", "Bearer tfe-whatever") })
	if r.checkCalls != 0 {
		t.Fatalf("a bearer request ran the browser check %d time(s)", r.checkCalls)
	}
}

// AC8: a cookie-authenticated state-changing request counts as activity and extends the idle
// limit; a GET does not, so polling cannot keep a forgotten tab alive.
func TestAuthenticateMiddleware_MutationsExtendIdleAndGETsDoNot(t *testing.T) {
	for method, extends := range map[string]bool{http.MethodGet: false, http.MethodPost: true, http.MethodDelete: true} {
		t.Run(method, func(t *testing.T) {
			r := newSessionRig(t)
			router := gin.New()
			router.Use(r.svc.AuthenticateMiddleware())
			router.Handle(method, "/api/v2/thing", func(c *gin.Context) { c.Status(http.StatusOK) })

			r.now = r.now.Add(50 * time.Minute)
			req := httptest.NewRequestWithContext(context.Background(), method, "/api/v2/thing", nil)
			withCookie(r.raw)(req)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("answered %d", w.Code)
			}

			r.now = r.now.Add(50 * time.Minute) // past the idle limit unless the request extended it
			_, err := r.sessions.Lookup(r.raw)
			if extended := err == nil; extended != extends {
				t.Errorf("%s extended the idle limit: %v, want %v (lookup: %v)", method, extended, extends, err)
			}
		})
	}
}

// A run's log-read-url minted for a browser session reads only while that session lives: signing
// out, a revoke, a back-channel logout, a liveness check or an idle limit all end the session, and
// the URL stops working with it rather than reading on until the token itself expires.
func TestLogToken_BoundToTheBrowserSession(t *testing.T) {
	logtoken.SetSecret([]byte("test-secret-key-32-bytes-long!!!"))
	t.Cleanup(func() { logtoken.SetSecret(nil) })

	readLogs := func(r *sessionRig, token string) (int, seen) {
		var got seen
		router := gin.New()
		router.Use(r.svc.AuthenticateMiddleware())
		router.GET("/api/v2/runs/:id/logs", func(c *gin.Context) {
			got.reached = true
			got.userID, _ = c.Get("user_id")
			got.authMethod, _ = c.Get("auth_method")
			c.Status(http.StatusOK)
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v2/runs/run-1/logs?token="+token, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code, got
	}

	t.Run("reads while the session lives, not after sign-out", func(t *testing.T) {
		r := newSessionRig(t)
		s, err := r.sessions.Lookup(r.raw)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		token := logtoken.Mint("run-1", logtoken.Credential{BrowserSessionID: s.ID})

		code, got := readLogs(r, token)
		if code != http.StatusOK || got.userID != r.user.ID || got.authMethod != "log_token" {
			t.Fatalf("live session: status %d, user %v, method %v; want 200 as the session's user", code, got.userID, got.authMethod)
		}
		if err := r.sessions.SignOut(context.Background(), s); err != nil {
			t.Fatalf("sign out: %v", err)
		}
		if code, got := readLogs(r, token); code != http.StatusUnauthorized || got.reached {
			t.Fatalf("after sign-out: status %d, reached %v; want 401", code, got.reached)
		}
	})

	t.Run("refused once a due liveness check finds the session ended", func(t *testing.T) {
		r := newSessionRig(t)
		s, err := r.sessions.Lookup(r.raw)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		token := logtoken.Mint("run-1", logtoken.Credential{BrowserSessionID: s.ID})
		// The user was deactivated in Zitadel after closing the browser: no cookie request runs the
		// check, so the log read must.
		r.now = s.NextCheckAt.Add(time.Second)
		r.liveness.err = ErrSessionEnded
		if code, got := readLogs(r, token); code != http.StatusUnauthorized || got.reached {
			t.Fatalf("ended at Zitadel: status %d, reached %v; want 401", code, got.reached)
		}
		if r.liveness.calls != 1 {
			t.Fatalf("liveness checks = %d, want 1: the log read runs the due check", r.liveness.calls)
		}
	})

	t.Run("refused past the session's idle limit", func(t *testing.T) {
		r := newSessionRig(t)
		s, err := r.sessions.Lookup(r.raw)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		token := logtoken.Mint("run-1", logtoken.Credential{BrowserSessionID: s.ID})
		r.now = r.now.Add(DefaultSessionLimits.Idle + time.Second)
		if code, got := readLogs(r, token); code != http.StatusUnauthorized || got.reached {
			t.Fatalf("past idle: status %d, reached %v; want 401", code, got.reached)
		}
	})
}
