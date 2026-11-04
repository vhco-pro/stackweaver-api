// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// recordingUpstream answers every request with 200 and an empty session, recording the body of the
// last session create or update; the proxy's follow-up reads are not recorded.
func recordingUpstream(t *testing.T, last *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPatch {
			raw, _ := io.ReadAll(r.Body)
			body := map[string]any{}
			_ = json.Unmarshal(raw, &body)
			*last = body
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sessionId":"s1","sessionToken":"tok"}`))
	}))
}

func TestSessionLifetime_ForwardedOnCreateAndUpdate(t *testing.T) {
	var last map[string]any
	upstream := recordingUpstream(t, &last)
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
	want := "44100s" // the default 12-hour absolute limit plus the 15-minute margin

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/sessions", `{"checks":{"user":{"userId":"123456"}},"lifetime":"999999s"}`)
	proxy.CreateSession(c)
	if got := last["lifetime"]; got != want {
		t.Errorf("create forwarded lifetime %v, want %s: an abandoned sign-in must expire, and the browser cannot choose", got, want)
	}

	sessionID := "realsession1234567"
	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{{ID: sessionID, Token: "tok", UserID: "u1"}})

	last = nil
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPatch, "/auth/sessions/"+sessionID, `{"checks":{"password":{"password":"x"}}}`)
	c.Params = gin.Params{{Key: "id", Value: sessionID}}
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}
	proxy.UpdateSession(c)
	if got := last["lifetime"]; got != want {
		t.Errorf("update forwarded lifetime %v, want %s: each sign-in step restarts it, so a reused session outlives the browser session built on it", got, want)
	}
}

// A decoy for an unknown login name must look like a real session, and real sessions now carry an
// expirationDate; without one on the decoy, a GET would tell real accounts from unknown ones.
func TestSessionLifetime_DecoyCarriesAnExpiration(t *testing.T) {
	entry := &sessionEntry{ID: "decoy1", LoginName: "nobody@example.com", Decoy: true}
	var got struct {
		Session map[string]any `json:"session"`
	}
	if err := json.Unmarshal(buildDecoyGetSessionResponse(entry, []byte("secret"), 12*time.Hour), &got); err != nil {
		t.Fatal(err)
	}
	created, err := time.Parse(time.RFC3339Nano, got.Session["creationDate"].(string))
	if err != nil {
		t.Fatal(err)
	}
	expires, ok := got.Session["expirationDate"].(string)
	if !ok {
		t.Fatalf("decoy session has no expirationDate: %v", got.Session)
	}
	exp, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		t.Fatal(err)
	}
	if d := exp.Sub(created); d != 12*time.Hour {
		t.Errorf("decoy expires %v after creation, want the session lifetime", d)
	}
}

// A JSON null body binds to a nil map; the handlers must answer 400, not panic on the lifetime write.
func TestSessionLifetime_NullBodyIsRejected(t *testing.T) {
	var last map[string]any
	upstream := recordingUpstream(t, &last)
	defer upstream.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/sessions", `null`)
	proxy.CreateSession(c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("create with a null body answered %d, want 400", w.Code)
	}

	sessionID := "realsession1234567"
	seed := httptest.NewRecorder()
	seedCtx, _ := gin.CreateTestContext(seed)
	seedCtx.Request = newTestRequest(http.MethodGet, "/")
	proxy.writeSessionCookie(seedCtx, []sessionEntry{{ID: sessionID, Token: "tok", UserID: "u1"}})
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPatch, "/auth/sessions/"+sessionID, `null`)
	c.Params = gin.Params{{Key: "id", Value: sessionID}}
	for _, ck := range seed.Result().Cookies() {
		c.Request.AddCookie(ck)
	}
	proxy.UpdateSession(c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("update with a null body answered %d, want 400", w.Code)
	}
}
