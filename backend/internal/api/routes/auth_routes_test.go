// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	v2handlers "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers"
)

// AC30 of backend-for-frontend-session-plan.md: no path on the SPA's origin hands OAuth tokens to
// the browser. The proxy's token and userinfo routes served the public client, which a script on
// the page could otherwise use to redeem a code of its own and hold tokens in JavaScript again.
//
// This replaces auth_proxy_token_refresh_test.go, which pinned the proxy's refresh grant: a refresh
// for a session deleted at Zitadel was refused and its new refresh token revoked. With the token
// route gone there is no refresh to judge, and none is issued (sign-in never asks for
// offline_access, TestAuthorize_UsesTheBFFsOwnParameters); an ended session is now refused by the
// liveness check and by back-channel logout instead.
func TestAuthProxyServesNoTokenEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	setupAuthProxyRoutes(r, v2handlers.NewAuthProxy(v2handlers.AuthProxyConfig{ZitadelInternalURL: "http://zitadel.invalid"}), middleware.NewOriginPolicy(true))

	for _, probe := range []struct{ method, path, body string }{
		{http.MethodPost, "/auth/oidc/token", "grant_type=authorization_code&code=x&client_id=frontend"},
		{http.MethodPost, "/auth/oidc/token", "grant_type=refresh_token&refresh_token=x&client_id=frontend"},
		{http.MethodGet, "/auth/oidc/userinfo", ""},
	} {
		req := httptest.NewRequestWithContext(context.Background(), probe.method, probe.path, strings.NewReader(probe.body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s answered %d, want 404", probe.method, probe.path, w.Code)
		}
	}
}
