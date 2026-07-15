// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestChangeRequestRoutesMatchTFE pins the one non-obvious thing about the change-request routes: TFE
// serves show/archive at /workspaces/change-requests/:id, putting a static segment exactly where
// /workspaces/:id already binds a wildcard. Gin resolves static before wildcard, so both coexist and we
// can use TFE's literal paths rather than inventing our own.
//
// This is a router-shape test, not a handler test: it registers the same path shapes RegisterRoutes
// uses (which needs a live DB) against stub handlers. It exists so a future route change that would
// break the collision, or a gin upgrade that stops allowing it, fails here instead of at API startup.
func TestChangeRequestRoutesMatchTFE(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	stub := func(name string) gin.HandlerFunc {
		return func(c *gin.Context) { c.String(http.StatusOK, name+"|"+c.Param("id")) }
	}

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("gin rejected the change-request route shape: %v", rec)
		}
	}()

	// The pre-existing workspace routes that the change-request paths have to coexist with.
	v2.GET("/workspaces/:id", stub("ws-show"))
	v2.GET("/workspaces/:id/runs", stub("ws-runs"))
	v2.GET("/workspaces/:id/notification-configurations", stub("ws-nc"))

	// The change-request routes, matching TFE.
	v2.GET("/workspaces/:id/change-requests", stub("cr-list"))
	v2.GET("/workspaces/change-requests/:id", stub("cr-show"))
	v2.PATCH("/workspaces/change-requests/:id", stub("cr-archive"))
	v2.POST("/workspaces/change-requests/:id", stub("cr-archive"))
	v2.DELETE("/workspaces/change-requests/:id", stub("cr-delete"))

	tests := []struct {
		name   string
		method string
		path   string
		want   string
	}{
		{"show a change request", "GET", "/api/v2/workspaces/change-requests/cr-abc", "cr-show|cr-abc"},
		{"archive via PATCH", "PATCH", "/api/v2/workspaces/change-requests/cr-abc", "cr-archive|cr-abc"},
		{"archive via POST (TFE docs describe both)", "POST", "/api/v2/workspaces/change-requests/cr-abc", "cr-archive|cr-abc"},
		{"delete a change request", "DELETE", "/api/v2/workspaces/change-requests/cr-abc", "cr-delete|cr-abc"},
		{"the static segment does not shadow a workspace", "GET", "/api/v2/workspaces/ws-1", "ws-show|ws-1"},
		{"nor a workspace subroute", "GET", "/api/v2/workspaces/ws-1/runs", "ws-runs|ws-1"},
		{"list a workspace's change requests", "GET", "/api/v2/workspaces/ws-1/change-requests", "cr-list|ws-1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil))
			if got := w.Body.String(); got != tc.want {
				t.Errorf("%s %s routed to %q, want %q", tc.method, tc.path, got, tc.want)
			}
		})
	}
}
