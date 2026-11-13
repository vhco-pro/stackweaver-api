// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// The Terraform CLI's `cloud` block refuses a host whose TFP-API-Version is below 2.5 ("The
// 'cloud' option is not supported with this version of Terraform Enterprise"), so the CLI-driven
// run workflow the docs describe needs at least 2.5. Import blocks (2.6) and minimal refresh are
// later features the CLI gates on higher versions, which the API does not claim.
func TestPing_AdvertisesTheAPIVersionTheCloudBlockNeeds(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v2/ping", Ping)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v2/ping", nil))
	if got := w.Header().Get("TFP-API-Version"); got != "2.5" {
		t.Errorf("TFP-API-Version = %q, want 2.5", got)
	}
}
