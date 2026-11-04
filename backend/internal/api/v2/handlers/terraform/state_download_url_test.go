// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/models"
)

// The state download URL names the scheme the client used: the one a TLS-terminating proxy
// reports in X-Forwarded-Proto, else the connection's own. Behind an ingress the API sees plain
// HTTP, and an http:// URL sends the client through a redirect that drops its credential.
func TestHostedStateDownloadURL_SchemeFollowsTheProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &StateVersionHandlerV2{}
	for _, tc := range []struct {
		name, forwarded string
		tls             bool
		want            string
	}{
		{"behind a TLS proxy", "https", false, "https://sw.example/api/v2/state-versions/sv-1/download"},
		{"proxy says http", "http", false, "http://sw.example/api/v2/state-versions/sv-1/download"},
		{"no proxy, plain connection", "", false, "http://sw.example/api/v2/state-versions/sv-1/download"},
		{"no proxy, TLS connection", "", true, "https://sw.example/api/v2/state-versions/sv-1/download"},
		{"forged value is ignored", "javascript", false, "http://sw.example/api/v2/state-versions/sv-1/download"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequestWithContext(t.Context(), "GET", "http://sw.example/x", nil)
			if tc.forwarded != "" {
				c.Request.Header.Set("X-Forwarded-Proto", tc.forwarded)
			}
			if tc.tls {
				c.Request.TLS = &tls.ConnectionState{}
			}
			if got := h.hostedStateDownloadURL(c, &models.StateVersion{ID: "sv-1"}); got != tc.want {
				t.Errorf("URL = %q, want %q", got, tc.want)
			}
		})
	}
}
