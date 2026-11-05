// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestRejectedTokenLog: a refused API token is logged with what identifies its caller, so a
// misconfigured client retrying with a revoked token can be found: the token's short id, the
// route, the client address and its User-Agent. The token itself is never logged, and a hostile
// User-Agent cannot forge log lines or flood the log.
func TestRejectedTokenLog(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v2/runner/register", http.NoBody)
	c.Request.RemoteAddr = "172.19.0.1:41234"
	c.Request.Header.Set("User-Agent", "old-runner/0.9\nauth: forged line "+strings.Repeat("x", 500))
	token := "tfe-secret-token-value"

	line := rejectedTokenLog(c, token)
	for _, want := range []string{shortTokenID(token), "POST /api/v2/runner/register", "172.19.0.1", "old-runner/0.9"} {
		if !strings.Contains(line, want) {
			t.Errorf("log line %q lacks %q", line, want)
		}
	}
	if strings.Contains(line, token) {
		t.Errorf("the log line carries the token: %q", line)
	}
	if strings.ContainsAny(line, "\n\r") {
		t.Errorf("the User-Agent broke the log line: %q", line)
	}
	if len(line) > 400 {
		t.Errorf("the log line is %d bytes; a long User-Agent is cut", len(line))
	}
}
