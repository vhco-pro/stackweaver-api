// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/models"
)

// A run queued without a configuration version takes its source from how the caller signed in:
// a browser is the UI, a token is the API (backend-for-frontend-session-plan.md, AC9).
func TestFormatRunResponse_SourceFollowsTheAuthMethod(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for method, want := range map[string]string{
		"session": "tfe-ui",
		"api_key": "tfe-api",
		"":        "tfe-api",
	} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		if method != "" {
			c.Set("auth_method", method)
		}
		run := &models.Run{ID: "run-source-test", WorkspaceID: "ws-source-test", Status: models.RunStatusPending, CreatedAt: time.Now()}
		if got := formatRunResponse(run, c, nil, nil).Attributes.Source; got != want {
			t.Errorf("auth_method %q: source = %q, want %q", method, got, want)
		}
	}
}
