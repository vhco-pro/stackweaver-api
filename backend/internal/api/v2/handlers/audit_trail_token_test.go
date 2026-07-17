// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestIsAuditRequest covers the token-type dispatch: only ?token=audit-trails selects the
// tfe_audit_trail_token variant; a missing or any other value stays the default organization token.
func TestIsAuditRequest(t *testing.T) {
	cases := []struct {
		query string
		want  bool
	}{
		{"?token=audit-trails", true},
		{"", false},
		{"?token=", false},
		{"?token=organization", false},
		{"?foo=audit-trails", false},
	}
	for _, tc := range cases {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/api/v2/organizations/acme/authentication-token"+tc.query, nil)
		if got := isAuditRequest(c); got != tc.want {
			t.Fatalf("isAuditRequest(%q) = %v, want %v", tc.query, got, tc.want)
		}
	}
}
