// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
)

// TestAgentTokenResource covers the JSON:API shaping for tfe_agent_token: the token value is present
// only on create, the resource type is authentication-tokens, and the description round-trips from the
// key name.
func TestAgentTokenResource(t *testing.T) {
	id := uuid.New()
	used := time.Now().Add(-time.Hour)
	key := &models.APIKey{ID: id, Name: "production agents", CreatedAt: time.Now(), LastUsedAt: &used}

	// On create: token value included. Assertions run against the marshaled document, so
	// "absent" and "present but null" stay distinguishable.
	created := wireShape(t, agentTokenResource(key, "tfe-agentsecret"))
	if created["type"] != "authentication-tokens" {
		t.Fatalf("type = %v, want authentication-tokens", created["type"])
	}
	if created["id"] != id.String() {
		t.Fatalf("id = %v, want %v", created["id"], id)
	}
	attrs := created["attributes"].(map[string]any)
	if attrs["token"] != "tfe-agentsecret" {
		t.Fatalf("token = %v, want the plaintext on create", attrs["token"])
	}
	if attrs["description"] != "production agents" {
		t.Fatalf("description = %v, want the key name", attrs["description"])
	}

	// On read: no token value, description still present.
	read := wireShape(t, agentTokenResource(key, ""))
	rattrs := read["attributes"].(map[string]any)
	if _, present := rattrs["token"]; present {
		t.Fatalf("token must be absent on read, got %v", rattrs["token"])
	}
	if rattrs["description"] != "production agents" {
		t.Fatalf("description not surfaced on read")
	}
	if rattrs["last-used-at"] == nil {
		t.Fatalf("last-used-at not surfaced on read")
	}
	// A never-rotated token keeps the exact TFE shape: no expiry member at all.
	if _, present := rattrs["expired-at"]; present {
		t.Fatalf("expired-at must be absent on a token without expiry, got %v", rattrs["expired-at"])
	}

	// A token retired by rotation reports when it stops working.
	expires := time.Now().Add(24 * time.Hour)
	key.ExpiresAt = &expires
	retired := wireShape(t, agentTokenResource(key, ""))
	if retired["attributes"].(map[string]any)["expired-at"] == nil {
		t.Fatalf("expired-at not surfaced on a rotated token")
	}
}

// TestRotateGrace covers the optional rotate body: absent body or attribute selects the default,
// an explicit value is honoured in hours, and values outside 0..168 are rejected.
func TestRotateGrace(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name    string
		body    string
		want    time.Duration
		wantErr bool
	}{
		{"no body", "", apikey.DefaultAgentTokenRotationGrace, false},
		{"no attribute", `{"data":{"type":"authentication-tokens","attributes":{}}}`, apikey.DefaultAgentTokenRotationGrace, false},
		{"explicit hours", `{"data":{"attributes":{"grace-period-hours":2}}}`, 2 * time.Hour, false},
		{"zero retires immediately", `{"data":{"attributes":{"grace-period-hours":0}}}`, 0, false},
		{"cap allowed", `{"data":{"attributes":{"grace-period-hours":168}}}`, apikey.MaxAgentTokenRotationGrace, false},
		{"above cap", `{"data":{"attributes":{"grace-period-hours":169}}}`, 0, true},
		{"negative", `{"data":{"attributes":{"grace-period-hours":-1}}}`, 0, true},
		{"malformed", `{"data":`, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(tc.body))
			c.Request.Header.Set("Content-Type", "application/vnd.api+json")
			got, err := rotateGrace(c)
			if (err != nil) != tc.wantErr {
				t.Fatalf("rotateGrace() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("rotateGrace() = %s, want %s", got, tc.want)
			}
		})
	}
}
