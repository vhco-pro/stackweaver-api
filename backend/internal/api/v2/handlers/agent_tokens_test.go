// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// TestAgentTokenResource covers the JSON:API shaping for tfe_agent_token: the token value is present
// only on create, the resource type is authentication-tokens, and the description round-trips from the
// key name.
func TestAgentTokenResource(t *testing.T) {
	id := uuid.New()
	used := time.Now().Add(-time.Hour)
	key := &models.APIKey{ID: id, Name: "production agents", CreatedAt: time.Now(), LastUsedAt: &used}

	// On create: token value included.
	created := agentTokenResource(key, "tfe-agentsecret")
	if created["type"] != "authentication-tokens" {
		t.Fatalf("type = %v, want authentication-tokens", created["type"])
	}
	if created["id"] != id {
		t.Fatalf("id = %v, want %v", created["id"], id)
	}
	attrs := created["attributes"].(gin.H)
	if attrs["token"] != "tfe-agentsecret" {
		t.Fatalf("token = %v, want the plaintext on create", attrs["token"])
	}
	if attrs["description"] != "production agents" {
		t.Fatalf("description = %v, want the key name", attrs["description"])
	}

	// On read: no token value, description still present.
	read := agentTokenResource(key, "")
	rattrs := read["attributes"].(gin.H)
	if _, present := rattrs["token"]; present {
		t.Fatalf("token must be absent on read, got %v", rattrs["token"])
	}
	if rattrs["description"] != "production agents" {
		t.Fatalf("description not surfaced on read")
	}
	if rattrs["last-used-at"] != key.LastUsedAt {
		t.Fatalf("last-used-at not surfaced on read")
	}
}
