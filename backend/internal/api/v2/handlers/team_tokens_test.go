// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// TestTeamTokenResource covers the JSON:API shaping for tfe_team_token: the token value is present
// only on create, the resource type/id/metadata match the authentication-tokens contract, and the
// legacy (descriptionless) token always reports a null description.
func TestTeamTokenResource(t *testing.T) {
	id := uuid.New()
	used := time.Now().Add(-time.Hour)
	exp := time.Now().Add(24 * time.Hour)
	key := &models.APIKey{ID: id, CreatedAt: time.Now(), LastUsedAt: &used, ExpiresAt: &exp}

	// On create: token value included.
	created := teamTokenResource(key, "tfe-teamsecret")
	data, ok := created["data"].(gin.H)
	if !ok {
		t.Fatalf("data is not an object: %T", created["data"])
	}
	if data["type"] != "authentication-tokens" {
		t.Fatalf("type = %v, want authentication-tokens", data["type"])
	}
	if data["id"] != id {
		t.Fatalf("id = %v, want %v", data["id"], id)
	}
	attrs := data["attributes"].(gin.H)
	if attrs["token"] != "tfe-teamsecret" {
		t.Fatalf("token = %v, want the plaintext on create", attrs["token"])
	}
	if attrs["expired-at"] != key.ExpiresAt {
		t.Fatalf("expired-at not surfaced")
	}
	// The legacy team token has no description; it must be present and null so go-tfe decodes *string nil.
	desc, present := attrs["description"]
	if !present || desc != nil {
		t.Fatalf("description = %v (present=%v), want present and nil", desc, present)
	}

	// On read: no token value.
	read := teamTokenResource(key, "")
	rattrs := read["data"].(gin.H)["attributes"].(gin.H)
	if _, present := rattrs["token"]; present {
		t.Fatalf("token must be absent on read, got %v", rattrs["token"])
	}
	if rattrs["last-used-at"] != key.LastUsedAt {
		t.Fatalf("last-used-at not surfaced on read")
	}
}
