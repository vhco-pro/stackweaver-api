// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// TestOrgTokenResource covers the JSON:API shaping: the token value is present only on create, and the
// resource type/id/metadata match the tfe_organization_token contract.
func TestOrgTokenResource(t *testing.T) {
	id := uuid.New()
	used := time.Now().Add(-time.Hour)
	exp := time.Now().Add(24 * time.Hour)
	key := &models.APIKey{ID: id, CreatedAt: time.Now(), LastUsedAt: &used, ExpiresAt: &exp}

	// On create: token value included.
	created := orgTokenResource(key, "tfe-secretvalue")
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
	if attrs["token"] != "tfe-secretvalue" {
		t.Fatalf("token = %v, want the plaintext on create", attrs["token"])
	}
	if attrs["expired-at"] != key.ExpiresAt {
		t.Fatalf("expired-at not surfaced")
	}

	// On read: no token value.
	read := orgTokenResource(key, "")
	rattrs := read["data"].(gin.H)["attributes"].(gin.H)
	if _, present := rattrs["token"]; present {
		t.Fatalf("token must be absent on read, got %v", rattrs["token"])
	}
	if rattrs["last-used-at"] != key.LastUsedAt {
		t.Fatalf("last-used-at not surfaced on read")
	}
}
