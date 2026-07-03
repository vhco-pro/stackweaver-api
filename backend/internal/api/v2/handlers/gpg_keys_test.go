// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// TestFormatGPGKeyResponse_TFEShape locks the wire contract terraform-provider-tfe
// expects (go-tfe type GPGKey): JSON:API primary type "gpg-keys", the resource id is
// the GPG key id (not our UUID), and every attribute is kebab-case. The provider stores
// key-id as the Terraform state id and addresses reads/deletes by {namespace}/{key_id},
// so id MUST equal key-id and namespace MUST be the organization name.
func TestFormatGPGKeyResponse_TFEShape(t *testing.T) {
	created := time.Date(2026, 7, 3, 10, 30, 0, 0, time.UTC)
	key := &models.GPGKey{
		ID:             uuid.New(),
		OrganizationID: uuid.New(),
		KeyID:          "9FC214C0",
		ASCIIArmor:     "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
		CreatedAt:      created,
		UpdatedAt:      created,
	}

	resp := formatGPGKeyResponse(key, "dev-test")

	if got := resp["type"]; got != gpgKeyType {
		t.Errorf("type = %v, want %q", got, gpgKeyType)
	}
	if got := resp["id"]; got != "9FC214C0" {
		t.Errorf("id = %v, want the key id %q (not the UUID)", got, "9FC214C0")
	}

	attrs, ok := resp["attributes"].(gin.H)
	if !ok {
		t.Fatalf("attributes has unexpected type %T", resp["attributes"])
	}

	// Kebab-case attribute names only — the provider unmarshals via jsonapi kebab tags.
	wantAttrs := map[string]any{
		"ascii-armor":     key.ASCIIArmor,
		"key-id":          "9FC214C0",
		"namespace":       "dev-test",
		"created-at":      "2026-07-03T10:30:00Z",
		"updated-at":      "2026-07-03T10:30:00Z",
		"source":          "",
		"source-url":      nil,
		"trust-signature": "",
	}
	for name, want := range wantAttrs {
		got, present := attrs[name]
		if !present {
			t.Errorf("missing attribute %q", name)
			continue
		}
		if got != want {
			t.Errorf("attribute %q = %v, want %v", name, got, want)
		}
	}

	// No snake_case leftovers from the old custom surface.
	for _, forbidden := range []string{"ascii_armor", "key_id", "created_at", "updated_at"} {
		if _, present := attrs[forbidden]; present {
			t.Errorf("attribute %q is snake_case; must be kebab-case", forbidden)
		}
	}
}
