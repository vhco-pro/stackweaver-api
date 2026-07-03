// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"reflect"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// TestFormatRegistryProviderResponse_TFEShape locks the go-tfe RegistryProvider wire contract:
// JSON:API type "registry-providers", kebab-case attributes including registry-name and a
// permissions.can-delete block, and an organization relationship.
func TestFormatRegistryProviderResponse_TFEShape(t *testing.T) {
	created := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	p := &models.Provider{
		ID:           uuid.New(),
		Name:         "example",
		Namespace:    "dev-test",
		RegistryName: "private",
		CreatedAt:    created,
		UpdatedAt:    created,
		Organization: models.Organization{Name: "dev-test"},
	}

	resp := formatRegistryProviderResponse(p)

	if resp["type"] != registryProviderType {
		t.Errorf("type = %v, want %q", resp["type"], registryProviderType)
	}
	if resp["id"] != p.ID.String() {
		t.Errorf("id = %v, want %q", resp["id"], p.ID.String())
	}

	attrs, ok := resp["attributes"].(gin.H)
	if !ok {
		t.Fatalf("attributes has unexpected type %T", resp["attributes"])
	}
	want := map[string]any{
		"name":          "example",
		"namespace":     "dev-test",
		"registry-name": "private",
		"created-at":    "2026-07-03T12:00:00Z",
		"updated-at":    "2026-07-03T12:00:00Z",
	}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("attribute %q = %v, want %v", k, attrs[k], v)
		}
	}
	perms, ok := attrs["permissions"].(gin.H)
	if !ok || perms["can-delete"] != true {
		t.Errorf("permissions.can-delete missing/false: %v", attrs["permissions"])
	}
	// No snake_case leftovers.
	for _, forbidden := range []string{"registry_name", "created_at", "updated_at"} {
		if _, present := attrs[forbidden]; present {
			t.Errorf("attribute %q is snake_case; must be kebab-case", forbidden)
		}
	}
}

// TestProtocolList verifies the stored comma-separated protocols string is split into the array
// Terraform's provider-install protocol expects, defaulting to ["5.0"] when empty.
func TestProtocolList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", []string{"5.0"}},
		{"  ", []string{"5.0"}},
		{"5.0", []string{"5.0"}},
		{"5.0,6.0", []string{"5.0", "6.0"}},
		{" 5.0 , 6.0 ", []string{"5.0", "6.0"}},
	}
	for _, tc := range cases {
		if got := protocolList(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("protocolList(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
