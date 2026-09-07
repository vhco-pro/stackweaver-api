// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
)

// TestFormatVaultOIDCConfigResponse verifies the JSON:API response structure matches what go-tfe
// expects (type, kebab-case attributes, relationships, links).
func TestFormatVaultOIDCConfigResponse(t *testing.T) {
	org := &models.Organization{
		ID:   uuid.New(),
		Name: "test-org",
	}

	config := &models.VaultOIDCConfiguration{
		ID:               "vaultoidc-1234567890abcdef",
		Address:          "https://vault.example.com:8200",
		RoleName:         "stackweaver",
		Namespace:        "admin/team-a",
		JWTAuthPath:      "jwt",
		TLSCACertificate: "LS0tLS1CRUdJTi...",
		OrganizationID:   org.ID,
		Organization:     org,
	}

	resp := formatVaultOIDCConfigResponse(config)

	if resp.ID != "vaultoidc-1234567890abcdef" {
		t.Errorf("expected id 'vaultoidc-1234567890abcdef', got '%v'", resp.ID)
	}
	if resp.Type != "vault-oidc-configurations" {
		t.Errorf("expected type 'vault-oidc-configurations', got '%v'", resp.Type)
	}

	attrs := wireShape(t, resp.Attributes)
	if attrs["address"] != config.Address {
		t.Errorf("expected address to round-trip, got '%v'", attrs["address"])
	}
	if attrs["role"] != config.RoleName {
		t.Errorf("expected role to round-trip, got '%v'", attrs["role"])
	}
	if attrs["namespace"] != config.Namespace {
		t.Errorf("expected namespace to round-trip, got '%v'", attrs["namespace"])
	}
	if attrs["auth-path"] != config.JWTAuthPath {
		t.Errorf("expected auth-path to round-trip, got '%v'", attrs["auth-path"])
	}
	if attrs["encoded-cacert"] != config.TLSCACertificate {
		t.Errorf("expected encoded-cacert to round-trip, got '%v'", attrs["encoded-cacert"])
	}

	rels, ok := resp.Relationships.(WorkspaceOnlyRelationshipsNamed)
	if !ok {
		t.Fatalf("relationships not a WorkspaceOnlyRelationshipsNamed: %T", resp.Relationships)
	}
	orgData := rels.Organization.Data
	if orgData == nil {
		t.Fatalf("organization data is nil")
	}
	if orgData.ID != "test-org" {
		t.Errorf("expected organization id 'test-org', got '%v'", orgData.ID)
	}

	links, ok := resp.Links.(jsonapi.SelfLink)
	if !ok {
		t.Fatalf("links not a jsonapi.SelfLink: %T", resp.Links)
	}
	if links.Self != "/api/v2/oidc-configurations/vaultoidc-1234567890abcdef" {
		t.Errorf("unexpected self link '%v'", links.Self)
	}
}

// TestVaultOIDCConfigTypeValidation documents the exact JSON:API type the provider sends.
func TestVaultOIDCConfigTypeValidation(t *testing.T) {
	cases := []struct {
		name     string
		dataType string
		want     bool
	}{
		{"correct type", "vault-oidc-configurations", true},
		{"gcp type", "gcp-oidc-configurations", false},
		{"aws type", "aws-oidc-configurations", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.dataType == vaultOIDCConfigType; got != tc.want {
				t.Errorf("dataType %q: got %v, want %v", tc.dataType, got, tc.want)
			}
		})
	}
}
