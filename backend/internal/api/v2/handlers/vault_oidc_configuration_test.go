// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

	if resp["id"] != "vaultoidc-1234567890abcdef" {
		t.Errorf("expected id 'vaultoidc-1234567890abcdef', got '%v'", resp["id"])
	}
	if resp["type"] != "vault-oidc-configurations" {
		t.Errorf("expected type 'vault-oidc-configurations', got '%v'", resp["type"])
	}

	attrs, ok := resp["attributes"].(gin.H)
	if !ok {
		t.Fatalf("attributes not a gin.H: %T", resp["attributes"])
	}
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

	rels, ok := resp["relationships"].(gin.H)
	if !ok {
		t.Fatalf("relationships not a gin.H: %T", resp["relationships"])
	}
	orgRel, ok := rels["organization"].(gin.H)
	if !ok {
		t.Fatalf("organization relationship not a gin.H")
	}
	orgData, ok := orgRel["data"].(gin.H)
	if !ok {
		t.Fatalf("organization data not a gin.H")
	}
	if orgData["id"] != "test-org" {
		t.Errorf("expected organization id 'test-org', got '%v'", orgData["id"])
	}

	links, ok := resp["links"].(gin.H)
	if !ok {
		t.Fatalf("links not a gin.H")
	}
	if links["self"] != "/api/v2/oidc-configurations/vaultoidc-1234567890abcdef" {
		t.Errorf("unexpected self link '%v'", links["self"])
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
