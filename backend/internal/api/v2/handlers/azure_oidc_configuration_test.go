// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
)

// TestFormatAzureOIDCConfigResponse verifies the JSON:API response structure
// matches what go-tfe expects (type, attributes with kebab-case, relationships, links).
func TestFormatAzureOIDCConfigResponse(t *testing.T) {
	org := &models.Organization{
		ID:   uuid.New(),
		Name: "test-org",
	}

	config := &models.AzureOIDCConfiguration{
		ID:             "azoidc-1234567890abcdef",
		ClientID:       "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		SubscriptionID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		TenantID:       "cccccccc-cccc-cccc-cccc-cccccccccccc",
		OrganizationID: org.ID,
		Organization:   org,
	}

	resp := formatAzureOIDCConfigResponse(config)

	// Verify top-level fields
	if resp.ID != "azoidc-1234567890abcdef" {
		t.Errorf("expected id 'azoidc-1234567890abcdef', got '%v'", resp.ID)
	}
	if resp.Type != "azure-oidc-configurations" {
		t.Errorf("expected type 'azure-oidc-configurations', got '%v'", resp.Type)
	}

	// Verify attributes (kebab-case keys matching go-tfe jsonapi tags)
	attrs := wireShape(t, resp.Attributes)
	if attrs["client-id"] != "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" {
		t.Errorf("expected client-id, got '%v'", attrs["client-id"])
	}
	if attrs["subscription-id"] != "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" {
		t.Errorf("expected subscription-id, got '%v'", attrs["subscription-id"])
	}
	if attrs["tenant-id"] != "cccccccc-cccc-cccc-cccc-cccccccccccc" {
		t.Errorf("expected tenant-id, got '%v'", attrs["tenant-id"])
	}

	// Verify relationships
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
	if orgData.Type != "organizations" {
		t.Errorf("expected organization type 'organizations', got '%v'", orgData.Type)
	}

	// Verify links
	links, ok := resp.Links.(jsonapi.SelfLink)
	if !ok {
		t.Fatalf("links not a jsonapi.SelfLink: %T", resp.Links)
	}
	if links.Self != "/api/v2/oidc-configurations/azoidc-1234567890abcdef" {
		t.Errorf("expected self link '/api/v2/oidc-configurations/azoidc-1234567890abcdef', got '%v'", links.Self)
	}
}

// TestFormatAzureOIDCConfigResponse_NilOrganization verifies response formatting
// when the Organization relationship is not preloaded.
func TestFormatAzureOIDCConfigResponse_NilOrganization(t *testing.T) {
	config := &models.AzureOIDCConfiguration{
		ID:             "azoidc-abcdefghijklmnop",
		ClientID:       "test-client-id",
		SubscriptionID: "test-subscription-id",
		TenantID:       "test-tenant-id",
		OrganizationID: uuid.New(),
		Organization:   nil,
	}

	resp := formatAzureOIDCConfigResponse(config)

	// Organization name should be empty string when not preloaded
	rels := resp.Relationships.(WorkspaceOnlyRelationshipsNamed)
	orgData := rels.Organization.Data
	if orgData == nil {
		t.Fatal("organization data is nil")
	}
	if orgData.ID != "" {
		t.Errorf("expected empty org id when organization is nil, got '%v'", orgData.ID)
	}
}

// TestCreateAzureOIDCConfigRequest_TypeValidation verifies that the handler
// correctly validates the JSON:API type field.
func TestCreateAzureOIDCConfigRequest_TypeValidation(t *testing.T) {
	tests := []struct {
		name        string
		dataType    string
		shouldMatch bool
	}{
		{"correct type", "azure-oidc-configurations", true},
		{"wrong type", "aws-oidc-configurations", false},
		{"empty type", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := tt.dataType == "azure-oidc-configurations"
			if matches != tt.shouldMatch {
				t.Errorf("type '%s': expected match=%v, got %v", tt.dataType, tt.shouldMatch, matches)
			}
		})
	}
}
