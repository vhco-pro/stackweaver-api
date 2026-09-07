// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
)

// TestFormatGCPOIDCConfigResponse verifies the JSON:API response structure matches what go-tfe
// expects (type, kebab-case attributes, relationships, links).
func TestFormatGCPOIDCConfigResponse(t *testing.T) {
	org := &models.Organization{
		ID:   uuid.New(),
		Name: "test-org",
	}

	config := &models.GCPOIDCConfiguration{
		ID:                   "gcpoidc-1234567890abcdef",
		ServiceAccountEmail:  "stackweaver@my-project.iam.gserviceaccount.com",
		ProjectNumber:        "123456789012",
		WorkloadProviderName: "projects/123456789012/locations/global/workloadIdentityPools/sw/providers/sw",
		OrganizationID:       org.ID,
		Organization:         org,
	}

	resp := formatGCPOIDCConfigResponse(config)

	if resp.ID != "gcpoidc-1234567890abcdef" {
		t.Errorf("expected id 'gcpoidc-1234567890abcdef', got '%v'", resp.ID)
	}
	if resp.Type != "gcp-oidc-configurations" {
		t.Errorf("expected type 'gcp-oidc-configurations', got '%v'", resp.Type)
	}

	attrs := wireShape(t, resp.Attributes)
	if attrs["service-account-email"] != config.ServiceAccountEmail {
		t.Errorf("expected service-account-email to round-trip, got '%v'", attrs["service-account-email"])
	}
	if attrs["project-number"] != config.ProjectNumber {
		t.Errorf("expected project-number to round-trip, got '%v'", attrs["project-number"])
	}
	if attrs["workload-provider-name"] != config.WorkloadProviderName {
		t.Errorf("expected workload-provider-name to round-trip, got '%v'", attrs["workload-provider-name"])
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
	if orgData.Type != "organizations" {
		t.Errorf("expected organization type 'organizations', got '%v'", orgData.Type)
	}

	links, ok := resp.Links.(jsonapi.SelfLink)
	if !ok {
		t.Fatalf("links not a jsonapi.SelfLink: %T", resp.Links)
	}
	if links.Self != "/api/v2/oidc-configurations/gcpoidc-1234567890abcdef" {
		t.Errorf("unexpected self link '%v'", links.Self)
	}
}

// TestGCPOIDCConfigTypeValidation documents the exact JSON:API type the provider sends.
func TestGCPOIDCConfigTypeValidation(t *testing.T) {
	cases := []struct {
		name     string
		dataType string
		want     bool
	}{
		{"correct type", "gcp-oidc-configurations", true},
		{"aws type", "aws-oidc-configurations", false},
		{"azure type", "azure-oidc-configurations", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.dataType == gcpOIDCConfigType; got != tc.want {
				t.Errorf("dataType %q: got %v, want %v", tc.dataType, got, tc.want)
			}
		})
	}
}
