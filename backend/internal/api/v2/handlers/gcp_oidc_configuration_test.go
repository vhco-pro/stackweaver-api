// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

	if resp["id"] != "gcpoidc-1234567890abcdef" {
		t.Errorf("expected id 'gcpoidc-1234567890abcdef', got '%v'", resp["id"])
	}
	if resp["type"] != "gcp-oidc-configurations" {
		t.Errorf("expected type 'gcp-oidc-configurations', got '%v'", resp["type"])
	}

	attrs, ok := resp["attributes"].(gin.H)
	if !ok {
		t.Fatalf("attributes not a gin.H: %T", resp["attributes"])
	}
	if attrs["service-account-email"] != config.ServiceAccountEmail {
		t.Errorf("expected service-account-email to round-trip, got '%v'", attrs["service-account-email"])
	}
	if attrs["project-number"] != config.ProjectNumber {
		t.Errorf("expected project-number to round-trip, got '%v'", attrs["project-number"])
	}
	if attrs["workload-provider-name"] != config.WorkloadProviderName {
		t.Errorf("expected workload-provider-name to round-trip, got '%v'", attrs["workload-provider-name"])
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
	if orgData["type"] != "organizations" {
		t.Errorf("expected organization type 'organizations', got '%v'", orgData["type"])
	}

	links, ok := resp["links"].(gin.H)
	if !ok {
		t.Fatalf("links not a gin.H")
	}
	if links["self"] != "/api/v2/oidc-configurations/gcpoidc-1234567890abcdef" {
		t.Errorf("unexpected self link '%v'", links["self"])
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
