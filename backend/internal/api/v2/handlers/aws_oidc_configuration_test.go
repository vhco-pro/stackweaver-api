// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
)

// TestFormatAWSOIDCConfigResponse verifies the JSON:API response structure matches what go-tfe
// expects (type, kebab-case attributes, relationships, links).
func TestFormatAWSOIDCConfigResponse(t *testing.T) {
	org := &models.Organization{
		ID:   uuid.New(),
		Name: "test-org",
	}

	config := &models.AWSOIDCConfiguration{
		ID:             "awsoidc-1234567890abcdef",
		RoleARN:        "arn:aws:iam::123456789012:role/stackweaver-oidc",
		OrganizationID: org.ID,
		Organization:   org,
	}

	resp := formatAWSOIDCConfigResponse(config)

	if resp.ID != "awsoidc-1234567890abcdef" {
		t.Errorf("expected id 'awsoidc-1234567890abcdef', got '%v'", resp.ID)
	}
	if resp.Type != "aws-oidc-configurations" {
		t.Errorf("expected type 'aws-oidc-configurations', got '%v'", resp.Type)
	}

	attrs := wireShape(t, resp.Attributes)
	if attrs["role-arn"] != "arn:aws:iam::123456789012:role/stackweaver-oidc" {
		t.Errorf("expected role-arn to round-trip, got '%v'", attrs["role-arn"])
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
	if links.Self != "/api/v2/oidc-configurations/awsoidc-1234567890abcdef" {
		t.Errorf("unexpected self link '%v'", links.Self)
	}
}

// TestAWSOIDCConfigTypeValidation documents the exact JSON:API type the provider sends.
func TestAWSOIDCConfigTypeValidation(t *testing.T) {
	cases := []struct {
		name     string
		dataType string
		want     bool
	}{
		{"correct type", "aws-oidc-configurations", true},
		{"azure type", "azure-oidc-configurations", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.dataType == awsOIDCConfigType; got != tc.want {
				t.Errorf("dataType %q: got %v, want %v", tc.dataType, got, tc.want)
			}
		})
	}
}
