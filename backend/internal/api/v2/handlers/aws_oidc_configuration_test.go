// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

	if resp["id"] != "awsoidc-1234567890abcdef" {
		t.Errorf("expected id 'awsoidc-1234567890abcdef', got '%v'", resp["id"])
	}
	if resp["type"] != "aws-oidc-configurations" {
		t.Errorf("expected type 'aws-oidc-configurations', got '%v'", resp["type"])
	}

	attrs, ok := resp["attributes"].(gin.H)
	if !ok {
		t.Fatalf("attributes not a gin.H: %T", resp["attributes"])
	}
	if attrs["role-arn"] != "arn:aws:iam::123456789012:role/stackweaver-oidc" {
		t.Errorf("expected role-arn to round-trip, got '%v'", attrs["role-arn"])
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
	if links["self"] != "/api/v2/oidc-configurations/awsoidc-1234567890abcdef" {
		t.Errorf("unexpected self link '%v'", links["self"])
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
