// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
)

func TestFormatAgentPoolResponse_Basic(t *testing.T) {
	poolID := uuid.New()
	orgName := "test-org"
	pool := &models.AgentPool{
		ID:                 poolID,
		OrganizationScoped: true,
		Name:               "production-pool",
		CreatedAt:          time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC),
	}

	resp := formatAgentPoolResponse(pool, orgName, 3)

	// Verify top-level fields
	if resp.ID != poolID.String() {
		t.Errorf("id = %v, want %s", resp.ID, poolID.String())
	}
	if resp.Type != "agent-pools" {
		t.Errorf("type = %v, want agent-pools", resp.Type)
	}

	// Verify attributes
	if resp.Attributes.Name != "production-pool" {
		t.Errorf("attributes.name = %v, want production-pool", resp.Attributes.Name)
	}
	if resp.Attributes.AgentCount != 3 {
		t.Errorf("attributes.agent-count = %v, want 3", resp.Attributes.AgentCount)
	}
	if !resp.Attributes.OrganizationScoped {
		t.Errorf("attributes.organization-scoped = %v, want true", resp.Attributes.OrganizationScoped)
	}

	// Verify relationships
	rels, ok := resp.Relationships.(AgentPoolRelationships)
	if !ok {
		t.Fatal("relationships is not AgentPoolRelationships")
	}
	if rels.Organization.Data == nil {
		t.Fatal("relationships.organization.data is nil")
	}
	if rels.Organization.Data.ID != orgName {
		t.Errorf("organization.data.id = %v, want %s", rels.Organization.Data.ID, orgName)
	}
	if rels.Organization.Data.Type != "organizations" {
		t.Errorf("organization.data.type = %v, want organizations", rels.Organization.Data.Type)
	}

	// Verify links
	links, ok := resp.Links.(jsonapi.SelfLink)
	if !ok {
		t.Fatal("links is not jsonapi.SelfLink")
	}
	expectedSelf := "/api/v2/agent-pools/" + poolID.String()
	if links.Self != expectedSelf {
		t.Errorf("links.self = %v, want %s", links.Self, expectedSelf)
	}
}

func TestFormatAgentPoolResponse_WithAllowedWorkspaces(t *testing.T) {
	pool := &models.AgentPool{
		ID:                 uuid.New(),
		OrganizationScoped: false,
		Name:               "scoped-pool",
		CreatedAt:          time.Now(),
		AllowedWorkspaces: []models.Workspace{
			{ID: "ws-workspace00001", Name: "ws-1"},
			{ID: "ws-workspace00002", Name: "ws-2"},
		},
	}

	resp := formatAgentPoolResponse(pool, "org", 0)
	rels := resp.Relationships.(AgentPoolRelationships)

	if rels.AllowedWorkspaces == nil {
		t.Fatal("relationships should include allowed-workspaces when workspaces are present")
	}
	data := rels.AllowedWorkspaces.Data
	if len(data) != 2 {
		t.Fatalf("allowed-workspaces.data has %d items, want 2", len(data))
	}
	if data[0].ID != "ws-workspace00001" {
		t.Errorf("allowed-workspaces.data[0].id = %v, want ws-workspace00001", data[0].ID)
	}
	if data[0].Type != "workspaces" {
		t.Errorf("allowed-workspaces.data[0].type = %v, want workspaces", data[0].Type)
	}
}

func TestFormatAgentPoolResponse_WithAllowedProjects(t *testing.T) {
	projID := uuid.New()
	pool := &models.AgentPool{
		ID:                 uuid.New(),
		OrganizationScoped: false,
		Name:               "project-pool",
		CreatedAt:          time.Now(),
		AllowedProjects: []models.Project{
			{ID: projID, Name: "project-1"},
		},
	}

	resp := formatAgentPoolResponse(pool, "org", 0)
	rels := resp.Relationships.(AgentPoolRelationships)
	if rels.AllowedProjects == nil {
		t.Fatal("relationships should include allowed-projects when projects are present")
	}
	data := rels.AllowedProjects.Data
	if len(data) != 1 {
		t.Fatalf("allowed-projects.data has %d items, want 1", len(data))
	}
	if data[0].ID != projID.String() {
		t.Errorf("allowed-projects.data[0].id = %v, want %s", data[0].ID, projID.String())
	}
	if data[0].Type != "projects" {
		t.Errorf("allowed-projects.data[0].type = %v, want projects", data[0].Type)
	}
}

func TestFormatAgentPoolResponse_WithExcludedWorkspaces(t *testing.T) {
	pool := &models.AgentPool{
		ID:                 uuid.New(),
		OrganizationScoped: true,
		Name:               "org-pool",
		CreatedAt:          time.Now(),
		ExcludedWorkspaces: []models.Workspace{
			{ID: "ws-excluded00001", Name: "excluded"},
		},
	}

	resp := formatAgentPoolResponse(pool, "org", 0)
	rels := resp.Relationships.(AgentPoolRelationships)
	if rels.ExcludedWorkspaces == nil {
		t.Fatal("relationships should include excluded-workspaces when exclusions are present")
	}
	data := rels.ExcludedWorkspaces.Data
	if len(data) != 1 {
		t.Fatalf("excluded-workspaces.data has %d items, want 1", len(data))
	}
	if data[0].ID != "ws-excluded00001" {
		t.Errorf("excluded-workspaces.data[0].id = %v, want ws-excluded00001", data[0].ID)
	}
}

func TestFormatAgentPoolResponse_NoRelationships(t *testing.T) {
	pool := &models.AgentPool{
		ID:                 uuid.New(),
		OrganizationScoped: true,
		Name:               "empty-pool",
		CreatedAt:          time.Now(),
	}

	resp := formatAgentPoolResponse(pool, "org", 0)
	rels := resp.Relationships.(AgentPoolRelationships)

	// Should only have organization relationship, not allowed/excluded (nil pointers are
	// omitted from the JSON via omitempty)
	if rels.AllowedWorkspaces != nil {
		t.Error("relationships should not include allowed-workspaces when empty")
	}
	if rels.AllowedProjects != nil {
		t.Error("relationships should not include allowed-projects when empty")
	}
	if rels.ExcludedWorkspaces != nil {
		t.Error("relationships should not include excluded-workspaces when empty")
	}
	if rels.Organization.Data == nil {
		t.Error("relationships should always include organization")
	}
}

func TestFormatAgentPoolResponse_ZeroAgentCount(t *testing.T) {
	pool := &models.AgentPool{
		ID:        uuid.New(),
		Name:      "new-pool",
		CreatedAt: time.Now(),
	}

	resp := formatAgentPoolResponse(pool, "org", 0)
	if resp.Attributes.AgentCount != 0 {
		t.Errorf("attributes.agent-count = %v, want 0", resp.Attributes.AgentCount)
	}
}

func TestExtractWorkspaceIDs(t *testing.T) {
	tests := []struct {
		name     string
		refs     []jsonAPIRef
		expected []string
	}{
		{
			name:     "multiple refs",
			refs:     []jsonAPIRef{{ID: "ws-abc"}, {ID: "ws-def"}},
			expected: []string{"ws-abc", "ws-def"},
		},
		{
			name:     "empty refs",
			refs:     []jsonAPIRef{},
			expected: []string{},
		},
		{
			name:     "skip empty IDs",
			refs:     []jsonAPIRef{{ID: "ws-abc"}, {ID: ""}, {ID: "ws-def"}},
			expected: []string{"ws-abc", "ws-def"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractWorkspaceIDs(tt.refs)
			if len(got) != len(tt.expected) {
				t.Fatalf("extractWorkspaceIDs() returned %d items, want %d", len(got), len(tt.expected))
			}
			for i, id := range got {
				if id != tt.expected[i] {
					t.Errorf("extractWorkspaceIDs()[%d] = %s, want %s", i, id, tt.expected[i])
				}
			}
		})
	}
}

func TestExtractProjectIDs(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()

	tests := []struct {
		name     string
		refs     []jsonAPIRef
		expected []uuid.UUID
	}{
		{
			name:     "valid UUIDs",
			refs:     []jsonAPIRef{{ID: id1.String()}, {ID: id2.String()}},
			expected: []uuid.UUID{id1, id2},
		},
		{
			name:     "empty refs",
			refs:     []jsonAPIRef{},
			expected: []uuid.UUID{},
		},
		{
			name:     "skip invalid UUIDs",
			refs:     []jsonAPIRef{{ID: id1.String()}, {ID: "not-a-uuid"}, {ID: id2.String()}},
			expected: []uuid.UUID{id1, id2},
		},
		{
			name:     "skip empty IDs",
			refs:     []jsonAPIRef{{ID: id1.String()}, {ID: ""}},
			expected: []uuid.UUID{id1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractProjectIDs(tt.refs)
			if len(got) != len(tt.expected) {
				t.Fatalf("extractProjectIDs() returned %d items, want %d", len(got), len(tt.expected))
			}
			for i, id := range got {
				if id != tt.expected[i] {
					t.Errorf("extractProjectIDs()[%d] = %s, want %s", i, id, tt.expected[i])
				}
			}
		})
	}
}
