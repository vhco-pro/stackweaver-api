// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func TestFormatWorkspaceResponse_Basic(t *testing.T) {
	ws := &models.Workspace{
		ID:               "ws-abcdef1234567890",
		Name:             "production",
		TerraformVersion: "1.9.0",
		WorkingDirectory: "infra/",
		AutoApply:        true,
		ExecutionMode:    "remote",
		Description:      "Production workspace",
		CreatedAt:        time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:        time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	resp := formatWorkspaceResponse(ws)

	if resp["id"] != "ws-abcdef1234567890" {
		t.Errorf("id = %v, want ws-abcdef1234567890", resp["id"])
	}
	if resp["type"] != "workspaces" {
		t.Errorf("type = %v, want workspaces", resp["type"])
	}

	attrs, ok := resp["attributes"].(gin.H)
	if !ok {
		t.Fatal("attributes is not gin.H")
	}
	if attrs["name"] != "production" {
		t.Errorf("name = %v, want production", attrs["name"])
	}
	if attrs["terraform-version"] != "1.9.0" {
		t.Errorf("terraform-version = %v, want 1.9.0", attrs["terraform-version"])
	}
	if attrs["working-directory"] != "infra/" {
		t.Errorf("working-directory = %v, want infra/", attrs["working-directory"])
	}
	if attrs["auto-apply"] != true {
		t.Errorf("auto-apply = %v, want true", attrs["auto-apply"])
	}
	if attrs["execution-mode"] != "remote" {
		t.Errorf("execution-mode = %v, want remote", attrs["execution-mode"])
	}
	if attrs["description"] != "Production workspace" {
		t.Errorf("description = %v, want Production workspace", attrs["description"])
	}
}

func TestFormatWorkspaceResponse_NoVCS(t *testing.T) {
	ws := &models.Workspace{
		ID:        "ws-test",
		Name:      "no-vcs",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	resp := formatWorkspaceResponse(ws)
	attrs, ok := resp["attributes"].(gin.H)
	if !ok {
		t.Fatal("attributes is not gin.H")
	}

	// When no VCS, vcs-repo should be nil
	if attrs["vcs-repo"] != nil {
		t.Errorf("vcs-repo = %v, want nil", attrs["vcs-repo"])
	}
}

func TestFormatWorkspaceResponse_WithVCS(t *testing.T) {
	ws := &models.Workspace{
		ID:                   "ws-vcs",
		Name:                 "with-vcs",
		VCSRepository:        "org/repo",
		VCSBranch:            "develop",
		VCSIngressSubmodules: true,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	resp := formatWorkspaceResponse(ws)
	attrs, ok := resp["attributes"].(gin.H)
	if !ok {
		t.Fatal("attributes is not gin.H")
	}

	vcsRepo, ok := attrs["vcs-repo"].(gin.H)
	if !ok {
		t.Fatal("vcs-repo is not gin.H")
	}
	if vcsRepo["identifier"] != "org/repo" {
		t.Errorf("vcs-repo.identifier = %v, want org/repo", vcsRepo["identifier"])
	}
	if vcsRepo["branch"] != "develop" {
		t.Errorf("vcs-repo.branch = %v, want develop", vcsRepo["branch"])
	}
	if vcsRepo["ingress-submodules"] != true {
		t.Errorf("vcs-repo.ingress-submodules = %v, want true", vcsRepo["ingress-submodules"])
	}
}

func TestFormatWorkspaceResponse_VCSDefaultBranch(t *testing.T) {
	ws := &models.Workspace{
		ID:            "ws-vcs-default",
		Name:          "vcs-default-branch",
		VCSRepository: "org/repo",
		VCSBranch:     "", // Empty branch should default to "main"
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	resp := formatWorkspaceResponse(ws)
	attrs := resp["attributes"].(gin.H)
	vcsRepo := attrs["vcs-repo"].(gin.H)
	if vcsRepo["branch"] != "main" {
		t.Errorf("vcs-repo.branch = %v, want main (default)", vcsRepo["branch"])
	}
}

func TestFormatWorkspaceResponse_Relationships(t *testing.T) {
	orgID := uuid.New()
	projectID := uuid.New()
	ws := &models.Workspace{
		ID:        "ws-rels",
		Name:      "rels-test",
		ProjectID: projectID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Project: models.Project{
			Name:           "test-project",
			OrganizationID: orgID,
		},
	}
	ws.Project.Organization.Name = "test-org"

	resp := formatWorkspaceResponse(ws)
	rels, ok := resp["relationships"].(gin.H)
	if !ok {
		t.Fatal("relationships is not gin.H")
	}

	// Should have organization and project relationships
	if _, hasOrg := rels["organization"]; !hasOrg {
		t.Error("missing organization relationship")
	}
	if _, hasProject := rels["project"]; !hasProject {
		t.Error("missing project relationship")
	}
}

func TestFormatWorkspaceResponse_ResponseStructure(t *testing.T) {
	ws := &models.Workspace{
		ID:        "ws-struct",
		Name:      "struct-test",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	resp := formatWorkspaceResponse(ws)

	// Verify top-level keys
	if _, ok := resp["id"]; !ok {
		t.Error("missing id key")
	}
	if _, ok := resp["type"]; !ok {
		t.Error("missing type key")
	}
	if _, ok := resp["attributes"]; !ok {
		t.Error("missing attributes key")
	}
	if _, ok := resp["relationships"]; !ok {
		t.Error("missing relationships key")
	}
}

func TestFormatRunForInclusion_Basic(t *testing.T) {
	run := &models.Run{
		ID:          "run-abc123",
		WorkspaceID: "ws-test",
		Status:      "applied",
		Operation:   "plan-and-apply",
		CreatedAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC),
	}

	resp := formatRunForInclusion(run)

	if resp["id"] != "run-abc123" {
		t.Errorf("id = %v, want run-abc123", resp["id"])
	}
	if resp["type"] != "runs" {
		t.Errorf("type = %v, want runs", resp["type"])
	}

	attrs, ok := resp["attributes"].(gin.H)
	if !ok {
		t.Fatal("attributes is not gin.H")
	}
	if attrs["status"] != "applied" {
		t.Errorf("status = %v, want applied", attrs["status"])
	}
}
