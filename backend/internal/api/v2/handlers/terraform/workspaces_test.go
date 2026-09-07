// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// #760: the builders return typed resources, so these assertions read struct fields. The
// properties under test are unchanged from the map-based originals - only how they are reached.

package terraform

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func TestFormatWorkspaceResponse_ResourceCount(t *testing.T) {
	// resource-count reflects the denormalized workspace.ResourceCount (maintained by the
	// state materializer on every state write), not a hardcoded 0.
	ws := &models.Workspace{ID: "ws-rc", Name: "rc", ResourceCount: 7}
	if got := formatWorkspaceResponse(ws).Attributes.ResourceCount; got != 7 {
		t.Errorf("resource-count = %v, want 7", got)
	}

	// Default (no resources) is 0.
	if got := formatWorkspaceResponse(&models.Workspace{ID: "ws-z", Name: "z"}).Attributes.ResourceCount; got != 0 {
		t.Errorf("resource-count = %v, want 0", got)
	}
}

func TestFormatWorkspaceResponse_Basic(t *testing.T) {
	ws := &models.Workspace{
		ID:               "ws-abcdef1234567890",
		Name:             "production",
		TofuVersion:      "1.9.0",
		WorkingDirectory: "infra/",
		AutoApply:        true,
		ExecutionMode:    "remote",
		Description:      "Production workspace",
		CreatedAt:        time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:        time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	resp := formatWorkspaceResponse(ws)

	if resp.ID != "ws-abcdef1234567890" {
		t.Errorf("id = %v, want ws-abcdef1234567890", resp.ID)
	}
	if resp.Type != "workspaces" {
		t.Errorf("type = %v, want workspaces", resp.Type)
	}

	attrs := resp.Attributes
	if attrs.Name != "production" {
		t.Errorf("name = %v, want production", attrs.Name)
	}
	if attrs.TerraformVersion != "1.9.0" {
		t.Errorf("terraform-version = %v, want 1.9.0", attrs.TerraformVersion)
	}
	if attrs.WorkingDirectory != "infra/" {
		t.Errorf("working-directory = %v, want infra/", attrs.WorkingDirectory)
	}
	if !attrs.AutoApply {
		t.Error("auto-apply = false, want true")
	}
	if attrs.ExecutionMode != "remote" {
		t.Errorf("execution-mode = %v, want remote", attrs.ExecutionMode)
	}
	if attrs.Description != "Production workspace" {
		t.Errorf("description = %v, want Production workspace", attrs.Description)
	}
}

func TestFormatWorkspaceResponse_NoVCS(t *testing.T) {
	ws := &models.Workspace{
		ID:        "ws-test",
		Name:      "no-vcs",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// When no VCS, vcs-repo must serialise as null - the pointer must stay nil.
	if got := formatWorkspaceResponse(ws).Attributes.VCSRepo; got != nil {
		t.Errorf("vcs-repo = %+v, want nil", got)
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

	vcsRepo := formatWorkspaceResponse(ws).Attributes.VCSRepo
	if vcsRepo == nil {
		t.Fatal("vcs-repo is nil")
	}
	if vcsRepo.Identifier != "org/repo" {
		t.Errorf("vcs-repo.identifier = %v, want org/repo", vcsRepo.Identifier)
	}
	if vcsRepo.Branch != "develop" {
		t.Errorf("vcs-repo.branch = %v, want develop", vcsRepo.Branch)
	}
	if !vcsRepo.IngressSubmodules {
		t.Error("vcs-repo.ingress-submodules = false, want true")
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

	vcsRepo := formatWorkspaceResponse(ws).Attributes.VCSRepo
	if vcsRepo == nil || vcsRepo.Branch != "main" {
		t.Errorf("vcs-repo.branch = %v, want main (default)", vcsRepo)
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

	rels := formatWorkspaceResponse(ws).Relationships
	if rels.Organization == nil {
		t.Error("missing organization relationship")
	}
	if rels.Project == nil {
		t.Error("missing project relationship")
	}
}

func TestFormatWorkspaceResponse_UnpooledAgentPoolIsNullNotAbsent(t *testing.T) {
	// go-tfe / tfe_workspace_settings read agent-pool either way, so an unpooled workspace
	// must emit {"data": null} rather than omitting the member.
	rels := formatWorkspaceResponse(&models.Workspace{ID: "ws-np", Name: "np"}).Relationships
	if rels.AgentPool == nil {
		t.Fatal("agent-pool relationship absent, want present with null data")
	}
	if rels.AgentPool.Data != nil {
		t.Errorf("agent-pool.data = %+v, want null", rels.AgentPool.Data)
	}
}

// TestFormatWorkspaceResponse_CanForceDelete guards the safe-delete drop-in: terraform-provider-tfe
// uses the presence of permissions.can-force-delete to decide whether this backend supports workspace
// safe-delete. Omitting it makes `terraform destroy` refuse unless the user sets force_delete=true,
// which breaks drop-in compatibility.
func TestFormatWorkspaceResponse_CanForceDelete(t *testing.T) {
	resp := formatWorkspaceResponse(&models.Workspace{ID: "ws-perm", Name: "perm-test"})
	if !resp.Attributes.Permissions.CanForceDelete {
		t.Error("permissions.can-force-delete = false, want true (provider needs it to enable safe-delete)")
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

	if resp.ID != "run-abc123" {
		t.Errorf("id = %v, want run-abc123", resp.ID)
	}
	if resp.Type != "runs" {
		t.Errorf("type = %v, want runs", resp.Type)
	}
	if resp.Attributes.Status != "applied" {
		t.Errorf("status = %v, want applied", resp.Attributes.Status)
	}
}
