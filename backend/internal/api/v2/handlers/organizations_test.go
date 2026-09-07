// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// boolPtr returns a pointer to b (test helper).
func boolPtr(b bool) *bool { return &b }

func TestBuildTFEOrganizationResponse_PolicyDefaults(t *testing.T) {
	orgID := uuid.New()
	org := &models.Organization{ID: orgID, Name: "acme", Email: "admin@acme.test"}

	// #760: the builder returns a typed resource now, so the assertions read struct fields.
	// The properties under test are unchanged - only how they are reached.
	resp := buildTFEOrganizationResponse(org, nil)

	if resp.ID != "acme" {
		t.Errorf("id = %v, want acme (TFE uses the org name as id)", resp.ID)
	}
	attrs := resp.Attributes
	if attrs.ExternalID != orgID.String() {
		t.Errorf("external-id = %v, want %s", attrs.ExternalID, orgID.String())
	}

	// Unset *bool policy flags must echo their TFE default of TRUE.
	if !attrs.UserTokensEnabled || !attrs.SpeculativePlanManagementEnabled {
		t.Errorf("user-tokens/speculative-plan-management = %v/%v, want true/true (TFE default)",
			attrs.UserTokensEnabled, attrs.SpeculativePlanManagementEnabled)
	}
	// Plain bool flags default false.
	if attrs.AggregatedCommitStatusEnabled || attrs.AssessmentsEnforced ||
		attrs.AllowForceDeleteWorkspaces || attrs.SendPassingStatusesForUntriggeredSpeculativePlans {
		t.Error("plain bool policy flags must default false")
	}
	// Declined surface: drift-free constants.
	if attrs.OwnersTeamSAMLRoleID != "" {
		t.Errorf("owners-team-saml-role-id = %v, want \"\"", attrs.OwnersTeamSAMLRoleID)
	}
	if attrs.EnforceHYOK || attrs.StacksEnabled || attrs.MaxTTLEnabled || attrs.TwoFactorConformant {
		t.Error("declined-surface constants must be false")
	}
	if attrs.SessionTimeout != nil || attrs.SessionRemember != nil {
		t.Errorf("session attrs = %v/%v, want null/null (Zitadel owns sessions)", attrs.SessionTimeout, attrs.SessionRemember)
	}

	// No default project passed => no default-project relationship.
	rels, ok := resp.Relationships.(OrganizationResponseRelationships)
	if !ok {
		t.Fatalf("relationships is %T, want OrganizationResponseRelationships", resp.Relationships)
	}
	if rels.DefaultProject != nil {
		t.Error("default-project relationship present, want omitted when nil")
	}
}

func TestBuildTFEOrganizationResponse_PolicyValuesAndDefaultProject(t *testing.T) {
	projectID := uuid.New()
	org := &models.Organization{
		ID:                               uuid.New(),
		Name:                             "acme",
		UserTokensEnabled:                boolPtr(false),
		SpeculativePlanManagementEnabled: boolPtr(false),
		AllowForceDeleteWorkspaces:       true,
		AssessmentsEnforced:              true,
		AggregatedCommitStatusEnabled:    true,
	}

	resp := buildTFEOrganizationResponse(org, &projectID)

	attrs := resp.Attributes
	if attrs.UserTokensEnabled || attrs.SpeculativePlanManagementEnabled {
		t.Error("explicit false pointers must echo false")
	}
	if !attrs.AllowForceDeleteWorkspaces || !attrs.AssessmentsEnforced || !attrs.AggregatedCommitStatusEnabled {
		t.Error("set bool flags must echo true")
	}

	rels := resp.Relationships.(OrganizationResponseRelationships)
	if rels.DefaultProject == nil || rels.DefaultProject.Data == nil {
		t.Fatal("default-project relationship missing")
	}
	if rels.DefaultProject.Data.ID != projectID.String() || rels.DefaultProject.Data.Type != "projects" {
		t.Errorf("default-project.data = %+v, want id=%s type=projects", rels.DefaultProject.Data, projectID.String())
	}
}

func TestApplyOrgPolicyAttributes_PointerSemantics(t *testing.T) {
	org := &models.Organization{
		UserTokensEnabled:          boolPtr(false),
		AllowForceDeleteWorkspaces: true,
	}

	// Empty attrs: nothing changes.
	if detail, ok := applyOrgPolicyAttributes(org, &OrganizationAttributes{}); !ok {
		t.Fatalf("empty attrs rejected: %s", detail)
	}
	if org.UserTokensAllowed() || !org.AllowForceDeleteWorkspaces {
		t.Error("empty attrs mutated existing values")
	}

	// Supplied attrs overwrite.
	attrs := &OrganizationAttributes{
		UserTokensEnabled:   boolPtr(true),
		AssessmentsEnforced: boolPtr(true),
	}
	if detail, ok := applyOrgPolicyAttributes(org, attrs); !ok {
		t.Fatalf("valid attrs rejected: %s", detail)
	}
	if !org.UserTokensAllowed() || !org.AssessmentsEnforced {
		t.Error("supplied attrs not applied")
	}
}

func TestApplyOrgPolicyAttributes_AggregatedExclusion(t *testing.T) {
	// Both set in one request: rejected.
	org := &models.Organization{}
	attrs := &OrganizationAttributes{
		AggregatedCommitStatusEnabled:                     boolPtr(true),
		SendPassingStatusesForUntriggeredSpeculativePlans: boolPtr(true),
	}
	if _, ok := applyOrgPolicyAttributes(org, attrs); ok {
		t.Error("aggregated + send-passing both true was accepted, want 422 detail")
	}

	// Cross-request: org already aggregated, request flips send-passing on.
	org = &models.Organization{AggregatedCommitStatusEnabled: true}
	attrs = &OrganizationAttributes{SendPassingStatusesForUntriggeredSpeculativePlans: boolPtr(true)}
	if _, ok := applyOrgPolicyAttributes(org, attrs); ok {
		t.Error("send-passing enabled while org is aggregated was accepted, want rejection")
	}

	// Disabling aggregated while enabling send-passing in the same request is coherent.
	org = &models.Organization{AggregatedCommitStatusEnabled: true}
	attrs = &OrganizationAttributes{
		AggregatedCommitStatusEnabled:                     boolPtr(false),
		SendPassingStatusesForUntriggeredSpeculativePlans: boolPtr(true),
	}
	if detail, ok := applyOrgPolicyAttributes(org, attrs); !ok {
		t.Errorf("coherent flip rejected: %s", detail)
	}
}

func TestOrganizationPolicyModelDefaults(t *testing.T) {
	org := &models.Organization{}
	if !org.UserTokensAllowed() {
		t.Error("nil UserTokensEnabled must mean allowed (TFE default true)")
	}
	if !org.SpeculativePlanManagement() {
		t.Error("nil SpeculativePlanManagementEnabled must mean enabled (TFE default true)")
	}
	off := false
	org.UserTokensEnabled = &off
	org.SpeculativePlanManagementEnabled = &off
	if org.UserTokensAllowed() || org.SpeculativePlanManagement() {
		t.Error("explicit false not honored")
	}
}
