// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// boolPtr returns a pointer to b (test helper).
func boolPtr(b bool) *bool { return &b }

func TestBuildTFEOrganizationResponse_PolicyDefaults(t *testing.T) {
	orgID := uuid.New()
	org := &models.Organization{ID: orgID, Name: "acme", Email: "admin@acme.test"}

	resp := buildTFEOrganizationResponse(org, nil)

	if resp["id"] != "acme" {
		t.Errorf("id = %v, want acme (TFE uses the org name as id)", resp["id"])
	}
	attrs, ok := resp["attributes"].(gin.H)
	if !ok {
		t.Fatal("attributes is not gin.H")
	}
	if attrs["external-id"] != orgID.String() {
		t.Errorf("external-id = %v, want %s", attrs["external-id"], orgID.String())
	}

	// Unset *bool policy flags must echo their TFE default of TRUE.
	for _, key := range []string{"user-tokens-enabled", "speculative-plan-management-enabled"} {
		if attrs[key] != true {
			t.Errorf("%s = %v, want true (TFE default)", key, attrs[key])
		}
	}
	// Plain bool flags default false.
	for _, key := range []string{
		"aggregated-commit-status-enabled",
		"assessments-enforced",
		"allow-force-delete-workspaces",
		"send-passing-statuses-for-untriggered-speculative-plans",
	} {
		if attrs[key] != false {
			t.Errorf("%s = %v, want false", key, attrs[key])
		}
	}
	// Declined surface: drift-free constants.
	if attrs["owners-team-saml-role-id"] != "" {
		t.Errorf("owners-team-saml-role-id = %v, want \"\"", attrs["owners-team-saml-role-id"])
	}
	for _, key := range []string{"enforce-hyok", "stacks-enabled", "max-ttl-enabled", "two-factor-conformant"} {
		if attrs[key] != false {
			t.Errorf("%s = %v, want false (declined constant)", key, attrs[key])
		}
	}
	if attrs["session-timeout"] != nil || attrs["session-remember"] != nil {
		t.Errorf("session attrs = %v/%v, want null/null (Zitadel owns sessions)", attrs["session-timeout"], attrs["session-remember"])
	}

	// No default project passed => no default-project relationship.
	rels, ok := resp["relationships"].(gin.H)
	if !ok {
		t.Fatal("relationships is not gin.H")
	}
	if _, present := rels["default-project"]; present {
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

	attrs := resp["attributes"].(gin.H)
	if attrs["user-tokens-enabled"] != false {
		t.Errorf("user-tokens-enabled = %v, want false", attrs["user-tokens-enabled"])
	}
	if attrs["speculative-plan-management-enabled"] != false {
		t.Errorf("speculative-plan-management-enabled = %v, want false", attrs["speculative-plan-management-enabled"])
	}
	if attrs["allow-force-delete-workspaces"] != true {
		t.Errorf("allow-force-delete-workspaces = %v, want true", attrs["allow-force-delete-workspaces"])
	}
	if attrs["assessments-enforced"] != true {
		t.Errorf("assessments-enforced = %v, want true", attrs["assessments-enforced"])
	}
	if attrs["aggregated-commit-status-enabled"] != true {
		t.Errorf("aggregated-commit-status-enabled = %v, want true", attrs["aggregated-commit-status-enabled"])
	}

	rels := resp["relationships"].(gin.H)
	projRel, ok := rels["default-project"].(gin.H)
	if !ok {
		t.Fatal("default-project relationship missing")
	}
	data := projRel["data"].(gin.H)
	if data["id"] != projectID.String() || data["type"] != "projects" {
		t.Errorf("default-project.data = %v, want id=%s type=projects", data, projectID.String())
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
