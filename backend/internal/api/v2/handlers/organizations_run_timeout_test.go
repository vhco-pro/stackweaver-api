// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

// TestApplyOrgRunTimeout covers the organization's level of the run timeout (#933, D0): zero
// inherits the deployment default, an absent attribute changes nothing, a negative number is refused,
// and the response carries the stored value.
func TestApplyOrgRunTimeout(t *testing.T) {
	intPtr := func(i int) *int { return &i }

	org := &models.Organization{RunTimeout: 900}
	if _, ok := applyOrgRunTimeout(org, nil); !ok || org.RunTimeout != 900 {
		t.Fatalf("absent attribute changed the timeout to %d", org.RunTimeout)
	}
	if _, ok := applyOrgRunTimeout(org, intPtr(1800)); !ok || org.RunTimeout != 1800 {
		t.Fatalf("set: got %d", org.RunTimeout)
	}
	if _, ok := applyOrgRunTimeout(org, intPtr(0)); !ok || org.RunTimeout != 0 {
		t.Fatalf("reset: got %d", org.RunTimeout)
	}
	if _, ok := applyOrgRunTimeout(org, intPtr(-3)); ok {
		t.Fatal("negative timeout accepted")
	}
	if got := buildTFEOrganizationResponse(&models.Organization{Name: "acme", RunTimeout: 1800}, nil).Attributes.RunTimeout; got != 1800 {
		t.Fatalf("response run-timeout = %d", got)
	}
}
