// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"strings"
	"testing"

	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
)

// AC19: a value of STACKWEAVER_ORGANIZATION_CREATION other than everyone or platform-admins stops
// the API at startup with an error naming the variable.
func TestPlatformAdminConfigFromEnv(t *testing.T) {
	t.Setenv("STACKWEAVER_PLATFORM_ADMINS", "ops@example.com")
	t.Setenv("STACKWEAVER_ORGANIZATION_CREATION", "")
	cfg, err := platformAdminConfigFromEnv()
	if err != nil || cfg.OrganizationCreation != platformadmin.OrganizationCreationEveryone || !cfg.Declared.Contains("OPS@example.com") {
		t.Fatalf("defaults: %+v, %v", cfg, err)
	}

	t.Setenv("STACKWEAVER_ORGANIZATION_CREATION", "platform-admins")
	if cfg, err := platformAdminConfigFromEnv(); err != nil || cfg.OrganizationCreation != platformadmin.OrganizationCreationPlatformAdmins {
		t.Fatalf("platform-admins: %+v, %v", cfg, err)
	}

	t.Setenv("STACKWEAVER_ORGANIZATION_CREATION", "admins-only")
	_, err = platformAdminConfigFromEnv()
	if err == nil || !strings.Contains(err.Error(), "STACKWEAVER_ORGANIZATION_CREATION") {
		t.Fatalf("an unknown value must fail naming the variable, got %v", err)
	}
}
