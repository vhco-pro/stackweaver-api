// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// An organization's cache size limit is a storage quota (#933, D7): an organization owner may set it
// up to the deployment's limit, and only a platform administrator above it, as with a hosted pool's
// cap. On a hosted deployment the tenant cannot grant itself unbounded storage.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestOrganizationCacheLimit

//go:build integration

package handlers

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/settings"
)

func TestOrganizationCacheLimit_AboveTheDeploymentIsForAPlatformAdmin(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	t.Setenv("CACHE_SIZE_LIMIT", "10Gi")
	ceiling := settings.DeploymentCacheSizeLimit(func(string) string { return "10Gi" })

	// The platform administrator also owns the organization, so only the cap decides.
	var owners models.Team
	if err := f.db.First(&owners, "organization_id = ? AND name = ?", f.orgA.ID, "owners").Error; err != nil {
		t.Fatal(err)
	}
	for _, row := range []any{
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.orgA.ID, UserID: f.admin.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: owners.ID, UserID: f.admin.ID},
	} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}

	orgRepo := repository.NewOrganizationRepository(f.db)
	teamRepo := repository.NewTeamRepository(f.db)
	projectRepo := repository.NewProjectRepository(f.db)
	h := NewOrganizationHandlerV2(orgRepo, teamRepo, projectRepo, repository.NewAgentPoolRepository(f.db), f.authSvc, nil,
		rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo), f.db)
	h.SetPlatformAdmin(f.admins)
	r := platformAdminRouter()
	r.PATCH("/api/v2/organizations/:name", h.Update)
	set := func(as identity, bytes int64) int {
		t.Helper()
		body := `{"data":{"type":"organizations","attributes":{"cache-size-limit":` + strconv.FormatInt(bytes, 10) + `}}}`
		rec := platformAdminCall(t, r, http.MethodPatch, "/api/v2/organizations/"+f.orgA.Name, as, body)
		return rec.Code
	}
	stored := func() int64 {
		t.Helper()
		var org models.Organization
		if err := f.db.First(&org, "id = ?", f.orgA.ID).Error; err != nil {
			t.Fatal(err)
		}
		return org.CacheSizeLimit
	}

	if code := set(browserAs(f.owner), ceiling); code != http.StatusOK {
		t.Errorf("an owner setting the deployment's limit = %d, want 200", code)
	}
	if code := set(browserAs(f.owner), ceiling/2); code != http.StatusOK || stored() != ceiling/2 {
		t.Errorf("an owner lowering the limit = %d (stored %d), want 200", code, stored())
	}
	if code := set(browserAs(f.owner), ceiling+1); code != http.StatusForbidden {
		t.Errorf("an owner raising the limit above the deployment's = %d, want 403", code)
	}
	if stored() != ceiling/2 {
		t.Errorf("the refused write stored %d", stored())
	}
	if code := set(browserAs(f.admin), 4*ceiling); code != http.StatusOK || stored() != 4*ceiling {
		t.Errorf("a platform administrator raising the limit = %d (stored %d), want 200", code, stored())
	}
	// An owner may still edit other settings, and lower the limit, while it is above the ceiling.
	if code := set(browserAs(f.owner), 0); code != http.StatusOK || stored() != 0 {
		t.Errorf("an owner resetting the limit to the deployment's = %d (stored %d), want 200", code, stored())
	}
}
