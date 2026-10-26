// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The caller's platform status on GET /api/v2/account/details (#132, D4, AC32): TFE's
// is-site-admin, the Stackweaver platform-admin-declared, and TFE's
// permissions.can-create-organizations, which follows the organization-creation setting and
// changes on the next request after a grant or a revoke.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAccountPermissions

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
	"github.com/michielvha/stackweaver/core/models"
)

func TestAccountPermissions(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	details := func(t *testing.T, setting platformadmin.OrganizationCreation, u *models.User) map[string]any {
		t.Helper()
		admins := f.service(platformadmin.Config{OrganizationCreation: setting})
		h := NewAccountHandlerV2(f.authSvc, f.users, nil)
		h.SetPlatformAdmin(admins)
		router := platformAdminRouter()
		router.GET("/api/v2/account/details", h.Details)
		rec := platformAdminCall(t, router, http.MethodGet, "/api/v2/account/details", browserAs(u), "")
		if rec.Code != http.StatusOK {
			t.Fatalf("details = %d", rec.Code)
		}
		var doc struct {
			Data struct {
				Attributes map[string]any `json:"attributes"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Data.Attributes
	}
	canCreate := func(attrs map[string]any) any {
		p, _ := attrs["permissions"].(map[string]any)
		return p["can-create-organizations"]
	}

	everyone, limited := platformadmin.OrganizationCreationEveryone, platformadmin.OrganizationCreationPlatformAdmins
	for _, tt := range []struct {
		name            string
		user            *models.User
		setting         platformadmin.OrganizationCreation
		siteAdmin, decl bool
		wantCanCreate   bool
	}{
		{"plain under everyone", f.plain, everyone, false, false, true},
		{"plain under platform-admins", f.plain, limited, false, false, false},
		{"owner under platform-admins", f.owner, limited, false, false, false},
		{"granted under platform-admins", f.admin, limited, true, false, true},
		{"declared under everyone", f.declared, everyone, true, true, true},
	} {
		attrs := details(t, tt.setting, tt.user)
		if attrs["is-site-admin"] != tt.siteAdmin || attrs["platform-admin-declared"] != tt.decl || canCreate(attrs) != tt.wantCanCreate {
			t.Errorf("%s: is-site-admin %v declared %v can-create %v, want %v %v %v", tt.name,
				attrs["is-site-admin"], attrs["platform-admin-declared"], canCreate(attrs), tt.siteAdmin, tt.decl, tt.wantCanCreate)
		}
	}

	// The next request after a grant and after a revoke reflects it.
	admins := f.service(platformadmin.Config{})
	if _, err := admins.Grant(t.Context(), f.admin, f.plain.ID); err != nil {
		t.Fatal(err)
	}
	if attrs := details(t, limited, f.plain); attrs["is-site-admin"] != true || canCreate(attrs) != true {
		t.Errorf("after a grant: %v", attrs)
	}
	if _, err := admins.Revoke(t.Context(), f.admin, f.plain.ID); err != nil {
		t.Fatal(err)
	}
	if attrs := details(t, limited, f.plain); attrs["is-site-admin"] != false || canCreate(attrs) != false {
		t.Errorf("after a revoke: %v", attrs)
	}
}
