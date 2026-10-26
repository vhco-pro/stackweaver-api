// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// GET /api/v2/platform/settings (#132, D6, AC19): the deployment's platform policy, readable by
// every authenticated identity, because an ordinary user's Organizations page needs it too.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestPlatformSettings

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
	"github.com/michielvha/stackweaver/core/models"
)

func TestPlatformSettings(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	for _, setting := range []platformadmin.OrganizationCreation{platformadmin.OrganizationCreationEveryone, platformadmin.OrganizationCreationPlatformAdmins} {
		t.Run(string(setting), func(t *testing.T) {
			router := platformAdminRouter()
			h := NewPlatformSettingsHandlerV2(f.service(platformadmin.Config{OrganizationCreation: setting}), f.authSvc)
			router.GET("/api/v2/platform/settings", h.Show)
			for _, who := range []struct {
				name string
				as   identity
			}{
				{"session", browserAs(f.plain)},
				{"plain user token", identity{user: f.plain.ID, method: "api_key", tokenKind: models.APIKeyKindUser}},
				{"organization-bound key", identity{user: f.owner.ID, method: "api_key", tokenKind: models.APIKeyKindOrg, scopes: []string{"org:" + f.orgA.ID.String() + ":read"}}},
			} {
				rec := platformAdminCall(t, router, http.MethodGet, "/api/v2/platform/settings", who.as, "")
				if rec.Code != http.StatusOK {
					t.Fatalf("%s: status %d (%s)", who.name, rec.Code, rec.Body.String())
				}
				var doc struct {
					Data struct {
						ID         string         `json:"id"`
						Type       string         `json:"type"`
						Attributes map[string]any `json:"attributes"`
					} `json:"data"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
				if doc.Data.Type != "platform-settings" || doc.Data.ID != "platform" || doc.Data.Attributes["organization-creation"] != string(setting) {
					t.Errorf("%s: %s", who.name, rec.Body.String())
				}
			}
			if rec := platformAdminCall(t, router, http.MethodGet, "/api/v2/platform/settings", identity{}, ""); rec.Code != http.StatusUnauthorized {
				t.Errorf("unauthenticated: status %d, want 401", rec.Code)
			}
		})
	}
}
