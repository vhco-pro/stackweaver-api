// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The platform admin token (#132, D5, AC12): POST /api/v2/tokens with platform_admin: true mints
// a user token whose scopes are exactly ["platform:admin"], for a signed-in platform
// administrator only; the listing marks such tokens; an API token gets 403 from InteractiveOnly.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestTokensPlatformAdmin

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestTokensPlatformAdmin(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	keys := apikey.NewService(repository.NewAPIKeyRepository(f.db), repository.NewOrganizationRepository(f.db),
		repository.NewProjectRepository(f.db), repository.NewTeamRepository(f.db))
	h := NewTokenHandlerV2(keys, f.authSvc)
	h.SetPlatformAdmin(f.admins)
	router := platformAdminRouter()
	g := router.Group("/api/v2/tokens", middleware.InteractiveOnly())
	g.GET("", h.List)
	g.POST("", h.Create)

	mint := func(as identity, platformAdmin *bool) (int, map[string]any, string) {
		attrs := `"description":"platadm-token"`
		if platformAdmin != nil {
			if *platformAdmin {
				attrs += `,"platform_admin":true`
			} else {
				attrs += `,"platform_admin":false`
			}
		}
		rec := platformAdminCall(t, router, http.MethodPost, "/api/v2/tokens", as, `{"data":{"type":"tokens","attributes":{`+attrs+`}}}`)
		var doc struct {
			Data struct {
				ID         string         `json:"id"`
				Attributes map[string]any `json:"attributes"`
			} `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &doc)
		return rec.Code, doc.Data.Attributes, doc.Data.ID
	}
	stored := func(id string) []string {
		var k models.APIKey
		if err := f.db.First(&k, "id = ?", id).Error; err != nil {
			t.Fatalf("read minted token %s: %v", id, err)
		}
		return []string(k.Scopes)
	}
	yes, no := true, false

	code, attrs, id := mint(jwtAs(f.admin), &yes)
	if code != http.StatusCreated || attrs["platform_admin"] != true {
		t.Fatalf("holder mint = %d %v, want 201 with platform_admin true", code, attrs)
	}
	if got := stored(id); !slices.Equal(got, []string{"platform:admin"}) {
		t.Errorf("minted scopes %v, want exactly [platform:admin]", got)
	}
	platformID := id

	code, attrs, id = mint(jwtAs(f.admin), &no)
	if code != http.StatusCreated || attrs["platform_admin"] != false || len(stored(id)) != 0 {
		t.Errorf("holder plain mint = %d %v scopes %v, want 201, false, none", code, attrs, stored(id))
	}
	plainID := id
	if code, _, _ := mint(jwtAs(f.admin), nil); code != http.StatusCreated {
		t.Errorf("mint without the attribute = %d, want 201", code)
	}

	if code, _, _ := mint(jwtAs(f.owner), &yes); code != http.StatusForbidden {
		t.Errorf("non-holder platform mint = %d, want 403", code)
	}
	for _, kind := range []string{models.APIKeyKindUser, models.APIKeyKindOrg} {
		if code, _, _ := mint(identity{user: f.admin.ID, method: "api_key", tokenKind: kind, scopes: []string{"platform:admin"}}, &yes); code != http.StatusForbidden {
			t.Errorf("%s token caller = %d, want 403 from InteractiveOnly", kind, code)
		}
	}

	rec := platformAdminCall(t, router, http.MethodGet, "/api/v2/tokens", jwtAs(f.admin), "")
	var list struct {
		Data []struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	marks := map[string]any{}
	for _, d := range list.Data {
		marks[d.ID] = d.Attributes["platform_admin"]
	}
	if marks[platformID] != true || marks[plainID] != false {
		t.Errorf("listing marks %v, want %s true and %s false", marks, platformID, plainID)
	}
}
