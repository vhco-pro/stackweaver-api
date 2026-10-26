// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// GET /api/v2/admin/users is a lookup, not a directory (#132, decision 8, AC31): a call carries
// filter[admin]=true or q set to one full email address, or it answers 400; a caller who is not a
// platform administrator gets 404 for every call, including the ones that would be 400.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAdminUsersLookup

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
)

func (f *platformAdminFixture) adminUserRoutes(router *gin.Engine, admins *platformadmin.Service) {
	h := NewAdminUsersHandlerV2(f.users, admins)
	router.GET("/api/v2/admin/users", h.List)
	router.POST("/api/v2/admin/users/:id/actions/grant_admin", h.GrantAdmin)
	router.POST("/api/v2/admin/users/:id/actions/revoke_admin", h.RevokeAdmin)
}

type adminUsersDoc struct {
	Data []struct {
		ID            string         `json:"id"`
		Type          string         `json:"type"`
		Attributes    map[string]any `json:"attributes"`
		Relationships map[string]any `json:"relationships"`
	} `json:"data"`
	Meta struct {
		Pagination map[string]any `json:"pagination"`
	} `json:"meta"`
}

func decodeAdminUsers(t *testing.T, body []byte) adminUsersDoc {
	t.Helper()
	var doc adminUsersDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	return doc
}

func TestAdminUsersLookup(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	router := platformAdminRouter()
	f.adminUserRoutes(router, f.admins)
	get := func(as identity, query string) (int, []byte) {
		rec := platformAdminCall(t, router, http.MethodGet, "/api/v2/admin/users"+query, as, "")
		return rec.Code, rec.Body.Bytes()
	}

	t.Run("filter[admin]=true lists every administrator", func(t *testing.T) {
		code, body := get(browserAs(f.admin), "?filter%5Badmin%5D=true&page%5Bsize%5D=100")
		if code != http.StatusOK {
			t.Fatalf("status %d, want 200 (%s)", code, body)
		}
		doc := decodeAdminUsers(t, body)
		seen := map[string]map[string]any{}
		for _, d := range doc.Data {
			if d.Type != "users" {
				t.Errorf("type %q, want users", d.Type)
			}
			if len(d.Relationships) != 0 {
				t.Errorf("user %s carries relationships %v, want none", d.ID, d.Relationships)
			}
			if d.Attributes["is-admin"] != true {
				t.Errorf("user %s listed with is-admin %v", d.ID, d.Attributes["is-admin"])
			}
			seen[d.ID] = d.Attributes
		}
		for _, want := range []struct {
			id       string
			declared bool
		}{{f.admin.ID.String(), false}, {f.declared.ID.String(), true}} {
			attrs, ok := seen[want.id]
			if !ok {
				t.Errorf("administrator %s missing from the listing", want.id)
				continue
			}
			for _, k := range []string{"username", "email", "avatar-url", "is-admin", "is-suspended", "is-site-auditor", "is-service-account", "platform-admin-declared"} {
				if _, ok := attrs[k]; !ok {
					t.Errorf("attribute %s missing", k)
				}
			}
			if attrs["platform-admin-declared"] != want.declared || attrs["is-suspended"] != false || attrs["is-site-auditor"] != false || attrs["is-service-account"] != false {
				t.Errorf("user %s attributes %v", want.id, attrs)
			}
		}
		for _, id := range []string{f.owner.ID.String(), f.plain.ID.String()} {
			if _, ok := seen[id]; ok {
				t.Errorf("non-administrator %s listed", id)
			}
		}
		if doc.Meta.Pagination["total-count"] == nil {
			t.Errorf("no pagination meta: %s", body)
		}
	})

	t.Run("q matches one full email whatever its case", func(t *testing.T) {
		code, body := get(browserAs(f.admin), "?q="+url.QueryEscape(strings.ToUpper(f.plain.Email)))
		if code != http.StatusOK {
			t.Fatalf("status %d (%s)", code, body)
		}
		doc := decodeAdminUsers(t, body)
		if len(doc.Data) != 1 || doc.Data[0].ID != f.plain.ID.String() || doc.Data[0].Attributes["is-admin"] != false {
			t.Fatalf("q lookup = %s, want exactly the plain user", body)
		}
	})

	t.Run("q for an unknown address is an empty list", func(t *testing.T) {
		code, body := get(browserAs(f.admin), "?q="+url.QueryEscape("nobody-"+f.sfx+"@test.local"))
		if code != http.StatusOK || len(decodeAdminUsers(t, body).Data) != 0 {
			t.Fatalf("status %d body %s, want 200 and no data", code, body)
		}
	})

	t.Run("q and filter[admin]=true narrow together", func(t *testing.T) {
		_, body := get(browserAs(f.admin), "?filter%5Badmin%5D=true&q="+url.QueryEscape(f.plain.Email))
		if n := len(decodeAdminUsers(t, body).Data); n != 0 {
			t.Errorf("a non-administrator matched filter[admin]=true (%d rows)", n)
		}
		_, body = get(browserAs(f.admin), "?filter%5Badmin%5D=true&q="+url.QueryEscape(f.declared.Email))
		if n := len(decodeAdminUsers(t, body).Data); n != 1 {
			t.Errorf("the declared administrator did not match (%d rows)", n)
		}
	})

	refused := []string{
		"",
		"?filter%5Badmin%5D=false",
		"?q=platadm",
		"?q=" + url.QueryEscape("platadm-plain-"+f.sfx+"@"),
		"?q=" + url.QueryEscape("@test.local"),
		"?filter%5Bsuspended%5D=true",
		"?filter%5Badmin%5D=true&filter%5Bsuspended%5D=false",
	}
	t.Run("any other call is 400", func(t *testing.T) {
		for _, q := range refused {
			code, body := get(browserAs(f.admin), q)
			if code != http.StatusBadRequest {
				t.Errorf("GET /admin/users%s = %d, want 400 (%s)", q, code, body)
				continue
			}
			if !strings.Contains(string(body), "set filter[admin]=true or q to one full email address") {
				t.Errorf("GET /admin/users%s: detail %s", q, body)
			}
		}
	})

	t.Run("a non-administrator gets 404 for every call", func(t *testing.T) {
		calls := append([]string{"?filter%5Badmin%5D=true", "?q=" + url.QueryEscape(f.plain.Email)}, refused...)
		for _, who := range []struct {
			name string
			as   identity
		}{{"owner of every organization", browserAs(f.owner)}, {"member", browserAs(f.member)}, {"plain", browserAs(f.plain)}} {
			for _, q := range calls {
				if code, body := get(who.as, q); code != http.StatusNotFound {
					t.Errorf("%s: GET /admin/users%s = %d, want 404 (%s)", who.name, q, code, body)
				}
			}
		}
	})
}
