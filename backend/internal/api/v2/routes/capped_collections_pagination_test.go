//go:build integration
// +build integration

// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package routes_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The three collections in #761 that cap their rows must honour page[number].
//
// They are the dangerous ones. A collection the handler returns in full can state
// "one page, n of n" and be done; nothing a client does with that can go wrong. These three cap
// (100 registry providers, 100 registry modules, 50 workflow runs) and now report the true
// total, which means `total-pages` can exceed 1 - and the moment it does, a client that walks
// the pages is entitled to get different rows each time.
//
// Getting exactly this wrong is what made the inventory-sources listing return every row twice
// while never reaching the tail: correct-looking meta over paging that ignored page[number]. The
// assertion that catches it is not "page 2 returns rows" but "page 2 returns DIFFERENT rows",
// which is why each case below compares ids across two single-row pages rather than counting.
func TestCappedCollectionsHonourPageNumber(t *testing.T) {
	h := setupGoldenHarness(t)

	orgName, ok := firstCol(h.db, "organizations", "name")
	if !ok {
		t.Skip("no seeded organization to page against")
	}

	get := func(t *testing.T, path string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+h.token)
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200: %s", path, rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("GET %s returned non-JSON: %v", path, err)
		}
		return body
	}

	ids := func(t *testing.T, body map[string]any) []string {
		t.Helper()
		data, ok := body["data"].([]any)
		if !ok {
			t.Fatalf("response has no data array; keys were %v", keysOf(body))
		}
		out := make([]string, 0, len(data))
		for _, raw := range data {
			res, _ := raw.(map[string]any)
			id, _ := res["id"].(string)
			out = append(out, id)
		}
		return out
	}

	pagination := func(t *testing.T, body map[string]any) map[string]any {
		t.Helper()
		meta, ok := body["meta"].(map[string]any)
		if !ok {
			t.Fatalf("response has no meta object; keys were %v", keysOf(body))
		}
		pag, ok := meta["pagination"].(map[string]any)
		if !ok {
			t.Fatalf("meta has no pagination block; meta keys were %v", keysOf(meta))
		}
		return pag
	}

	cases := []struct {
		name  string
		table string
		path  string
	}{
		{
			name:  "registry providers",
			table: "providers",
			path:  fmt.Sprintf("/api/v2/organizations/%s/registry-providers", orgName),
		},
		{
			name:  "registry modules",
			table: "modules",
			path:  fmt.Sprintf("/api/v2/organizations/%s/registry/modules", orgName),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Scoped to the organization being listed, not the whole table: a second seeded
			// organization would otherwise make the total-count assertion below fail for a
			// reason that has nothing to do with paging.
			var seeded int64
			h.db.Table(tc.table).
				Where("organization_id = (SELECT id FROM organizations WHERE name = ?)", orgName).
				Count(&seeded)
			if seeded < 2 {
				t.Skipf("need at least 2 rows in %s for organization %s to prove paging, found %d",
					tc.table, orgName, seeded)
			}

			first := get(t, tc.path+"?page%5Bsize%5D=1&page%5Bnumber%5D=1")
			second := get(t, tc.path+"?page%5Bsize%5D=1&page%5Bnumber%5D=2")

			f, s := ids(t, first), ids(t, second)
			if len(f) != 1 {
				t.Fatalf("page[size]=1 returned %d rows, want 1 - the parameter is ignored", len(f))
			}
			if len(s) != 1 {
				t.Fatalf("page 2 returned %d rows, want 1", len(s))
			}
			if f[0] == s[0] {
				t.Errorf("page 2 returned the same row as page 1 (%s) - page[number] is ignored, "+
					"so a client walking the pages collects duplicates and never reaches the tail", f[0])
			}

			pag := pagination(t, first)
			if got, _ := pag["total-count"].(float64); int64(got) != seeded {
				t.Errorf("total-count = %v, want %d - the total must describe the whole "+
					"collection, not the page", got, seeded)
			}
			if got, _ := pag["current-page"].(float64); int(got) != 1 {
				t.Errorf("current-page = %v, want 1", got)
			}
			if got, _ := pagination(t, second)["current-page"].(float64); int(got) != 2 {
				t.Errorf("page 2 reports current-page = %v, want 2", got)
			}
		})
	}

	// page[size] must be clamped, or it becomes a way to pull a whole table in one request.
	t.Run("page[size] is capped", func(t *testing.T) {
		body := get(t, fmt.Sprintf("/api/v2/organizations/%s/registry/modules?page%%5Bsize%%5D=100000", orgName))
		if got, _ := pagination(t, body)["page-size"].(float64); int(got) > 100 {
			t.Errorf("page-size = %v; an unbounded page[size] lets one request pull the whole table", got)
		}
	})
}
