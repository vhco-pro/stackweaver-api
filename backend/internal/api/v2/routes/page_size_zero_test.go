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

// #774: `page[size]=0` must fall back to the handler's default, not reach the query as LIMIT 0.
//
// Every hand-rolled page parser in the tree clamped page[size] from above and not from below, so
// a zero went straight through to the database. The response that came back was internally
// contradictory: zero rows in `data`, while `meta.pagination` reported a non-zero `total-count`
// and one page. A client is told the collection is non-empty and handed nothing, with no error -
// fetchAllPages returns `{items: [], total: N}` and the screen renders empty under a count that
// says otherwise.
//
// Measured before the fix against /ansible/inventories/:id/groups on an inventory holding one
// group: `page[size]=0` returned 0 rows with `page-size: 1, total-count: 1, total-pages: 1`.
//
// The endpoints below are sampled across the packages the sweep touched (ansible, terraform,
// top-level handlers) rather than exhaustively, because they now share one parser: the point is
// that the shared parser behaves, not that twenty call sites each re-derive it. Any endpoint
// whose collection is empty on this seed is skipped rather than silently passing - "zero rows
// came back" is the failure being tested for, so it cannot also be the reason to pass.
func TestZeroPageSizeFallsBackToTheDefault(t *testing.T) {
	h := setupGoldenHarness(t)

	orgName, ok := firstCol(h.db, "organizations", "name")
	if !ok {
		t.Skip("no seeded organization")
	}
	inventoryID, hasInventory := firstCol(h.db, "ansible_inventories", "id")

	get := func(t *testing.T, path string) (rows int, pagination map[string]any, status int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+h.token)
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			return 0, nil, rec.Code
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("GET %s returned non-JSON: %v", path, err)
		}
		data, _ := body["data"].([]any)
		meta, _ := body["meta"].(map[string]any)
		pag, _ := meta["pagination"].(map[string]any)
		return len(data), pag, rec.Code
	}

	cases := []struct {
		name string
		path string
		skip bool
	}{
		{"ansible inventory groups", fmt.Sprintf("/api/v2/ansible/inventories/%s/groups", inventoryID), !hasInventory},
		{"ansible inventory hosts", fmt.Sprintf("/api/v2/ansible/inventories/%s/hosts", inventoryID), !hasInventory},
		{"ansible inventories", fmt.Sprintf("/api/v2/organizations/%s/ansible/inventories", orgName), false},
		{"ansible jobs", fmt.Sprintf("/api/v2/organizations/%s/ansible/jobs", orgName), false},
		{"organization teams", fmt.Sprintf("/api/v2/organizations/%s/teams", orgName), false},
		{"workspaces", fmt.Sprintf("/api/v2/organizations/%s/workspaces", orgName), false},
	}

	ran := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip {
				t.Skip("no seeded parent resource")
			}

			// Establish the collection is non-empty, so an empty page[size]=0 response is
			// unambiguously the defect rather than an empty collection.
			baseline, _, status := get(t, tc.path)
			if status != http.StatusOK {
				t.Skipf("GET %s returned %d on this seed", tc.path, status)
			}
			if baseline == 0 {
				t.Skipf("collection is empty on this seed, so it cannot demonstrate the defect")
			}

			rows, pag, _ := get(t, tc.path+"?page%5Bsize%5D=0")
			if rows == 0 {
				t.Errorf("page[size]=0 returned no rows out of %d, while meta reported %v - the "+
					"parameter reached the query as LIMIT 0 instead of falling back to the default",
					baseline, pag)
			}
			ran++
		})
	}

	if ran == 0 {
		t.Skip("no endpoint on this seed had a non-empty collection; nothing was proven")
	}
}
