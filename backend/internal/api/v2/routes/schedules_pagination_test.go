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

// AC2 for #761: the Ansible schedules listing must honour page[number]/page[size] and answer in
// the JSON:API envelope.
//
// Both halves are load-bearing, and each was independently broken:
//
//   - The handler read `limit`/`offset` while every client sends `page[number]`/`page[size]`
//     (frontend/src/api/ansible.ts builds the latter for every Ansible route), so the requested
//     size was discarded and the handler's own default of 20 applied instead.
//   - It replied through response.Paginated, whose envelope is a top-level
//     {data,total,limit,offset,has_more} with no `meta` at all. fetchAllPages
//     (frontend/src/lib/pagination.ts) reads meta.pagination.total-pages, so it fell back to
//     "one page" and never requested the second - capping the Schedules screen at 20 rows with
//     no error and nothing in the console.
//
// Asking for one row out of a collection known to hold more proves both: a single row comes back
// (the parameter was honoured) and the true total is reported (the envelope carries it).
func TestSchedulesListHonoursJSONAPIPagination(t *testing.T) {
	h := setupGoldenHarness(t)

	orgName, ok := firstCol(h.db, "organizations", "name")
	if !ok {
		t.Skip("no seeded organization to page against")
	}

	var seeded int64
	h.db.Table("ansible_schedules").Count(&seeded)
	if seeded < 2 {
		t.Skipf("need at least 2 seeded schedules to prove paging, found %d", seeded)
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

	base := fmt.Sprintf("/api/v2/organizations/%s/ansible/schedules", orgName)

	t.Run("page[size] is honoured", func(t *testing.T) {
		body := get(t, base+"?page%5Bsize%5D=1&page%5Bnumber%5D=1")
		data, _ := body["data"].([]any)
		if len(data) != 1 {
			t.Errorf("page[size]=1 returned %d rows, want exactly 1 - the handler is ignoring the parameter", len(data))
		}
	})

	t.Run("the envelope is JSON:API, not the legacy paginated shape", func(t *testing.T) {
		body := get(t, base)

		// The legacy response.Paginated envelope put these at the top level. Their presence
		// means the handler still answers in a shape fetchAllPages cannot read.
		for _, legacy := range []string{"total", "limit", "offset", "has_more"} {
			if _, present := body[legacy]; present {
				t.Errorf("response carries top-level %q - still the response.Paginated envelope", legacy)
			}
		}

		meta, ok := body["meta"].(map[string]any)
		if !ok {
			t.Fatalf("response has no meta object; keys were %v", keysOf(body))
		}
		pag, ok := meta["pagination"].(map[string]any)
		if !ok {
			t.Fatalf("meta has no pagination block; meta keys were %v", keysOf(meta))
		}
		for _, member := range []string{
			"current-page", "page-size", "prev-page", "next-page", "total-pages", "total-count",
		} {
			if _, present := pag[member]; !present {
				t.Errorf("meta.pagination is missing %q", member)
			}
		}
	})

	t.Run("total-count reports the whole collection, not the page", func(t *testing.T) {
		body := get(t, base+"?page%5Bsize%5D=1&page%5Bnumber%5D=1")
		meta, ok := body["meta"].(map[string]any)
		if !ok {
			t.Fatalf("response has no meta object; keys were %v", keysOf(body))
		}
		pag, ok := meta["pagination"].(map[string]any)
		if !ok {
			t.Fatalf("meta has no pagination block; meta keys were %v", keysOf(meta))
		}
		total, _ := pag["total-count"].(float64)
		if int64(total) != seeded {
			t.Errorf("total-count = %v, want %d (the full collection, not the page)", total, seeded)
		}
		if pages, _ := pag["total-pages"].(float64); int64(pages) != seeded {
			t.Errorf("total-pages = %v, want %d at page[size]=1", pages, seeded)
		}
	})
}
