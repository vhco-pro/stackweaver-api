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

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// The inventory sources listing must page by page[number]/page[size].
//
// This one fails differently from the schedules listing, and worse. That handler answered in the
// legacy envelope, so fetchAllPages (frontend/src/lib/pagination.ts) could not find
// meta.pagination at all, fell back to "one page" and simply stopped after 20 rows. This handler
// already emits correct meta - it just reads `limit`/`offset` while every client sends
// `page[number]`/`page[size]` (pageQuery in frontend/src/api/ansible.ts). So the meta truthfully
// says total-pages is 2, fetchAllPages duly asks for page 2, and the handler applies its own
// default offset of 0 and serves the FIRST page again:
//
//	21 sources -> page 1 = rows 1-20, page 2 = rows 1-20 again
//	           -> the Sources tab lists 40 entries, every one of them a duplicate,
//	              and source 21 is not among them.
//
// Asking for one row per page and comparing the two pages' ids is the whole proof: distinct ids
// mean page[number] moved the window, identical ids mean it did not.
func TestInventorySourcesListHonoursJSONAPIPagination(t *testing.T) {
	h := setupGoldenHarness(t)

	inventoryID, ok := firstCol(h.db, "ansible_inventories", "id")
	if !ok {
		t.Skip("no seeded ansible inventory to page against")
	}
	invUUID, err := uuid.Parse(inventoryID)
	if err != nil {
		t.Fatalf("seeded inventory id %q is not a uuid: %v", inventoryID, err)
	}

	// The seed gives an inventory at most one source, which cannot demonstrate paging. Add
	// enough to make a second page exist. The harness runs against a throwaway database that is
	// dropped in t.Cleanup, so these rows never touch a real one.
	var before int64
	h.db.Model(&models.AnsibleInventorySource{}).Where("inventory_id = ?", invUUID).Count(&before)
	for i := 1; i <= 3; i++ {
		src := models.AnsibleInventorySource{
			InventoryID: invUUID,
			Name:        fmt.Sprintf("zz-paging-probe-%02d", i),
			Type:        models.InventorySourceTypeCustom,
		}
		if err := h.db.Create(&src).Error; err != nil {
			t.Fatalf("seed inventory source %d: %v", i, err)
		}
	}
	total := before + 3

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

	// ids returns the resource ids of one page, so two pages can be compared directly.
	ids := func(t *testing.T, body map[string]any) []string {
		t.Helper()
		data, ok := body["data"].([]any)
		if !ok {
			t.Fatalf("response has no data array; keys were %v", keysOf(body))
		}
		out := make([]string, 0, len(data))
		for _, raw := range data {
			res, ok := raw.(map[string]any)
			if !ok {
				t.Fatalf("data member is not an object: %T", raw)
			}
			id, _ := res["id"].(string)
			out = append(out, id)
		}
		return out
	}

	base := fmt.Sprintf("/api/v2/ansible/inventories/%s/sources", inventoryID)

	t.Run("page[size] is honoured", func(t *testing.T) {
		got := ids(t, get(t, base+"?page%5Bsize%5D=1&page%5Bnumber%5D=1"))
		if len(got) != 1 {
			t.Errorf("page[size]=1 returned %d rows, want exactly 1 - the handler is ignoring the parameter", len(got))
		}
	})

	t.Run("page[number] moves the window instead of repeating page one", func(t *testing.T) {
		first := ids(t, get(t, base+"?page%5Bsize%5D=1&page%5Bnumber%5D=1"))
		second := ids(t, get(t, base+"?page%5Bsize%5D=1&page%5Bnumber%5D=2"))
		if len(first) == 0 || len(second) == 0 {
			t.Fatalf("expected a row on each of the first two pages, got %d and %d", len(first), len(second))
		}
		if first[0] == second[0] {
			t.Errorf("page 2 returned the same row as page 1 (%s) - page[number] is ignored, so a "+
				"client walking the pages collects duplicates and never reaches the tail", first[0])
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
		if got, _ := pag["total-count"].(float64); int64(got) != total {
			t.Errorf("total-count = %v, want %d (the full collection, not the page)", got, total)
		}
		if got, _ := pag["current-page"].(float64); int(got) != 1 {
			t.Errorf("current-page = %v, want 1", got)
		}
		if got, _ := pag["page-size"].(float64); int(got) != 1 {
			t.Errorf("page-size = %v, want 1 (the size the client asked for)", got)
		}
	})
}
