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
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// The inventory sync history must page by page[number]/page[size].
//
// This was the last endpoint carrying the combination #761 showed to be the most dangerous one:
// a correct six-member meta block, including a true total, over paging that read limit/offset.
// A true total means total-pages can exceed 1, so a client is invited to request page 2 - and
// the offset it sends was never read, so it got page 1 back. That is the inventory-sources bug
// that rendered every row twice.
//
// It never bit in production because the single caller sent ?limit=50 and never paged. That is
// not a safety property, it is a coincidence about today's only consumer, which is why this is
// pinned rather than left alone.
func TestInventorySyncsListHonoursJSONAPIPagination(t *testing.T) {
	h := setupGoldenHarness(t)

	inventoryID, ok := firstCol(h.db, "ansible_inventories", "id")
	if !ok {
		t.Skip("no seeded ansible inventory to page against")
	}
	invUUID, err := uuid.Parse(inventoryID)
	if err != nil {
		t.Fatalf("seeded inventory id %q is not a uuid: %v", inventoryID, err)
	}

	// The harness database is created and dropped per test, so seeding here touches nothing real.
	var before int64
	h.db.Model(&models.AnsibleInventorySync{}).Where("inventory_id = ?", invUUID).Count(&before)
	for i := 1; i <= 3; i++ {
		started := time.Now().Add(-time.Duration(i) * time.Minute)
		sync := models.AnsibleInventorySync{
			InventoryID: invUUID,
			Status:      models.InventorySyncStatusSuccessful,
			TriggeredBy: "manual",
			StartedAt:   &started,
		}
		if err := h.db.Create(&sync).Error; err != nil {
			t.Fatalf("seed inventory sync %d: %v", i, err)
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

	base := fmt.Sprintf("/api/v2/ansible/inventories/%s/syncs", inventoryID)

	t.Run("page[number] moves the window instead of repeating page one", func(t *testing.T) {
		first := ids(t, get(t, base+"?page%5Bsize%5D=1&page%5Bnumber%5D=1"))
		second := ids(t, get(t, base+"?page%5Bsize%5D=1&page%5Bnumber%5D=2"))
		if len(first) != 1 || len(second) != 1 {
			t.Fatalf("expected one row per page, got %d and %d", len(first), len(second))
		}
		if first[0] == second[0] {
			t.Errorf("page 2 returned the same row as page 1 (%s) - page[number] is ignored, so a "+
				"client walking the pages collects duplicates and never reaches the tail", first[0])
		}
	})

	t.Run("total-count describes the whole collection", func(t *testing.T) {
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
			t.Errorf("total-count = %v, want %d", got, total)
		}
	})

	// PageParams falls back to the handler default rather than passing 0 through. An unclamped
	// parser sends LIMIT 0, which answers every page with zero rows while still advertising
	// total-pages - a client paging that never terminates on data it can see.
	t.Run("a zero page[size] falls back to the default rather than returning nothing", func(t *testing.T) {
		body := get(t, base+"?page%5Bsize%5D=0")
		if rows := ids(t, body); len(rows) == 0 && total > 0 {
			t.Errorf("page[size]=0 returned no rows out of %d - the parameter is passed straight "+
				"through to LIMIT instead of falling back to the default", total)
		}
	})
}
