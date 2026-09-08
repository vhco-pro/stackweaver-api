// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AC1 for #761: every JSON:API collection states how many rows exist and how many pages there
// are.
//
// This reads the recorded golden corpus rather than serving requests, so it needs no database
// and runs in the ordinary `go test` on every PR - which is the point. #756 converged the
// collections that already emitted a `meta.pagination` onto one six-member block, and #761
// gave the block to the 36 that emitted none. Neither is self-sustaining: the next collection
// added without one would put the corpus straight back to a mixed contract, and the failure is
// invisible from the browser because fetchAllPages silently falls back to "one page" and shows
// a subset with no error.
//
// A fixture is in scope when its response body's `data` is an array. The exceptions are named
// individually below, with the reason each is exempt, so that exempting a new one is a
// deliberate edit to this list and shows up in review.
package routes_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// paginationExempt maps an exempt route to why it is exempt. Adding an entry is a decision:
// the exemption says a client cannot learn this collection's true size from the response.
var paginationExempt = map[string]string{
	// #756, owner decision: this one keeps the offset-style block (limit/offset/total) it has
	// always emitted. It is the single deliberate survivor of the pre-#756 shape.
	"/api/v2/activities": "keeps its offset block by owner decision in #756",

	// Top-N views, not collections. Each returns "the first N" with no way to ask for more and
	// no count of the rest, so the honest six-member block would need a COUNT query that #761
	// put out of scope (its design turns on no COUNT being required). Reporting a total equal
	// to the rows returned would be a lie a client cannot detect - the failure mode that made
	// the inventory-sources bug worse than a plain truncation.
	"/api/v2/activities/recent":                      "top-N view; a true total needs a COUNT (out of scope in #761)",
	"/api/v2/organizations/:name/ansible/jobs/queue": "top-N view; a true total needs a COUNT (out of scope in #761)",
	"/api/v2/organizations/:name/runs/queue":         "top-N view; a true total needs a COUNT (out of scope in #761)",
}

// The six members NewPaginationMeta produces. go-tfe reads all of them.
var paginationMembers = []string{
	"current-page", "page-size", "prev-page", "next-page", "total-pages", "total-count",
}

func TestEveryCollectionStatesItsPagination(t *testing.T) {
	dir := filepath.Join("testdata", "golden")
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden fixtures under %s (err %v) - this test proves nothing without them", dir, err)
	}

	type fixture struct {
		Method string          `json:"method"`
		Path   string          `json:"path"`
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
	}

	var collections, missing, unusedExempt []string
	exercised := map[string]bool{}

	for _, f := range files {
		// #nosec G304 -- f comes from Glob over a fixed testdata directory, not from input
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var fx fixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			continue // errors/ subdir and any non-fixture file
		}
		if fx.Status < 200 || fx.Status >= 300 {
			continue
		}

		// The registry-protocol routes under /v1/ are HashiCorp's published spec, not ours;
		// they carry limit/current_offset/next_offset and must not be converted.
		if strings.HasPrefix(fx.Path, "/v1/") || strings.Contains(fx.Path, "/registry/v1/") {
			continue
		}

		var body map[string]json.RawMessage
		if json.Unmarshal(fx.Body, &body) != nil {
			continue
		}
		var data []json.RawMessage
		if json.Unmarshal(body["data"], &data) != nil {
			continue // `data` is a single resource or null, not a collection
		}

		collections = append(collections, fx.Path)
		if _, exempt := paginationExempt[fx.Path]; exempt {
			exercised[fx.Path] = true
			continue
		}

		var meta struct {
			Pagination map[string]json.RawMessage `json:"pagination"`
		}
		_ = json.Unmarshal(body["meta"], &meta)
		if meta.Pagination == nil {
			missing = append(missing, fx.Path+"  ("+filepath.Base(f)+")")
			continue
		}
		for _, member := range paginationMembers {
			if _, ok := meta.Pagination[member]; !ok {
				missing = append(missing, fx.Path+"  (meta.pagination is missing "+member+")")
				break
			}
		}
	}

	for path := range paginationExempt {
		if !exercised[path] {
			unusedExempt = append(unusedExempt, path)
		}
	}

	sort.Strings(missing)
	sort.Strings(unusedExempt)

	if len(collections) == 0 {
		t.Fatal("found no list-shaped fixtures at all - the corpus or this test's parsing is broken")
	}
	t.Logf("%d collection fixtures, %d exempt", len(collections), len(paginationExempt))

	if len(missing) > 0 {
		t.Errorf("%d collection(s) emit no complete meta.pagination block.\n"+
			"A client cannot learn their true size, and fetchAllPages "+
			"(frontend/src/lib/pagination.ts) falls back to one page and silently shows a "+
			"subset. Emit jsonapi.NewFullPageMeta(len(data)) when the handler returns "+
			"everything, or jsonapi.NewPaginationMeta with the real total when it does not:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}

	// A stale exemption is its own bug: it reads as "we decided this one cannot state its
	// size" long after the endpoint changed or disappeared.
	if len(unusedExempt) > 0 {
		t.Errorf("%d exemption(s) in paginationExempt match no fixture and should be removed:\n  %s",
			len(unusedExempt), strings.Join(unusedExempt, "\n  "))
	}
}
