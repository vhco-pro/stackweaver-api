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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// paginationExempt maps an exempt route to why it is exempt. Adding an entry is a decision:
// the exemption says a client cannot learn this collection's true size from the response.
var paginationExempt = map[string]string{
	// Empty by owner decision (#858, Q4): the activities offset block, the last survivor of the
	// pre-#756 shapes, converged on page[number] and page[size]. An entry here is a decision that
	// a client cannot learn this collection's true size from the response.
}

// The six members NewPaginationMeta produces. go-tfe reads all of them.
var paginationMembers = []string{
	"current-page", "page-size", "prev-page", "next-page", "total-pages", "total-count",
}

func TestEveryCollectionStatesItsPagination(t *testing.T) {
	problems := collectionCensus(t, filepath.Join("testdata", "golden"), paginationExempt)
	if len(problems) > 0 {
		t.Errorf("%d problem(s) in the collection census:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
}

const censusGuideline = "docs/internal/guidelines/api/json-api-everywhere.md"

// collectionCensus reads every recorded 2xx fixture in dir whose data is an array and reports
// what breaks the collection rule: a missing or incomplete meta.pagination block, an element
// that is not a resource object with type and id, and a stale exemption in either list.
func collectionCensus(t *testing.T, dir string, exempt map[string]string) []string {
	t.Helper()
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

	var collections, missing, badElements, unusedExempt []string
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

		// Every element is a resource object (#858, D1): an object with a type and an id, not
		// a bare string or a database row.
		for i, el := range data {
			var res struct {
				Type *string `json:"type"`
				ID   *string `json:"id"`
			}
			if json.Unmarshal(el, &res) == nil && res.Type != nil && res.ID != nil {
				continue
			}
			badElements = append(badElements, fmt.Sprintf("%s %s: data[%d] is not a resource object with type and id  (%s)",
				fx.Method, fx.Path, i, filepath.Base(f)))
			break
		}

		if _, isExempt := exempt[fx.Path]; isExempt {
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

	for path := range exempt {
		if !exercised[path] {
			unusedExempt = append(unusedExempt, path)
		}
	}

	if len(collections) == 0 {
		t.Fatal("found no list-shaped fixtures at all - the corpus or this test's parsing is broken")
	}
	t.Logf("%d collection fixtures, %d exempt", len(collections), len(exempt))

	var problems []string
	if len(missing) > 0 {
		sort.Strings(missing)
		problems = append(problems, fmt.Sprintf("%d collection(s) emit no complete meta.pagination block. "+
			"A client cannot learn their true size, and fetchAllPages "+
			"(frontend/src/lib/pagination.ts) falls back to one page and silently shows a "+
			"subset. Emit jsonapi.NewFullPageMeta(len(data)) when the handler returns "+
			"everything, jsonapi.NewPaginationMeta with the real total when it does not, or "+
			"jsonapi.NewProviderPageMeta for a provider page with no total (%s):\n    %s",
			len(missing), censusGuideline, strings.Join(missing, "\n    ")))
	}
	sort.Strings(badElements)
	for _, b := range badElements {
		problems = append(problems, b+"; a collection holds resource objects, see "+censusGuideline)
	}
	// A stale exemption is its own bug: it reads as "we decided this one cannot state its
	// size" long after the endpoint changed or disappeared.
	if len(unusedExempt) > 0 {
		sort.Strings(unusedExempt)
		problems = append(problems, fmt.Sprintf("%d exemption(s) match no fixture that needs one and should be removed (%s):\n    %s",
			len(unusedExempt), censusGuideline, strings.Join(unusedExempt, "\n    ")))
	}
	return problems
}

// TestCollectionCensusRefusesNonResourceElements drives the census over synthetic fixtures, so
// the element check is proven to fail where it must (#858, D12 Guard 2): a collection holds
// resource objects, never bare strings or rows without a type and an id.
func TestCollectionCensusRefusesNonResourceElements(t *testing.T) {
	block := `"meta": {"pagination": {"current-page": 1, "page-size": 2, "prev-page": null, "next-page": null, "total-pages": 1, "total-count": 2}}`
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"strings under data", `{"data": ["TF_VAR_a", "TF_VAR_b"], ` + block + `}`, "GET /api/v2/widgets: data[0] is not a resource object with type and id"},
		{"a bare row", `{"data": [{"name": "row", "created_at": "x"}], ` + block + `}`, "GET /api/v2/widgets: data[0] is not a resource object with type and id"},
		{"resources", `{"data": [{"type": "widgets", "id": "1"}, {"type": "widgets", "id": "2"}], ` + block + `}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			fx := `{"method": "GET", "path": "/api/v2/widgets", "status": 200, "body": ` + tt.body + `}`
			if err := os.WriteFile(filepath.Join(dir, "get_api_v2_widgets.json"), []byte(fx), 0o600); err != nil {
				t.Fatal(err)
			}
			problems := collectionCensus(t, dir, map[string]string{})
			if tt.wantErr == "" {
				if len(problems) != 0 {
					t.Errorf("want no problem, got %q", problems)
				}
				return
			}
			if len(problems) != 1 || !strings.Contains(problems[0], tt.wantErr) {
				t.Fatalf("want one problem containing %q, got %q", tt.wantErr, problems)
			}
			if !strings.Contains(problems[0], "docs/internal/guidelines/api/json-api-everywhere.md") {
				t.Errorf("the problem does not name the guideline: %q", problems[0])
			}
		})
	}
}
