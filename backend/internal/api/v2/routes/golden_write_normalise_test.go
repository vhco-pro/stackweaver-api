// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package routes_test

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestNormaliseRequest pins what happens to a recorded request before it is committed and
// published as an example (#869, AC2).
//
// A request cannot go through normalise, the function the response fixtures use. normalise sorts
// every array, which is right for a collection the API returns in no defined order and wrong for
// a list a client sends: `input-inventory-ids` and a credential list are ordered input, and an
// example that reorders them documents a different request from the one the server accepted.
// What a request does share with a response is the values that differ on every reseed.
func TestNormaliseRequest(t *testing.T) {
	var in any
	raw := `{
		"data": {
			"type": "inventories",
			"id": "0b6f1c1e-2c1a-4f5e-9d53-7a1b2c3d4e5f",
			"attributes": {
				"name": "constructed",
				"input-inventory-ids": ["ffffffff-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000001"],
				"tags": ["zeta", "alpha"],
				"starts-at": "2026-09-01T12:00:00Z",
				"retries": 3,
				"enabled": false,
				"note": null
			},
			"relationships": {
				"workspace": {"data": {"type": "workspaces", "id": "ws-AbCdEfGhIjKlMnOp"}}
			}
		}
	}`
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}

	var want any
	wantRaw := `{
		"data": {
			"type": "inventories",
			"id": "<uuid>",
			"attributes": {
				"name": "constructed",
				"input-inventory-ids": ["<uuid>", "<uuid>"],
				"tags": ["zeta", "alpha"],
				"starts-at": "<timestamp>",
				"retries": 3,
				"enabled": false,
				"note": null
			},
			"relationships": {
				"workspace": {"data": {"type": "workspaces", "id": "<id>"}}
			}
		}
	}`
	if err := json.Unmarshal([]byte(wantRaw), &want); err != nil {
		t.Fatal(err)
	}

	got := normaliseRequest(in)
	if !reflect.DeepEqual(got, want) {
		g, _ := json.MarshalIndent(got, "", "  ")
		t.Fatalf("normaliseRequest changed more, or less, than identifiers and timestamps:\n%s", g)
	}

	// The order of an array is input. "tags" above is deliberately not in sorted order.
	tags := got.(map[string]any)["data"].(map[string]any)["attributes"].(map[string]any)["tags"].([]any)
	if tags[0] != "zeta" || tags[1] != "alpha" {
		t.Fatalf("array order was not kept: %v", tags)
	}

	// And the response normaliser is left exactly as it was: it still sorts.
	sorted := normalise(in).(map[string]any)["data"].(map[string]any)["attributes"].(map[string]any)["tags"].([]any)
	if sorted[0] != "alpha" || sorted[1] != "zeta" {
		t.Fatalf("normalise no longer sorts arrays, which the read fixtures depend on: %v", sorted)
	}
}
