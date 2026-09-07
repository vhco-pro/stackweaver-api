// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"testing"
)

// wireShape renders a typed response value the way the wire sees it. Wire-contract tests
// assert against this rather than against Go field names, so the JSON member names - the
// part terraform-provider-tfe actually parses - stay locked after the #760 typing
// migration. It also keeps present-but-null distinguishable from absent, which struct
// field access cannot express.
func wireShape(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal wire shape: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal wire shape: %v", err)
	}
	return out
}
