// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"encoding/json"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

func strs(values ...string) *[]string {
	list := values
	return &list
}

// trigger-prefixes and trigger-patterns drive VCS path filtering, so the request handling has to
// distinguish "attribute omitted" (leave the stored list alone) from "attribute sent as []" (clear
// it). Before #678 both were plain slices guarded by len() > 0, which made a list impossible to
// remove once set.
func TestApplyTriggerLists(t *testing.T) {
	tests := []struct {
		name         string
		workspace    models.Workspace
		prefixes     *[]string
		patterns     *[]string
		wantPrefixes string
		wantPatterns string
	}{
		{
			name:         "omitted attributes leave both lists alone",
			workspace:    models.Workspace{TriggerPrefixes: `["modules"]`},
			wantPrefixes: `["modules"]`,
		},
		{
			name:         "prefixes are stored as a JSON array",
			prefixes:     strs("modules/network", "modules/database"),
			wantPrefixes: `["modules/network","modules/database"]`,
		},
		{
			name:         "an empty array clears the stored prefixes",
			workspace:    models.Workspace{TriggerPrefixes: `["modules"]`},
			prefixes:     strs(),
			wantPrefixes: "",
		},
		{
			name:         "an empty array clears the stored patterns",
			workspace:    models.Workspace{TriggerPatterns: `["**/*.tf"]`},
			patterns:     strs(),
			wantPatterns: "",
		},
		{
			name:         "setting patterns clears stored prefixes",
			workspace:    models.Workspace{TriggerPrefixes: `["modules"]`},
			patterns:     strs("**/*.tf"),
			wantPatterns: `["**/*.tf"]`,
		},
		{
			name:         "setting prefixes clears stored patterns",
			workspace:    models.Workspace{TriggerPatterns: `["**/*.tf"]`},
			prefixes:     strs("modules"),
			wantPrefixes: `["modules"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws := tt.workspace
			applyTriggerLists(&ws, tt.prefixes, tt.patterns, nil)

			if ws.TriggerPrefixes != tt.wantPrefixes {
				t.Errorf("TriggerPrefixes = %q, want %q", ws.TriggerPrefixes, tt.wantPrefixes)
			}
			if ws.TriggerPatterns != tt.wantPatterns {
				t.Errorf("TriggerPatterns = %q, want %q", ws.TriggerPatterns, tt.wantPatterns)
			}
		})
	}
}

// The activity diff has to name every column the request actually moved, including the one cleared
// as a side effect of switching filtering modes.
func TestApplyTriggerListsRecordsChanges(t *testing.T) {
	ws := models.Workspace{TriggerPrefixes: `["modules"]`}
	changes := map[string]interface{}{}

	applyTriggerLists(&ws, nil, strs("**/*.tf"), changes)

	if _, ok := changes["trigger_patterns"]; !ok {
		t.Error("changes is missing trigger_patterns")
	}
	if _, ok := changes["trigger_prefixes"]; !ok {
		t.Error("changes is missing trigger_prefixes, which was cleared by setting patterns")
	}

	// A no-op request records nothing.
	unchanged := map[string]interface{}{}
	applyTriggerLists(&ws, nil, strs("**/*.tf"), unchanged)
	if len(unchanged) != 0 {
		t.Errorf("re-applying the same patterns recorded %v", unchanged)
	}
}

// TFE and the provider schema treat the two lists as mutually exclusive; a request that sets both
// is rejected rather than resolved by precedence.
func TestTriggerListsConflict(t *testing.T) {
	tests := []struct {
		name     string
		prefixes *[]string
		patterns *[]string
		want     bool
	}{
		{name: "neither set", want: false},
		{name: "prefixes only", prefixes: strs("modules"), want: false},
		{name: "patterns only", patterns: strs("**/*.tf"), want: false},
		{name: "both set", prefixes: strs("modules"), patterns: strs("**/*.tf"), want: true},
		{name: "one of them empty is not a conflict", prefixes: strs(), patterns: strs("**/*.tf"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := triggerListsConflict(tt.prefixes, tt.patterns); got != tt.want {
				t.Errorf("triggerListsConflict() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The stored JSON has to round-trip through the response builder, which unmarshals both columns
// back into the JSON:API payload.
func TestTriggerListsRoundTripAsJSON(t *testing.T) {
	ws := models.Workspace{}
	applyTriggerLists(&ws, strs("modules/network"), nil, nil)

	var decoded []string
	if err := json.Unmarshal([]byte(ws.TriggerPrefixes), &decoded); err != nil {
		t.Fatalf("stored prefixes are not valid JSON: %v", err)
	}
	if len(decoded) != 1 || decoded[0] != "modules/network" {
		t.Errorf("decoded prefixes = %v, want [modules/network]", decoded)
	}
}
