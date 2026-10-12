// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"errors"
	"testing"
)

// TestExtraVarsColumn pins what the `extra-vars` attribute of a workflow or a workflow node may
// hold (#899): a JSON object, or the empty string for none. The handler tests in
// workflow_validation_test.go show the same rule through the API; this one runs without a
// database.
func TestExtraVarsColumn(t *testing.T) {
	tests := []struct {
		name    string
		attr    string
		want    string
		wantErr bool
	}{
		{name: "the empty string is the empty object", attr: "", want: "{}"},
		{name: "the empty object", attr: "{}", want: "{}"},
		{name: "an object is stored as sent", attr: `{"region": "eu", "hosts": ["a", "b"]}`, want: `{"region": "eu", "hosts": ["a", "b"]}`},
		{name: "an object with surrounding space", attr: " {\"a\":1}\n", want: " {\"a\":1}\n"},
		{name: "a nested object", attr: `{"a":{"b":null}}`, want: `{"a":{"b":null}}`},
		{name: "text that is not JSON", attr: "region: eu", wantErr: true},
		{name: "a truncated object", attr: `{"region":`, wantErr: true},
		{name: "a list", attr: `["eu","us"]`, wantErr: true},
		{name: "a list of objects", attr: `[{"a":1}]`, wantErr: true},
		{name: "a string", attr: `"eu"`, wantErr: true},
		{name: "a number", attr: `42`, wantErr: true},
		{name: "a boolean", attr: `true`, wantErr: true},
		{name: "null", attr: `null`, wantErr: true},
		{name: "only spaces", attr: "   ", wantErr: true},
		{name: "an object followed by more", attr: `{"a":1} {"b":2}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extraVarsColumn(tt.attr)
			if tt.wantErr {
				if !errors.Is(err, errExtraVarsNotObject) {
					t.Fatalf("extraVarsColumn(%q) error = %v, want errExtraVarsNotObject", tt.attr, err)
				}
				if got != nil {
					t.Errorf("extraVarsColumn(%q) = %s alongside an error, want nothing", tt.attr, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("extraVarsColumn(%q) error = %v, want none", tt.attr, err)
			}
			if string(got) != tt.want {
				t.Errorf("extraVarsColumn(%q) = %s, want %s", tt.attr, got, tt.want)
			}
		})
	}
}
