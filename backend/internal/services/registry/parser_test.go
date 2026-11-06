// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

func TestModuleParserInputMetadataFidelity(t *testing.T) {
	tests := []struct {
		name              string
		typeExpression    string
		defaultExpression string
		wantType          string
		wantDefault       string
	}{
		{"empty list", "list(string)", "[]", "list(string)", "[]"},
		{"empty set", "set(string)", "[]", "set(string)", "[]"},
		{"empty tuple", "tuple([])", "[]", "tuple([])", "[]"},
		{"nested empty list", "list(list(string))", "[[]]", "list(list(string))", "[[]]"},
		{"object with empty list", "object({ items = list(string) })", "{ items = [] }", "object({ items = list(string) })", `{"items":[]}`},
		{"map with empty list", "map(list(string))", "{ items = [] }", "map(list(string))", `{"items":[]}`},
		{"tuple", "tuple([string, number])", `["a", 1]`, "tuple([string, number])", `["a",1]`},
		{"nested tuple", "list(tuple([string, number]))", `[["a", 1]]`, "list(tuple([string, number]))", `[["a",1]]`},
		{"object with tuple", "object({ pair = tuple([string, bool]) })", `{ pair = ["a", true] }`, "object({ pair = tuple([string, bool]) })", `{"pair":["a",true]}`},
		{"explicit null", "list(string)", "null", "list(string)", "null"},
		{"populated list", "list(string)", `["a", "b"]`, "list(string)", `["a","b"]`},
		{"populated set", "set(number)", "[1, 2]", "set(number)", "[1,2]"},
		{"populated map", "map(string)", `{ name = "demo" }`, "map(string)", `{"name":"demo"}`},
		{"empty object", "object({})", "{}", "object({})", "{}"},
		{"populated object", "object({ enabled = bool })", "{ enabled = true }", "object({ enabled = bool })", `{"enabled":true}`},
		{"optional attribute", "object({ name = optional(string) })", `{ name = "demo" }`, "object({ name = optional(string) })", `{"name":"demo"}`},
		{"string", "string", `"demo"`, "string", `"demo"`},
		{"number", "number", "1.5", "number", "1.5"},
		{"boolean", "bool", "false", "bool", "false"},
		{"required list", "list(string)", "", "list(string)", "null"},
		{"required tuple", "tuple([string, number])", "", "tuple([string, number])", "null"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			source := fmt.Sprintf("variable \"value\" {\n  type = %s\n", tt.typeExpression)
			if tt.defaultExpression != "" {
				source += fmt.Sprintf("  default = %s\n", tt.defaultExpression)
			}
			source += "}\n"
			path := filepath.Join(dir, "variables.tf")
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			validateModuleInputFixture(t, path)

			metadata, err := NewModuleParser().ParseModule(dir)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(metadata.ConvertToJSONB())
			if err != nil {
				t.Fatal(err)
			}
			var stored struct {
				Inputs []struct {
					Name     string          `json:"name"`
					Type     string          `json:"type"`
					Default  json.RawMessage `json:"default"`
					Required bool            `json:"required"`
				} `json:"inputs"`
			}
			if err := json.Unmarshal(encoded, &stored); err != nil {
				t.Fatal(err)
			}
			if len(stored.Inputs) != 1 {
				t.Fatalf("stored input count = %d, want 1; JSON: %s", len(stored.Inputs), encoded)
			}
			input := stored.Inputs[0]
			if input.Name != "value" {
				t.Errorf("stored name = %q, want value", input.Name)
			}
			if input.Type != tt.wantType {
				t.Errorf("stored type = %q, want %q; JSON: %s", input.Type, tt.wantType, encoded)
			}
			if string(input.Default) != tt.wantDefault {
				t.Errorf("stored default = %s, want %s; JSON: %s", input.Default, tt.wantDefault, encoded)
			}
			if wantRequired := tt.defaultExpression == ""; input.Required != wantRequired {
				t.Errorf("stored required = %t, want %t", input.Required, wantRequired)
			}
		})
	}
}

// Check that fixtures describe valid HCL constraints with compatible defaults.
func validateModuleInputFixture(t *testing.T, path string) {
	t.Helper()
	file, diags := hclparse.NewParser().ParseHCLFile(path)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	block := file.Body.(*hclsyntax.Body).Blocks[0]
	ty, diags := typeexpr.TypeConstraint(block.Body.Attributes["type"].Expr)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	if attr, ok := block.Body.Attributes["default"]; ok {
		value, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			t.Fatal(diags.Error())
		}
		if _, err := convert.Convert(value, ty); err != nil {
			t.Fatalf("fixture default is incompatible with its type: %v", err)
		}
	}
}

func TestModuleParserEmptyTypedCollections(t *testing.T) {
	tests := []struct {
		name  string
		value cty.Value
	}{
		{"list", cty.ListValEmpty(cty.String)},
		{"set", cty.SetValEmpty(cty.String)},
		{"tuple", cty.EmptyTupleVal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := json.Marshal(NewModuleParser().ctyValueToInterface(tt.value))
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != "[]" {
				t.Errorf("empty %s JSON = %s, want []", tt.name, encoded)
			}
		})
	}
}

func TestModuleParserSubmodules(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]string
		wantPaths []string
	}{
		{
			name: "directory suffix only",
			files: map[string]string{
				filepath.Join("modules", "data", "assets.tf", "README.md"): "# Supporting assets\n",
			},
		},
		{
			name: "real source file",
			files: map[string]string{
				filepath.Join("modules", "real", "real.tf"): "output \"example\" { value = \"real\" }\n",
			},
			wantPaths: []string{filepath.Join("modules", "real")},
		},
		{
			name: "nested source inside suffix directory",
			files: map[string]string{
				filepath.Join("modules", "group", "assets.tf", "main.tf"): "output \"example\" { value = \"nested\" }\n",
			},
			wantPaths: []string{filepath.Join("modules", "group", "assets.tf")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.files["main.tf"] = "output \"root\" { value = \"root\" }\n"
			for name, source := range tt.files {
				path := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
				if filepath.Ext(path) == ".tf" {
					if _, diags := hclparse.NewParser().ParseHCLFile(path); diags.HasErrors() {
						t.Fatal(diags.Error())
					}
				}
			}

			metadata, err := NewModuleParser().ParseModule(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(metadata.Submodules) != len(tt.wantPaths) {
				t.Errorf("submodules = %#v, want paths %v", metadata.Submodules, tt.wantPaths)
			} else {
				for i, submodule := range metadata.Submodules {
					if submodule.Path != tt.wantPaths[i] || submodule.Empty {
						t.Errorf("submodule %d = %#v, want path %q with empty false", i, submodule, tt.wantPaths[i])
					}
				}
			}

			encoded, err := json.Marshal(metadata.ConvertToJSONB())
			if err != nil {
				t.Fatal(err)
			}
			var stored struct {
				Submodules json.RawMessage `json:"submodules"`
			}
			if err := json.Unmarshal(encoded, &stored); err != nil {
				t.Fatal(err)
			}
			if len(tt.wantPaths) == 0 && string(stored.Submodules) != "[]" {
				t.Errorf("stored submodules = %s, want []", stored.Submodules)
			}
			var submodules []map[string]any
			if err := json.Unmarshal(stored.Submodules, &submodules); err != nil {
				t.Fatal(err)
			}
			if len(submodules) != len(tt.wantPaths) {
				t.Fatalf("stored submodules = %s, want paths %v", stored.Submodules, tt.wantPaths)
			}
			for i, submodule := range submodules {
				if len(submodule) != 3 || submodule["path"] != tt.wantPaths[i] || submodule["empty"] != false || submodule["readme"] != "" {
					t.Errorf("stored submodule %d = %#v, want only path %q, empty false and empty readme", i, submodule, tt.wantPaths[i])
				}
			}
		})
	}
}
