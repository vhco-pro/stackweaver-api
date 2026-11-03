// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

func TestModuleParserProviderDependencies(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		source   string
		style    string
		want     []ProviderDependency
	}{
		{
			name: "modern objects", filename: "versions.tf", style: "block",
			source: `terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = ">= 3.6.0" }
  }
}`,
			want: []ProviderDependency{
				{Name: "aws", Source: "hashicorp/aws", Version: "~> 5.0"},
				{Name: "random", Source: "hashicorp/random", Version: ">= 3.6.0"},
			},
		},
		{
			name: "modern version string", filename: "versions.tf", style: "block",
			source: `terraform {
  required_providers {
    random = ">= 3.6.0"
  }
}`,
			want: []ProviderDependency{{Name: "random", Source: "hashicorp/random", Version: ">= 3.6.0"}},
		},
		{
			name: "modern object default source", filename: "versions.tf", style: "block",
			source: `terraform {
  required_providers {
    aws = { version = "~> 5.0" }
  }
}`,
			want: []ProviderDependency{{Name: "aws", Source: "hashicorp/aws", Version: "~> 5.0"}},
		},
		{
			name: "modern source without version", filename: "versions.tf", style: "block",
			source: `terraform {
  required_providers {
    random = { source = "hashicorp/random" }
  }
}`,
			want: []ProviderDependency{{Name: "random", Source: "hashicorp/random"}},
		},
		{
			name: "modern empty block", filename: "versions.tf", style: "block",
			source: `terraform {
  required_providers {}
}`,
		},
		{
			name: "legacy object", filename: "versions.tf", style: "attribute",
			source: `terraform {
  required_providers = {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}`,
			want: []ProviderDependency{{Name: "aws", Source: "hashicorp/aws", Version: "~> 5.0"}},
		},
		{
			name: "legacy version string", filename: "versions.tf", style: "attribute",
			source: `terraform {
  required_providers = { random = ">= 3.6.0" }
}`,
			want: []ProviderDependency{{Name: "random", Source: "hashicorp/random", Version: ">= 3.6.0"}},
		},
		{
			name: "legacy empty attribute", filename: "versions.tf", style: "attribute",
			source: `terraform {
  required_providers = {}
}`,
		},
		{
			name: "no provider declarations", filename: "versions.tf", style: "none",
			source: `terraform {
  required_version = ">= 1.6.0"
}`,
		},
		{
			name: "no terraform block", filename: "versions.tf", style: "none",
			source: `locals { example = "module" }`,
		},
		{
			name: "terraform filename fallback", filename: "terraform.tf", style: "block",
			source: `terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}`,
			want: []ProviderDependency{{Name: "aws", Source: "hashicorp/aws", Version: "~> 5.0"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tt.filename)
			if err := os.WriteFile(path, []byte(tt.source), 0o600); err != nil {
				t.Fatal(err)
			}
			validateProviderRequirementsFixture(t, path, tt.style, len(tt.want))
			metadata, err := NewModuleParser().ParseModule(dir)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(metadata.ConvertToJSONB())
			if err != nil {
				t.Fatal(err)
			}
			var stored struct {
				Dependencies json.RawMessage `json:"dependencies"`
			}
			if err := json.Unmarshal(encoded, &stored); err != nil {
				t.Fatal(err)
			}
			if len(tt.want) == 0 && string(stored.Dependencies) != "[]" {
				t.Errorf("stored dependencies = %s, want []", stored.Dependencies)
			}
			var dependencies []ProviderDependency
			if err := json.Unmarshal(stored.Dependencies, &dependencies); err != nil {
				t.Fatal(err)
			}
			if len(dependencies) != len(tt.want) {
				t.Errorf("stored dependency count = %d, want %d; JSON: %s", len(dependencies), len(tt.want), encoded)
			}
			byName := make(map[string]ProviderDependency, len(dependencies))
			for _, dependency := range dependencies {
				byName[dependency.Name] = dependency
			}
			for _, want := range tt.want {
				if got, ok := byName[want.Name]; !ok || got != want {
					t.Errorf("stored dependency %s = %#v (present: %t), want %#v", want.Name, got, ok, want)
				}
			}
		})
	}
}

func validateProviderRequirementsFixture(t *testing.T, path, style string, wantCount int) {
	t.Helper()
	file, diags := hclparse.NewParser().ParseHCLFile(path)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	var blockCount, attributeCount, declarationCount int
	for _, block := range file.Body.(*hclsyntax.Body).Blocks {
		if block.Type != "terraform" {
			continue
		}
		if attr, ok := block.Body.Attributes["required_providers"]; ok {
			attributeCount++
			value, diags := attr.Expr.Value(nil)
			if diags.HasErrors() {
				t.Fatal(diags.Error())
			}
			if !value.Type().IsObjectType() {
				t.Fatal("fixture required_providers attribute is not an object")
			}
			declarationCount += len(value.AsValueMap())
		}
		for _, requirements := range block.Body.Blocks {
			if requirements.Type != "required_providers" {
				continue
			}
			blockCount++
			for _, attr := range requirements.Body.Attributes {
				value, diags := attr.Expr.Value(nil)
				if diags.HasErrors() {
					t.Fatal(diags.Error())
				}
				if !value.Type().IsObjectType() && value.Type() != cty.String {
					t.Fatal("fixture provider requirement is neither an object nor a string")
				}
				declarationCount++
			}
		}
	}
	if declarationCount != wantCount {
		t.Fatalf("fixture has %d declarations, want %d", declarationCount, wantCount)
	}
	switch style {
	case "block":
		if blockCount != 1 || attributeCount != 0 {
			t.Fatalf("fixture has %d blocks and %d attributes, want one block only", blockCount, attributeCount)
		}
	case "attribute":
		if blockCount != 0 || attributeCount != 1 {
			t.Fatalf("fixture has %d blocks and %d attributes, want one attribute only", blockCount, attributeCount)
		}
	case "none":
		if blockCount != 0 || attributeCount != 0 {
			t.Fatal("fixture unexpectedly declares providers")
		}
	default:
		t.Fatalf("unknown fixture style %q", style)
	}
}

// These are HCL robustness cases, not Terraform-semantic validation fixtures.
func TestModuleParserNullableProviderStrings(t *testing.T) {
	tests := []struct {
		name        string
		provider    string
		property    string
		typed       bool
		wantVersion string
	}{
		{"typed null source", `{ source = true ? null : "hashicorp/aws", version = ">= 1.0" }`, "source", true, ">= 1.0"},
		{"literal null source", `{ source = null, version = ">= 1.0" }`, "source", false, ">= 1.0"},
		{"typed null object version", `{ source = "hashicorp/aws", version = true ? null : ">= 1.0" }`, "version", true, ""},
		{"literal null object version", `{ source = "hashicorp/aws", version = null }`, "version", false, ""},
		{"typed null direct version", `true ? null : ">= 1.0"`, "", true, ""},
		{"literal null direct provider", `null`, "", false, ""},
	}
	for _, style := range []string{"modern", "legacy"} {
		for _, tt := range tests {
			t.Run(style+"/"+tt.name, func(t *testing.T) {
				dir := t.TempDir()
				requirements := "required_providers { aws = " + tt.provider + " }"
				if style == "legacy" {
					requirements = "required_providers = { aws = " + tt.provider + " }"
				}
				path := filepath.Join(dir, "versions.tf")
				if err := os.WriteFile(path, []byte("terraform {\n"+requirements+"\n}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				file, diags := hclparse.NewParser().ParseHCLFile(path)
				if diags.HasErrors() {
					t.Fatal(diags.Error())
				}
				terraform := file.Body.(*hclsyntax.Body).Blocks[0]
				if terraform.Type != "terraform" {
					t.Fatal("fixture has no terraform block")
				}
				var value cty.Value
				if style == "modern" {
					if len(terraform.Body.Blocks) != 1 || terraform.Body.Blocks[0].Type != "required_providers" {
						t.Fatal("fixture has no modern required_providers block")
					}
					value, diags = terraform.Body.Blocks[0].Body.Attributes["aws"].Expr.Value(nil)
				} else {
					value, diags = terraform.Body.Attributes["required_providers"].Expr.Value(nil)
					if !diags.HasErrors() {
						value = value.GetAttr("aws")
					}
				}
				if diags.HasErrors() {
					t.Fatal(diags.Error())
				}
				if tt.property != "" {
					value = value.GetAttr(tt.property)
				}
				wantType := cty.DynamicPseudoType
				if tt.typed {
					wantType = cty.String
				}
				if !value.IsKnown() || !value.IsNull() || !value.Type().Equals(wantType) {
					t.Fatalf("fixture null = %#v, want known null of %s", value, wantType.FriendlyName())
				}

				defer func() {
					if panicValue := recover(); panicValue != nil {
						t.Errorf("ParseModule panicked for nullable provider metadata: %v", panicValue)
					}
				}()
				metadata, err := NewModuleParser().ParseModule(dir)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(metadata.ConvertToJSONB())
				if err != nil {
					t.Fatal(err)
				}
				var stored struct {
					Dependencies []ProviderDependency `json:"dependencies"`
				}
				if err := json.Unmarshal(encoded, &stored); err != nil {
					t.Fatal(err)
				}
				if len(stored.Dependencies) != 1 {
					t.Fatalf("stored dependency count = %d, want 1; JSON: %s", len(stored.Dependencies), encoded)
				}
				want := ProviderDependency{Name: "aws", Source: "hashicorp/aws", Version: tt.wantVersion}
				if got := stored.Dependencies[0]; got != want {
					t.Errorf("stored dependency = %#v, want %#v", got, want)
				}
			})
		}
	}
}

func TestModuleParserNullableProviderContainers(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		modern    bool
		container bool
		typed     bool
	}{
		{"modern typed null provider object", `true ? null : { source = "hashicorp/aws" }`, true, false, true},
		{"modern literal null provider", `null`, true, false, false},
		{"legacy typed null provider object", `true ? null : { source = "hashicorp/aws" }`, false, false, true},
		{"legacy literal null provider", `null`, false, false, false},
		{"typed null requirements object", `true ? null : { aws = { source = "hashicorp/aws" } }`, false, true, true},
		{"literal null requirements", `null`, false, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			requirements := "required_providers = { aws = " + tt.value + " }"
			if tt.modern {
				requirements = "required_providers { aws = " + tt.value + " }"
			} else if tt.container {
				requirements = "required_providers = " + tt.value
			}
			path := filepath.Join(dir, "versions.tf")
			if err := os.WriteFile(path, []byte("terraform {\n"+requirements+"\n}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			file, diags := hclparse.NewParser().ParseHCLFile(path)
			if diags.HasErrors() {
				t.Fatal(diags.Error())
			}
			terraform := file.Body.(*hclsyntax.Body).Blocks[0]
			if terraform.Type != "terraform" {
				t.Fatal("fixture has no terraform block")
			}
			var value cty.Value
			if tt.modern {
				if len(terraform.Body.Blocks) != 1 || terraform.Body.Blocks[0].Type != "required_providers" {
					t.Fatal("fixture has no modern required_providers block")
				}
				value, diags = terraform.Body.Blocks[0].Body.Attributes["aws"].Expr.Value(nil)
			} else {
				value, diags = terraform.Body.Attributes["required_providers"].Expr.Value(nil)
				if !diags.HasErrors() && !tt.container {
					value = value.GetAttr("aws")
				}
			}
			if diags.HasErrors() {
				t.Fatal(diags.Error())
			}
			if !value.IsKnown() || !value.IsNull() {
				t.Fatalf("fixture value = %#v, want known null", value)
			}
			if tt.typed {
				if !value.Type().IsObjectType() {
					t.Fatalf("fixture type = %s, want object", value.Type().FriendlyName())
				}
			} else if value.Type() != cty.DynamicPseudoType {
				t.Fatalf("literal-null fixture type = %s, want dynamic", value.Type().FriendlyName())
			}

			defer func() {
				if panicValue := recover(); panicValue != nil {
					t.Errorf("ParseModule panicked for nullable provider container: %v", panicValue)
				}
			}()
			metadata, err := NewModuleParser().ParseModule(dir)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(metadata.ConvertToJSONB())
			if err != nil {
				t.Fatal(err)
			}
			var stored struct {
				Dependencies json.RawMessage `json:"dependencies"`
			}
			if err := json.Unmarshal(encoded, &stored); err != nil {
				t.Fatal(err)
			}
			if tt.container {
				if string(stored.Dependencies) != "[]" {
					t.Errorf("stored dependencies = %s, want []", stored.Dependencies)
				}
				return
			}
			var dependencies []ProviderDependency
			if err := json.Unmarshal(stored.Dependencies, &dependencies); err != nil {
				t.Fatal(err)
			}
			if len(dependencies) != 1 {
				t.Fatalf("stored dependency count = %d, want 1; JSON: %s", len(dependencies), encoded)
			}
			want := ProviderDependency{Name: "aws", Source: "hashicorp/aws"}
			if got := dependencies[0]; got != want {
				t.Errorf("stored dependency = %#v, want %#v", got, want)
			}
		})
	}
}
