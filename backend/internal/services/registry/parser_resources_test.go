// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package registry

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

func TestModuleParserResourceScope(t *testing.T) {
	rootMain := "resource \"aws_vpc\" \"root\" { cidr_block = \"10.0.0.0/16\" }\n"
	rootNetworking := "resource \"aws_subnet\" \"root_subnet\" {\n  vpc_id = aws_vpc.root.id\n  cidr_block = \"10.0.1.0/24\"\n}\n"
	example := "resource \"aws_s3_bucket\" \"example_only\" { bucket = \"registry-parser-example-fixture\" }\n"
	nested := "resource \"aws_security_group\" \"nested_only\" {\n  name = \"registry-parser-nested-fixture\"\n  vpc_id = \"vpc-00000000000000000\"\n}\n"
	child := "resource \"aws_eip\" \"child_only\" { domain = \"vpc\" }\n"
	resourceFree := "output \"label\" { value = \"resource-free-fixture\" }\n"
	primary := map[string]string{
		"main.tf": rootMain, "networking.tf": rootNetworking,
		"examples/basic/main.tf": example, "nested/helper/main.tf": nested,
		"modules/child/main.tf": child, ".hidden/main.tf": example,
	}
	tests := []struct {
		name          string
		files         map[string]string
		selected      string
		want          []ResourceType
		invalid       map[string]bool
		links         map[string]string
		directoryLink bool
		missing       bool
	}{
		{
			name: "root excludes example and unrelated nested declarations", files: primary,
			want: []ResourceType{{Name: "root", Type: "aws_vpc"}, {Name: "root_subnet", Type: "aws_subnet"}},
		},
		{
			name: "resource-free root excludes its example", files: map[string]string{
				"main.tf": resourceFree, "examples/basic/main.tf": example,
			},
		},
		{name: "resource-free module keeps nil and JSON empty array", files: map[string]string{"main.tf": resourceFree}},
		{
			name: "example can be selected directly", files: primary, selected: "examples/basic",
			want: []ResourceType{{Name: "example_only", Type: "aws_s3_bucket"}},
		},
		{
			name: "child module can be selected directly", files: primary, selected: "modules/child",
			want: []ResourceType{{Name: "child_only", Type: "aws_eip"}},
		},
		{
			name: "top-level ordering filters and malformed-file handling stay intact",
			files: map[string]string{
				"main.tf":       rootMain + "resource \"aws_vpc\" \"second\" { cidr_block = \"10.2.0.0/16\" }\n",
				"networking.tf": rootNetworking, "bad.tf": "resource {\n",
				".hidden.tf": example, ".hidden/main.tf": example, "modules/child/main.tf": child,
				"unsupported.TF": example, "unsupported.tofu": example,
				"unsupported.tf.json": `{"resource":{"aws_s3_bucket":{"json_only":{"bucket":"registry-parser-json-fixture"}}}}`,
			},
			invalid: map[string]bool{"bad.tf": true},
			want: []ResourceType{
				{Name: "root", Type: "aws_vpc"}, {Name: "second", Type: "aws_vpc"}, {Name: "root_subnet", Type: "aws_subnet"},
			},
		},
		{
			name: "top-level tf file symlink keeps its behavior", files: map[string]string{"source.txt": rootMain},
			links: map[string]string{"main.tf": "source.txt"}, want: []ResourceType{{Name: "root", Type: "aws_vpc"}},
		},
		{name: "directory symlink is not traversed", files: map[string]string{"main.tf": resourceFree}, directoryLink: true},
		{name: "broken tf symlink stays a skipped diagnostic", files: map[string]string{"main.tf": resourceFree}, links: map[string]string{"broken.tf": "absent"}},
		{name: "missing selected root retains its error", files: map[string]string{"main.tf": resourceFree}, selected: "absent", missing: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range tt.files {
				filename := filepath.Join(root, name)
				var invalid bool
				if strings.HasSuffix(name, ".tf.json") {
					_, diagnostics := hclparse.NewParser().ParseJSON([]byte(content), filename)
					invalid = diagnostics.HasErrors()
				} else {
					_, diagnostics := hclsyntax.ParseConfig([]byte(content), filename, hcl.Pos{Line: 1, Column: 1})
					invalid = diagnostics.HasErrors()
				}
				if invalid != tt.invalid[name] {
					t.Fatalf("fixture %s syntax invalid = %t, want %t", name, invalid, tt.invalid[name])
				}
				writeResourceScopeFixture(t, filename, content)
			}
			for name, target := range tt.links {
				if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
					t.Fatalf("creating fixture symlink %s: %v", name, err)
				}
			}
			if tt.directoryLink {
				target := t.TempDir()
				writeResourceScopeFixture(t, filepath.Join(target, "main.tf"), nested)
				if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
					t.Fatalf("creating directory symlink fixture: %v", err)
				}
			}
			metadata, err := NewModuleParser().ParseModule(filepath.Join(root, tt.selected))
			if tt.missing {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("missing selected root error = %v, want not-exist", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsing fixture: %v", err)
			}
			if !slices.Equal(metadata.Resources, tt.want) {
				t.Errorf("resources = %#v, want %#v", metadata.Resources, tt.want)
			}
			if len(tt.want) == 0 && metadata.Resources != nil {
				t.Errorf("resource-free Go slice = %#v, want nil", metadata.Resources)
			}
			encoded, err := json.Marshal(metadata.ConvertToJSONB())
			if err != nil {
				t.Fatalf("marshaling actual metadata: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatalf("reading serialized metadata: %v", err)
			}
			wantJSON := []byte("[]")
			if len(tt.want) != 0 {
				wantJSON, err = json.Marshal(tt.want)
				if err != nil {
					t.Fatalf("marshaling expected declarations: %v", err)
				}
			}
			if string(fields["resources"]) != string(wantJSON) {
				t.Errorf("serialized resources = %s, want %s", fields["resources"], wantJSON)
			}
		})
	}
}

func writeResourceScopeFixture(t *testing.T, filename, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatalf("creating fixture directory: %v", err)
	}
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
}
