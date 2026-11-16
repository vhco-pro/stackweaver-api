// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package api_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A VCS capture's configuration lives at the key its upload recorded (#938, AC-19, R-48 and R-49),
// so a reader that builds the fixed configuration key itself reads the wrong object, or one a
// canceled upload wrote late. Readers go through ConfigurationVersion.TarballKey. The fixed key
// is still written by the TFE upload URL, the one place allowed to name it here.
var fixedConfigurationKeyAllowed = map[string]bool{
	"backend/internal/api/v2/handlers/terraform/configuration_versions.go": true,
}

func TestConfigurationReadersUseTheRecordedKey(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	repo := os.DirFS(root)
	var found []string
	for _, tree := range []string{"backend", "core/services", "core/repository"} {
		err := fs.WalkDir(repo, tree, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := fs.ReadFile(repo, path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), "ConfigurationTarballKey(") && !fixedConfigurationKeyAllowed[path] {
				found = append(found, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(found) > 0 {
		t.Errorf("these files build the fixed configuration key; read ConfigurationVersion.TarballKey() instead:\n  %s", strings.Join(found, "\n  "))
	}
}
