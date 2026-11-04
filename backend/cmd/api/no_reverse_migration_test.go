// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// reverseMigration matches a name that would offer a reverse migration: a downgrade, a rollback
// or a migration run backwards.
var reverseMigration = regexp.MustCompile(`(?i)downgrade|rollback|roll-back|reverse[-_ ]?migrat|migrat\w*[-_ ]?down\b|down[-_ ]?migrat`)

// The upgrade to the launcher architecture is forward-only (#933, decision 21): rolling back is a
// restore of the database and object storage backups taken before the upgrade. No binary flag or
// subcommand, no API route and no chart value offers a reverse migration, so an operator is never
// pointed at a path that does not exist (AC80).
func TestNoReverseMigrationIsOffered(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}

	// The binaries' flags and subcommands, and the models' exported functions.
	for _, dir := range []string{"backend/cmd", "core/models"} {
		walkGo(t, filepath.Join(root, dir), func(path string, file *ast.File) {
			ast.Inspect(file, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BasicLit:
					if x.Kind == token.STRING {
						if s, err := strconv.Unquote(x.Value); err == nil && looksLikeAName(s) && reverseMigration.MatchString(s) {
							t.Errorf("%s: the name %q offers a reverse migration", rel(root, path), s)
						}
					}
				case *ast.FuncDecl:
					if x.Name.IsExported() && reverseMigration.MatchString(x.Name.Name) {
						t.Errorf("%s: the function %s offers a reverse migration", rel(root, path), x.Name.Name)
					}
				}
				return true
			})
		})
	}

	// The API's route table.
	routes, err := os.ReadFile(filepath.Join(root, "backend/internal/api/v2/routes/testdata/golden/routes.json")) //nolint:gosec // a fixed path in this repository
	if err != nil {
		t.Fatalf("reading the route table: %v", err)
	}
	for _, line := range strings.Split(string(routes), "\n") {
		if strings.Contains(line, `"path":`) && reverseMigration.MatchString(line) {
			t.Errorf("the route %s offers a reverse migration", strings.TrimSpace(line))
		}
	}

	// The chart's values.
	values, err := os.ReadFile(filepath.Join(root, "deploy/helm/stackweaver/values.yaml")) //nolint:gosec // a fixed path in this repository
	if err != nil {
		t.Fatalf("reading the chart values: %v", err)
	}
	for i, line := range strings.Split(string(values), "\n") {
		key, _, isKey := strings.Cut(strings.TrimSpace(line), ":")
		if isKey && !strings.HasPrefix(key, "#") && reverseMigration.MatchString(key) {
			t.Errorf("values.yaml line %d: the value %q offers a reverse migration", i+1, key)
		}
	}
}

// looksLikeAName reports whether a string literal could be a flag, subcommand or route: one word,
// not prose. A sentence that mentions a rollback is documentation, not an offer.
func looksLikeAName(s string) bool {
	return s != "" && !strings.ContainsAny(s, " \t\n")
}

func walkGo(t *testing.T, dir string, visit func(path string, file *ast.File)) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		visit(path, file)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
}

func rel(root, path string) string {
	if r, err := filepath.Rel(root, path); err == nil {
		return r
	}
	return path
}
