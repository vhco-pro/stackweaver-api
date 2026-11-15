// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package api_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The API process runs no git (#938, owner decisions Q8 and Q9, AC-23). Every clone of a customer
// repository happens in an executor, through a work item whose clone source the API resolves
// within the target's organization; pull-request path filtering reads the changed files from the
// provider's API. This guard parses the non-test Go files of the API's own trees and of the core
// services it links, and fails on any exec.Command or exec.CommandContext whose program is the
// literal "git".
var gitFreeTrees = []string{"backend/internal/api", "backend/cmd/api", "core/services"}

// gitStillRun names functions, by file and function, allowed to run git. #938 moved every site
// into the executor, so it is empty: any git call in these trees fails the guard. An entry whose
// function no longer runs git fails it too, so the list can never hold a stale exception.
var gitStillRun = map[string]string{}

func TestTheAPIRunsNoGit(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	var found []string
	seen := map[string]bool{}
	for _, tree := range gitFreeTrees {
		dir := filepath.Join(root, tree)
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Errorf("parsing %s: %v", path, err)
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				for _, line := range gitCalls(fset, fn.Body) {
					site := rel + "#" + fn.Name.Name
					if _, listed := gitStillRun[site]; listed {
						seen[site] = true
						continue
					}
					found = append(found, rel+":"+strconv.Itoa(line)+" ("+fn.Name.Name+")")
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", tree, err)
		}
	}
	sort.Strings(found)
	if len(found) > 0 {
		t.Errorf("the API process runs git at %d place(s); clones belong in an executor work item:\n  %s",
			len(found), strings.Join(found, "\n  "))
	}
	for site, task := range gitStillRun {
		if !seen[site] {
			t.Errorf("%s no longer runs git; remove its entry from gitStillRun (%s)", site, task)
		}
	}
}

// gitCalls returns the line of every exec.Command or exec.CommandContext under body whose program
// is the literal "git".
func gitCalls(fset *token.FileSet, body ast.Node) []int {
	var lines []int
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext") {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "exec" {
			return true
		}
		program := 0
		if sel.Sel.Name == "CommandContext" {
			program = 1
		}
		if len(call.Args) <= program {
			return true
		}
		lit, ok := call.Args[program].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if name, err := strconv.Unquote(lit.Value); err == nil && name == "git" {
			lines = append(lines, fset.Position(call.Pos()).Line)
		}
		return true
	})
	return lines
}
