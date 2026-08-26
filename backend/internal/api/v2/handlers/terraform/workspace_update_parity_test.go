// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// TestWorkspaceUpdateHandlersApplySameAttributes guards the two workspace update paths against
// silently diverging.
//
// `Update` (PATCH /organizations/:name/workspaces/:workspace_name) and `UpdateByID`
// (PATCH /api/v2/workspaces/:id) accept the SAME request struct, so any attribute one applies and
// the other ignores is dropped on a 200 - the caller sees success and the value never changes.
// That is not hypothetical: `auto-queue-runs` and `vcs-provider` were missing from `UpdateByID`,
// and since go-tfe's Workspaces.UpdateByID is the path the stock terraform-provider-tfe uses for
// tfe_workspace, those attributes silently no-op'd and the config drifted forever.
//
// The test reads the handlers' own source and compares which `attrs.X` fields each one reads, so a
// newly added attribute that is only wired into one handler fails here instead of in a user's plan.
func TestWorkspaceUpdateHandlersApplySameAttributes(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "workspaces.go", nil, 0)
	if err != nil {
		t.Fatalf("parse workspaces.go: %v", err)
	}

	// attrsRead walks a function body and collects every `attrs.<Field>` selector it touches.
	attrsRead := func(fn *ast.FuncDecl) map[string]bool {
		found := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "attrs" {
				found[sel.Sel.Name] = true
			}
			return true
		})
		return found
	}

	var byName, byID map[string]bool
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil {
			continue
		}
		switch fn.Name.Name {
		case "Update":
			byName = attrsRead(fn)
		case "UpdateByID":
			byID = attrsRead(fn)
		}
	}
	if byName == nil || byID == nil {
		t.Fatal("could not locate both Update and UpdateByID on WorkspaceHandlerV2")
	}

	// `Name` is legitimately by-ID only: the by-name route takes the name from the URL, and
	// renaming through it is handled separately.
	exempt := map[string]bool{"Name": true}

	var missing []string
	for attr := range byName {
		if !byID[attr] && !exempt[attr] {
			missing = append(missing, attr)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("UpdateByID ignores attribute(s) that Update applies: %s\n"+
			"PATCH /api/v2/workspaces/:id would return 200 and silently drop them (this is the path "+
			"the stock tfe provider uses). Wire them into UpdateByID, or add to `exempt` with a reason.",
			strings.Join(missing, ", "))
	}
}
