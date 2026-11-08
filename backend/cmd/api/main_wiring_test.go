// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The API builds its Ansible services once, in the routes (#885, AC5, AC9). main.go used to build a
// second job service, workflow engine, inventory source service and scheduler of its own for the
// ticking scheduler, and a third job service for a release loop when ANSIBLE_SCHEDULER_ENABLED was
// false. The second wiring lagged the first: its job service never got work items, so a scheduled
// launch skipped its update-on-launch syncs, and the disabled mode advanced nothing but held jobs.
// main.go now starts the scheduler the routes built, in both modes, and constructs none of these.

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestMain_BuildsNoAnsibleServicesOfItsOwn(t *testing.T) {
	forbiddenCalls := map[string]bool{
		"NewJobServiceWithVariables": true,
		"NewJobService":              true,
		"NewWorkflowEngineService":   true,
		"NewInventorySourceService":  true,
		"NewSchedulerService":        true,
		// The scheduler's tick releases held jobs in both modes; a loop of main.go's own is the
		// disabled-mode wiring this replaces.
		"ReleaseHeldJobs": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && forbiddenCalls[sel.Sel.Name] {
				t.Errorf("%s calls %s; the API's Ansible services are built once, in the routes", fset.Position(call.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
}
