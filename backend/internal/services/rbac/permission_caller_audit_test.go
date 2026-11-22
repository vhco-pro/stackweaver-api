// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package rbac

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

const (
	permissionAuditDocument = "docs/internal/plans/infrastructure/runners/running-jobs-survive-upgrades-and-database-errors.md"
	permissionAuditFollowUp = "docs/internal/TODO.md#permission-read-error-response-follow-up"
)

type permissionReference struct {
	path, scope, target, kind string
	occurrence                int
}

func (r permissionReference) key() string {
	return fmt.Sprintf("%s | %s | %s | %s | %d", r.path, r.scope, r.target, r.kind, r.occurrence)
}

func permissionInventory(root, subjectPath string, env []string) (map[string]struct{}, error) {
	loaded, err := packages.Load(&packages.Config{
		Mode: packages.LoadSyntax, Dir: root, Env: env,
	}, "./...")
	if err != nil {
		return nil, err
	}
	if packages.PrintErrors(loaded) != 0 {
		return nil, fmt.Errorf("load production permission consumers")
	}
	var subject *types.Package
	for _, pkg := range loaded {
		if pkg.PkgPath == subjectPath {
			subject = pkg.Types
			break
		}
	}
	if subject == nil {
		return nil, fmt.Errorf("package %s missing from the production inventory", subjectPath)
	}
	service, ok := subject.Scope().Lookup("Service").(*types.TypeName)
	if !ok {
		return nil, fmt.Errorf("RBAC Service type missing from %s", subjectPath)
	}
	pointer := types.NewPointer(service.Type())
	methods := types.NewMethodSet(pointer)

	inventory := make(map[string]struct{})
	for _, pkg := range loaded {
		for _, file := range pkg.Syntax {
			path, err := filepath.Rel(root, pkg.Fset.Position(file.Pos()).Filename)
			if err != nil {
				return nil, err
			}
			if !filepath.IsLocal(path) {
				continue
			}
			counts := make(map[[3]string]int)
			for _, decl := range file.Decls {
				scope := "<package initializer>"
				if declared, ok := decl.(*ast.FuncDecl); ok {
					scope = pkg.TypesInfo.Defs[declared.Name].(*types.Func).FullName()
				}
				report := func(target *types.Func, kind string) {
					name := target.Origin().FullName()
					group := [3]string{scope, name, kind}
					counts[group]++
					ref := permissionReference{"backend/" + filepath.ToSlash(path), scope, name, kind, counts[group]}
					inventory[ref.key()] = struct{}{}
				}
				ast.Inspect(decl, func(node ast.Node) bool {
					switch use := node.(type) {
					case *ast.Ident:
						target, ok := pkg.TypesInfo.Uses[use].(*types.Func)
						if ok && target.Pkg() == subject && target.Exported() {
							report(target, permissionReferenceKind(file, use))
						}
					case *ast.SelectorExpr:
						sel := pkg.TypesInfo.Selections[use]
						iface, ok := interfaceReceiver(sel)
						if ok && types.Implements(pointer, iface) {
							match := methods.Lookup(subject, sel.Obj().Name())
							if match != nil {
								target := match.Obj().(*types.Func)
								if target.Pkg() == subject {
									report(target, "interface "+permissionReferenceKind(file, use.Sel))
								}
							}
						}
					}
					return true
				})
			}
		}
	}
	if len(inventory) == 0 {
		return nil, fmt.Errorf("no typed permission references found")
	}
	return inventory, nil
}

func interfaceReceiver(sel *types.Selection) (*types.Interface, bool) {
	if sel == nil || sel.Kind() == types.FieldVal || !sel.Obj().Exported() {
		return nil, false
	}
	iface, ok := sel.Recv().Underlying().(*types.Interface)
	return iface, ok
}

func permissionReferenceKind(file *ast.File, id *ast.Ident) string {
	path, _ := astutil.PathEnclosingInterval(file, id.Pos(), id.End())
	var value ast.Node = id
	for _, parent := range path {
		switch expr := parent.(type) {
		case *ast.SelectorExpr:
			if expr.Sel == id {
				value = expr
			}
		case *ast.ParenExpr:
			if expr.X == value {
				value = expr
			}
		case *ast.CallExpr:
			if expr.Fun == value {
				return "call"
			}
			return "value"
		}
	}
	return "value"
}

func checkPermissionAudit(inventory map[string]struct{}, table string) error {
	seen := make(map[string]struct{}, len(inventory))
	for _, line := range strings.Split(table, "\n") {
		if !strings.HasPrefix(line, "| backend/") {
			continue
		}
		row := strings.Split(strings.Trim(line, "|"), "|")
		if len(row) != 10 {
			return fmt.Errorf("expected 10 permission audit columns: %s", line)
		}
		for i := range row {
			row[i] = strings.TrimSpace(row[i])
			if row[i] == "" || (i >= 5 && i < 9 && unresolvedPermissionDisposition(row[i])) {
				return fmt.Errorf("missing permission audit disposition: %s", line)
			}
		}
		key := strings.Join(row[:5], " | ")
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate permission reference: %s", key)
		}
		if _, exists := inventory[key]; !exists {
			return fmt.Errorf("permission reference is absent from source: %s", key)
		}
		if row[9] != "None" && row[9] != permissionAuditFollowUp {
			return fmt.Errorf("untracked permission follow-up: %s", key)
		}
		seen[key] = struct{}{}
	}
	if len(seen) != len(inventory) {
		for key := range inventory {
			if _, exists := seen[key]; !exists {
				return fmt.Errorf("missing permission reference: %s", key)
			}
		}
	}
	return nil
}

func unresolvedPermissionDisposition(text string) bool {
	for _, word := range strings.FieldsFunc(text, func(r rune) bool { return !unicode.IsLetter(r) }) {
		switch strings.ToLower(word) {
		case "unknown", "unclassified", "unresolved", "pending", "tbd", "todo":
			return true
		}
	}
	return false
}

func TestPermissionCallerAuditCoverage(t *testing.T) {
	backend, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(backend)
	plan, err := os.ReadFile(filepath.Join(root, permissionAuditDocument))
	if err != nil {
		t.Fatal(err)
	}
	_, audit, ok := strings.Cut(string(plan), "\n### Permission caller audit\n")
	if !ok {
		t.Fatal("permission caller audit section missing")
	}
	table, _, _ := strings.Cut(audit, "\n## Scope\n")
	todo, err := os.ReadFile(filepath.Join(root, "docs/internal/TODO.md"))
	if err != nil || !strings.Contains(string(todo), "\n### Permission read error response follow-up\n") {
		t.Fatal("permission caller follow-up heading missing")
	}

	// Load the Linux API's published architectures. Merge their source reference sets,
	// since a reference may be present in both builds.
	subject := "github.com/michielvha/stackweaver/backend/internal/services/rbac"
	inventory := map[string]struct{}{}
	for _, architecture := range []string{"amd64", "arm64"} {
		env := append(os.Environ(), "GOOS=linux", "GOARCH="+architecture, "CGO_ENABLED=0")
		entries, err := permissionInventory(backend, subject, env)
		if err != nil {
			t.Fatalf("linux/%s: %v", architecture, err)
		}
		for key := range entries {
			inventory[key] = struct{}{}
		}
	}
	if err := checkPermissionAudit(inventory, table); err != nil {
		t.Fatal(err)
	}
}

func TestPermissionCallerAuditDetectsUnlistedTypedReferences(t *testing.T) {
	root := t.TempDir()
	const subject = "permission.example/rbac"
	write := func(path, source string) {
		t.Helper()
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module permission.example\n\ngo 1.27\n")
	write("rbac/rbac.go", `package rbac
type Service struct{}
func (*Service) Check() (bool, error) { return false, nil }
`)
	const consumer = `package consumer
import "permission.example/rbac"
func baseline(service *rbac.Service) (bool, error) { return service.Check() }
`
	env := append(os.Environ(), "GOWORK=off")
	write("consumer.go", consumer)
	baseline, err := permissionInventory(root, subject, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline) != 1 {
		t.Fatalf("fixture baseline has %d permission references, want one", len(baseline))
	}
	var table string
	for key := range baseline {
		table = "| " + key + " | propagate | deny | fixture | source | None |\n"
	}
	if err := checkPermissionAudit(baseline, table); err != nil {
		t.Fatal(err)
	}
	for _, example := range []struct {
		name, table, diagnostic string
	}{
		{"missing row", "", "missing permission reference"},
		{"duplicate row", table + table, "duplicate permission reference"},
		{"unclassified error", strings.Replace(table, "propagate", "Unknown error", 1), "missing permission audit disposition"},
		{"unclassified denial", strings.Replace(table, "deny", "TBD", 1), "missing permission audit disposition"},
		{"unclassified proof", strings.Replace(table, "source", "pending proof", 1), "missing permission audit disposition"},
		{"untracked follow-up", strings.Replace(table, "None", "see later", 1), "untracked permission follow-up"},
	} {
		t.Run(example.name, func(t *testing.T) {
			err := checkPermissionAudit(baseline, example.table)
			if err == nil || !strings.Contains(err.Error(), example.diagnostic) {
				t.Fatalf("want %q, got %v", example.diagnostic, err)
			}
		})
	}
	if err := checkPermissionAudit(baseline, strings.Replace(table, "None", permissionAuditFollowUp, 1)); err != nil {
		t.Fatalf("tracked follow-up rejected: %v", err)
	}
	for _, example := range []struct {
		name, source, kind string
	}{
		{"wrapper", "func added(s *rbac.Service) (bool, error) { return s.Check() }", "call"},
		{"method value", "func added(s *rbac.Service) (bool, error) { check := s.Check; return check() }", "value"},
		{"interface dispatch", "type permission interface{ Check() (bool, error) }; func added(p permission) (bool, error) { return p.Check() }", "interface call"},
	} {
		t.Run(example.name, func(t *testing.T) {
			write("consumer.go", consumer+example.source+"\n")
			inventory, err := permissionInventory(root, subject, env)
			if err != nil {
				t.Fatal(err)
			}
			err = checkPermissionAudit(inventory, table)
			if len(inventory) != 2 || err == nil || !strings.Contains(err.Error(), "missing permission reference") || !strings.Contains(err.Error(), " | "+example.kind+" | ") {
				t.Fatalf("unlisted %s produced %d references and %v", example.kind, len(inventory), err)
			}
		})
	}
}
