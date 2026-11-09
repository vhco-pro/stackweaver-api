// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package api_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The backend terminology guard (one-launcher spec, B3, AC30, AC31). The text users and operators
// read uses the standard names (Hosted capacity, Agent pool, Launcher) and never Executor: the
// details of the API's errors, the reasons a lost launcher's runs and jobs end with, and the failure
// reasons the launcher and the executor send. The retired terms and the allowed exceptions are read
// from the glossary, docs/internal/guidelines/terminology.md, so this test holds no list of its own.
//
// It reads, with the Go parser, the string arguments of the jsonapi.WriteError* calls and of
// writeRunnerForbidden in the handlers and the middleware, the LostDuring* reasons, and the messages
// the launcher and the executor build with fmt.Errorf, errors.New and fmt.Sprintf where their
// failure reasons come from. Identifiers, routes and other string arguments are not read.

type glossaryPattern struct {
	name string
	re   *regexp.Regexp
}

type glossary struct {
	retired    []glossaryPattern
	exceptions []glossaryPattern
}

// tableRows returns the first cell and the backticked pattern of each row of a glossary table.
func tableRows(markdown, heading string) [][2]string {
	_, section, ok := strings.Cut(markdown, "\n## "+heading+"\n")
	if !ok {
		return nil
	}
	section, _, _ = strings.Cut(section, "\n## ")
	var rows [][2]string
	for line := range strings.SplitSeq(section, "\n") {
		if !strings.HasPrefix(line, "|") || strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(line, "|")), "-") {
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(cells) < 2 {
			continue
		}
		first, pattern := strings.TrimSpace(cells[0]), strings.TrimSpace(cells[1])
		if len(pattern) > 2 && strings.HasPrefix(pattern, "`") && strings.HasSuffix(pattern, "`") {
			rows = append(rows, [2]string{first, pattern[1 : len(pattern)-1]})
		}
	}
	return rows
}

func loadGlossary(t *testing.T, markdown string) glossary {
	t.Helper()
	compile := func(heading string) []glossaryPattern {
		var out []glossaryPattern
		for _, row := range tableRows(markdown, heading) {
			re, err := regexp.Compile("(?i)" + row[1])
			if err != nil {
				t.Fatalf("glossary %s pattern %q: %v", heading, row[1], err)
			}
			out = append(out, glossaryPattern{name: row[0], re: re})
		}
		return out
	}
	g := glossary{retired: compile("Retired terms"), exceptions: compile("Allowed exceptions")}
	if len(g.retired) < 5 || len(g.exceptions) < 5 {
		t.Fatalf("the glossary yields %d retired terms and %d exceptions; its tables did not parse", len(g.retired), len(g.exceptions))
	}
	return g
}

// retiredIn names the first retired term in text once the exceptions are removed, or "".
func (g glossary) retiredIn(text string) string {
	for _, e := range g.exceptions {
		text = e.re.ReplaceAllString(text, " ")
	}
	for _, r := range g.retired {
		if r.re.MatchString(text) {
			return r.name
		}
	}
	return ""
}

// scope says which calls of a file carry user-facing text.
type scope struct {
	writeErrors bool // jsonapi.WriteError* and writeRunnerForbidden
	messages    bool // fmt.Errorf, errors.New and fmt.Sprintf
	lostReasons bool // the LostDuring* constants
}

// stringsOf returns the literal text of an expression: string literals, concatenations and the
// format of a fmt call nested in it.
func stringsOf(e ast.Expr) []*ast.BasicLit {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			return []*ast.BasicLit{v}
		}
	case *ast.BinaryExpr:
		return append(stringsOf(v.X), stringsOf(v.Y)...)
	case *ast.ParenExpr:
		return stringsOf(v.X)
	case *ast.CallExpr:
		if isCall(v, "fmt", "Sprintf") && len(v.Args) > 0 {
			return stringsOf(v.Args[0])
		}
	}
	return nil
}

func isCall(c *ast.CallExpr, pkg, prefix string) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg && strings.HasPrefix(sel.Sel.Name, prefix)
}

func isFunc(c *ast.CallExpr, name string) bool {
	id, ok := c.Fun.(*ast.Ident)
	return ok && id.Name == name
}

type finding struct {
	pos  token.Position
	text string
	term string
}

// check returns the user-facing strings of one parsed file that use a retired term.
func check(fset *token.FileSet, f *ast.File, s scope, g glossary) []finding {
	var lits []*ast.BasicLit
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			switch {
			case s.writeErrors && (isCall(v, "jsonapi", "WriteError") || isFunc(v, "writeRunnerForbidden")):
				for _, a := range v.Args {
					lits = append(lits, stringsOf(a)...)
				}
			case s.messages && (isCall(v, "fmt", "Errorf") || isCall(v, "errors", "New") || isCall(v, "fmt", "Sprintf")):
				if len(v.Args) > 0 {
					lits = append(lits, stringsOf(v.Args[0])...)
				}
			}
		case *ast.ValueSpec:
			if s.lostReasons {
				for i, name := range v.Names {
					if strings.HasPrefix(name.Name, "LostDuring") && i < len(v.Values) {
						lits = append(lits, stringsOf(v.Values[i])...)
					}
				}
			}
		}
		return true
	})
	var out []finding
	seen := map[token.Pos]bool{}
	for _, lit := range lits {
		if seen[lit.Pos()] {
			continue // a fmt.Sprintf inside a WriteError call is reached twice
		}
		seen[lit.Pos()] = true
		text, err := strconv.Unquote(lit.Value)
		if err != nil {
			text = lit.Value
		}
		if term := g.retiredIn(text); term != "" {
			out = append(out, finding{pos: fset.Position(lit.Pos()), text: text, term: term})
		}
	}
	return out
}

// guarded lists the production sources, relative to the repository root, and what each carries.
func guarded(t *testing.T, root string) map[string]scope {
	t.Helper()
	files := map[string]scope{
		"core/repository/runner.go":                 {lostReasons: true},
		"backend/internal/launcher/supervise.go":    {messages: true},
		"backend/internal/executor/client.go":       {messages: true},
		"backend/internal/launcher/client.go":       {messages: true},
		"backend/internal/launcher/launcher.go":     {messages: true},
		"backend/internal/launcher/main.go":         {messages: true},
		"backend/internal/executor/syncexec/run.go": {messages: true},
	}
	add := func(glob string, s scope) {
		matches, err := filepath.Glob(filepath.Join(root, glob))
		if err != nil || len(matches) == 0 {
			t.Fatalf("no sources match %s: %v", glob, err)
		}
		for _, m := range matches {
			if strings.HasSuffix(m, "_test.go") {
				continue
			}
			rel, _ := filepath.Rel(root, m)
			files[filepath.ToSlash(rel)] = s
		}
	}
	add("backend/internal/api/v2/handlers/*.go", scope{writeErrors: true})
	add("backend/internal/api/v2/handlers/*/*.go", scope{writeErrors: true})
	add("backend/internal/api/middleware/*.go", scope{writeErrors: true})
	add("backend/internal/launcher/driver/*.go", scope{messages: true})
	return files
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.work above the test directory")
		}
		dir = parent
	}
}

func readGlossary(t *testing.T, root string) glossary {
	t.Helper()
	md, err := os.ReadFile(filepath.Join(root, "docs/internal/guidelines/terminology.md")) //nolint:gosec // G304: the repository's own glossary
	if err != nil {
		t.Fatalf("reading the glossary: %v", err)
	}
	return loadGlossary(t, string(md))
}

// A retired term in any guarded place fails; the kept wire names pass.
func TestTerminologyGuardFixture(t *testing.T) {
	g := readGlossary(t, repoRoot(t))
	src := `package fixture

const (
	LostDuringApply = "runner lost during apply: re-queue it"
	LostDuringJob   = "launcher lost during job"
)

func handler(c *gin.Context) {
	jsonapi.WriteError(c, 403, "Forbidden", "the hosted pool is read-only")
	jsonapi.WriteErrorNoDetail(c, 404, "Runner not found")
	writeRunnerForbidden(c, "job is not owned by this " + "runner")
	jsonapi.WriteError(c, 403, "Forbidden", fmt.Sprintf("the executor of %s refused", id))
	jsonapi.WriteError(c, 403, "Forbidden", "API key lacks the launcher registration scope (runner:register)")
	jsonapi.WriteError(c, 404, "Not Found", "no route /api/v2/runner/jobs for runner_id")
}

func place() error {
	return fmt.Errorf("copying stackweaver-executor into stackweaver-opentofu-runner: %w", err)
}

func fail() error { return errors.New("refused under hosted.strict") }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	for _, fd := range check(fset, f, scope{writeErrors: true, messages: true, lostReasons: true}, g) {
		lines = append(lines, fd.pos.Line)
	}
	want := []int{4, 9, 10, 11, 12, 21}
	if !slicesEqual(lines, want) {
		t.Errorf("the fixture's findings are on lines %v, want %v", lines, want)
	}
}

func slicesEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// AC31: no guarded backend string uses a retired term.
func TestTerminologyGuard(t *testing.T) {
	root := repoRoot(t)
	g := readGlossary(t, root)
	var offenders []string
	for rel, s := range guarded(t, root) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", rel, err)
		}
		for _, fd := range check(fset, f, s, g) {
			offenders = append(offenders, rel+":"+strconv.Itoa(fd.pos.Line)+": "+strconv.Quote(fd.text)+" uses "+fd.term)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("user-facing backend text uses a retired term (docs/internal/guidelines/terminology.md):\n  %s", strings.Join(offenders, "\n  "))
	}
}
