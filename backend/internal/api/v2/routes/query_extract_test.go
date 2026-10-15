// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Which query parameters a handler reads, taken from the handler's own code (#869, AC4).
//
// gin has no hook on c.Query, so a recording cannot show what a handler would have read from a
// query string nobody sent. The code can: a parameter is read by a call to one of *gin.Context's
// query accessors with the name as a constant, in the handler or in a function the handler passes
// its context to. This pass follows those calls with type information and collects the names.
//
// It lives in a test file because nothing in the server needs it; the golden harness writes its
// result into the route manifest and the generator reads it from there. The file carries no build
// tag so that its own tests run in the unit suite, with no database.

package routes_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

const ginContextType = "*github.com/gin-gonic/gin.Context"

// queryAccessors are the methods of *gin.Context that read one named query parameter.
var queryAccessors = map[string]bool{
	"Query": true, "DefaultQuery": true, "GetQuery": true,
	"QueryArray": true, "GetQueryArray": true,
	"QueryMap": true, "GetQueryMap": true,
}

// querySite is a place in the code where the pass could not read a parameter name.
type querySite struct {
	Func string // the function whose body holds it, as the type checker names it
	Pos  string // file:line
	What string
}

func (s querySite) String() string { return s.Pos + ": " + s.What }

// queryReads is what one handler's call tree does with the query string.
type queryReads struct {
	// Names are the parameters read by a constant name, sorted.
	Names []string
	// Whole lists where the query string is taken as a whole (c.Request.URL.Query(), RawQuery),
	// so the names cannot be known from the code.
	Whole []querySite
	// Dynamic lists accessor calls whose name is computed at run time.
	Dynamic []querySite
	// Unfollowed lists calls that hand the context to something the pass cannot see into: an
	// interface method, a function value, a function with no source in the loaded packages.
	Unfollowed []querySite
}

// complete reports whether Names is the whole answer.
func (q queryReads) complete() bool {
	return len(q.Whole) == 0 && len(q.Dynamic) == 0 && len(q.Unfollowed) == 0
}

// queryRule says what a site the pass cannot read does. It is attached to the function the site
// is in, so it applies to every route that reaches that function and to nothing else.
type queryRule struct {
	// names are the parameters the site reads.
	names []string
	// namesFrom is a package-level map whose keys are the names, read from the source so that
	// the list is not restated here.
	namesFrom string
	// forwarded marks a site that hands the whole query string on, unread.
	forwarded bool
}

// queryRules are the sites with no literal to read. There are three shapes, and this is the
// one place each is declared.
var queryRules = map[string]queryRule{
	// Tag filters are numbered pairs, read in a loop with the index formatted into the name.
	// The pair is declared at index 0, which is where the numbering starts.
	"github.com/michielvha/stackweaver/backend/internal/api/v2/handlers/terraform.wsParseTaggedFilter": {
		names: []string{"filter[tagged][0][key]", "filter[tagged][0][value]"},
	},
	// The auth proxy hands the authorize and end-session query strings to the identity provider
	// as they arrive. Those operations declare no parameters and say they are passed through.
	"(*github.com/michielvha/stackweaver/backend/internal/api/v2/handlers.AuthProxy).Authorize":  {forwarded: true},
	"(*github.com/michielvha/stackweaver/backend/internal/api/v2/handlers.AuthProxy).EndSession": {forwarded: true},
	// The settings proxy forwards only the parameters on its allowlist.
	"(*github.com/michielvha/stackweaver/backend/internal/api/v2/handlers.AuthProxy).settingsProxy": {
		namesFrom: "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers.allowedSettingsQueryParams",
	},
}

// queryRouteRules are parameters read before the handler runs, by middleware gin does not name
// as the route's handler. The authentication middleware accepts a token in the query string for
// the run log route, so that a log URL with an embedded token works.
var queryRouteRules = map[string][]string{
	"GET /api/v2/runs/:id/logs": {"token"},
}

// routeQuery is what the document declares for one route.
type routeQuery struct {
	Names     []string
	Forwarded bool
}

// forRoute resolves a route to the parameters it reads: the names its handler's call tree reads,
// plus what the rules declare for the sites in that tree the pass cannot read. Anything left
// over is a problem: a site with no rule, or a call the pass cannot follow.
//
// used, when not nil, collects the rules that applied, so a rule nothing reaches can be reported.
func (e *queryExtractor) forRoute(method, path, ginHandler string, used map[string]bool) (routeQuery, []string) {
	reads, err := e.forHandler(ginHandler)
	if err != nil {
		return routeQuery{}, []string{err.Error()}
	}
	var out routeQuery
	var problems []string
	names := append([]string{}, reads.Names...)
	for _, site := range append(append([]querySite{}, reads.Whole...), reads.Dynamic...) {
		rule, ok := queryRules[site.Func]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s (in %s), and no rule says what it reads", site, site.Func))
			continue
		}
		if used != nil {
			used[site.Func] = true
		}
		names = append(names, rule.names...)
		if rule.namesFrom != "" {
			keys, ok := e.mapKeys[rule.namesFrom]
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: the rule reads its names from %s, which is not a map with constant keys", site, rule.namesFrom))
			}
			names = append(names, keys...)
		}
		out.Forwarded = out.Forwarded || rule.forwarded
	}
	for _, site := range reads.Unfollowed {
		problems = append(problems, site.String())
	}
	if extra, ok := queryRouteRules[method+" "+path]; ok {
		if used != nil {
			used[method+" "+path] = true
		}
		names = append(names, extra...)
	}
	out.Names = sortedUnique(names)
	return out, problems
}

type funcSource struct {
	body *ast.BlockStmt
	lits []*ast.FuncLit // the function literals inside the body, outermost first
	info *types.Info
	fset *token.FileSet
}

// queryExtractor holds the type-checked source of every function in the loaded packages.
type queryExtractor struct {
	funcs map[string]*funcSource // by (*types.Func).FullName
	memo  map[string]*queryReads
	// mapKeys holds the constant string keys of every package-level map literal, by
	// "pkg/path.name", for the rules that read a list out of the source.
	mapKeys map[string][]string
}

// loadQueryExtractor type-checks the packages matching patterns, from dir.
//
// Names are matched with types and not by spelling: without them any method called Query,
// database/sql's included, would be taken for gin's.
func loadQueryExtractor(dir string, patterns ...string) (*queryExtractor, error) {
	cfg := &packages.Config{
		Dir: dir,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, fmt.Errorf("loading packages: %w", err)
	}
	e := &queryExtractor{funcs: map[string]*funcSource{}, memo: map[string]*queryReads{}, mapKeys: map[string][]string{}}
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			return nil, fmt.Errorf("package %s does not type-check: %v", pkg.PkgPath, pkg.Errors[0])
		}
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
					e.collectMapKeys(pkg, gd)
					continue
				}
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				fn, ok := pkg.TypesInfo.Defs[fd.Name].(*types.Func)
				if !ok {
					continue
				}
				src := &funcSource{body: fd.Body, info: pkg.TypesInfo, fset: pkg.Fset}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if lit, ok := n.(*ast.FuncLit); ok {
						src.lits = append(src.lits, lit)
					}
					return true
				})
				e.funcs[fn.FullName()] = src
			}
		}
	}
	if len(e.funcs) == 0 {
		return nil, fmt.Errorf("no function found in %v", patterns)
	}
	return e, nil
}

// collectMapKeys records the constant string keys of the map literals a var declaration holds.
func (e *queryExtractor) collectMapKeys(pkg *packages.Package, decl *ast.GenDecl) {
	for _, spec := range decl.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || len(vs.Names) != len(vs.Values) {
			continue
		}
		for i, value := range vs.Values {
			lit, ok := value.(*ast.CompositeLit)
			if !ok {
				continue
			}
			if _, isMap := pkg.TypesInfo.TypeOf(lit).Underlying().(*types.Map); !isMap {
				continue
			}
			var keys []string
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if tv := pkg.TypesInfo.Types[kv.Key]; tv.Value != nil && tv.Value.Kind() == constant.String {
					keys = append(keys, constant.StringVal(tv.Value))
				}
			}
			e.mapKeys[pkg.PkgPath+"."+vs.Names[i].Name] = sortedUnique(keys)
		}
	}
}

// closureSuffix matches what the runtime appends to a function's name for a function literal
// inside it: .func1, .func2.1, .func1.func3 and so on.
var closureSuffix = regexp.MustCompile(`(\.func\d+|\.\d+)+$`)

// handlerFuncName turns the name gin reports for a route's last handler into the name the type
// checker gives the same function, and reports whether the handler is a function literal inside it.
//
// gin's name is the runtime's: "pkg/path.(*Type).Method-fm" for a method value, "pkg/path.Func"
// for a function, and the enclosing function's name plus ".funcN" for a literal.
func handlerFuncName(ginName string) (fullName string, isLiteral bool) {
	name := strings.TrimSuffix(ginName, "-fm")
	if loc := closureSuffix.FindStringIndex(name); loc != nil {
		name, isLiteral = name[:loc[0]], true
	}
	slash := strings.LastIndex(name, "/")
	dot := strings.Index(name[slash+1:], ".")
	if dot < 0 {
		return name, isLiteral
	}
	pkg, rest := name[:slash+1+dot], name[slash+1+dot+1:]
	switch {
	case strings.HasPrefix(rest, "(*"):
		// (*Type).Method
		typeName, method, _ := strings.Cut(strings.TrimPrefix(rest, "(*"), ").")
		return "(*" + pkg + "." + typeName + ")." + method, isLiteral
	case strings.Contains(rest, "."):
		// Type.Method, a value receiver
		typeName, method, _ := strings.Cut(rest, ".")
		return "(" + pkg + "." + typeName + ")." + method, isLiteral
	default:
		return pkg + "." + rest, isLiteral
	}
}

// forHandler returns what the handler gin names reads from the query string.
//
// A name that resolves to no function in the loaded packages is an error, so that a new way of
// wrapping a handler cannot hide it from the document without anyone noticing.
func (e *queryExtractor) forHandler(ginName string) (queryReads, error) {
	fullName, isLiteral := handlerFuncName(ginName)
	src, ok := e.funcs[fullName]
	if !ok {
		return queryReads{}, fmt.Errorf("handler %s resolves to %s, which is no function in the loaded packages", ginName, fullName)
	}
	if !isLiteral {
		return *e.reads(fullName), nil
	}

	// A handler written inline where it is registered. The runtime numbers the literals of a
	// function, and that numbering is not something to parse a document out of, so the pass
	// asks a question whose answer does not depend on it: does any literal in the enclosing
	// function touch the query string? If none does, this one does not.
	acc := &queryReads{}
	for _, lit := range src.lits {
		e.walk(lit.Body, fullName, src, acc, map[string]bool{})
	}
	finish(acc)
	if len(acc.Names) > 0 || !acc.complete() {
		return *acc, fmt.Errorf("handler %s is a function literal inside %s, where a literal reads the query string; "+
			"name the handler so its parameters can be attributed to it", ginName, fullName)
	}
	return *acc, nil
}

// reads is the memoised result for one named function, with everything it calls folded in.
func (e *queryExtractor) reads(fullName string) *queryReads {
	if got, ok := e.memo[fullName]; ok {
		return got
	}
	acc := &queryReads{}
	e.walk(e.funcs[fullName].body, fullName, e.funcs[fullName], acc, map[string]bool{fullName: true})
	finish(acc)
	e.memo[fullName] = acc
	return acc
}

func finish(q *queryReads) {
	q.Names = sortedUnique(q.Names)
	for _, sites := range []*[]querySite{&q.Whole, &q.Dynamic, &q.Unfollowed} {
		sort.Slice(*sites, func(i, j int) bool { return (*sites)[i].String() < (*sites)[j].String() })
	}
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Strings(in)
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// walk collects into acc what body, which belongs to the function named in, does with the query
// string, following the context into the functions it is passed to. visiting stops a recursive
// function from being followed forever.
func (e *queryExtractor) walk(body ast.Node, in string, src *funcSource, acc *queryReads, visiting map[string]bool) {
	isGinContext := func(expr ast.Expr) bool {
		t := src.info.TypeOf(expr)
		return t != nil && t.String() == ginContextType
	}
	// requestURL reports whether expr is `<gin context>.Request.URL`.
	requestURL := func(expr ast.Expr) bool {
		url, ok := ast.Unparen(expr).(*ast.SelectorExpr)
		if !ok || url.Sel.Name != "URL" {
			return false
		}
		req, ok := ast.Unparen(url.X).(*ast.SelectorExpr)
		return ok && req.Sel.Name == "Request" && isGinContext(req.X)
	}
	site := func(n ast.Node, format string, args ...any) querySite {
		p := src.fset.Position(n.Pos())
		return querySite{Func: in, Pos: fmt.Sprintf("%s:%d", shortPath(p.Filename), p.Line), What: fmt.Sprintf(format, args...)}
	}
	passesContext := func(call *ast.CallExpr) bool {
		for _, arg := range call.Args {
			if isGinContext(arg) {
				return true
			}
		}
		return false
	}
	// follow folds in a statically known callee that was handed the context.
	follow := func(call *ast.CallExpr, fn *types.Func) {
		name := fn.Origin().FullName()
		callee, ok := e.funcs[name]
		if !ok {
			acc.Unfollowed = append(acc.Unfollowed, site(call, "the context is passed to %s, which has no source in the loaded packages", name))
			return
		}
		if visiting[name] {
			return
		}
		visiting[name] = true
		e.walk(callee.body, name, callee, acc, visiting)
		delete(visiting, name)
	}

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if node.Sel.Name == "RawQuery" && requestURL(node.X) {
				acc.Whole = append(acc.Whole, site(node, "reads the raw query string"))
			}

		case *ast.CallExpr:
			switch fun := ast.Unparen(node.Fun).(type) {
			case *ast.SelectorExpr:
				sel := src.info.Selections[fun]
				if sel == nil {
					// pkg.Func(...): a qualified identifier, not a selection.
					if fn, ok := src.info.Uses[fun.Sel].(*types.Func); ok && passesContext(node) {
						follow(node, fn)
					}
					return true
				}
				fn, isMethod := sel.Obj().(*types.Func)
				switch {
				case !isMethod:
					// A field holding a function.
					if passesContext(node) {
						acc.Unfollowed = append(acc.Unfollowed, site(node, "the context is passed to a function value"))
					}
				case isGinContext(fun.X) && queryAccessors[fn.Name()]:
					if len(node.Args) == 0 {
						return true
					}
					tv := src.info.Types[node.Args[0]]
					if tv.Value != nil && tv.Value.Kind() == constant.String {
						acc.Names = append(acc.Names, constant.StringVal(tv.Value))
					} else {
						acc.Dynamic = append(acc.Dynamic, site(node, "the parameter name is computed at run time"))
					}
				case fn.Name() == "Query" && requestURL(fun.X):
					acc.Whole = append(acc.Whole, site(node, "reads the whole query string"))
				case passesContext(node):
					if types.IsInterface(sel.Recv()) {
						acc.Unfollowed = append(acc.Unfollowed, site(node, "the context is passed to %s through an interface", fn.Name()))
					} else {
						follow(node, fn)
					}
				}

			case *ast.Ident:
				if !passesContext(node) {
					return true
				}
				switch obj := src.info.Uses[fun].(type) {
				case *types.Func:
					follow(node, obj)
				case *types.Var:
					acc.Unfollowed = append(acc.Unfollowed, site(node, "the context is passed to a function value"))
				}
			}
		}
		return true
	})
}

// shortPath keeps a position readable and the same on every machine.
func shortPath(filename string) string {
	if i := strings.Index(filename, "/backend/"); i >= 0 {
		return filename[i+1:]
	}
	return filename
}

// --- tests ---------------------------------------------------------------------------------

const queryExtractTestPkg = "github.com/michielvha/stackweaver/backend/internal/api/v2/routes/testdata/queryextract/handlers"

// TestQueryExtraction runs the pass over small sources, one function per way a handler in the
// tree reads the query string or hides that it does.
func TestQueryExtraction(t *testing.T) {
	if testing.Short() {
		t.Skip("type-checks source, which needs the go command")
	}
	e, err := loadQueryExtractor(".", "./testdata/queryextract/handlers", "./testdata/queryextract/paging")
	if err != nil {
		t.Fatalf("load the test sources: %v", err)
	}
	method := func(name string) string { return queryExtractTestPkg + ".(*Handler)." + name + "-fm" }

	t.Run("literal names, through a constant, a method and a helper in another package", func(t *testing.T) {
		got, err := e.forHandler(method("List"))
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"filter[email]", "filter[status]", "include", "page[number]", "page[size]", "search", "sort"}
		if !reflect.DeepEqual(got.Names, want) {
			t.Errorf("names = %v, want %v", got.Names, want)
		}
		if !got.complete() {
			t.Errorf("reported as incomplete: %+v", got)
		}
	})

	t.Run("a method called Query that is not gin's is not a parameter", func(t *testing.T) {
		got, _ := e.forHandler(method("List"))
		for _, n := range got.Names {
			if n == "select 1" {
				t.Error("the argument of a Query method on another type was taken for a query parameter")
			}
		}
	})

	t.Run("a plain function", func(t *testing.T) {
		got, err := e.forHandler(queryExtractTestPkg + ".Plain")
		if err != nil || !reflect.DeepEqual(got.Names, []string{"plain"}) {
			t.Errorf("got %v, %v; want [plain]", got.Names, err)
		}
	})

	t.Run("a handler that reads nothing", func(t *testing.T) {
		got, err := e.forHandler(method("None"))
		if err != nil || len(got.Names) != 0 || !got.complete() {
			t.Errorf("got %+v, %v; want nothing read and nothing reported", got, err)
		}
	})

	t.Run("a recursive handler terminates", func(t *testing.T) {
		got, err := e.forHandler(method("Recursive"))
		if err != nil || !reflect.DeepEqual(got.Names, []string{"depth"}) {
			t.Errorf("got %v, %v; want [depth]", got.Names, err)
		}
	})

	// What the pass cannot name it has to report, because the alternative is a document that
	// declares no parameter where the handler reads one.
	reported := []struct {
		name    string
		handler string
		field   func(queryReads) []querySite
		says    string
	}{
		{"a name computed at run time", method("Dynamic"), func(q queryReads) []querySite { return q.Dynamic }, "computed at run time"},
		{"the whole query string", method("Forward"), func(q queryReads) []querySite { return q.Whole }, "whole query string"},
		{"the raw query string", method("ForwardRaw"), func(q queryReads) []querySite { return q.Whole }, "raw query string"},
		{"a call through an interface", method("ThroughInterface"), func(q queryReads) []querySite { return q.Unfollowed }, "through an interface"},
		{"a call through a function value", method("ThroughValue"), func(q queryReads) []querySite { return q.Unfollowed }, "function value"},
	}
	for _, c := range reported {
		t.Run(c.name+" is reported", func(t *testing.T) {
			got, err := e.forHandler(c.handler)
			if err != nil {
				t.Fatal(err)
			}
			if got.complete() {
				t.Fatalf("nothing reported: %+v", got)
			}
			list := c.field(got)
			if len(list) != 1 || !strings.Contains(list[0].What, c.says) || !strings.Contains(list[0].Pos, "handlers.go:") {
				t.Fatalf("reported %v, want one entry saying %q with its position", list, c.says)
			}
			if want, _ := handlerFuncName(c.handler); list[0].Func != want {
				t.Errorf("the site is attributed to %s, want the function it is in, %s", list[0].Func, want)
			}
			// With no rule for the function the site is in, the route is a problem and not a guess.
			if _, problems := e.forRoute("GET", "/x", c.handler, nil); len(problems) != 1 {
				t.Errorf("forRoute reported %v, want exactly one problem", problems)
			}
		})
	}

	t.Run("a rule declares what an unreadable site reads", func(t *testing.T) {
		dynamic, _ := handlerFuncName(method("Dynamic"))
		forward, _ := handlerFuncName(method("Forward"))
		queryRules[dynamic] = queryRule{names: []string{"filter[tagged][0][key]"}}
		queryRules[forward] = queryRule{forwarded: true}
		queryRouteRules["GET /logs"] = []string{"token"}
		t.Cleanup(func() {
			delete(queryRules, dynamic)
			delete(queryRules, forward)
			delete(queryRouteRules, "GET /logs")
		})

		used := map[string]bool{}
		got, problems := e.forRoute("GET", "/tagged", method("Dynamic"), used)
		if len(problems) != 0 || !reflect.DeepEqual(got.Names, []string{"filter[tagged][0][key]"}) || got.Forwarded {
			t.Errorf("a ruled dynamic site: got %+v, problems %v", got, problems)
		}
		got, problems = e.forRoute("GET", "/forward", method("Forward"), used)
		if len(problems) != 0 || len(got.Names) != 0 || !got.Forwarded {
			t.Errorf("a ruled forwarding site: got %+v, problems %v", got, problems)
		}
		got, problems = e.forRoute("GET", "/logs", method("None"), used)
		if len(problems) != 0 || !reflect.DeepEqual(got.Names, []string{"token"}) {
			t.Errorf("a route rule: got %+v, problems %v", got, problems)
		}
		if !used[dynamic] || !used[forward] || !used["GET /logs"] {
			t.Errorf("used = %v, want all three rules marked as applied", used)
		}
	})

	t.Run("a rule can take its names from a map in the source", func(t *testing.T) {
		const allowlist = "github.com/michielvha/stackweaver/backend/internal/api/v2/routes/testdata/queryextract/handlers.allowed"
		if got := e.mapKeys[allowlist]; !reflect.DeepEqual(got, []string{"ctx.orgId", "locale"}) {
			t.Fatalf("map keys = %v, want [ctx.orgId locale]", got)
		}
		forward, _ := handlerFuncName(method("Forward"))
		queryRules[forward] = queryRule{namesFrom: allowlist}
		t.Cleanup(func() { delete(queryRules, forward) })
		got, problems := e.forRoute("GET", "/settings", method("Forward"), nil)
		if len(problems) != 0 || !reflect.DeepEqual(got.Names, []string{"ctx.orgId", "locale"}) {
			t.Errorf("got %+v, problems %v", got, problems)
		}
	})

	t.Run("an inline handler that reads nothing resolves", func(t *testing.T) {
		got, err := e.forHandler(queryExtractTestPkg + ".Register.func1")
		if err != nil || len(got.Names) != 0 {
			t.Errorf("got %+v, %v; want nothing read", got, err)
		}
	})

	t.Run("an inline handler that reads is refused", func(t *testing.T) {
		if _, err := e.forHandler(queryExtractTestPkg + ".RegisterReading.func1"); err == nil {
			t.Error("a function literal that reads a parameter was accepted; its parameter would be attributed to nothing")
		}
	})

	t.Run("a wrapper that hides the handler is refused", func(t *testing.T) {
		// Registered last on a route, Gate's closure is what gin names, and the handler it
		// calls is a function value.
		if _, err := e.forHandler(queryExtractTestPkg + ".Gate.func1"); err == nil {
			t.Error("a wrapping closure was accepted; the handler behind it would go undocumented")
		}
	})

	t.Run("a name that resolves to no function is an error", func(t *testing.T) {
		if _, err := e.forHandler(method("Gone")); err == nil {
			t.Error("a handler name with no function behind it was accepted")
		}
	})
}

// TestHandlerFuncName pins the translation from the runtime's function names to the type checker's.
func TestHandlerFuncName(t *testing.T) {
	cases := []struct {
		gin, want string
		literal   bool
	}{
		{"example.com/m/pkg/handlers.(*WorkspaceHandler).List-fm", "(*example.com/m/pkg/handlers.WorkspaceHandler).List", false},
		{"example.com/m/pkg/handlers.Value.Get-fm", "(example.com/m/pkg/handlers.Value).Get", false},
		{"example.com/m/pkg/handlers.Ping", "example.com/m/pkg/handlers.Ping", false},
		{"example.com/m/pkg/routes.SetupRoutes.func1", "example.com/m/pkg/routes.SetupRoutes", true},
		{"example.com/m/pkg/routes.SetupRoutes.func2.1", "example.com/m/pkg/routes.SetupRoutes", true},
		{"example.com/m/pkg/handlers.(*H).Wrap.func1", "(*example.com/m/pkg/handlers.H).Wrap", true},
		{"gopkg.in/yaml.v3/handlers.(*H).Get-fm", "(*gopkg.in/yaml.v3/handlers.H).Get", false},
	}
	for _, c := range cases {
		got, literal := handlerFuncName(c.gin)
		if got != c.want || literal != c.literal {
			t.Errorf("handlerFuncName(%q) = %q, %v; want %q, %v", c.gin, got, literal, c.want, c.literal)
		}
	}
}
