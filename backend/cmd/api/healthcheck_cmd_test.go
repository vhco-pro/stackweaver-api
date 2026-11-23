// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// addressEnv lists every variable the server and the healthcheck read for the listen address, so
// each case starts from a clean environment.
var addressEnv = []string{"CONFIG_PATH", "SERVER_HOST", "SERVER_PORT", "STACKWEAVER_ENV_FILE"}

func clearAddressEnv(t *testing.T) {
	t.Helper()
	for _, k := range addressEnv {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("unsetting %s: %v", k, err)
		}
	}
}

// inDir runs the case from dir, so the implicit default path config/config.yaml is dir's.
func inDir(t *testing.T, dir string) {
	t.Helper()
	t.Chdir(dir)
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

var (
	// pkgDir is this package's directory, read before any test changes the working directory.
	pkgDir, _ = os.Getwd()
	buildOnce sync.Once
	binPath   string
	errBuild  error
)

// apiBinary builds the API binary once per test run.
func apiBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sw-api-healthcheck-")
		if err != nil {
			errBuild = err
			return
		}
		binPath = filepath.Join(dir, "stackweaver-api")
		cmd := exec.CommandContext(context.Background(), "go", "build", "-o", binPath, ".") //nolint:gosec // G204: builds this package into a test temp dir
		cmd.Dir = pkgDir
		out, err := cmd.CombinedOutput()
		if err != nil {
			errBuild = errors.New(string(out))
		}
	})
	if errBuild != nil {
		t.Fatalf("building the API binary: %v", errBuild)
	}
	return binPath
}

// runHealthcheckBinary runs `stackweaver-api healthcheck` in dir with the test's environment.
func runHealthcheckBinary(t *testing.T, dir string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, apiBinary(t), "healthcheck") //nolint:gosec // G204: runs the binary this test just built
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, stderr.String()
	case errors.As(err, &exit):
		return exit.ExitCode(), stderr.String()
	default:
		t.Fatalf("running healthcheck: %v", err)
		return -1, ""
	}
}

// routeListenerAt serves code on /readyz and 404 elsewhere at addr.
func routeListenerAt(t *testing.T, addr string, code int) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("listening on %s: %v", addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}}
	srv.Start()
	t.Cleanup(srv.Close)
}

// freePort returns a port that is free on host at the moment of the call.
func freePort(t *testing.T, host string) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("finding a free port on %s: %v", host, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func nonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
			return n.IP.String()
		}
	}
	t.Fatal("this host has no non-loopback IPv4 address")
	return ""
}

func TestDefaultConfigurationAddresses(t *testing.T) {
	clearAddressEnv(t)
	inDir(t, t.TempDir())
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loading the default configuration: %v", err)
	}
	if got := serverListenAddr(cfg); got != "0.0.0.0:8022" {
		t.Errorf("listen address = %q, want 0.0.0.0:8022", got)
	}
	url, err := healthcheckURL(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if url != "http://127.0.0.1:8022/readyz" {
		t.Errorf("healthcheck URL = %q, want http://127.0.0.1:8022/readyz", url)
	}
}

// TestServerAndHealthcheckAgree configures each address form, checks the exact listen and dial
// strings, binds a listener where the server would listen, and runs the real binary against it.
func TestServerAndHealthcheckAgree(t *testing.T) {
	ip := nonLoopbackIPv4(t)
	cases := []struct {
		name       string
		bindHost   string // where a free port is found
		setup      func(t *testing.T, dir string, port int)
		wantListen string // with %d for the port
		wantURL    string
	}{
		{"SERVER_PORT", "127.0.0.1", func(t *testing.T, _ string, p int) {
			t.Setenv("SERVER_PORT", strconv.Itoa(p))
		}, "0.0.0.0:%d", "http://127.0.0.1:%d/readyz"},
		{"CONFIG_PATH file port", "127.0.0.1", func(t *testing.T, dir string, p int) {
			path := filepath.Join(dir, "custom.yaml")
			writeFile(t, path, "server:\n  port: "+strconv.Itoa(p)+"\n", 0o600)
			t.Setenv("CONFIG_PATH", path)
		}, "0.0.0.0:%d", "http://127.0.0.1:%d/readyz"},
		{"non-loopback host", ip, func(t *testing.T, _ string, p int) {
			t.Setenv("SERVER_HOST", ip)
			t.Setenv("SERVER_PORT", strconv.Itoa(p))
		}, ip + ":%d", "http://" + ip + ":%d/readyz"},
		{"IPv4 wildcard", "127.0.0.1", func(t *testing.T, _ string, p int) {
			t.Setenv("SERVER_HOST", "0.0.0.0")
			t.Setenv("SERVER_PORT", strconv.Itoa(p))
		}, "0.0.0.0:%d", "http://127.0.0.1:%d/readyz"},
		{"bare IPv6 wildcard", "::1", func(t *testing.T, _ string, p int) {
			t.Setenv("SERVER_HOST", "::")
			t.Setenv("SERVER_PORT", strconv.Itoa(p))
		}, "[::]:%d", "http://[::1]:%d/readyz"},
		{"bracketed IPv6 wildcard", "::1", func(t *testing.T, _ string, p int) {
			t.Setenv("SERVER_HOST", "[::]")
			t.Setenv("SERVER_PORT", strconv.Itoa(p))
		}, "[::]:%d", "http://[::1]:%d/readyz"},
		{"bracketed IPv6 loopback", "::1", func(t *testing.T, _ string, p int) {
			t.Setenv("SERVER_HOST", "[::1]")
			t.Setenv("SERVER_PORT", strconv.Itoa(p))
		}, "[::1]:%d", "http://[::1]:%d/readyz"},
		{"empty host in the file", "127.0.0.1", func(t *testing.T, dir string, p int) {
			writeFile(t, filepath.Join(dir, "config", "config.yaml"), "server:\n  host: \"\"\n  port: "+strconv.Itoa(p)+"\n", 0o600)
		}, "0.0.0.0:%d", "http://127.0.0.1:%d/readyz"},
		{"unparsable SERVER_PORT keeps the file port", "127.0.0.1", func(t *testing.T, dir string, p int) {
			writeFile(t, filepath.Join(dir, "config", "config.yaml"), "server:\n  port: "+strconv.Itoa(p)+"\n", 0o600)
			t.Setenv("SERVER_PORT", "eighty")
		}, "0.0.0.0:%d", "http://127.0.0.1:%d/readyz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAddressEnv(t)
			dir := t.TempDir()
			inDir(t, dir)
			port := freePort(t, tc.bindHost)
			tc.setup(t, dir, port)

			cfg, err := loadConfig()
			if err != nil {
				t.Fatalf("loading configuration: %v", err)
			}
			listen := serverListenAddr(cfg)
			if want := strings.Replace(tc.wantListen, "%d", strconv.Itoa(port), 1); listen != want {
				t.Errorf("listen address = %q, want %q", listen, want)
			}
			url, err := healthcheckURL(cfg)
			if err != nil {
				t.Fatalf("healthcheck URL: %v", err)
			}
			if want := strings.Replace(tc.wantURL, "%d", strconv.Itoa(port), 1); url != want {
				t.Errorf("healthcheck URL = %q, want %q", url, want)
			}

			routeListenerAt(t, listen, http.StatusOK)
			if code, stderr := runHealthcheckBinary(t, dir); code != 0 {
				t.Errorf("healthcheck against a ready listener: exit %d (%s), want 0", code, stderr)
			}
		})
	}
}

func TestHealthcheckFailsOnUnreadyListener(t *testing.T) {
	clearAddressEnv(t)
	dir := t.TempDir()
	inDir(t, dir)
	port := freePort(t, "127.0.0.1")
	t.Setenv("SERVER_PORT", strconv.Itoa(port))
	routeListenerAt(t, "0.0.0.0:"+strconv.Itoa(port), http.StatusServiceUnavailable)
	code, stderr := runHealthcheckBinary(t, dir)
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.HasPrefix(stderr, "healthcheck:") {
		t.Errorf("stderr = %q, want a healthcheck: line", stderr)
	}
}

func TestScopedIPv6URL(t *testing.T) {
	clearAddressEnv(t)
	inDir(t, t.TempDir())
	t.Setenv("SERVER_HOST", "fe80::1%eth0")
	t.Setenv("SERVER_PORT", "8022")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got := serverListenAddr(cfg); got != "[fe80::1%eth0]:8022" {
		t.Errorf("listen address = %q, want [fe80::1%%eth0]:8022", got)
	}
	url, err := healthcheckURL(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if url != "http://[fe80::1%25eth0]:8022/readyz" {
		t.Errorf("healthcheck URL = %q, want http://[fe80::1%%25eth0]:8022/readyz", url)
	}
}

func TestPortZero(t *testing.T) {
	clearAddressEnv(t)
	dir := t.TempDir()
	inDir(t, dir)
	t.Setenv("SERVER_PORT", "0")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got := serverListenAddr(cfg); got != "0.0.0.0:0" {
		t.Errorf("the server's listen address = %q, want 0.0.0.0:0", got)
	}
	code, stderr := runHealthcheckBinary(t, dir)
	if code != 1 || !strings.HasPrefix(stderr, "healthcheck:") {
		t.Errorf("port 0: exit %d (%q), want 1 with a healthcheck: line", code, stderr)
	}
}

// TestConfigurationFailures checks that each unusable configuration makes both the server's loader
// and the healthcheck command fail.
func TestConfigurationFailures(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"explicit CONFIG_PATH missing", func(t *testing.T, dir string) {
			t.Setenv("CONFIG_PATH", filepath.Join(dir, "missing.yaml"))
		}},
		{"explicit CONFIG_PATH without read permission", func(t *testing.T, dir string) {
			path := filepath.Join(dir, "locked.yaml")
			writeFile(t, path, "server:\n  port: 9000\n", 0o000)
			t.Setenv("CONFIG_PATH", path)
		}},
		{"explicit CONFIG_PATH is a directory", func(t *testing.T, dir string) {
			t.Setenv("CONFIG_PATH", dir)
		}},
		{"implicit default path is a directory", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "config", "config.yaml"), 0o750); err != nil {
				t.Fatal(err)
			}
		}},
		{"malformed YAML", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "config", "config.yaml"), "server: [port\n", 0o600)
		}},
	}
	if os.Geteuid() == 0 {
		t.Fatal("run these tests as a non-root user: root reads a file without read permission")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAddressEnv(t)
			dir := t.TempDir()
			inDir(t, dir)
			tc.setup(t, dir)
			if _, err := loadConfig(); err == nil {
				t.Error("the server's loader accepted the configuration")
			}
			code, stderr := runHealthcheckBinary(t, dir)
			if code != 1 || !strings.HasPrefix(stderr, "healthcheck:") {
				t.Errorf("exit %d (%q), want 1 with a healthcheck: line", code, stderr)
			}
		})
	}
}

// TestImplicitDefaultFallbacks checks that a missing or unreadable default file means defaults for
// both the server and the command, which then reaches a listener on SERVER_PORT.
func TestImplicitDefaultFallbacks(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"missing", func(*testing.T, string) {}},
		{"without read permission", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "config", "config.yaml"), "server:\n  port: 9000\n", 0o000)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAddressEnv(t)
			dir := t.TempDir()
			inDir(t, dir)
			tc.setup(t, dir)
			cfg, err := loadConfig()
			if err != nil {
				t.Fatalf("the server's loader: %v", err)
			}
			if cfg.Server.Host != "0.0.0.0" || cfg.Server.Port != 8022 {
				t.Errorf("loaded %s:%d, want the defaults 0.0.0.0:8022", cfg.Server.Host, cfg.Server.Port)
			}
			port := freePort(t, "127.0.0.1")
			t.Setenv("SERVER_PORT", strconv.Itoa(port))
			routeListenerAt(t, "0.0.0.0:"+strconv.Itoa(port), http.StatusOK)
			if code, stderr := runHealthcheckBinary(t, dir); code != 0 {
				t.Errorf("exit %d (%s), want 0", code, stderr)
			}
		})
	}
}

func TestHealthcheckIgnoresTheCredentialsFile(t *testing.T) {
	clearAddressEnv(t)
	dir := t.TempDir()
	inDir(t, dir)
	port := freePort(t, "127.0.0.1")
	t.Setenv("SERVER_PORT", strconv.Itoa(port))
	t.Setenv("STACKWEAVER_ENV_FILE", filepath.Join(dir, "missing.env"))
	routeListenerAt(t, "0.0.0.0:"+strconv.Itoa(port), http.StatusOK)
	if code, stderr := runHealthcheckBinary(t, dir); code != 0 {
		t.Errorf("a missing credentials file changed the result: exit %d (%s), want 0", code, stderr)
	}
}

// TestMainPassesItsDatabaseToTheRoutes checks the wiring /readyz depends on: main hands the GORM
// handle repository.NewDatabase returned to routes.SetupRoutes, whose db.DB() is the pool readiness
// pings (TestMainPoolIsTheHandlesPool in the routes package).
func TestMainPassesItsDatabaseToTheRoutes(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var dbFromNewDatabase, passedToRoutes bool
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if call, ok := n.Rhs[0].(*ast.CallExpr); ok && isSelector(call.Fun, "repository", "NewDatabase") {
				if id, ok := n.Lhs[0].(*ast.Ident); ok && id.Name == "db" {
					dbFromNewDatabase = true
				}
			}
		case *ast.CallExpr:
			if isSelector(n.Fun, "routes", "SetupRoutes") && len(n.Args) > 0 {
				if id, ok := n.Args[0].(*ast.Ident); ok && id.Name == "db" {
					passedToRoutes = true
				}
			}
		}
		return true
	})
	if !dbFromNewDatabase || !passedToRoutes {
		t.Errorf("main must pass the db from repository.NewDatabase to routes.SetupRoutes (from NewDatabase: %v, to SetupRoutes: %v)", dbFromNewDatabase, passedToRoutes)
	}
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg && sel.Sel.Name == name
}
