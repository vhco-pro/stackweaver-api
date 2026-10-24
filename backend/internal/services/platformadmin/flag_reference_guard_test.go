// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package platformadmin

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// flagReference matches a read or write of the platform administrator columns on a user value:
// a field selector (`u.PlatformAdmin`, `u.PlatformAdminDeclared`) or a keyed literal
// (`PlatformAdmin: true`). Method names that merely contain the word, such as IsPlatformAdmin or
// SetPlatformAdmin, do not match.
var flagReference = regexp.MustCompile(`(\.PlatformAdmin(Declared)?\b)|(\bPlatformAdmin(Declared)?\s*:)`)

// flagAllowed lists the production files, relative to the repository root, that may touch the
// columns: the model, the repository that stores them, this package, and the account resource,
// which reports the caller's own status. The seeder interface in auth never touches them.
var flagAllowed = []string{
	"core/models/user.go",
	"core/repository/user.go",
	"backend/internal/services/platformadmin/",
	"backend/internal/api/v2/handlers/account.go",
}

// AC3: the flag is interpreted in one place. Every install-wide check goes through Require or
// IsPlatformAdmin, so a second interpretation (a handler testing the field itself) is the defect
// class this guard keeps out. Test files are not interpretation and are not scanned.
func TestPlatformAdminFlagIsInterpretedInOnePlace(t *testing.T) {
	root := repoRoot(t)
	var offenders []string
	for _, dir := range []string{"core", "backend"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			for _, allowed := range flagAllowed {
				if rel == allowed || (strings.HasSuffix(allowed, "/") && strings.HasPrefix(rel, allowed)) {
					return nil
				}
			}
			src, err := os.ReadFile(path) //nolint:gosec // G304: walking the repository's own sources
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(src), "\n") {
				if flagReference.MatchString(line) {
					offenders = append(offenders, rel+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("the platform administrator flag is read outside the platformadmin package:\n  %s\n"+
			"Call platformadmin.Service.Require, IsPlatformAdmin or platformadmin.Status instead.",
			strings.Join(offenders, "\n  "))
	}
}

// AC3: the auth service reaches this package only through its own PlatformAdminSeeder interface;
// an import would be a cycle, since this package imports auth.
func TestAuthDoesNotImportPlatformAdmin(t *testing.T) {
	root := repoRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "backend/internal/services/auth/*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("list the auth package: %v (%d files)", err, len(files))
	}
	for _, f := range files {
		src, err := os.ReadFile(f) //nolint:gosec // G304: a file of the repository's auth package
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), `"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"`) {
			t.Errorf("%s imports the platformadmin package", filepath.Base(f))
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.work")); err != nil {
		t.Fatalf("repository root not found at %s: %v", dir, err)
	}
	return dir
}
