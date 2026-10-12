// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEnvFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing env file: %v", err)
	}
	return path
}

func TestLoadEnvFile(t *testing.T) {
	tests := []struct {
		name   string
		file   string
		preset map[string]string // process environment before loading
		want   map[string]string // expected values after loading
		unset  []string          // keys that must not be set after loading
	}{
		{
			name:   "file wins over a value the container was created with",
			file:   "SW_ENVFILE_TOKEN=fresh\n",
			preset: map[string]string{"SW_ENVFILE_TOKEN": "stale"},
			want:   map[string]string{"SW_ENVFILE_TOKEN": "fresh"},
		},
		{
			name:   "file fills a variable the container got as an empty string",
			file:   "SW_ENVFILE_TOKEN=generated\n",
			preset: map[string]string{"SW_ENVFILE_TOKEN": ""},
			want:   map[string]string{"SW_ENVFILE_TOKEN": "generated"},
		},
		{
			name:   "an empty value in the file never replaces what the environment has",
			file:   "SW_ENVFILE_BUCKET=\n",
			preset: map[string]string{"SW_ENVFILE_BUCKET": "default-from-compose"},
			want:   map[string]string{"SW_ENVFILE_BUCKET": "default-from-compose"},
		},
		{
			name:  "an empty value in the file sets nothing",
			file:  "SW_ENVFILE_EMPTY=\n",
			unset: []string{"SW_ENVFILE_EMPTY"},
		},
		{
			name: "comments and blank lines are skipped",
			file: "# a comment\n\n   # an indented comment\nSW_ENVFILE_A=1\n",
			want: map[string]string{"SW_ENVFILE_A": "1"},
		},
		{
			name: "an export prefix and surrounding whitespace are accepted",
			file: "export SW_ENVFILE_A=1\n  SW_ENVFILE_B = two \n",
			want: map[string]string{"SW_ENVFILE_A": "1", "SW_ENVFILE_B": "two"},
		},
		{
			name: "one matching pair of quotes is stripped",
			file: "SW_ENVFILE_A=\"double quoted\"\nSW_ENVFILE_B='single quoted'\nSW_ENVFILE_C=\"unbalanced\n",
			want: map[string]string{"SW_ENVFILE_A": "double quoted", "SW_ENVFILE_B": "single quoted", "SW_ENVFILE_C": "\"unbalanced"},
		},
		{
			name: "the value keeps everything after the first equals sign",
			file: "SW_ENVFILE_URL=https://example.test/path?a=1&b=2\n",
			want: map[string]string{"SW_ENVFILE_URL": "https://example.test/path?a=1&b=2"},
		},
		{
			name:   "no interpolation",
			file:   "SW_ENVFILE_A=${SW_ENVFILE_OTHER}/path\n",
			preset: map[string]string{"SW_ENVFILE_OTHER": "expanded"},
			want:   map[string]string{"SW_ENVFILE_A": "${SW_ENVFILE_OTHER}/path"},
		},
		{
			name:  "a line without an equals sign is ignored",
			file:  "SW_ENVFILE_NOVALUE\nSW_ENVFILE_A=1\n",
			want:  map[string]string{"SW_ENVFILE_A": "1"},
			unset: []string{"SW_ENVFILE_NOVALUE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, key := range tt.unset {
				t.Setenv(key, "")
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("unsetting %s: %v", key, err)
				}
			}
			for key := range tt.want {
				t.Setenv(key, "")
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("unsetting %s: %v", key, err)
				}
			}
			for key, value := range tt.preset {
				t.Setenv(key, value)
			}

			if err := loadEnvFile(writeEnvFile(t, tt.file)); err != nil {
				t.Fatalf("loadEnvFile: %v", err)
			}

			for key, want := range tt.want {
				if got := os.Getenv(key); got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
			for _, key := range tt.unset {
				if got, ok := os.LookupEnv(key); ok {
					t.Errorf("%s is set to %q, want it unset", key, got)
				}
			}
		})
	}
}

// The API's user reads the file as "other". A file it cannot read must stop startup with an
// error that names the path and the fix, not start without credentials.
func TestLoadEnvFile_UnreadableFileNamesPathAndFix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.env")

	err := loadEnvFile(path)
	if err == nil {
		t.Fatal("loadEnvFile on a missing file returned nil, want an error")
	}
	for _, want := range []string{path, envFileVar, "chmod 644"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// Kubernetes and the dev stack do not set the variable; startup must not look for a file.
func TestLoadEnvFileFromEnvironment_UnsetLoadsNothing(t *testing.T) {
	t.Setenv(envFileVar, "")

	if err := loadEnvFileFromEnvironment(); err != nil {
		t.Fatalf("loadEnvFileFromEnvironment with %s empty: %v", envFileVar, err)
	}
}

func TestLoadEnvFileFromEnvironment_LoadsTheNamedFile(t *testing.T) {
	t.Setenv("SW_ENVFILE_A", "before")
	t.Setenv(envFileVar, writeEnvFile(t, "SW_ENVFILE_A=after\n"))

	if err := loadEnvFileFromEnvironment(); err != nil {
		t.Fatalf("loadEnvFileFromEnvironment: %v", err)
	}
	if got := os.Getenv("SW_ENVFILE_A"); got != "after" {
		t.Errorf("SW_ENVFILE_A = %q, want %q", got, "after")
	}
}
