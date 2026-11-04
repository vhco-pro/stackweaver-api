// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/michielvha/stackweaver/core/envfile"
)

// zitadelInitConfiguration are the values zitadel-init writes to .env that the API does not read
// from the file at start: configuration the operator or the overlay already gave the container,
// and from which Compose derives other values when it creates it (the instance header from
// ZITADEL_EXTERNAL_HOST).
var zitadelInitConfiguration = []string{"ZITADEL_ISSUER", "ZITADEL_EXTERNAL_HOST", "ZITADEL_TLS_MODE"}

// Every value zitadel-init generates into a Compose install's .env is either one the API takes from
// the file when it starts (envfile.Generated) or configuration it deliberately leaves to Compose,
// so a key zitadel-init starts writing has to be placed in one or the other.
func TestEnvFileGeneratedNamesMatchZitadelInit(t *testing.T) {
	root := filepath.Join("..", "..", "..", "scripts", "zitadel-init")
	var src string
	for _, file := range []string{filepath.Join(root, "internal", "output", "compose.go"), filepath.Join(root, "main.go")} {
		b, err := os.ReadFile(filepath.Clean(file)) //nolint:gosec // a fixed path inside this repository
		if os.IsNotExist(err) {
			t.Skip("zitadel-init's source is not in this checkout")
		}
		if err != nil {
			t.Fatal(err)
		}
		src += string(b) + "\n"
	}
	constants := map[string]string{}
	for _, m := range regexp.MustCompile(`const (\w+) = "([A-Z0-9_]+)"`).FindAllStringSubmatch(src, -1) {
		constants[m[1]] = m[2]
	}
	// Every KEY=value pair zitadel-init hands the env file writer: the end-of-run list in
	// WriteComposeEnv and the values each provisioning step records as Zitadel returns them.
	var written []string
	for _, lit := range regexp.MustCompile(`(?s)\[\]\[2\]string\{(.*?)\}\)?(?:, err|; err|\n\t\})`).FindAllStringSubmatch(src, -1) {
		for _, m := range regexp.MustCompile(`\{\s*(?:"([A-Z][A-Z0-9_]+)"|(composeBFFSecretKey))\s*,`).FindAllStringSubmatch(lit[1], -1) {
			name := m[1]
			if name == "" {
				name = constants[m[2]]
			}
			if name == "" {
				t.Fatalf("cannot resolve the env key %q", m[2])
			}
			if !slices.Contains(written, name) {
				written = append(written, name)
			}
		}
	}
	if !slices.Contains(written, "STACKWEAVER_HOSTED_SECRET") || !slices.Contains(written, "ZITADEL_ISSUER") {
		t.Fatalf("parsed only %v from zitadel-init's env writes", written)
	}

	generated := envfile.Generated()
	for _, name := range written {
		if !slices.Contains(generated, name) && !slices.Contains(zitadelInitConfiguration, name) {
			t.Errorf("zitadel-init writes %s, which is neither in envfile.Generated nor configuration left to Compose", name)
		}
	}
	for _, name := range generated {
		if !slices.Contains(written, name) {
			t.Errorf("envfile.Generated names %s, which zitadel-init does not write", name)
		}
	}
}
