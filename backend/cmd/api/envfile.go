// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// envFileVar names an env file the API reads once, before anything else, and whose values win
// over the environment the container was created with.
//
// It exists for Docker Compose installs. Compose fixes every container's environment when the
// command starts, before zitadel-init has generated the client IDs and the login service token
// and written them to .env, so the first API container would start without them. Reading the
// same .env at process start, after zitadel-init has finished, gives a working first run from one
// `docker compose up -d`. Kubernetes and the dev stack leave the variable unset.
const envFileVar = "STACKWEAVER_ENV_FILE"

// loadEnvFileFromEnvironment loads the file named by envFileVar, if any.
func loadEnvFileFromEnvironment() error {
	path := os.Getenv(envFileVar)
	if path == "" {
		return nil
	}
	return loadEnvFile(path)
}

// loadEnvFile sets every non-empty KEY=VALUE of the file in the process environment.
//
// It reads the file the way Compose reads an env_file, minus interpolation: blank lines and
// comments are skipped, an `export ` prefix is accepted, the line splits on its first `=`, and
// one matching pair of surrounding quotes is stripped. A key with an empty value is ignored, so
// an empty entry never replaces a default the compose file supplies.
func loadEnvFile(path string) error {
	file, err := os.Open(path) //nolint:gosec // the path comes from the operator's own configuration
	if err != nil {
		return fmt.Errorf("reading the env file named by %s (%s): %w; the API's user must be able to read it (chmod 644 %s)",
			envFileVar, path, err, path)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := parseEnvLine(scanner.Text())
		if !ok || value == "" {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("setting %s from %s: %w", key, path, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading the env file named by %s (%s): %w", envFileVar, path, err)
	}
	return nil
}

// parseEnvLine returns the key and value of one env-file line, or ok=false for a line that
// carries none.
func parseEnvLine(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	line = strings.TrimSpace(strings.TrimPrefix(line, "export "))

	key, value, found := strings.Cut(line, "=")
	if !found {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", "", false
	}
	return key, unquote(strings.TrimSpace(value)), true
}

// unquote strips one matching pair of surrounding single or double quotes.
func unquote(value string) string {
	if len(value) < 2 {
		return value
	}
	first, last := value[0], value[len(value)-1]
	if first == last && (first == '"' || first == '\'') {
		return value[1 : len(value)-1]
	}
	return value
}
