// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The deployment's runner settings read back, read-only, on platform-settings (#933, D0, D15): what
// the chart and env files set, and not one secret among them.
func TestDeploymentSettings(t *testing.T) {
	env := map[string]string{ //nolint:gosec // G101: test fixtures, made-up values
		"IMAGES_ALLOWED_REGISTRIES":                      "ghcr.io/acme, quay.io",
		"STACKWEAVER_HOSTED_DEFAULT_MAX_CONCURRENT_JOBS": "6",
		"STACKWEAVER_RUN_TIMEOUT_DEFAULT":                "5400",
		"STACKWEAVER_SYNC_TIMEOUT":                       "900",
		"STACKWEAVER_JOB_LOG_MAX_BYTES":                  "1048576",
		"CACHE_SIZE_LIMIT":                               "20Gi",
		"RUNNER_RATE_LIMIT_RPS":                          "50",
		"TOFU_RELEASES_URL":                              "https://mirror.internal/tofu",
		"STACKWEAVER_GALAXY_SERVERS":                     "hub=https://hub.internal/api/",
		"STACKWEAVER_GALAXY_SERVER_HUB_TOKEN":            "hub-s3cret",
		"STACKWEAVER_JOB_HTTPS_PROXY":                    "http://proxyuser:proxy-s3cret@proxy.internal:3128",
		"STACKWEAVER_JOB_CA_FILE":                        "/etc/ca.pem",
	}
	readFile := func(string) ([]byte, error) { return []byte("-----BEGIN CERTIFICATE-----\nca-body\n"), nil }
	got := deploymentSettings(func(k string) string { return env[k] }, readFile)
	if len(got.ImagesAllowedRegistries) != 2 || got.HostedDefaultMaxConcurrentJobs != 6 || got.RunTimeoutDefault != 5400 ||
		got.SyncTimeout != 900 || got.JobLogMaxBytes != 1<<20 || got.CacheSizeLimit != 20<<30 {
		t.Errorf("settings = %+v", got)
	}
	if got.RunnerRateLimit.RPS != 50 || got.RunnerRateLimit.Burst != 40 || got.JobRateLimit.RPS != 20 {
		t.Errorf("rate budgets = %+v / %+v", got.RunnerRateLimit, got.JobRateLimit)
	}
	if got.Mirror == nil || !got.Mirror.HasCACertificates || len(got.Mirror.GalaxyServers) != 1 {
		t.Fatalf("mirror = %+v", got.Mirror)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"hub-s3cret", "proxy-s3cret", "ca-body"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("%q is in the platform settings: %s", secret, raw)
		}
	}
	for _, want := range []string{`"images-allowed-registries"`, `"runner-rate-limit"`, `"https://hub.internal/api/"`, `"http://proxy.internal:3128"`, `"has-ca-certificates":true`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("no %s in %s", want, raw)
		}
	}

	d := deploymentSettings(func(string) string { return "" }, func(string) ([]byte, error) { return nil, errors.New("unset") })
	if d.ImagesAllowedRegistries == nil || d.Mirror != nil || d.RunTimeoutDefault != 7200 || d.SyncTimeout != 3600 || d.CacheSizeLimit != 50<<30 {
		t.Errorf("defaults = %+v, want an empty allowlist, no mirror and the documented defaults", d)
	}
}
