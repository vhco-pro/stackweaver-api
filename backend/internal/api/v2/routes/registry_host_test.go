// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package routes

import "testing"

// The registry host is the host a job's module sources name the private registry by, and the host
// its registry token is minted for (#933, D2, AC14). The chart and Compose set the app URL and,
// on the chart, the registry host itself; a deployment with neither public URL still names one.
func TestRegistryHostFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"explicit host", map[string]string{"STACKWEAVER_REGISTRY_HOST": "registry.example.test", "STACKWEAVER_APP_URL": "https://app.example.test"}, "registry.example.test"},
		{"explicit URL", map[string]string{"STACKWEAVER_REGISTRY_HOST": "https://registry.example.test/"}, "registry.example.test"},
		{"public API URL", map[string]string{"STACKWEAVER_PUBLIC_URL": "https://api.example.test", "STACKWEAVER_APP_URL": "https://app.example.test"}, "api.example.test"},
		{"API URL", map[string]string{"API_URL": "https://api.example.test:8443/", "STACKWEAVER_APP_URL": "https://app.example.test"}, "api.example.test:8443"},
		{"single origin: the app URL", map[string]string{"STACKWEAVER_APP_URL": "https://stackweaver.127.0.0.1.nip.io"}, "stackweaver.127.0.0.1.nip.io"},
		{"none", map[string]string{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := registryHostFrom(func(k string) string { return tc.env[k] }); got != tc.want {
				t.Errorf("registry host = %q, want %q", got, tc.want)
			}
		})
	}
}
