// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/michielvha/stackweaver/backend/internal/services/auth"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// In release mode the API refuses to start without the credentials browser sign-in needs: the BFF
// client and the login service account's token. Outside release mode a missing one only means
// browser sign-in is unavailable, so the dev stack can still start.
func TestCheckBrowserAuthConfig_RequiredInRelease(t *testing.T) {
	full := map[string]string{
		"ZITADEL_BFF_CLIENT_ID":            "bff-id",
		"ZITADEL_BFF_CLIENT_SECRET":        "bff-secret",
		"ZITADEL_LOGIN_SERVICE_USER_TOKEN": "pat",
		"STACKWEAVER_APP_URL":              "https://app.example.com",
	}
	if _, err := checkBrowserAuthConfig(envOf(full), true); err != nil {
		t.Fatalf("complete release config refused: %v", err)
	}
	for _, missing := range []string{"ZITADEL_BFF_CLIENT_ID", "ZITADEL_BFF_CLIENT_SECRET", "ZITADEL_LOGIN_SERVICE_USER_TOKEN"} {
		t.Run("release without "+missing, func(t *testing.T) {
			env := map[string]string{}
			for k, v := range full {
				env[k] = v
			}
			delete(env, missing)
			_, err := checkBrowserAuthConfig(envOf(env), true)
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("want a refusal naming %s, got %v", missing, err)
			}
		})
		t.Run("dev without "+missing, func(t *testing.T) {
			env := map[string]string{}
			for k, v := range full {
				env[k] = v
			}
			delete(env, missing)
			if _, err := checkBrowserAuthConfig(envOf(env), false); err != nil {
				t.Fatalf("outside release a missing %s must not stop the API: %v", missing, err)
			}
		})
	}
}

// Browser sign-in needs HTTPS or localhost, because the session cookie is __Host- prefixed and
// therefore Secure. A plain-http app URL on any other host gets a startup warning.
func TestCheckBrowserAuthConfig_PlainHTTPWarning(t *testing.T) {
	cases := []struct {
		appURL string
		warn   bool
	}{
		{"https://app.example.com", false},
		{"http://localhost:5173", false},
		{"http://127.0.0.1:5173", false},
		{"http://[::1]:5173", false},
		{"http://10.0.0.5:5173", true},
		{"http://stackweaver.lan", true},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.appURL, func(t *testing.T) {
			warnings, err := checkBrowserAuthConfig(envOf(map[string]string{"STACKWEAVER_APP_URL": tc.appURL}), false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := false
			for _, w := range warnings {
				if strings.Contains(w, "HTTPS") {
					got = true
				}
			}
			if got != tc.warn {
				t.Fatalf("warning = %v, want %v (warnings: %v)", got, tc.warn, warnings)
			}
		})
	}
}

// AC8: the idle timeout, the absolute lifetime and the liveness interval are configurable, with
// the NIST AAL2 defaults when unset; a value that is not a positive duration refuses to start.
func TestSessionLimitsFromEnv(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }

	got, err := sessionLimitsFromEnv(env(nil))
	if err != nil || got != auth.DefaultSessionLimits {
		t.Fatalf("unset: %+v %v, want the defaults %+v", got, err, auth.DefaultSessionLimits)
	}

	got, err = sessionLimitsFromEnv(env(map[string]string{
		"STACKWEAVER_SESSION_IDLE_TIMEOUT":      "15m",
		"STACKWEAVER_SESSION_MAX_LIFETIME":      "8h",
		"STACKWEAVER_SESSION_LIVENESS_INTERVAL": "1m",
	}))
	want := auth.SessionLimits{Idle: 15 * time.Minute, Absolute: 8 * time.Hour, Liveness: time.Minute}
	if err != nil || got != want {
		t.Fatalf("set: %+v %v, want %+v", got, err, want)
	}

	for _, bad := range []map[string]string{
		{"STACKWEAVER_SESSION_IDLE_TIMEOUT": "an hour"},
		{"STACKWEAVER_SESSION_MAX_LIFETIME": "0s"},
		{"STACKWEAVER_SESSION_LIVENESS_INTERVAL": "-5m"},
	} {
		if _, err := sessionLimitsFromEnv(env(bad)); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}
