// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/michielvha/stackweaver/backend/internal/services/auth"
)

// browserAuthRequired are the settings browser sign-in cannot work without: the confidential BFF
// client the API completes sign-in with, and the login service account's token, which the login
// UI and the session liveness checks use.
var browserAuthRequired = []string{
	"ZITADEL_BFF_CLIENT_ID",
	"ZITADEL_BFF_CLIENT_SECRET",
	"ZITADEL_LOGIN_SERVICE_USER_TOKEN",
}

// checkBrowserAuthConfig validates the configuration browser sign-in needs. In release mode a
// missing required setting is an error, so a misconfigured production API refuses to start
// rather than serving a sign-in that cannot complete. In any mode a plain-http
// STACKWEAVER_APP_URL on a host other than localhost is a warning: the session cookie is
// __Host- prefixed and therefore Secure, so browsers drop it over plain HTTP there.
func checkBrowserAuthConfig(getenv func(string) string, production bool) (warnings []string, err error) {
	if production {
		var missing []string
		for _, key := range browserAuthRequired {
			if getenv(key) == "" {
				missing = append(missing, key)
			}
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("browser sign-in needs %s; zitadel-init writes them for the bundled Zitadel", strings.Join(missing, ", "))
		}
	}

	if appURL := getenv("STACKWEAVER_APP_URL"); appURL != "" {
		if u, perr := url.Parse(appURL); perr == nil && u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
			warnings = append(warnings, fmt.Sprintf(
				"STACKWEAVER_APP_URL is plain http on %q: browser sign-in needs HTTPS (or localhost), because the session cookie is Secure; put TLS in front of Stackweaver", u.Hostname()))
		}
	}
	return warnings, nil
}

// isLoopbackHost reports whether host is localhost or a loopback address, which browsers treat as
// a secure context even over plain HTTP.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sessionLimitsFromEnv reads the browser-session lifetimes: STACKWEAVER_SESSION_IDLE_TIMEOUT,
// STACKWEAVER_SESSION_MAX_LIFETIME and STACKWEAVER_SESSION_LIVENESS_INTERVAL, Go durations such as
// "1h" or "15m". An unset one takes its default (auth.DefaultSessionLimits); one that is not a
// positive duration is an error, so a typo cannot quietly change how long sessions last.
func sessionLimitsFromEnv(getenv func(string) string) (auth.SessionLimits, error) {
	limits := auth.DefaultSessionLimits
	for _, setting := range []struct {
		key  string
		into *time.Duration
	}{
		{"STACKWEAVER_SESSION_IDLE_TIMEOUT", &limits.Idle},
		{"STACKWEAVER_SESSION_MAX_LIFETIME", &limits.Absolute},
		{"STACKWEAVER_SESSION_LIVENESS_INTERVAL", &limits.Liveness},
	} {
		raw := strings.TrimSpace(getenv(setting.key))
		if raw == "" {
			continue
		}
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return auth.SessionLimits{}, fmt.Errorf("%s=%q is not a positive duration such as 1h or 15m", setting.key, raw)
		}
		*setting.into = d
	}
	return limits, nil
}
