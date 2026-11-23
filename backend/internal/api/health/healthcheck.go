// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package health

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HealthcheckTimeout bounds one healthcheck request, inside the 5 second timeout Compose gives it.
const HealthcheckTimeout = 4 * time.Second

// RunHealthcheck sends one GET to url and returns the process exit status: 0 when the addressed
// listener itself answers 200, otherwise 1 with a line on stderr that starts with "healthcheck:".
// Proxy variables in the environment are ignored and redirects are not followed, so only the
// listener at url can pass the check.
func RunHealthcheck(ctx context.Context, url string, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(ctx, HealthcheckTimeout)
	defer cancel()
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "healthcheck: %s: building request: %v\n", url, err)
		return 1
	}
	resp, err := client.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "healthcheck: %s: %v\n", url, err)
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(stderr, "healthcheck: %s: answered %d\n", url, resp.StatusCode)
		return 1
	}
	return 0
}
