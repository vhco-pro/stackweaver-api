// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// acceptAzureDevOpsTokens makes the Azure DevOps account check succeed for the rest of the test.
// Creating an Azure DevOps connection proves its token against the Azure DevOps organization it
// names (ValidateTokenAndOrg), and a test that records a successful create has no real Azure
// DevOps to ask. Requests to the two hosts that check uses are answered 200; every other request
// goes to the real transport. The default transport is restored when the test ends.
func acceptAzureDevOpsTokens(t *testing.T) {
	t.Helper()
	real := http.DefaultTransport
	http.DefaultTransport = azureDevOpsAccepting{next: real}
	t.Cleanup(func() { http.DefaultTransport = real })
}

type azureDevOpsAccepting struct{ next http.RoundTripper }

func (a azureDevOpsAccepting) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "app.vssps.visualstudio.com" || req.URL.Host == "dev.azure.com" {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Request:    req,
		}, nil
	}
	return a.next.RoundTrip(req)
}
