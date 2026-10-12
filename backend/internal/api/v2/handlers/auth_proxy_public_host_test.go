// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import "testing"

// #866: the proxy reaches Zitadel at an internal address and names the instance with
// x-zitadel-instance-host. Zitadel then builds the issuer of every token from that host, which
// carries no port, so on http://localhost:8080 it issued "http://localhost" and the API, which
// expects ZITADEL_ISSUER, rejected every token. Telling Zitadel the public host, taken from the
// issuer the API itself validates against, makes the two agree.
func TestRequestHeadersCarryIssuerPublicHost(t *testing.T) {
	tests := []struct {
		name    string
		headers string // CUSTOM_REQUEST_HEADERS
		issuer  string // ZITADEL_ISSUER
		want    string // expected x-zitadel-public-host, "" for absent
	}{
		{
			name:    "a non-default port is carried",
			headers: "x-zitadel-instance-host:localhost",
			issuer:  "http://localhost:8080",
			want:    "localhost:8080",
		},
		{
			name:    "a default port adds the bare host",
			headers: "x-zitadel-instance-host:auth.example.com",
			issuer:  "https://auth.example.com",
			want:    "auth.example.com",
		},
		{
			name:    "the header name is matched case-insensitively",
			headers: "X-Zitadel-Instance-Host:localhost",
			issuer:  "http://localhost:8080",
			want:    "localhost:8080",
		},
		{
			name:    "an operator's own public host is left alone",
			headers: "x-zitadel-instance-host:localhost,x-zitadel-public-host:login.example.com",
			issuer:  "http://localhost:8080",
			want:    "login.example.com",
		},
		{
			name:   "no instance host header means no public host header",
			issuer: "http://localhost:8080",
			want:   "",
		},
		{
			name:    "an empty instance host adds nothing",
			headers: "x-zitadel-instance-host:",
			issuer:  "http://localhost:8080",
			want:    "",
		},
		{
			name:    "an issuer that does not parse adds nothing",
			headers: "x-zitadel-instance-host:localhost",
			issuer:  "://not a url",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &AuthProxy{config: AuthProxyConfig{CustomRequestHeaders: tt.headers, ZitadelIssuer: tt.issuer}}

			got := ""
			for name, value := range p.parsedHeaders() {
				if equalHeaderName(name, zitadelPublicHostHeader) {
					got = value
				}
			}
			if got != tt.want {
				t.Errorf("%s = %q, want %q", zitadelPublicHostHeader, got, tt.want)
			}
		})
	}
}
