// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package health

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// normalizeHost strips one pair of brackets and turns an empty host into the IPv4 wildcard, so the
// server and the healthcheck command read a configured host the same way.
func normalizeHost(host string) string {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return "0.0.0.0"
	}
	return host
}

// ListenAddr is the address the API server binds for a configured host and port. Port 0 is passed
// through, so the server keeps binding an ephemeral port as it always has.
func ListenAddr(host string, port int) string {
	return net.JoinHostPort(normalizeHost(host), strconv.Itoa(port))
}

// ResolveProbeAddr is the address the healthcheck command dials to reach a server configured with
// host and port: a wildcard host dials the loopback address of its family. It rejects port 0, whose
// ephemeral port another process cannot learn.
func ResolveProbeAddr(host string, port int) (string, error) {
	if port == 0 {
		return "", errors.New("port 0 is ephemeral and cannot be probed")
	}
	h := normalizeHost(host)
	switch h {
	case "0.0.0.0":
		h = "127.0.0.1"
	case "::":
		h = "::1"
	}
	return net.JoinHostPort(h, strconv.Itoa(port)), nil
}

// ProbeURL is the /readyz URL for a dial address; an IPv6 zone is encoded as %25.
func ProbeURL(addr string) string {
	return (&url.URL{Scheme: "http", Host: addr, Path: "/readyz"}).String()
}
