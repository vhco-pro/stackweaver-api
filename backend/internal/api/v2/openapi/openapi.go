// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package openapi serves Stackweaver's OpenAPI 3 document (#755, Phase 4).
//
// The path is /openapi/stable.json because that is where hashicorp/go-tfe v2 looks: its
// openapi.go fetches /openapi/stable.json from a TFE server, with If-Modified-Since caching,
// so matching the path lets a go-tfe client discover Stackweaver's API the same way it
// discovers HashiCorp's. Matching the path is a compatibility affordance and nothing more -
// the document identifies itself as Stackweaver, not as TFE.
//
// It is unauthenticated, like the neighbouring .well-known/terraform.json discovery document.
// That leaks nothing: the route table of an open-source server is already public, and a client
// that cannot read the API description before authenticating cannot generate a client at all.
package openapi

import (
	_ "embed"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Spec is the generated document, produced by cmd/openapi-gen from the golden response
// fixtures. It is committed so that the served bytes are reviewable in a diff, and CI fails
// when it drifts from what the generator would produce.
//
//go:embed spec.json
var Spec []byte

// stamp is the Last-Modified value the server reports. It lives in a committed file that
// cmd/openapi-gen rewrites ONLY when the spec bytes change, which is the property everything
// else hangs on:
//
//   - It moves exactly when the document moves, so a client that cached the spec revalidates
//     with If-Modified-Since and gets fresh bytes after a release that changed the API. The
//     first version of this file hardcoded a constant and documented an ldflags override that
//     no build ever wired, which would have answered 304 forever - a client that cached once
//     would never have seen an updated spec.
//   - It is NOT part of the document body, so the committed artifact stays byte-comparable to
//     what the generator produces and the CI drift check remains possible.
//   - It is content-derived rather than build-time, so two replicas built at different times
//     agree, and a rebuild without an API change does not invalidate every client's cache.
//
//go:embed stamp.txt
var stamp string

func lastModified() time.Time {
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(stamp)); err == nil {
		return t.UTC()
	}
	// An unparseable stamp falls back to the epoch: every If-Modified-Since then answers 200,
	// which serves stale-cache clients correctly at the cost of extra bytes - the safe side.
	return time.Unix(0, 0).UTC()
}

// Handler serves the document with conditional-request support.
//
// go-tfe sends If-Modified-Since and expects a 304 when nothing has changed; without that it
// re-downloads a half-megabyte document on every client construction.
func Handler(c *gin.Context) {
	lm := lastModified()
	c.Header("Last-Modified", lm.Format(http.TimeFormat))
	c.Header("Cache-Control", "public, max-age=300")

	if ims := c.GetHeader("If-Modified-Since"); ims != "" {
		if since, err := http.ParseTime(ims); err == nil {
			// HTTP times have one-second resolution, so compare truncated: a Last-Modified
			// echoed back verbatim must count as "not modified" rather than missing by
			// sub-second drift.
			if !lm.Truncate(time.Second).After(since.Truncate(time.Second)) {
				c.Status(http.StatusNotModified)
				return
			}
		}
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", Spec)
}

// RegisterRoutes mounts the document on the root router.
//
// It sits outside /api/v2 on purpose: routes under that prefix pass through the org-resolution
// wall, which fails closed and would return 403 to every API-key caller for an unclassified
// route. A public discovery document has no organization to resolve.
func RegisterRoutes(r *gin.Engine) {
	r.GET("/openapi/stable.json", Handler)
}
