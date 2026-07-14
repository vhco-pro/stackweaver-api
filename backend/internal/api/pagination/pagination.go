// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package pagination provides a single TFE-compatible pagination parser shared across the v2
// handlers (AUD-061). Most handlers already read the JSON:API/TFE `page[number]` / `page[size]`
// query parameters, but a handful (organizations, projects, VCS connections, state versions, and
// — most visibly — GET /workspaces/:id/runs) only read the legacy `page` / `per_page`, so go-tfe,
// which sends the bracketed form, was stuck on page 1 forever. Parse reads the TFE form first and
// falls back to the legacy names so existing callers keep working.
package pagination

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

// Parse returns the 1-based page number and page size from the request, preferring the TFE
// `page[number]` / `page[size]` parameters and falling back to the legacy `page` / `per_page`.
// defaultPerPage is used when no size is supplied.
func Parse(c *gin.Context, defaultPerPage int) (page, perPage int) {
	page = 1
	perPage = defaultPerPage

	if n, ok := firstPositiveInt(c.Query("page[number]"), c.Query("page")); ok {
		page = n
	}
	if n, ok := firstPositiveInt(c.Query("page[size]"), c.Query("per_page")); ok {
		perPage = n
	}
	return page, perPage
}

// firstPositiveInt returns the first of the given raw values that parses to a positive integer.
func firstPositiveInt(values ...string) (int, bool) {
	for _, v := range values {
		if v == "" {
			continue
		}
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n, true
		}
	}
	return 0, false
}
