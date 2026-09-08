// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package jsonapi

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

// PageParams reads the JSON:API `page[number]`/`page[size]` query parameters, falling back to
// page 1 and the caller's default size, and clamping the size to maxSize.
//
// It exists because getting this wrong is not a cosmetic bug. Two handlers in #761 read
// `limit`/`offset` while every client sends `page[number]`/`page[size]`: the Ansible schedules
// listing silently capped itself at 20 rows, and the inventory-sources listing - which reported
// a correct total - served page 1 again for every page requested, so the UI rendered every row
// twice and never reached the tail.
//
// Both bounds matter, and the lower one is the reason #774 exists. The hand-rolled parsers this
// replaced clamped `page[size]` from above but not from below, so `page[size]=0` reached the
// query as `LIMIT 0`: zero rows came back while the same response reported a non-zero
// `total-count` and one page. A client is told the collection is non-empty and handed nothing,
// with no error. Falling back to the handler's default instead is the fix.
//
// maxSize is a parameter rather than a package constant because the caps are NOT uniform - the
// Ansible job-events listing allows 500 where everything else allows 100. Hiding that in the
// helper would have silently shrunk it to 100 during the #774 sweep. Stating it at the call site
// keeps the limit where a reader of the handler can see it.
func PageParams(c *gin.Context, defaultSize, maxSize int) (page, pageSize int) {
	page, _ = strconv.Atoi(c.DefaultQuery("page[number]", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ = strconv.Atoi(c.DefaultQuery("page[size]", strconv.Itoa(defaultSize)))
	if pageSize < 1 {
		pageSize = defaultSize
	}
	if maxSize > 0 && pageSize > maxSize {
		pageSize = maxSize
	}
	return page, pageSize
}

// Offset is the row offset for a 1-based page of the given size.
func Offset(page, pageSize int) int {
	return (page - 1) * pageSize
}
