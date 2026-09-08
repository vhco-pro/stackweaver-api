// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package jsonapi

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

// maxPageSize caps what a caller can ask for, so `page[size]=100000` cannot be used to pull a
// whole table in one request.
const maxPageSize = 100

// PageParams reads the JSON:API `page[number]`/`page[size]` query parameters, falling back to
// page 1 and the caller's default size.
//
// It exists because getting this wrong is not a cosmetic bug. Two handlers in #761 read
// `limit`/`offset` while every client sends `page[number]`/`page[size]`: the Ansible schedules
// listing silently capped itself at 20 rows, and the inventory-sources listing - which reported
// a correct total - served page 1 again for every page requested, so the UI rendered every row
// twice and never reached the tail.
//
// This is deliberately NOT retrofitted onto the handlers that already parse the pair inline.
// #761 excluded that: it would touch every v2 handler for a tidiness gain, inside a change whose
// safety argument rests on a small, reviewable golden-fixture diff. New paging code should use
// this; converting the existing call sites is separate work.
//
// Both values are clamped to at least 1, so a hostile or malformed `page[number]=0` cannot
// produce a negative offset.
func PageParams(c *gin.Context, defaultSize int) (page, pageSize int) {
	page, _ = strconv.Atoi(c.DefaultQuery("page[number]", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ = strconv.Atoi(c.DefaultQuery("page[size]", strconv.Itoa(defaultSize)))
	if pageSize < 1 {
		pageSize = defaultSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize
}

// Offset is the row offset for a 1-based page of the given size.
func Offset(page, pageSize int) int {
	return (page - 1) * pageSize
}
