// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package paging stands in for the pagination helpers, which live outside the handler packages:
// a handler's page parameters are read here, not in the handler.
package paging

import "github.com/gin-gonic/gin"

func Parse(c *gin.Context) (number, size string) {
	return c.Query("page[number]"), c.DefaultQuery("page[size]", "20")
}
