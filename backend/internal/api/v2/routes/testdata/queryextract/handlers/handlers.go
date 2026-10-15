// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package handlers is source for the tests of the query-parameter extraction pass (#869). Each
// function is one way a handler in the real tree reads, or does not read, the query string. It
// is never built into anything.
package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/michielvha/stackweaver/backend/internal/api/v2/routes/testdata/queryextract/paging"
)

type Handler struct {
	store Store
	next  func(*gin.Context)
}

// Store is called through an interface, so the pass cannot see which implementation runs.
type Store interface {
	Load(c *gin.Context)
}

// rows has a method called Query that is not gin's.
type rows struct{}

func (rows) Query(sql string) string { return sql }

const sortParam = "sort"

// allowed is an allowlist the way the settings proxy keeps one.
var allowed = map[string]struct{}{
	"locale":    {},
	"ctx.orgId": {},
}

// List reads by every accessor, through a constant, through a method of its own and through a
// helper in another package.
func (h *Handler) List(c *gin.Context) {
	_ = c.Query("search")
	_ = c.DefaultQuery(sortParam, "name")
	_, _ = c.GetQuery("include")
	_ = c.QueryArray("filter[email]")
	_ = rows{}.Query("select 1")
	paging.Parse(c)
	h.filters(c)
}

func (h *Handler) filters(c *gin.Context) {
	_ = c.Query("filter[status]")
}

// Plain is registered as a function, not as a method value.
func Plain(c *gin.Context) {
	_ = c.Query("plain")
}

func (h *Handler) None(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Dynamic builds the name at run time, so there is no literal to read.
func (h *Handler) Dynamic(c *gin.Context) {
	_ = c.Query(fmt.Sprintf("filter[tagged][%d][key]", 0))
}

// Forward takes the query string whole.
func (h *Handler) Forward(c *gin.Context) {
	for name := range c.Request.URL.Query() {
		if _, ok := allowed[name]; ok {
			c.Status(http.StatusOK)
		}
	}
}

func (h *Handler) ForwardRaw(c *gin.Context) {
	c.String(http.StatusOK, c.Request.URL.RawQuery)
}

func (h *Handler) ThroughInterface(c *gin.Context) {
	h.store.Load(c)
}

func (h *Handler) ThroughValue(c *gin.Context) {
	h.next(c)
}

// Recursive calls itself, which the pass must survive.
func (h *Handler) Recursive(c *gin.Context) {
	_ = c.Query("depth")
	h.Recursive(c)
}

// Gate wraps a handler. Registered as the last handler of a route, gin names the closure and
// not the handler it calls.
func Gate(final gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		final(c)
	}
}

// Register has one inline handler that reads nothing.
func Register(r *gin.Engine) {
	r.GET("/health", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
}

// RegisterReading has an inline handler that reads a parameter.
func RegisterReading(r *gin.Engine) {
	r.GET("/inline", func(c *gin.Context) {
		_ = c.Query("inline")
	})
}
