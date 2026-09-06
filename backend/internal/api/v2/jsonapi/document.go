// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package jsonapi

import "github.com/gin-gonic/gin"

// Document is the top-level JSON:API response envelope.
//
// Every member is omitempty except Data, because JSON:API requires `data` to be present even
// when it is null (a to-one relationship that resolves to nothing) or an empty array (an empty
// collection). Dropping it would turn "this resource has no project" into "the server forgot to
// tell you", which go-tfe and the frontend both read as a different thing.
type Document struct {
	Data     any `json:"data"`
	Included any `json:"included,omitempty"`
	Meta     any `json:"meta,omitempty"`
	Links    any `json:"links,omitempty"`
}

// WriteDocument sends a JSON:API document.
func WriteDocument(c *gin.Context, code int, data any) {
	c.JSON(code, Document{Data: data})
}

// WriteDocumentMeta sends a JSON:API document with a meta member, which is how the paginated
// collections carry `meta.pagination`.
func WriteDocumentMeta(c *gin.Context, code int, data, meta any) {
	c.JSON(code, Document{Data: data, Meta: meta})
}

// Pagination is the TFE-compatible `meta.pagination` block.
//
// go-tfe's Pagination struct reads all four members, so none of them may be omitted: a missing
// total-pages makes a client loop forever or stop after the first page.
type Pagination struct {
	CurrentPage int `json:"current-page"`
	PageSize    int `json:"page-size"`
	TotalPages  int `json:"total-pages"`
	TotalCount  int `json:"total-count"`
}

// PaginationMeta wraps Pagination in the `meta` member TFE clients expect.
type PaginationMeta struct {
	Pagination Pagination `json:"pagination"`
}
