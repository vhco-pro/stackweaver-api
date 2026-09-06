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

// Pagination is the TFE-compatible `meta.pagination` block (#756).
//
// Every member is emitted unconditionally. go-tfe's Pagination struct reads all of them, and
// `omitempty` on any would be actively harmful: a dropped `total-count` of zero reads to a
// client as "unknown" rather than "empty", and a dropped `total-pages` makes it stop after the
// first page.
//
// PrevPage and NextPage are pointers so they serialise as JSON null at the first and last page
// rather than disappearing. go-tfe reads them as pointers and distinguishes null from missing;
// the run-task data sources page until next-page is null, so an absent member ends the loop
// early rather than at the true end.
type Pagination struct {
	CurrentPage int   `json:"current-page"`
	PageSize    int   `json:"page-size"`
	PrevPage    *int  `json:"prev-page"`
	NextPage    *int  `json:"next-page"`
	TotalPages  int   `json:"total-pages"`
	TotalCount  int64 `json:"total-count"`
}

// PaginationMeta wraps Pagination in the `meta` member TFE clients expect.
type PaginationMeta struct {
	Pagination Pagination `json:"pagination"`
}

// NewPaginationMeta builds the block for one page of a collection.
//
// This is the single source of the shape. Before #756 the tree carried nine different
// `meta.pagination` variants across the collections - six-member, five-member, four-member,
// three-member, `{page, per_page, total}`, `{total}` - so what a client got depended on which
// endpoint it called. `terraform-provider-tfe` decoded zeros from the workspaces, projects and
// runs endpoints and stopped after page one.
//
// total is int64 because it comes from a COUNT and the handlers already carry it that way.
func NewPaginationMeta(page, pageSize int, total int64) PaginationMeta {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 1
	}

	// Round up, and never report zero pages: a client that sees total-pages of 0 concludes
	// there is nothing to fetch and skips the request, so an empty collection reports one
	// (empty) page instead.
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	if totalPages < 1 {
		totalPages = 1
	}

	p := Pagination{
		CurrentPage: page,
		PageSize:    pageSize,
		TotalPages:  totalPages,
		TotalCount:  total,
	}
	if page > 1 {
		prev := page - 1
		p.PrevPage = &prev
	}
	if page < totalPages {
		next := page + 1
		p.NextPage = &next
	}
	return PaginationMeta{Pagination: p}
}
