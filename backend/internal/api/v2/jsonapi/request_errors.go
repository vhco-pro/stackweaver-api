// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package jsonapi

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// WriteDocumentRequired answers a request whose body carries no `data` member: a flat body, an
// empty object, or anything else that is not a JSON:API document.
//
// It exists so that every JSON:API-only endpoint says the same sentence. gin's own message for a
// missing required field ("Key: 'X.Data' Error:Field validation for 'Data' failed on the
// 'required' tag") names a Go struct, which tells a client nothing about what to send; this names
// the document instead, with the resource type the endpoint expects.
func WriteDocumentRequired(c *gin.Context, resourceType string) {
	WriteError(c, http.StatusBadRequest, TitleBadRequest, fmt.Sprintf(
		`request body must be a JSON:API document: {"data": {"type": %q, "attributes": {...}}}`,
		resourceType,
	))
}

// WriteWrongType answers a document whose `data.type` is missing or names another resource.
//
// The type is checked rather than ignored because that is what hashicorp/jsonapi, and therefore
// Terraform Enterprise, does: a document typed "workspaces" posted to the runs endpoint is a
// client bug, and accepting it would hide the bug until the attributes happened to disagree.
func WriteWrongType(c *gin.Context, want, got string) {
	WriteWrongTypeAt(c, "data", want, got)
}

// WriteWrongTypeAt answers a resource identifier whose `type` is missing or wrong at path, the
// dotted member that holds it (`data`, or `data.relationships.<name>.data` for a relationship).
//
// One sentence covers the primary data and every relationship, so a client reads the same rule
// wherever it got the type wrong, and the path tells it which identifier to fix.
func WriteWrongTypeAt(c *gin.Context, path, want, got string) {
	WriteError(c, http.StatusBadRequest, TitleBadRequest, fmt.Sprintf(
		"%s.type must be %q (got %q)", path, want, got,
	))
}

// WriteIdentifierRequired answers a request that attaches an existing resource by identity alone
// and carries no resource identifier object under `data`.
//
// It differs from WriteDocumentRequired only in the example it shows: such a request names the
// resource by `type` and `id` and has no attributes to send.
func WriteIdentifierRequired(c *gin.Context, resourceType string) {
	WriteError(c, http.StatusBadRequest, TitleBadRequest, fmt.Sprintf(
		`request body must be a JSON:API resource identifier: {"data": {"type": %q, "id": "..."}}`,
		resourceType,
	))
}
