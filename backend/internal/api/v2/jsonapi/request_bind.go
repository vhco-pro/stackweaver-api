// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package jsonapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// TypedDocument is a request document that can report its primary data: the request structs
// whose Data member is a pointer tagged `json:"data" binding:"required"` implement it, so that
// a flat body cannot bind silently to zero values.
type TypedDocument interface {
	// PrimaryType returns data.type, and whether data was present at all.
	PrimaryType() (string, bool)
}

// BindDocument binds the request body into req and answers, the one way every endpoint does,
// the request that is not the document it expects: WriteDocumentRequired when there is no
// data member (a flat object, {}, null, no body), gin's validator text for any other bind
// failure, and WriteWrongType when data.type is not resourceType. It reports whether the
// handler may go on; when it returns false the answer is written.
//
// The rule it holds: docs/internal/guidelines/api/json-api-everywhere.md
func BindDocument(c *gin.Context, req TypedDocument, resourceType string) bool {
	return bind(c, req, resourceType, false)
}

// BindOptionalDocument is BindDocument for an endpoint whose body is optional. A body with no
// bytes, or only whitespace, makes the decoder return io.EOF, and that alone means "no body":
// present is false and ok is true. A body that is there must be the document, so {} and null
// are refused like a flat body, and a malformed one is refused with the decoder's text.
func BindOptionalDocument(c *gin.Context, req TypedDocument, resourceType string) (present, ok bool) {
	if err := c.ShouldBindJSON(req); err != nil {
		if errors.Is(err, io.EOF) {
			return false, true
		}
		if _, hasData := req.PrimaryType(); !hasData && !isSyntaxError(err) {
			WriteDocumentRequired(c, resourceType)
			return false, false
		}
		WriteError(c, http.StatusBadRequest, TitleBadRequest, err.Error())
		return false, false
	}
	if typ, _ := req.PrimaryType(); typ != resourceType {
		WriteWrongType(c, resourceType, typ)
		return false, false
	}
	return true, true
}

// BindIdentifier binds a request that names an existing resource by identity alone, whose data
// is a resource identifier object ({"type", "id"}). A body without one is answered by
// WriteIdentifierRequired; the type is checked as BindDocument checks it.
func BindIdentifier(c *gin.Context, req TypedDocument, resourceType string) bool {
	return bind(c, req, resourceType, true)
}

// bind is BindDocument and BindIdentifier; identifier selects the sentence for a body without
// data. It calls the writers directly rather than through a function value, so the route
// manifest's reading of which query parameters a handler reads can follow the context.
func bind(c *gin.Context, req TypedDocument, resourceType string, identifier bool) bool {
	if err := c.ShouldBindJSON(req); err != nil {
		// A body without data gets the sentence that names the expected document; gin's
		// validator text names a Go struct field instead.
		if _, hasData := req.PrimaryType(); !hasData {
			if identifier {
				WriteIdentifierRequired(c, resourceType)
			} else {
				WriteDocumentRequired(c, resourceType)
			}
			return false
		}
		WriteError(c, http.StatusBadRequest, TitleBadRequest, err.Error())
		return false
	}
	if typ, _ := req.PrimaryType(); typ != resourceType {
		WriteWrongType(c, resourceType, typ)
		return false
	}
	return true
}

// isSyntaxError reports a body that is not JSON at all, whose decoder text is more use to the
// caller than the sentence about the document.
func isSyntaxError(err error) bool {
	var syntax *json.SyntaxError
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &syntax)
}

// RelationshipID returns the id a to-one relationship of a request document names. An absent
// relationship, or one whose data is null, names none and returns "". A relationship whose
// type is not want is answered with WriteWrongTypeAt at data.relationships.<name>.data, and ok
// is false: a document that names the right resource under the wrong type is a client bug.
func RelationshipID(c *gin.Context, rel *Relationship, name, want string) (id string, ok bool) {
	if rel == nil || rel.Data == nil {
		return "", true
	}
	if rel.Data.Type != want {
		WriteWrongTypeAt(c, "data.relationships."+name+".data", want, rel.Data.Type)
		return "", false
	}
	return rel.Data.ID, true
}
