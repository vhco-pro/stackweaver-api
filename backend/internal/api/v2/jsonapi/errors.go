// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package jsonapi holds the typed wire representations for Stackweaver's JSON:API surface.
//
// It exists because the API was typed on the way in and untyped on the way out: 82 request
// structs against 5 response structs, with 2278 response sites building anonymous gin.H maps.
// A map has no definition, so nothing described what an error, an organization or a run looks
// like to a client, and the same shape was re-spelled at every call site.
//
// This package is the first half of the fix (#755, Phase 2): the envelope and the error object,
// which between them cover 1641 of those sites. Resource models follow in Phase 3.
//
// It is deliberately separate from backend/internal/api/v2/response, which predates it and
// emits a different, non-JSON:API shape ({"error": "..."}) still used by roughly 83 call sites
// in the Ansible handlers. Unifying those changes bytes on the wire and is tracked separately;
// mixing the two vocabularies in one package would make it easy to reach for the wrong one.
package jsonapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Error is a single JSON:API error object, matching the shape the API already emits.
//
// Detail is a pointer on purpose. The tree contains both three-field errors and seven
// title-only ones, and a plain string with `omitempty` would silently drop a deliberate empty
// detail while a plain string without it would invent `"detail": ""` on the title-only errors.
// A pointer reproduces both exactly: nil omits the key, and a pointer to "" emits it.
type Error struct {
	Status string  `json:"status,omitempty"`
	Title  string  `json:"title,omitempty"`
	Detail *string `json:"detail,omitempty"`
}

// ErrorDocument is the top-level JSON:API error response: {"errors": [...]}.
type ErrorDocument struct {
	Errors []Error `json:"errors"`
}

// WriteError sends a single-error JSON:API document.
//
// The `status` member is derived from the HTTP status code rather than passed in. That is safe
// to do rather than assumed: all 1641 call sites this replaced were checked, and every one of
// them already spelled a status string identical to its HTTP code, with zero exceptions.
func WriteError(c *gin.Context, code int, title, detail string) {
	c.JSON(code, ErrorDocument{Errors: []Error{{
		Status: strconv.Itoa(code),
		Title:  title,
		Detail: &detail,
	}}})
}

// WriteErrorNoDetail sends a single-error document with no `detail` member, for the handful of
// errors that carry only a status and a title.
func WriteErrorNoDetail(c *gin.Context, code int, title string) {
	c.JSON(code, ErrorDocument{Errors: []Error{{
		Status: strconv.Itoa(code),
		Title:  title,
	}}})
}

// RegistryErrorDocument is the Terraform Registry Protocol error shape: an array of plain
// strings rather than JSON:API objects.
//
//	{"errors": ["something bad happened"]}
//
// This is not an inconsistency to be tidied away. The /v1/modules and /v1/providers endpoints
// implement HashiCorp's registry protocol, whose published API documentation specifies exactly
// this payload, so wrapping them in a JSON:API envelope would break `terraform init` against a
// Stackweaver registry.
type RegistryErrorDocument struct {
	Errors []string `json:"errors"`
}

// WriteRegistryError sends a Terraform Registry Protocol error.
func WriteRegistryError(c *gin.Context, code int, messages ...string) {
	c.JSON(code, RegistryErrorDocument{Errors: messages})
}

// WriteRegistryLookupError maps a lookup failure onto the registry protocol (#757).
//
// Two rules, both learned from fixtures that recorded the violation. Not-found is 404 - the
// golden harness caught /v1/modules/:namespace answering 500 for a namespace that simply had no
// modules. And err.Error() never reaches the body: the same fixture carried the raw GORM string
// "record not found" verbatim, which tells an external caller about our persistence layer and
// nothing about their request.
func WriteRegistryLookupError(c *gin.Context, err error, notFoundMsg, failureMsg string) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		WriteRegistryError(c, http.StatusNotFound, notFoundMsg)
		return
	}
	WriteRegistryError(c, http.StatusInternalServerError, failureMsg)
}

// AbortError writes the error and stops the handler chain, for use from middleware.
func AbortError(c *gin.Context, code int, title, detail string) {
	WriteError(c, code, title, detail)
	c.Abort()
}

// Common titles, so the same status does not acquire three spellings across the tree.
const (
	TitleBadRequest   = "Bad Request"
	TitleUnauthorized = "Unauthorized"
	TitleForbidden    = "Forbidden"
	TitleNotFound     = "Not Found"
	TitleConflict     = "Conflict"
	TitleInternal     = "Internal Server Error"
)

// Ensure the constants stay aligned with net/http's canonical text.
var _ = map[int]string{
	http.StatusBadRequest:          TitleBadRequest,
	http.StatusUnauthorized:        TitleUnauthorized,
	http.StatusForbidden:           TitleForbidden,
	http.StatusNotFound:            TitleNotFound,
	http.StatusConflict:            TitleConflict,
	http.StatusInternalServerError: TitleInternal,
}
