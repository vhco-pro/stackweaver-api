// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// The non-JSON:API payloads this API also emits (#755, Phase 3).
//
// These are not JSON:API documents and are not pretending to be. They cover the endpoints that
// answer with a bare acknowledgement or a legacy `{"error": ...}` body: internal callbacks, the
// TOTP and session flows, the GitHub webhook receiver, and the Ansible handlers that predate
// the JSON:API convention.
//
// They are typed for the same reason everything else here is - a map has no definition, so
// nothing describes the shape to a client or to the OpenAPI generator - but typing them does
// not endorse them. Converging the `{"error": ...}` responses onto the JSON:API envelope
// changes bytes on the wire and is tracked separately.

// MessageResponse is a bare acknowledgement: {"message": "..."}.
type MessageResponse struct {
	Message string `json:"message"`
}

// StatusResponse is a bare status body: {"status": "..."}.
type StatusResponse struct {
	Status string `json:"status"`
}

// CodeMessageResponse pairs a numeric code with a human message.
//
// Code is an int because every call site emits the HTTP status as a JSON number, not a string.
// That differs from the JSON:API error object, where `status` is a string - a real divergence
// in the API, preserved here rather than quietly unified.
type CodeMessageResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Message sends a MessageResponse.
func Message(c *gin.Context, code int, message string) {
	c.JSON(code, MessageResponse{Message: message})
}

// OKMessage sends a 200 MessageResponse.
func OKMessage(c *gin.Context, message string) {
	c.JSON(http.StatusOK, MessageResponse{Message: message})
}

// Status sends a StatusResponse.
func Status(c *gin.Context, code int, status string) {
	c.JSON(code, StatusResponse{Status: status})
}

// LegacyError sends the pre-JSON:API error body, {"error": "..."}.
//
// Named "legacy" deliberately: new endpoints should use jsonapi.WriteError. This exists so the
// roughly 85 call sites still emitting this shape have a type rather than a map, without
// silently changing what they return.
func LegacyError(c *gin.Context, code int, message string) {
	c.JSON(code, ErrorResponse{Error: message})
}

// LegacyErrorDetails sends {"error": "...", "details": "..."}.
func LegacyErrorDetails(c *gin.Context, code int, message, details string) {
	c.JSON(code, ErrorResponse{Error: message, Details: details})
}
