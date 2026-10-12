// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package response

import (
	"github.com/gin-gonic/gin"
)

// The non-JSON:API payloads this API also emits (#755, Phase 3).
//
// These are not JSON:API documents and are not pretending to be. They cover the endpoints that
// answer with a bare acknowledgement: internal callbacks, the TOTP and session flows, the
// GitHub webhook receiver, and the schedule actions.
//
// They are typed for the same reason everything else here is - a map has no definition, so
// nothing describes the shape to a client or to the OpenAPI generator.
//
// This package holds no error shape. Errors are JSON:API error documents written through
// jsonapi.WriteError (or apierror.Internal for a server-side failure). The flat
// `{"error": ...}` body and the `{"code", "message"}` pair once lived here; #757 removed the
// second and some writers of the first, and #857 removed the rest (ErrorResponse and its six
// helpers, which four Ansible handlers still called at 77 sites). With the helpers gone the
// compiler is the guard: nothing can call a function that does not exist.

// MessageResponse is a bare acknowledgement: {"message": "..."}.
type MessageResponse struct {
	Message string `json:"message"`
}

// StatusResponse is a bare status body: {"status": "..."}.
type StatusResponse struct {
	Status string `json:"status"`
}

// Message sends a MessageResponse.
func Message(c *gin.Context, code int, message string) {
	c.JSON(code, MessageResponse{Message: message})
}

// Status sends a StatusResponse.
func Status(c *gin.Context, code int, status string) {
	c.JSON(code, StatusResponse{Status: status})
}
