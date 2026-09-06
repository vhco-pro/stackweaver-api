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
// nothing describes the shape to a client or to the OpenAPI generator. The legacy
// `{"error": ...}` body and the `{"code", "message"}` pair that used to live here were
// converged onto the JSON:API envelope in #757 and their helpers deleted, so those shapes
// cannot quietly return; what remains is the non-error acknowledgements.

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

// OKMessage sends a 200 MessageResponse.
func OKMessage(c *gin.Context, message string) {
	c.JSON(http.StatusOK, MessageResponse{Message: message})
}

// Status sends a StatusResponse.
func Status(c *gin.Context, code int, status string) {
	c.JSON(code, StatusResponse{Status: status})
}
