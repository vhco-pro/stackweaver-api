// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package response

import (
	"github.com/gin-gonic/gin"
)

// The non-JSON:API acknowledgements of the protocol surfaces, and nothing else (#858, D12).
//
// Every endpoint Stackweaver defines answers a JSON:API document through the jsonapi package's
// writers (docs/internal/guidelines/api/json-api-everywhere.md). The bodies here belong to
// surfaces whose shape a protocol defines: the VCS webhook receivers in
// handlers/vcs_app_installation.go acknowledge a delivery with Message, and the runner control
// plane in handlers/runner_agent.go answers the runner binaries with Status, as the health check
// outside /api/v2 (routes/routes.go) does. A handler outside
// the protocol files may not call this package: scripts/check-handler-response-typing.js fails on
// any call from a file not in its PROTOCOL_FILES list, and the compiler refuses one from outside
// the handler trees only if it is removed here, so new callers are a review question, not an
// accident.
//
// They are typed for the same reason everything else here is: a map has no definition, so
// nothing describes the shape to a client or to the OpenAPI generator.
//
// This package holds no error shape. Errors are JSON:API error documents written through
// jsonapi.WriteError (or apierror.Internal for a server-side failure).

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
