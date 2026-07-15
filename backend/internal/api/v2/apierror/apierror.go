// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package apierror centralizes JSON:API error responses so internal error text never leaks to
// clients. Several handlers used to put a raw err.Error() (SQL text, file paths, upstream host
// names) straight into the response `detail` on a 500 (AUD-063); Internal logs the real error
// server-side and returns only a generic, operator-authored message to the caller.
package apierror

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/logger"
)

// Internal logs err with the given context and replies with a JSON:API 500 whose `detail` is the
// caller-supplied publicMessage only — never the underlying error. Use for any server-side failure
// (DB, storage, upstream) where the cause is not safe to expose.
func Internal(c *gin.Context, publicMessage string, err error) {
	logger.Errorf("%s: %v", publicMessage, err)
	c.JSON(http.StatusInternalServerError, gin.H{
		"errors": []gin.H{
			{
				"status": "500",
				"title":  "Internal Server Error",
				"detail": publicMessage,
			},
		},
	})
}
