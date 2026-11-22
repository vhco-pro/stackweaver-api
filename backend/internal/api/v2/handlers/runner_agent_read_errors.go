// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
)

// writeRunnerJobReadError identifies a missing job only after a successful absence lookup.
func writeRunnerJobReadError(c *gin.Context, err error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		jsonapi.WriteCodedError(c, http.StatusNotFound, runnercontract.ErrorCodeJobDeleted, "Job not found", "the job no longer exists")
		return
	}
	jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
}
