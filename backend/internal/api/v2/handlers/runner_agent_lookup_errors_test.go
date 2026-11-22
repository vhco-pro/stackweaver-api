// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
)

func TestRunnerJobLookupError(t *testing.T) {
	for _, tt := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"database", errors.New("database unavailable"), http.StatusInternalServerError, ""},
		{"wrapped database", fmt.Errorf("reading job: %w", errors.New("cached plan changed")), http.StatusInternalServerError, ""},
		{"absent", gorm.ErrRecordNotFound, http.StatusNotFound, runnercontract.ErrorCodeJobDeleted},
		{"wrapped absence", fmt.Errorf("reading job: %w", gorm.ErrRecordNotFound), http.StatusNotFound, runnercontract.ErrorCodeJobDeleted},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			writeRunnerJobReadError(c, tt.err)
			code, _ := runnercontract.DecodeError(rec.Body.Bytes())
			if rec.Code != tt.status || code != tt.code {
				t.Errorf("response = %d with code %q, want %d with code %q", rec.Code, code, tt.status, tt.code)
			}
		})
	}
}
