// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// Round 26 Wave 9 (CRIT-1): pin the MaxBodyBytes contract. The middleware
// MUST reject Content-Length > limit pre-emptively (no body read) AND
// reject streamed bodies that exceed the limit at first read.

func init() {
	gin.SetMode(gin.TestMode)
}

func TestMaxBodyBytes_RejectsOversizeContentLength(t *testing.T) {
	r := gin.New()
	r.Use(MaxBodyBytes(64))
	bodyRead := false
	r.POST("/x", func(c *gin.Context) {
		_, _ = io.ReadAll(c.Request.Body)
		bodyRead = true
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", bytes.NewReader(make([]byte, 200)))
	req.ContentLength = 200
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", w.Code)
	}
	if bodyRead {
		t.Errorf("handler must NOT execute when Content-Length exceeds limit")
	}
}

func TestMaxBodyBytes_AllowsBodyAtLimit(t *testing.T) {
	r := gin.New()
	r.Use(MaxBodyBytes(64))
	r.POST("/x", func(c *gin.Context) {
		_, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		c.Status(http.StatusOK)
	})

	body := strings.Repeat("a", 64)
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", strings.NewReader(body))
	req.ContentLength = 64
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("body at limit must be accepted; got %d", w.Code)
	}
}

func TestMaxBodyBytes_RejectsStreamedOversizeBody(t *testing.T) {
	r := gin.New()
	r.Use(MaxBodyBytes(64))
	r.POST("/x", func(c *gin.Context) {
		// Read should fail past 64 bytes; the handler propagates the
		// error so the response doesn't claim success.
		_, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.AbortWithStatus(http.StatusRequestEntityTooLarge)
			return
		}
		c.Status(http.StatusOK)
	})

	// Use Content-Length=0 (or unset) to bypass the pre-emptive header
	// check and exercise the MaxBytesReader path. We send 200 bytes
	// streamed.
	body := bytes.NewReader(make([]byte, 200))
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", body)
	req.ContentLength = -1 // unknown length → header check skipped
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("streamed oversize body must 413; got %d", w.Code)
	}
}
