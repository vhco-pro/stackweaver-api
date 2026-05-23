// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func newReq(method, target string, body io.Reader) *http.Request {
	req, _ := http.NewRequestWithContext(context.Background(), method, target, body)
	return req
}

func init() {
	gin.SetMode(gin.TestMode)
}

func setupCSRFRouter(origins []string) *gin.Engine {
	r := gin.New()
	r.Use(CSRFProtection(origins))
	r.POST("/auth/sessions", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	r.GET("/auth/settings/login", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	return r
}

func TestCSRF_AllowsGETWithoutOrigin(t *testing.T) {
	r := setupCSRFRouter([]string{"http://localhost:5173"})
	w := httptest.NewRecorder()
	req := newReq(http.MethodGet, "/auth/settings/login", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCSRF_AllowsPOSTWithValidOrigin(t *testing.T) {
	r := setupCSRFRouter([]string{"http://localhost:5173"})
	w := httptest.NewRecorder()
	req := newReq(http.MethodPost, "/auth/sessions", strings.NewReader("{}"))
	req.Header.Set("Origin", "http://localhost:5173")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCSRF_BlocksPOSTWithInvalidOrigin(t *testing.T) {
	r := setupCSRFRouter([]string{"http://localhost:5173"})
	w := httptest.NewRecorder()
	req := newReq(http.MethodPost, "/auth/sessions", strings.NewReader("{}"))
	req.Header.Set("Origin", "http://evil.com")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCSRF_AllowsPOSTWithValidReferer(t *testing.T) {
	r := setupCSRFRouter([]string{"http://localhost:5173"})
	w := httptest.NewRecorder()
	req := newReq(http.MethodPost, "/auth/sessions", strings.NewReader("{}"))
	// No Origin header, but valid Referer
	req.Header.Set("Referer", "http://localhost:5173/login/password")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCSRF_BlocksPOSTWithInvalidReferer(t *testing.T) {
	r := setupCSRFRouter([]string{"http://localhost:5173"})
	w := httptest.NewRecorder()
	req := newReq(http.MethodPost, "/auth/sessions", strings.NewReader("{}"))
	req.Header.Set("Referer", "http://evil.com/phish")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCSRF_AllowsPOSTWithNoOriginNoReferer(t *testing.T) {
	r := setupCSRFRouter([]string{"http://localhost:5173"})
	w := httptest.NewRecorder()
	req := newReq(http.MethodPost, "/auth/sessions", strings.NewReader("{}"))
	// No Origin, no Referer — direct API call (curl, etc.)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for no-origin-no-referer, got %d", w.Code)
	}
}

func TestCSRF_AllowsOriginWithTrailingSlash(t *testing.T) {
	r := setupCSRFRouter([]string{"http://localhost:5173"})
	w := httptest.NewRecorder()
	req := newReq(http.MethodPost, "/auth/sessions", strings.NewReader("{}"))
	req.Header.Set("Origin", "http://localhost:5173/")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for origin with trailing slash, got %d", w.Code)
	}
}
