// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gin-gonic/gin"
)

// responseDeadlineRecorder explicitly supplies deadline support to non-network unit tests.
// Actual delivery under production server timeouts is proved by the socket integration tests.
type responseDeadlineRecorder struct {
	gin.ResponseWriter
	deadlines   []time.Time
	maxWrite    int
	unsupported bool
}

func (w *responseDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	if w.unsupported {
		return http.ErrNotSupported
	}
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func (w *responseDeadlineRecorder) Write(data []byte) (int, error) {
	w.maxWrite = max(w.maxWrite, len(data))
	return w.ResponseWriter.Write(data)
}

func TestRunnerReadResponse_SelectionPrecedesReads(t *testing.T) {
	for _, tc := range []struct {
		name, method, pattern, path string
		acquisition                 time.Duration
	}{
		{"artifacts", "GET", "/runner/jobs/:id/artifacts", "/runner/jobs/job/artifacts", 5 * time.Minute},
		{"config", "GET", "/runner/jobs/:id/blob/*name", "/runner/jobs/job/blob/config.tar.gz", 5 * time.Minute},
		{"state", "GET", "/runner/jobs/:id/blob/*name", "/runner/jobs/job/blob/state", 5 * time.Minute},
		{"plan", "GET", "/runner/jobs/:id/plan", "/runner/jobs/job/plan", 5 * time.Minute},
		{"snapshot", "GET", "/runner/jobs/:id/playbook-snapshot", "/runner/jobs/job/playbook-snapshot", 5 * time.Minute},
		{"org cache", "GET", "/runner/cache/:kind/:sha256", "/runner/cache/provider/" + strings.Repeat("a", 64), 2 * time.Minute},
		{"job cache", "GET", "/runner/jobs/:id/blob/*name", "/runner/jobs/job/blob/cache/provider/" + strings.Repeat("a", 64), 2 * time.Minute},
		{"unknown cache kind", "GET", "/runner/jobs/:id/blob/*name", "/runner/jobs/job/blob/cache/unknown/" + strings.Repeat("a", 64), 5 * time.Minute},
		{"uppercase cache hash", "GET", "/runner/jobs/:id/blob/*name", "/runner/jobs/job/blob/cache/provider/" + strings.Repeat("A", 64), 5 * time.Minute},
		{"cache extra segment", "GET", "/runner/jobs/:id/blob/*name", "/runner/jobs/job/blob/cache/provider/" + strings.Repeat("a", 64) + "/extra", 5 * time.Minute},
		{"status", "GET", "/runner/jobs/:id/status", "/runner/jobs/job/status", 0},
		{"upload", "POST", "/runner/jobs/:id/plan", "/runner/jobs/job/plan", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				router := gin.New()
				var writer *responseDeadlineRecorder
				router.Use(func(c *gin.Context) {
					writer = &responseDeadlineRecorder{ResponseWriter: c.Writer}
					c.Writer = writer
					c.Next()
				})
				v2 := router.Group("/api/v2", RunnerReadResponse())
				v2.Use(func(c *gin.Context) {
					if tc.acquisition == 0 {
						if len(writer.deadlines) != 0 {
							t.Error("unrelated response or upload changed its server deadline")
						}
					} else if len(writer.deadlines) == 0 || time.Until(writer.deadlines[0]) != tc.acquisition {
						t.Errorf("deadline before authentication/storage = %v, want %s", writer.deadlines, tc.acquisition)
					}
					c.Next()
				})
				v2.Handle(tc.method, tc.pattern, func(c *gin.Context) { c.Data(http.StatusOK, "application/octet-stream", []byte("verified")) })
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), tc.method, "/api/v2"+tc.path, nil))
				if recorder.Code != http.StatusOK || recorder.Body.String() != "verified" {
					t.Fatalf("content changed: %d %q", recorder.Code, recorder.Body.String())
				}
			})
		})
	}
}

func TestRunnerReadResponse_SingleWritesAreBounded(t *testing.T) {
	for _, representation := range []string{"data", "json", "string"} {
		t.Run(representation, func(t *testing.T) {
			router := gin.New()
			var writer *responseDeadlineRecorder
			router.Use(func(c *gin.Context) {
				writer = &responseDeadlineRecorder{ResponseWriter: c.Writer}
				c.Writer = writer
				c.Next()
			}, RunnerReadResponse())
			payload := strings.Repeat("content", 30_000)
			router.GET("/api/v2/runner/jobs/:id/artifacts", func(c *gin.Context) {
				c.Header("ETag", "\"immutable\"")
				switch representation {
				case "data":
					c.Data(http.StatusOK, "application/octet-stream", []byte(payload))
				case "json":
					c.JSON(http.StatusOK, payload)
				case "string":
					if _, err := io.WriteString(c.Writer, payload); err != nil {
						t.Error(err)
					}
				}
			})
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/runner/jobs/job/artifacts", nil))
			want := []byte(payload)
			if representation == "json" {
				want = []byte("\"" + payload + "\"")
			}
			if !bytes.Equal(recorder.Body.Bytes(), want) || recorder.Header().Get("ETag") != "\"immutable\"" {
				t.Error("chunking changed content or validators")
			}
			if writer.maxWrite > 32<<10 || writer.maxWrite == 0 {
				t.Errorf("largest downstream body write = %d, want 1..32768", writer.maxWrite)
			}
		})
	}
}

func TestRunnerReadResponse_UnsupportedDeadlineRefusesBeforeReads(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Writer = &responseDeadlineRecorder{ResponseWriter: c.Writer, unsupported: true}
		c.Next()
	}, RunnerReadResponse())
	read := false
	router.GET("/api/v2/runner/jobs/:id/artifacts", func(c *gin.Context) { read = true; c.Status(http.StatusOK) })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/runner/jobs/job/artifacts", nil))
	if read || recorder.Code != http.StatusInternalServerError {
		t.Fatalf("unsupported delivery capability: read=%v status=%d", read, recorder.Code)
	}
}

func TestRunnerReadResponse_StalledBodyCancelsWithoutReviving(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		router := gin.New()
		var writer *responseDeadlineRecorder
		router.Use(func(c *gin.Context) {
			writer = &responseDeadlineRecorder{ResponseWriter: c.Writer}
			c.Writer = writer
			c.Next()
		}, RunnerReadResponse())
		router.GET("/api/v2/runner/jobs/:id/artifacts", func(c *gin.Context) {
			c.Writer.WriteHeaderNow()
			start := time.Now()
			<-c.Request.Context().Done()
			if elapsed := time.Since(start); elapsed != 30*time.Second {
				t.Errorf("stalled server read canceled after %s, want 30s", elapsed)
			}
			if n, err := c.Writer.Write([]byte("late")); n != 0 || !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("expired response resumed: %d %v", n, err)
			}
			for _, deadline := range writer.deadlines {
				if deadline.After(time.Now()) && time.Until(deadline) <= 30*time.Second {
					t.Error("expired body received a fresh idle allowance")
				}
			}
		})
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/runner/jobs/job/artifacts", nil)
		router.ServeHTTP(httptest.NewRecorder(), request)
	})
}

func TestRunnerReadResponse_RecoveryKeepsBoundedResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		router := gin.New()
		var writer *responseDeadlineRecorder
		router.Use(gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, _ any) {
			c.AbortWithStatus(http.StatusInternalServerError)
		}), func(c *gin.Context) {
			writer = &responseDeadlineRecorder{ResponseWriter: c.Writer}
			c.Writer = writer
			c.Next()
		}, RunnerReadResponse())
		router.GET("/api/v2/runner/jobs/:id/artifacts", func(*gin.Context) { panic("delivery fixture") })
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/runner/jobs/job/artifacts", nil))
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("recovery response: %d", recorder.Code)
		}
		if len(writer.deadlines) == 0 || time.Until(writer.deadlines[len(writer.deadlines)-1]) != 30*time.Second {
			t.Errorf("recovery inherited the acquisition deadline: %v", writer.deadlines)
		}
	})
}
