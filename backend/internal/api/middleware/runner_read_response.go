// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

const runnerReadIdle = 30 * time.Second

func runnerReadAcquisition(c *gin.Context) time.Duration {
	if c.Request.Method != http.MethodGet {
		return 0
	}
	switch c.FullPath() {
	case "/api/v2/runner/cache/:kind/:sha256":
		return 2 * time.Minute
	case "/api/v2/runner/jobs/:id/blob/*name":
		name := strings.TrimPrefix(c.Param("name"), "/")
		if rest, ok := strings.CutPrefix(name, "cache/"); ok {
			kind, sum, found := strings.Cut(rest, "/")
			if found && runnercontract.CacheKind(kind).Valid() && len(sum) == 64 && strings.Trim(sum, "0123456789abcdef") == "" {
				return 2 * time.Minute
			}
		}
		return 5 * time.Minute
	case "/api/v2/runner/jobs/:id/artifacts", "/api/v2/runner/jobs/:id/plan", "/api/v2/runner/jobs/:id/playbook-snapshot":
		return 5 * time.Minute
	default:
		return 0
	}
}

// RunnerReadResponse selects the delivery policy of runner content reads.
func RunnerReadResponse() gin.HandlerFunc {
	return func(c *gin.Context) {
		acquisition := runnerReadAcquisition(c)
		if acquisition == 0 {
			c.Next()
			return
		}
		original := c.Writer
		ctx, cancel := context.WithCancelCause(c.Request.Context())
		writer := &runnerReadWriter{
			ResponseWriter: original,
			controller:     http.NewResponseController(original),
			ctx:            ctx,
			cancel:         cancel,
			deadline:       readResponseDeadline(ctx, acquisition),
		}
		if err := writer.controller.SetWriteDeadline(writer.deadline); err != nil {
			cancel(err)
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			c.Abort()
			return
		}
		writer.mu.Lock()
		writer.timer = time.AfterFunc(time.Until(writer.deadline), writer.checkDeadline)
		writer.mu.Unlock()
		writer.stopCancellation = context.AfterFunc(ctx, func() { writer.fail(context.Cause(ctx)) })
		defer func() {
			writer.close()
			// Recovery and the router's final header flush retain their original writer.
			c.Writer = original
		}()
		c.Writer = writer
		c.Request = c.Request.WithContext(ctx)
		c.Next()
		if !writer.Written() {
			writer.WriteHeaderNow()
		}
	}
}

func readResponseDeadline(ctx context.Context, allowance time.Duration) time.Time {
	deadline := time.Now().Add(allowance)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		return parent
	}
	return deadline
}

// runnerReadWriter moves from acquisition to a rolling body-progress bound. Its timer also
// cancels a blocked storage read, while the real writer deadline bounds blocked network writes.
type runnerReadWriter struct {
	gin.ResponseWriter
	controller       *http.ResponseController
	ctx              context.Context
	cancel           context.CancelCauseFunc
	stopCancellation func() bool
	mu               sync.Mutex
	timer            *time.Timer
	deadline         time.Time
	headers          bool
	closed           bool
	err              error
}

func (w *runnerReadWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *runnerReadWriter) failLocked(err error) {
	if w.closed || w.err != nil {
		return
	}
	w.err = err
	w.timer.Stop()
	// This is best effort after failure; no later operation may renew the deadline.
	_ = w.controller.SetWriteDeadline(time.Now())
	w.cancel(err)
}

func (w *runnerReadWriter) fail(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.failLocked(err)
}

func (w *runnerReadWriter) liveLocked() error {
	if w.closed {
		return io.ErrClosedPipe
	}
	if w.err == nil && w.ctx.Err() != nil {
		w.failLocked(context.Cause(w.ctx))
	}
	if w.err == nil && !time.Now().Before(w.deadline) {
		w.failLocked(context.DeadlineExceeded)
	}
	return w.err
}

func (w *runnerReadWriter) renewLocked() error {
	w.deadline = readResponseDeadline(w.ctx, runnerReadIdle)
	if err := w.controller.SetWriteDeadline(w.deadline); err != nil {
		w.failLocked(err)
		return err
	}
	w.timer.Reset(time.Until(w.deadline))
	return nil
}

func (w *runnerReadWriter) begin() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.liveLocked(); err != nil {
		return err
	}
	if !w.headers {
		w.headers = true
		if err := w.renewLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (w *runnerReadWriter) progress() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.liveLocked(); err != nil {
		return err
	}
	return w.renewLocked()
}

func (w *runnerReadWriter) checkDeadline() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.err != nil {
		return
	}
	if remaining := time.Until(w.deadline); remaining > 0 {
		// A callback already queued when progress reset the timer observes the new deadline.
		w.timer.Reset(remaining)
		return
	}
	w.failLocked(context.DeadlineExceeded)
}

func (w *runnerReadWriter) WriteHeaderNow() {
	if w.begin() == nil {
		w.ResponseWriter.WriteHeaderNow()
	}
}

func (w *runnerReadWriter) Write(data []byte) (int, error) {
	if err := w.begin(); err != nil {
		return 0, err
	}
	w.ResponseWriter.WriteHeaderNow()
	total := 0
	for len(data) > 0 {
		if err := w.begin(); err != nil {
			return total, err
		}
		part := data[:min(len(data), 32<<10)]
		n, err := w.ResponseWriter.Write(part)
		total += n
		if err == nil && n != len(part) {
			err = io.ErrShortWrite
		}
		if err != nil {
			w.fail(err)
			return total, err
		}
		if err := w.progress(); err != nil {
			return total, err
		}
		data = data[n:]
	}
	return total, nil
}

func (w *runnerReadWriter) WriteString(value string) (int, error) {
	total := 0
	for len(value) > 0 {
		part := value[:min(len(value), 32<<10)]
		n, err := w.Write([]byte(part))
		total += n
		if err != nil {
			return total, err
		}
		value = value[n:]
	}
	return total, nil
}

func (w *runnerReadWriter) FlushError() error {
	if err := w.begin(); err != nil {
		return err
	}
	w.ResponseWriter.WriteHeaderNow()
	err := w.controller.Flush()
	if err != nil {
		w.fail(err)
	}
	return err
}

func (w *runnerReadWriter) Flush() { _ = w.FlushError() }

func (w *runnerReadWriter) close() {
	w.mu.Lock()
	if !w.headers && w.liveLocked() == nil {
		// An outer recovery handler may still send its error response. Keep that write
		// within thirty seconds and the original acquisition deadline after cleanup.
		deadline := readResponseDeadline(w.ctx, runnerReadIdle)
		if w.deadline.Before(deadline) {
			deadline = w.deadline
		}
		if err := w.controller.SetWriteDeadline(deadline); err != nil {
			w.failLocked(err)
		}
	}
	w.closed = true
	w.timer.Stop()
	w.mu.Unlock()
	w.stopCancellation()
	w.cancel(context.Canceled)
}
