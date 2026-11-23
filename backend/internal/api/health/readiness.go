// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package health serves the API's probe endpoints and the healthcheck command that probes them.
//
// /livez reports that the process answers. /readyz reports whether the API's own database pool can
// ping Postgres within ReadinessTimeout. Neither handler logs, and no error text reaches a response.
package health

import (
	"context"
	"net/http"
	"time"
)

// ReadinessTimeout bounds the database ping of one /readyz request, counted from the request's arrival.
const ReadinessTimeout = 2 * time.Second

// Pinger is the one method readiness needs from the API's main pool; *sql.DB satisfies it.
type Pinger interface {
	PingContext(ctx context.Context) error
}

var (
	okBody          = []byte(`{"status":"ok"}`)
	unavailableBody = []byte(`{"status":"unavailable","failing":["postgres"]}`)
)

// Readiness answers /readyz with one PingContext call on the pool it holds.
type Readiness struct {
	pool Pinger
}

// NewReadiness returns the /readyz handler for the API's main pool. It opens no pool of its own.
func NewReadiness(pool Pinger) *Readiness {
	return &Readiness{pool: pool}
}

// ServeHTTP pings the pool under a context that ends ReadinessTimeout after the request arrived, or
// when the request is cancelled, and answers 200 on success and 503 on any error.
func (r *Readiness) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), ReadinessTimeout)
	defer cancel()
	if err := r.pool.PingContext(ctx); err != nil {
		write(w, req, http.StatusServiceUnavailable, unavailableBody)
		return
	}
	write(w, req, http.StatusOK, okBody)
}

// Livez returns the /livez handler, which answers 200 whenever the process can serve a request.
func Livez() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		write(w, req, http.StatusOK, okBody)
	})
}

// write sends a probe answer: JSON, never cached, and no body for HEAD.
func write(w http.ResponseWriter, req *http.Request, code int, body []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if req.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}
