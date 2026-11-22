// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package routes_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	v2routes "github.com/michielvha/stackweaver/backend/internal/api/v2/routes"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type runnerReadDeadlineRecorder struct {
	gin.ResponseWriter
	deadlines []time.Time
}

func (w *runnerReadDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func TestRunnerReadResponse_ProductionWiring(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL is required for production runner read wiring")
	}
	t.Setenv("DEV_INSECURE_KEY", "1")
	// Requests stop at authentication. Avoid loading ambient cloud credentials at startup.
	t.Setenv("STORAGE_BACKEND", "unconfigured-for-route-wiring")
	db, err := dbtest.Open(t, dsn, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	var names []string
	var writer *runnerReadDeadlineRecorder
	engine.Use(func(c *gin.Context) {
		names = c.HandlerNames()
		writer = &runnerReadDeadlineRecorder{ResponseWriter: c.Writer}
		c.Writer = writer
		c.Next()
	})
	v2routes.SetupV2Routes(engine, db, auth.NewService(repository.NewUserRepository(db)), nil)

	for _, tc := range []struct {
		name, method, path string
		acquisition        time.Duration
	}{
		{"artifacts", http.MethodGet, "/api/v2/runner/jobs/run-wiring/artifacts", 5 * time.Minute},
		{"blob", http.MethodGet, "/api/v2/runner/jobs/run-wiring/blob/config", 5 * time.Minute},
		{"job cache", http.MethodGet, "/api/v2/runner/jobs/run-wiring/blob/cache/provider/" + strings.Repeat("a", 64), 2 * time.Minute},
		{"saved plan", http.MethodGet, "/api/v2/runner/jobs/run-wiring/plan", 5 * time.Minute},
		{"snapshot", http.MethodGet, "/api/v2/runner/jobs/work-wiring/playbook-snapshot", 5 * time.Minute},
		{"organization cache", http.MethodGet, "/api/v2/runner/cache/provider/" + strings.Repeat("a", 64), 2 * time.Minute},
		{"control", http.MethodGet, "/api/v2/runner/jobs/run-wiring/status", 0},
		{"state upload", http.MethodPost, "/api/v2/runner/jobs/run-wiring/state", 0},
		{"plan upload", http.MethodPost, "/api/v2/runner/jobs/run-wiring/plan", 0},
		{"snapshot upload", http.MethodPost, "/api/v2/runner/jobs/work-wiring/snapshot", 0},
		{"cache upload", http.MethodPut, "/api/v2/runner/cache/provider/" + strings.Repeat("a", 64), 0},
		{"unrelated API", http.MethodGet, "/api/v2/organizations", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			names, writer = nil, nil
			response := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil)
			started := time.Now()
			engine.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("production authentication returned HTTP %d, want 401", response.Code)
			}
			index := func(part string) int {
				for i, name := range names {
					if strings.Contains(name, "."+part+".") {
						return i
					}
				}
				return -1
			}
			read, authenticate, wall := index("RunnerReadResponse"), index("AuthenticateMiddleware"), index("OrgResolutionWall")
			if read != 1 || authenticate <= read || wall <= authenticate {
				t.Fatalf("read policy must be the first v2 handler before authentication and the org wall: %v", names)
			}
			if strings.HasPrefix(tc.path, "/api/v2/runner/") && index("RunnerAuth") <= wall {
				t.Fatalf("runner authentication must follow the org wall: %v", names)
			}
			if tc.acquisition == 0 {
				if len(writer.deadlines) != 0 {
					t.Fatalf("excluded operation changed its response deadline: %v", writer.deadlines)
				}
				return
			}
			if len(writer.deadlines) == 0 {
				t.Fatal("selected response never installed its deadline before authentication")
			}
			if allowance := writer.deadlines[0].Sub(started); allowance < tc.acquisition-time.Second || allowance > tc.acquisition+time.Second {
				t.Fatalf("initial selected deadline = %s, want %s", allowance, tc.acquisition)
			}
		})
	}
}
