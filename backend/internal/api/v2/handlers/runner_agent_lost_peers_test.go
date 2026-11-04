// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test for reaping a replaced launcher's leftovers (#933, D3, AC67): a launcher's
// heartbeat names the runners of its pool the monitor marked offline, so it stops and removes
// what they left running; a live peer is never named.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set.

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

func TestHeartbeat_NamesTheLostPeersOfThePool(t *testing.T) {
	f := setupAgentPrepFixture(t)
	h := &RunnerAgentHandler{db: f.db, runnerRepo: repository.NewRunnerRepository(f.db)}
	r := f.router(func(authed *gin.RouterGroup) {
		authed.POST("/heartbeat", middleware.RequireRunnerToken(), h.Heartbeat)
	})
	beat := func() runnercontract.HeartbeatResponse {
		t.Helper()
		rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/heartbeat", runnercontract.HeartbeatRequest{RunnerID: f.runnerA1.ID.String(), Status: "online"})
		if rec.Code != http.StatusOK {
			t.Fatalf("heartbeat = %d %s", rec.Code, rec.Body.String())
		}
		var resp runnercontract.HeartbeatResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if got := beat().ReapRunners; slices.Contains(got, f.runnerA2.ID.String()) {
		t.Errorf("a live peer was named for reaping: %v", got)
	}
	recent := time.Now().Add(-5 * time.Minute)
	if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA2.ID).Updates(map[string]any{"status": models.RunnerStatusOffline, "last_heartbeat_at": recent}).Error; err != nil {
		t.Fatal(err)
	}
	if got := beat().ReapRunners; !slices.Contains(got, f.runnerA2.ID.String()) || slices.Contains(got, f.runnerA1.ID.String()) {
		t.Errorf("reap runners = %v, want the offline peer %s and not the caller", got, f.runnerA2.ID)
	}
}
