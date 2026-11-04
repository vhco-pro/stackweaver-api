// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test for the hosted queue depth (#933, D11, AC78): a hosted launcher's heartbeat and
// GET /runner/queue-depth report the pending work per engine across every hosted pool of its
// group, so an operator scaling hosted capacity needs no per-pool key.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set.

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

func TestHostedDepth_AggregatesTheGroupsPendingWork(t *testing.T) {
	f := setupHostedRunnerFixture(t)
	f.hostedOrgRun(t, "depth-a")
	f.hostedOrgRun(t, "depth-b")
	h := &RunnerAgentHandler{db: f.db, runnerRepo: repository.NewRunnerRepository(f.db)}
	r := f.router(func(authed *gin.RouterGroup) {
		authed.GET("/queue-depth", middleware.RequireRunnerToken(), h.HostedQueueDepth)
		authed.POST("/heartbeat", middleware.RequireRunnerToken(), h.Heartbeat)
	})

	rec := runnerDo(t, r, "hosted", http.MethodGet, "/api/v2/runner/queue-depth", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("queue depth = %d %s", rec.Code, rec.Body.String())
	}
	var depth runnercontract.HostedDepth
	if err := json.Unmarshal(rec.Body.Bytes(), &depth); err != nil {
		t.Fatal(err)
	}
	if depth.Tofu != 2 || depth.Ansible != 0 || depth.Group != f.group {
		t.Errorf("depth = %+v, want two OpenTofu runs in group %s", depth, f.group)
	}

	// A full launcher's heartbeat carries the same, so it can ask for more capacity.
	rec = runnerDo(t, r, "hosted", http.MethodPost, "/api/v2/runner/heartbeat", runnercontract.HeartbeatRequest{RunnerID: f.runner.ID.String(), Status: "busy", CurrentJobs: 4})
	var resp runnercontract.HeartbeatResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.HostedDepth == nil || resp.HostedDepth.Tofu != 2 {
		t.Errorf("heartbeat hosted depth = %+v", resp.HostedDepth)
	}

	// A customer launcher has no hosted depth to read.
	if rec := runnerDo(t, r, "a1", http.MethodGet, "/api/v2/runner/queue-depth", nil); rec.Code != http.StatusForbidden {
		t.Errorf("a customer launcher reading the hosted depth = %d, want 403", rec.Code)
	}
}
