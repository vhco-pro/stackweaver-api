// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the placement record (#933, D4, AC77): a run or job stores where it ran
// (attempt, driver, placement id, image and digest, the level the image came from, identity binding,
// node), reported by the launcher at the claim and by the executor once placed, and exposes it
// read-only through the API.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestPlacement

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/placement"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func (f *agentPrepFixture) placementRouter() *gin.Engine {
	h := &RunnerAgentHandler{
		db: f.db, runnerRepo: repository.NewRunnerRepository(f.db), jobExecRepo: repository.NewRunnerJobExecutionRepository(f.db),
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db), storageClient: newSnapshotStore(),
	}
	return f.router(func(authed *gin.RouterGroup) {
		authed.POST("/jobs/:id/start", middleware.RequireRunnerToken(), h.JobStart)
		authed.POST("/jobs/:id/output", h.JobOutput)
	})
}

var claimPlacement = map[string]any{"driver": "container", "image": "registry.example.test/tofu:1.9", "image_digest": "sha256:abc", "image_level": "workspace"}

func TestPlacement_RecordedFromTheClaimAndTheExecutor(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := f.placementRouter()

	job := f.seedJob(t, nil, nil)
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+job.ID.String()+"/start", map[string]any{"runner_id": f.runnerA1.ID.String(), "placement": claimPlacement}); rec.Code != http.StatusOK {
		t.Fatalf("claim: %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+job.ID.String()+"/output", map[string]any{"runner_id": f.runnerA1.ID.String(), "output": "ok", "placement": map[string]any{"placement_id": "c0ffee", "node": "node-1"}}); rec.Code != http.StatusOK {
		t.Fatalf("output: %d (%s)", rec.Code, rec.Body.String())
	}
	var stored models.AnsibleJob
	if err := f.db.First(&stored, "id = ?", job.ID).Error; err != nil {
		t.Fatal(err)
	}
	p := stored.Placement
	if p.Driver != "container" || p.Image != "registry.example.test/tofu:1.9" || p.ImageDigest != "sha256:abc" || p.ImageLevel != "workspace" || p.PlacementID != "c0ffee" || p.Node != "node-1" || stored.Attempt != 1 {
		t.Fatalf("job placement = %+v attempt %d", p, stored.Attempt)
	}

	run := f.seedRun(t, f.runnerA1)
	if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Updates(map[string]any{"status": models.RunStatusPending, "runner_id": nil}).Error; err != nil {
		t.Fatal(err)
	}
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+run.ID+"/start", map[string]any{"runner_id": f.runnerA1.ID.String(), "placement": claimPlacement}); rec.Code != http.StatusOK {
		t.Fatalf("run claim: %d (%s)", rec.Code, rec.Body.String())
	}
	var storedRun models.Run
	if err := f.db.First(&storedRun, "id = ?", run.ID).Error; err != nil {
		t.Fatal(err)
	}
	if storedRun.Placement.Driver != "container" || storedRun.Placement.ImageDigest != "sha256:abc" {
		t.Fatalf("run placement = %+v", storedRun.Placement)
	}
}

func TestPlacement_AttributesWireShape(t *testing.T) {
	attrs := placement.FromModel(2, models.JobPlacement{Driver: "kubernetes", PlacementID: "sw-job-1", Image: "img", ImageDigest: "sha256:1", ImageLevel: "project", Node: "n1"})
	b, err := json.Marshal(attrs)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"attempt", "driver", "placement-id", "image", "image-digest", "image-level", "identity-binding-id", "node"} {
		if _, ok := m[k]; !ok {
			t.Errorf("placement attributes lack %q: %s", k, b)
		}
	}
	if m["attempt"] != float64(2) || m["driver"] != "kubernetes" {
		t.Errorf("placement attributes = %s", b)
	}
}

// A launcher whose kubelet pulled the image reports the digest it learnt from the pod, after the
// claim and with no output of its own (the Kubernetes driver): the API takes a placement-only
// report for a run, a job and a work item alike, and keeps what the claim recorded.
func TestPlacement_AReportWithOnlyAPlacementRecordsTheDigest(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := f.placementRouter()
	digestOnly := map[string]any{"image_digest": "sha256:" + strings.Repeat("d", 64)}

	run := f.seedRun(t, f.runnerA1)
	if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Updates(map[string]any{"status": models.RunStatusPending, "runner_id": nil}).Error; err != nil {
		t.Fatal(err)
	}
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+run.ID+"/start", map[string]any{"runner_id": f.runnerA1.ID.String(), "placement": map[string]any{"driver": "kubernetes", "image": "registry.example.test/tofu:1.9", "image_level": "workspace"}}); rec.Code != http.StatusOK {
		t.Fatalf("run claim: %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+run.ID+"/output", map[string]any{"runner_id": f.runnerA1.ID.String(), "placement": digestOnly}); rec.Code != http.StatusOK {
		t.Fatalf("placement-only report for a run: %d (%s)", rec.Code, rec.Body.String())
	}
	var storedRun models.Run
	if err := f.db.First(&storedRun, "id = ?", run.ID).Error; err != nil {
		t.Fatal(err)
	}
	if p := storedRun.Placement; p.ImageDigest != digestOnly["image_digest"] || p.Driver != "kubernetes" || p.Image != "registry.example.test/tofu:1.9" {
		t.Errorf("run placement = %+v, want the claim's record with the reported digest", p)
	}

	job := f.seedJob(t, nil, nil)
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+job.ID.String()+"/start", map[string]any{"runner_id": f.runnerA1.ID.String(), "placement": map[string]any{"driver": "kubernetes"}}); rec.Code != http.StatusOK {
		t.Fatalf("job claim: %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+job.ID.String()+"/output", map[string]any{"runner_id": f.runnerA1.ID.String(), "placement": digestOnly}); rec.Code != http.StatusOK {
		t.Fatalf("placement-only report for a job: %d (%s)", rec.Code, rec.Body.String())
	}
	var storedJob models.AnsibleJob
	if err := f.db.First(&storedJob, "id = ?", job.ID).Error; err != nil {
		t.Fatal(err)
	}
	if storedJob.Placement.ImageDigest != digestOnly["image_digest"] {
		t.Errorf("job placement = %+v, want the reported digest", storedJob.Placement)
	}

	// A report with nothing in it is still refused.
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+run.ID+"/output", map[string]any{"runner_id": f.runnerA1.ID.String()}); rec.Code != http.StatusBadRequest {
		t.Errorf("an empty report: %d, want 400", rec.Code)
	}
}
