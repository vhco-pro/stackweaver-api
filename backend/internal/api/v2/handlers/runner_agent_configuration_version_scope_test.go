// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What GET /api/v2/runner/jobs/:id/artifacts sends a self-hosted OpenTofu runner for a run that
// names a configuration version uploaded to another workspace (#916). The API refuses to create
// such a run, but a run row written before it did may name one, and this endpoint is where the
// uploaded code is read from storage for an agent: it must not be.
//
// The defect this test was written against: the handler read the archive of whatever
// configuration version the run named straight from storage, so the runner of one organization
// received code uploaded to a workspace of another.
//
// This is the agent-mode half. The platform runner reads the same archive itself; see
// TestProcessJob_ConfigurationVersionOfAnotherWorkspace in cmd/runner.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Every row is created under
// a unique name and removed by primary key. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRunnerRunArtifacts_ConfigurationVersion

//go:build integration

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func TestRunnerRunArtifacts_ConfigurationVersionOfAnotherWorkspace(t *testing.T) {
	f := setupAgentPrepFixture(t)
	sfx := uuid.NewString()[:8]
	// The archives are distinct strings, so that the response shows whose code it carries.
	const ownCode, otherCode = "configuration of its own workspace", "configuration of the other organization"

	otherProject := &models.Project{ID: uuid.New(), OrganizationID: f.runnerB1.OrganizationID, Name: "artcv-proj-" + sfx}
	workspace := &models.Workspace{ID: "ws-" + sfx + "9160000", ProjectID: f.projectA, Name: "artcv-ws-" + sfx, ExecutionMode: "agent", AgentPoolID: &f.poolA}
	otherWorkspace := &models.Workspace{ID: "ws-" + sfx + "9161111", ProjectID: otherProject.ID, Name: "artcv-ws-" + sfx}
	version := func(suffix, workspaceID string) *models.ConfigurationVersion {
		return &models.ConfigurationVersion{ID: "cv-" + sfx + suffix, WorkspaceID: workspaceID, Status: models.ConfigurationVersionStatusUploaded}
	}
	own, other := version("9160000", workspace.ID), version("9161111", otherWorkspace.ID)
	// Written directly: the shape of a run row stored before a run create checked its
	// configuration version.
	run := func(suffix string, configurationVersion *models.ConfigurationVersion) *models.Run {
		return &models.Run{
			ID: "run-" + sfx + suffix, WorkspaceID: workspace.ID, ConfigurationVersionID: &configurationVersion.ID,
			Status: models.RunStatusPending, Operation: models.RunOperationPlanOnly, AgentPoolID: &f.poolA,
		}
	}
	ownRun, storedEarlier := run("9160000", own), run("9161111", other)
	for _, row := range []any{otherProject, workspace, otherWorkspace, own, other, ownRun, storedEarlier} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}
	t.Cleanup(func() {
		// Children before parents (foreign-key order), each statement scoped to this run's rows.
		f.db.Where("id IN ?", []string{ownRun.ID, storedEarlier.ID}).Delete(&models.Run{})
		f.db.Where("id IN ?", []string{own.ID, other.ID}).Delete(&models.ConfigurationVersion{})
		f.db.Where("id IN ?", []string{workspace.ID, otherWorkspace.ID}).Delete(&models.Workspace{})
		f.db.Where("id = ?", otherProject.ID).Delete(&models.Project{})
	})

	store := newSnapshotStore()
	for configurationVersion, code := range map[*models.ConfigurationVersion]string{own: ownCode, other: otherCode} {
		if err := store.Put(t.Context(), "configuration-versions/"+configurationVersion.ID+"/config.tar.gz", []byte(code)); err != nil {
			t.Fatalf("storing the archive of %s: %v", configurationVersion.ID, err)
		}
	}
	h := &RunnerAgentHandler{db: f.db, storageClient: store}
	router := f.router(func(authed *gin.RouterGroup) {
		authed.GET("/jobs/:id/artifacts", h.GetJobArtifacts)
	})
	tarball := func(t *testing.T, run *models.Run) (string, bool) {
		t.Helper()
		rec := runnerGet(t, router, "a1", "/api/v2/runner/jobs/"+run.ID+"/artifacts")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET artifacts: status = %d (%s)", rec.Code, rec.Body.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("decoding the artifacts: %v", err)
		}
		encoded, ok := doc["config_tarball"].(string)
		return encoded, ok
	}

	if encoded, ok := tarball(t, storedEarlier); ok {
		t.Errorf("the artifacts of a run naming another workspace's configuration version carry an archive")
		if strings.Contains(encoded, base64.StdEncoding.EncodeToString([]byte(otherCode))) {
			t.Errorf("the archive is the other organization's code")
		}
	}
	if encoded, _ := tarball(t, ownRun); encoded != base64.StdEncoding.EncodeToString([]byte(ownCode)) {
		t.Errorf("the artifacts of a run naming its workspace's configuration version do not carry its archive")
	}
}
