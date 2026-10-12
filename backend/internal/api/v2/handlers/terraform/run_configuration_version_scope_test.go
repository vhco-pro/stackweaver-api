// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a run may name as its configuration version (#916): one that belongs to the run's own
// workspace. A configuration version of another workspace is answered exactly like an identifier
// that names nothing, and a run row that already names one downloads nothing of it.
//
// The defect these tests were written against: a run create stored the configuration version the
// body named, and a runner downloads a run's configuration version by identifier. A run in one
// organization's workspace could name a configuration version uploaded to a workspace of
// another, and would plan that organization's code. An identifier that named nothing failed at
// the foreign key with a 500.
//
// Terraform Enterprise documents 404 for "organization or workspace not found, or user
// unauthorized" on run create and nothing for this case, so the 404 pinned here is this API's
// own choice within the documented answers.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run 'TestRunConfigurationVersion'

//go:build integration

package terraform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// runConfigurationVersionFixture is runCreateScopeFixture with configuration versions: one of
// the run's workspace, one of a sibling workspace in the same organization, and one uploaded to
// a workspace of the second organization, where the caller has no team.
type runConfigurationVersionFixture struct {
	*runCreateScopeFixture
	own, sibling, other *models.ConfigurationVersion
}

func setupRunConfigurationVersions(t *testing.T) *runConfigurationVersionFixture {
	t.Helper()
	base := setupRunCreateScope(t)
	if err := base.db.AutoMigrate(&models.ConfigurationVersion{}); err != nil {
		t.Fatalf("migrating configuration versions: %v", err)
	}
	sfx := uuid.NewString()[:8]
	otherProject := &models.Project{ID: uuid.New(), OrganizationID: base.orgB, Name: "runcv-proj-" + sfx}
	otherWorkspace := &models.Workspace{ID: "ws-" + sfx + "9161111", ProjectID: otherProject.ID, Name: "runcv-other"}
	siblingWorkspace := &models.Workspace{ID: "ws-" + sfx + "9162222", ProjectID: base.projectA, Name: "runcv-sibling-" + sfx}
	version := func(suffix, workspaceID string) *models.ConfigurationVersion {
		return &models.ConfigurationVersion{ID: "cv-" + sfx + suffix, WorkspaceID: workspaceID, Status: models.ConfigurationVersionStatusUploaded}
	}
	f := &runConfigurationVersionFixture{
		runCreateScopeFixture: base,
		own:                   version("9160000", base.workspace),
		sibling:               version("9162222", siblingWorkspace.ID),
		other:                 version("9161111", otherWorkspace.ID),
	}
	for _, row := range []any{otherProject, otherWorkspace, siblingWorkspace, f.own, f.sibling, f.other} {
		if err := base.db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}
	versionIDs := []string{f.own.ID, f.sibling.ID, f.other.ID}
	workspaceIDs := []string{otherWorkspace.ID, siblingWorkspace.ID}
	t.Cleanup(func() {
		// Registered after the shared fixture's cleanup, so it runs before it; children before
		// parents, each statement scoped to this run's identifiers.
		base.db.Where("configuration_version_id IN ?", versionIDs).Delete(&models.Run{})
		base.db.Where("id IN ?", versionIDs).Delete(&models.ConfigurationVersion{})
		base.db.Where("id IN ?", workspaceIDs).Delete(&models.Workspace{})
		base.db.Where("id = ?", otherProject.ID).Delete(&models.Project{})
	})
	return f
}

// post creates a plan-only run of the fixture's workspace naming the configuration version.
func (f *runConfigurationVersionFixture) post(t *testing.T, configurationVersion string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"data": map[string]any{
		"type":       "runs",
		"attributes": map[string]any{"message": "configuration version scope", "plan-only": true},
		"relationships": map[string]any{
			"workspace":             map[string]any{"data": map[string]any{"type": "workspaces", "id": f.workspace}},
			"configuration-version": map[string]any{"data": map[string]any{"type": "configuration-versions", "id": configurationVersion}},
		},
	}})
	if err != nil {
		t.Fatalf("marshalling the request document: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// runsNaming counts the runs that name the configuration version.
func (f *runConfigurationVersionFixture) runsNaming(t *testing.T, configurationVersion string) int64 {
	t.Helper()
	var n int64
	if err := f.db.Model(&models.Run{}).Where("configuration_version_id = ?", configurationVersion).Count(&n).Error; err != nil {
		t.Fatalf("counting the runs: %v", err)
	}
	return n
}

func TestRunConfigurationVersion_AnotherWorkspaceReadsAsNotFound(t *testing.T) {
	f := setupRunConfigurationVersions(t)
	missing := f.post(t, "cv-"+uuid.NewString()[:8]+"9169999")
	if missing.Code != http.StatusNotFound || !strings.Contains(missing.Body.String(), "Configuration version not found") {
		t.Fatalf("a configuration version that does not exist: %d %s, want 404 Configuration version not found", missing.Code, missing.Body.String())
	}
	for name, version := range map[string]*models.ConfigurationVersion{
		"a workspace of another organization":        f.other,
		"another workspace of the same organization": f.sibling,
	} {
		t.Run(name, func(t *testing.T) {
			foreign := f.post(t, version.ID)
			if foreign.Code != missing.Code || !bytes.Equal(foreign.Body.Bytes(), missing.Body.Bytes()) {
				t.Errorf("another workspace's configuration version and one that does not exist are answered differently:\n  other workspace: %d %s\n  does not exist:  %d %s",
					foreign.Code, foreign.Body.String(), missing.Code, missing.Body.String())
			}
			if got := f.runsNaming(t, version.ID); got != 0 {
				t.Errorf("%d run(s) name the other workspace's configuration version", got)
			}
		})
	}
}

func TestRunConfigurationVersion_OwnWorkspaceIsAccepted(t *testing.T) {
	f := setupRunConfigurationVersions(t)
	rec := f.post(t, f.own.ID)
	if rec.Code != http.StatusCreated {
		t.Fatalf("a run naming its workspace's configuration version: %d %s", rec.Code, rec.Body.String())
	}
	if got := f.runsNaming(t, f.own.ID); got != 1 {
		t.Errorf("%d run(s) name the workspace's own configuration version, want the one created", got)
	}
}

// TestRunConfigurationVersion_StoredRowIsNotTrusted writes run rows directly, the way one stored
// before the API checked would be, and asks what the token of each run's task may download.
func TestRunConfigurationVersion_StoredRowIsNotTrusted(t *testing.T) {
	f := setupRunConfigurationVersions(t)
	stored := func(version *models.ConfigurationVersion) *models.Run {
		t.Helper()
		run := &models.Run{
			ID: "run-" + uuid.NewString()[:8] + "9160000", WorkspaceID: f.workspace, ConfigurationVersionID: &version.ID,
			Status: models.RunStatusPending, Operation: models.RunOperationPlanOnly,
		}
		if err := f.db.Create(run).Error; err != nil {
			t.Fatalf("writing the run row: %v", err)
		}
		return run
	}
	match := TaskTokenMatchesConfigurationVersion(f.runRepo, repository.NewConfigurationVersionRepository(f.db))
	download := func(run *models.Run, configurationVersion string) bool {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Params = gin.Params{{Key: "id", Value: configurationVersion}}
		return match(c, "taskrs-unused", run.ID)
	}

	storedEarlier, own := stored(f.other), stored(f.own)
	if download(storedEarlier, f.other.ID) {
		t.Errorf("the task token of a run naming another workspace's configuration version may download it")
	}
	if !download(own, f.own.ID) {
		t.Errorf("the task token of a run may not download its own workspace's configuration version")
	}
	if download(own, f.other.ID) {
		t.Errorf("the task token of a run may download a configuration version the run does not name")
	}
}
