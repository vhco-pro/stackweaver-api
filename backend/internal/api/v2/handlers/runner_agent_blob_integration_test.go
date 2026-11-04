// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for large-artifact delivery (#933, D2, AC13): above the inline threshold a
// configuration tarball or a state reaches a capable runner through GET /runner/jobs/:id/blob/*name
// on the API itself, once per attempt and under the job token, never as a storage URL; an older
// agent still gets them inline. A large state is uploaded as a raw request body.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestBlob

//go:build integration

package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/state"
)

func (f *agentPrepFixture) blobRouter(t *testing.T, store *snapshotStore) (*gin.Engine, *apikey.Service) {
	t.Helper()
	cs, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	stateSvc := state.NewService(repository.NewStateVersionRepository(f.db), repository.NewStateLockRepository(f.db), repository.NewWorkspaceRepository(f.db), store, nil, cs)
	h := &RunnerAgentHandler{
		db:                  f.db,
		runnerRepo:          repository.NewRunnerRepository(f.db),
		apiKeyService:       svc,
		ansibleJobRepo:      repository.NewAnsibleJobRepository(f.db),
		storageClient:       store,
		cryptoService:       cs,
		stateService:        stateSvc,
		inlineArtifactLimit: 64,
		registryHost:        "registry.example.test",
	}
	return f.router(func(authed *gin.RouterGroup) {
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.GET("/jobs/:id/artifacts", middleware.JobData(), h.GetJobArtifacts)
		authed.GET("/jobs/:id/blob/*name", middleware.JobData(), h.GetJobBlob)
		authed.POST("/jobs/:id/state", middleware.JobData(), h.UploadState)
	}), svc
}

// seedRunWithConfig seeds a run whose configuration version holds tarball.
func (f *agentPrepFixture) seedRunWithConfig(t *testing.T, store *snapshotStore, tarball []byte) *models.Run {
	t.Helper()
	run := f.seedRun(t, f.runnerA1)
	cv := &models.ConfigurationVersion{ID: "cv-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16], WorkspaceID: run.WorkspaceID, Status: models.ConfigurationVersionStatus("uploaded")}
	if err := f.db.Create(cv).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", cv.ID).Delete(&models.ConfigurationVersion{}) })
	if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Update("configuration_version_id", cv.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Put(t.Context(), "configuration-versions/"+cv.ID+"/config.tar.gz", tarball); err != nil {
		t.Fatal(err)
	}
	run.ConfigurationVersionID = &cv.ID
	return run
}

func artifactsAs(t *testing.T, r *gin.Engine, key, runID, capabilities string) (runnercontract.TofuArtifacts, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/runner/jobs/"+runID+"/artifacts", nil)
	req.Header.Set("X-Test-Key", key)
	if capabilities != "" {
		req.Header.Set(runnercontract.CapabilitiesHeader, capabilities)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("artifacts: %d (%s)", rec.Code, rec.Body.String())
	}
	var arts runnercontract.TofuArtifacts
	if err := json.Unmarshal(rec.Body.Bytes(), &arts); err != nil {
		t.Fatal(err)
	}
	return arts, rec.Body.String()
}

func TestBlob_LargeTarballThroughTheBlobRouteOnce(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc := f.blobRouter(t, store)
	tarball := bytes.Repeat([]byte("large configuration "), 50)
	run := f.seedRunWithConfig(t, store, tarball)
	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}

	arts, raw := artifactsAs(t, r, "job", run.ID, runnercontract.CapabilityBlob)
	if arts.ConfigTarball != "" {
		t.Error("a tarball above the threshold was inlined")
	}
	if arts.ConfigTarballBlob == nil || arts.ConfigTarballBlob.Path != "/api/v2/runner/jobs/"+run.ID+"/blob/config.tar.gz" || arts.ConfigTarballBlob.SizeBytes != int64(len(tarball)) {
		t.Fatalf("config_tarball_blob = %+v", arts.ConfigTarballBlob)
	}
	sum := sha256.Sum256(tarball)
	if arts.ConfigTarballBlob.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("blob sha256 = %s", arts.ConfigTarballBlob.SHA256)
	}
	for _, leak := range []string{"http://", "https://", "X-Amz", "Signature="} {
		if strings.Contains(raw, leak) {
			t.Errorf("the artifacts response carries %q", leak)
		}
	}

	got := runnerDo(t, r, "job", http.MethodGet, arts.ConfigTarballBlob.Path, nil)
	if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), tarball) {
		t.Fatalf("blob download: %d, %d bytes", got.Code, got.Body.Len())
	}
	if again := runnerDo(t, r, "job", http.MethodGet, arts.ConfigTarballBlob.Path, nil); again.Code != http.StatusGone {
		t.Errorf("a second download of the same blob in the same attempt: %d, want 410", again.Code)
	}
	if other := runnerDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/blob/../../etc", nil); other.Code != http.StatusNotFound {
		t.Errorf("an unknown blob name: %d, want 404", other.Code)
	}
}

func TestBlob_OlderAgentGetsTheTarballInline(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, _ := f.blobRouter(t, store)
	tarball := bytes.Repeat([]byte("large configuration "), 50)
	run := f.seedRunWithConfig(t, store, tarball)
	arts, _ := artifactsAs(t, r, "a1", run.ID, runnercontract.CapabilityPlaybookSnapshot)
	if arts.ConfigTarball == "" || arts.ConfigTarballBlob != nil {
		t.Fatalf("an agent without the blob capability got inline=%t blob=%+v, want the tarball inline", arts.ConfigTarball != "", arts.ConfigTarballBlob)
	}
}

func TestBlob_LargeStateUploadedAsARawBody(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc := f.blobRouter(t, store)
	run := f.seedRun(t, f.runnerA1)
	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	stateFile := []byte(`{"version":4,"terraform_version":"1.9.0","serial":1,"lineage":"blob-test","outputs":{},"resources":[]}`)
	rec := rawPost(t, r, "job", "/api/v2/runner/jobs/"+run.ID+"/state", stateFile)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("raw state upload: %d (%s)", rec.Code, rec.Body.String())
	}
	t.Cleanup(func() { f.db.Where("workspace_id = ?", run.WorkspaceID).Delete(&models.StateVersion{}) })
	var n int64
	f.db.Model(&models.StateVersion{}).Where("workspace_id = ?", run.WorkspaceID).Count(&n)
	if n != 1 {
		t.Fatalf("state versions after the upload = %d, want 1", n)
	}

	// The latest state is now delivered through the blob route too.
	arts, _ := artifactsAs(t, r, "job", run.ID, runnercontract.CapabilityBlob)
	if arts.StateJSON != "" || arts.StateBlob == nil {
		t.Fatalf("state above the threshold: inline=%t blob=%+v", arts.StateJSON != "", arts.StateBlob)
	}
	got := runnerDo(t, r, "job", http.MethodGet, arts.StateBlob.Path, nil)
	if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), stateFile) {
		t.Fatalf("state blob: %d (%s)", got.Code, got.Body.String())
	}
}
