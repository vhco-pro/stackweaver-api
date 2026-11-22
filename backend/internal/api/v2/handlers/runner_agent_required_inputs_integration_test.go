// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/state"
	"github.com/michielvha/stackweaver/core/services/variable"
	"github.com/michielvha/stackweaver/core/storage"
)

type requiredInputStore struct {
	storage.Client
	getError    error
	listError   error
	streamError error
	read        func(context.Context, string) ([]byte, error)
}

func (s *requiredInputStore) Get(ctx context.Context, key string) ([]byte, error) {
	if s.read != nil {
		return s.read(ctx, key)
	}
	if s.getError != nil {
		return nil, s.getError
	}
	return s.Client.Get(ctx, key)
}

func (s *requiredInputStore) List(ctx context.Context, prefix string) ([]storage.ObjectInfo, error) {
	if s.listError != nil {
		return nil, s.listError
	}
	return s.Client.List(ctx, prefix)
}

func TestRequiredInputs_FailBeforeArtifactsSuccess(t *testing.T) {
	for _, name := range []string{"configuration_storage", "configuration_missing", "configuration_unavailable", "state_storage", "state_missing", "state_decryption", "state_empty", "variables_database", "environment_database", "variables_decryption", "environment_decryption", "plan_descriptor", "plan_download"} {
		for _, blobCapable := range []bool{false, true} {
			mode := "inline"
			if blobCapable {
				mode = "blob-reference"
			}
			t.Run(name+"/"+mode, func(t *testing.T) {
				f := setupClaimRouteFixture(t)
				f.handler.inlineArtifactLimit = 1
				cfg := startRouteCases[2]
				if name == "plan_descriptor" || name == "plan_download" {
					cfg = startRouteCases[4]
				}
				id, _, token := f.startCompletion(t, cfg)
				var run models.Run
				if err := f.db.First(&run, "id = ?", id).Error; err != nil {
					t.Fatal(err)
				}
				store := &requiredInputStore{Client: newSnapshotStore()}
				f.handler.storageClient = store
				f.handler.variableService = variable.NewServiceWithVariableSetsAndWorkspace(repository.NewVariableRepository(f.db), nil, nil, []byte("0123456789abcdef0123456789abcdef"))
				f.handler.stateService = state.NewService(repository.NewStateVersionRepository(f.db), repository.NewStateLockRepository(f.db), repository.NewWorkspaceRepository(f.db), store, nil, f.handler.cryptoService)
				group := f.router.Group("/api/v2/runner", middleware.RunnerAuth(repository.NewRunnerRepository(f.db), nil))
				group.GET("/jobs/:id/artifacts", middleware.JobData(), f.handler.GetJobArtifacts)
				group.GET("/jobs/:id/plan", middleware.JobData(), f.handler.DownloadPlan)
				path := "/jobs/" + id + "/artifacts"
				failure := errors.New("required input storage interrupted")
				switch name {
				case "configuration_storage", "configuration_missing", "configuration_unavailable":
					cv := &models.ConfigurationVersion{WorkspaceID: run.WorkspaceID, Status: models.ConfigurationVersionStatusUploaded}
					if err := f.db.Create(cv).Error; err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { f.db.Where("id = ?", cv.ID).Delete(&models.ConfigurationVersion{}) })
					if err := f.db.Model(&models.Run{}).Where("id = ?", id).Update("configuration_version_id", cv.ID).Error; err != nil {
						t.Fatal(err)
					}
					store.getError = failure
					if name == "configuration_unavailable" {
						f.handler.storageClient = nil
					}
					if name == "configuration_missing" {
						store.getError = storage.ErrNotFound
					}
				case "state_storage", "state_missing", "state_decryption", "state_empty":
					sv := &models.StateVersion{WorkspaceID: run.WorkspaceID, Version: 1}
					if err := f.db.Create(sv).Error; err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { f.db.Where("id = ?", sv.ID).Delete(&models.StateVersion{}) })
					store.getError = failure
					if name == "state_missing" {
						store.getError = storage.ErrNotFound
					}
					if name == "state_empty" {
						store.getError = nil
						if err := store.Put(t.Context(), models.StateObjectKey(run.WorkspaceID, 1), nil); err != nil {
							t.Fatal(err)
						}
					}
					if name == "state_decryption" {
						store.getError = nil
						if err := store.Put(t.Context(), models.StateObjectKey(run.WorkspaceID, 1), []byte("invalid encrypted state")); err != nil {
							t.Fatal(err)
						}
					}
				case "variables_decryption", "environment_decryption":
					category := "terraform"
					if name == "environment_decryption" {
						category = "env"
					}
					v := &models.Variable{WorkspaceID: run.WorkspaceID, Key: "required_secret", Value: "invalid ciphertext", Encrypted: true, Sensitive: true, Category: category}
					if err := f.db.Create(v).Error; err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { f.db.Where("id = ?", v.ID).Delete(&models.Variable{}) })
				case "plan_descriptor":
					store.listError = failure
				case "plan_download":
					store.getError = failure
					path = "/jobs/" + id + "/plan"
				}
				before := f.completionSnapshot(t, "runs", id)
				call := func() *httptest.ResponseRecorder {
					headers := map[string]string{runnercontract.ArtifactSequenceHeader: "1"}
					if blobCapable {
						headers[runnercontract.CapabilitiesHeader] = runnercontract.CapabilityBlob
					}
					return f.do(t, token.Token, http.MethodGet, path, nil, headers)
				}
				var rec *httptest.ResponseRecorder
				if name == "variables_database" || name == "environment_database" {
					occurrence := 1
					if name == "environment_database" {
						occurrence = 2
					}
					rec = runnerReadFailure(t, f.db, "variables", occurrence, failure, call)
				} else {
					rec = call()
				}
				if rec.Code != http.StatusInternalServerError {
					t.Errorf("required read = HTTP %d, want 500", rec.Code)
				}
				if after := f.completionSnapshot(t, "runs", id); after != before {
					t.Error("required-input failure changed the claim or credentials")
				}
				if code := errorCode(t, rec.Body.Bytes()); code != "" {
					t.Errorf("required read failure has stop code %q", code)
				}
			})
		}
	}
}

func (s *requiredInputStore) GetStream(ctx context.Context, key string) (io.ReadCloser, error) {
	if s.streamError != nil {
		return nil, s.streamError
	}
	return s.Client.GetStream(ctx, key)
}
