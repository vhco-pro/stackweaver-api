// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/executor"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/variable"
	"github.com/michielvha/stackweaver/core/storage"
	"gorm.io/gorm"
)

func setupBlobRecoveryClaim(t *testing.T, legacy bool) (*claimRouteFixture, string, runnercontract.JobToken, []byte, *requiredInputStore) {
	t.Helper()
	f, id, token := setupOrderedRegistryClaim(t, legacy)
	f.handler.registryHost = ""
	f.handler.inlineArtifactLimit = 64
	var run models.Run
	if err := f.db.First(&run, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	if run.ClaimRecovery == legacy {
		t.Fatal("fixture has incorrect persisted recovery mode")
	}
	cv := &models.ConfigurationVersion{WorkspaceID: run.WorkspaceID, Status: models.ConfigurationVersionStatusUploaded}
	if err := f.db.Create(cv).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("job_id = ?", id).Delete(&models.RunnerBlobFetch{})
		f.db.Where("id = ?", cv.ID).Delete(&models.ConfigurationVersion{})
	})
	if err := f.db.Model(&models.Run{}).Where("id = ?", id).Update("configuration_version_id", cv.ID).Error; err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("configuration"), 100)
	store := &requiredInputStore{Client: newSnapshotStore()}
	if err := store.Put(t.Context(), models.ConfigurationTarballKey(cv.ID), data); err != nil {
		t.Fatal(err)
	}
	f.handler.storageClient = store
	group := f.router.Group("/api/v2/runner", middleware.RunnerAuth(repository.NewRunnerRepository(f.db), nil))
	group.GET("/jobs/:id/blob/*name", middleware.JobData(), f.handler.GetJobBlob)
	return f, id, token, data, store
}

func TestBlobRecovery_FixedClaimReplaysAuthorizedContent(t *testing.T) {
	f, id, token, data, _ := setupBlobRecoveryClaim(t, false)
	headers := map[string]string{"If-Match": "\"" + sha256Hex(data) + "\""}
	path := "/jobs/" + id + "/blob/config.tar.gz"
	for range 3 {
		rec := f.do(t, token.Token, http.MethodGet, path, nil, headers)
		if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), data) {
			t.Errorf("fixed-claim read = HTTP %d, body length %d", rec.Code, rec.Body.Len())
		}
	}
	var count int64
	if err := f.db.Model(&models.RunnerBlobFetch{}).Where("job_id = ?", id).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("replayable claim created %d legacy consumption rows", count)
	}
}

func TestBlobRecovery_FixedClaimRequiresStrongValidator(t *testing.T) {
	f, id, token, data, _ := setupBlobRecoveryClaim(t, false)
	valid := "\"" + sha256Hex(data) + "\""
	for _, value := range []string{"", "*", "W/" + valid, strings.Trim(valid, "\""), "\"" + strings.Repeat("A", 64) + "\"", valid + ", " + valid, "\"short\""} {
		t.Run(value, func(t *testing.T) {
			rec := f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/blob/config.tar.gz", nil, map[string]string{"If-Match": value})
			if rec.Code != http.StatusBadRequest {
				t.Errorf("invalid validator = HTTP %d, want 400", rec.Code)
			}
		})
	}
	rec := f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/blob/config.tar.gz", nil, map[string]string{"If-Match": "\"" + strings.Repeat("0", 64) + "\""})
	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("changed content = HTTP %d, want 412", rec.Code)
	}
	if code := errorCode(t, rec.Body.Bytes()); code != "" {
		t.Errorf("content change has stop code %q", code)
	}
}

func TestBlobRecovery_LegacyClaimKeepsOneFetchAfterRunnerUpgrade(t *testing.T) {
	f, id, token, data, _ := setupBlobRecoveryClaim(t, true)
	if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA1.ID).Update("capabilities", models.RunnerLabels{runnercontract.CapabilityJobToken, runnercontract.CapabilityClaimRecovery, runnercontract.CapabilityBlob}).Error; err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{runnercontract.CapabilitiesHeader: runnercontract.CapabilityClaimRecovery, "If-Match": "\"" + sha256Hex(data) + "\""}
	path := "/jobs/" + id + "/blob/config.tar.gz"
	if rec := f.do(t, token.Token, http.MethodGet, path, nil, headers); rec.Code != http.StatusOK {
		t.Fatalf("legacy first read = HTTP %d", rec.Code)
	}
	if rec := f.do(t, token.Token, http.MethodGet, path, nil, headers); rec.Code != http.StatusGone {
		t.Errorf("legacy repeat = HTTP %d, want 410", rec.Code)
	}
}

func TestBlobRecovery_RevalidatesAfterStorage(t *testing.T) {
	for _, name := range []string{"completed", "later_attempt", "claim_consumed", "different_phase", "token_revoked", "token_expired", "assignment_changed"} {
		t.Run(name, func(t *testing.T) {
			f, id, token, data, store := setupBlobRecoveryClaim(t, false)
			key, err := f.keys.VerifyAPIKey(token.Token)
			if err != nil {
				t.Fatal(err)
			}
			store.read = func(ctx context.Context, keyName string) ([]byte, error) {
				data, err := store.Client.Get(ctx, keyName)
				if err != nil {
					return nil, err
				}
				var updateErr error
				switch name {
				case "completed":
					updateErr = f.db.Model(&models.Run{}).Where("id = ?", id).Update("status", models.RunStatusErrored).Error
				case "later_attempt":
					updateErr = f.db.Model(&models.Run{}).Where("id = ?", id).Update("attempt", 2).Error
				case "claim_consumed":
					updateErr = f.db.Model(&models.Run{}).Where("id = ?", id).Update("dispatched_at", nil).Error
				case "different_phase":
					updateErr = f.db.Model(&models.Run{}).Where("id = ?", id).Updates(map[string]any{"claimed_phase": "apply", "claimed_run_type": "apply", "status": models.RunStatusApplying}).Error
				case "token_revoked":
					updateErr = f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}).Error
				case "token_expired":
					updateErr = f.db.Model(&models.APIKey{}).Where("id = ?", key.ID).Update("expires_at", time.Now().Add(-time.Minute)).Error
				case "assignment_changed":
					updateErr = f.db.Model(&models.Run{}).Where("id = ?", id).Update("runner_id", f.runnerA2.ID).Error
				}
				if updateErr != nil {
					return nil, updateErr
				}
				return data, nil
			}
			rec := f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/blob/config.tar.gz", nil, map[string]string{"If-Match": "\"" + sha256Hex(data) + "\""})
			if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
				t.Errorf("post-storage %s = HTTP %d, want refusal", name, rec.Code)
			}
			if bytes.Equal(rec.Body.Bytes(), data) {
				t.Error("post-storage refusal exposed content")
			}
		})
	}
}

func TestBlobRecovery_ConcurrentReplicasServeSameFixedClaim(t *testing.T) {
	f, id, token, data, _ := setupBlobRecoveryClaim(t, false)
	// Separate handler values share only the authoritative database and object store.
	replica := *f.handler
	authService := auth.NewService(repository.NewUserRepository(f.db))
	authService.SetAPIKeyService(f.keys)
	second := gin.New()
	second.Use(middleware.AuthMiddleware(authService))
	group := second.Group("/api/v2/runner", middleware.RunnerAuth(repository.NewRunnerRepository(f.db), nil))
	group.GET("/jobs/:id/blob/*name", middleware.JobData(), replica.GetJobBlob)
	var wg sync.WaitGroup
	codes := make(chan int, 4)
	routers := []*gin.Engine{f.router, second}
	for i := range 4 {
		wg.Go(func() {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/runner/jobs/"+id+"/blob/config.tar.gz", nil)
			req.Header.Set("Authorization", "Bearer "+token.Token)
			req.Header.Set("If-Match", "\""+sha256Hex(data)+"\"")
			rec := httptest.NewRecorder()
			routers[i%len(routers)].ServeHTTP(rec, req)
			codes <- rec.Code
		})
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusOK {
			t.Errorf("concurrent read = HTTP %d", code)
		}
	}
}

func TestBlobRecovery_StorageFailureIsRetryable(t *testing.T) {
	f, id, token, data, store := setupBlobRecoveryClaim(t, false)
	store.getError = errors.New("storage read interrupted")
	rec := f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/blob/config.tar.gz", nil, map[string]string{"If-Match": "\"" + sha256Hex(data) + "\""})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("storage failure = HTTP %d, want 500", rec.Code)
	}
}

func TestBlobRecovery_CacheJobDatabaseFailure(t *testing.T) {
	f := setupClaimRouteFixture(t)
	id, _, token := f.startCompletion(t, startRouteCases[0])
	group := f.router.Group("/api/v2/runner", middleware.RunnerAuth(repository.NewRunnerRepository(f.db), nil))
	group.GET("/jobs/:id/blob/*name", middleware.JobData(), f.handler.GetJobBlob)
	rec := runnerReadFailure(t, f.db, "ansible_jobs", 1, errors.New("cache job database interrupted"), func() *httptest.ResponseRecorder {
		return f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/blob/cache/tofu/"+strings.Repeat("a", 64), nil)
	})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("cache job database failure = HTTP %d, want 500", rec.Code)
	}
}

func TestBlobRecovery_CacheStorageFailureAndAbsence(t *testing.T) {
	for _, failure := range []error{errors.New("cache storage interrupted"), storage.ErrNotFound} {
		t.Run(failure.Error(), func(t *testing.T) {
			f, id, token, _, store := setupBlobRecoveryClaim(t, false)
			sum := strings.Repeat("a", 64)
			entry := &models.CacheEntry{OrganizationID: f.orgA, Kind: string(runnercontract.CacheKindTofu), SHA256: sum, SizeBytes: 100}
			if err := f.db.Create(entry).Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.db.Where("id = ?", entry.ID).Delete(&models.CacheEntry{}) })
			store.streamError = failure
			rec := f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/blob/cache/tofu/"+sum, nil)
			expected := http.StatusInternalServerError
			if errors.Is(failure, storage.ErrNotFound) {
				expected = http.StatusNotFound
			}
			if rec.Code != expected {
				t.Errorf("cache storage response = HTTP %d, want %d", rec.Code, expected)
			}
		})
	}
}

func TestRequiredInputs_StorageUsesRequestContext(t *testing.T) {
	for _, route := range []string{"artifacts", "blob/config.tar.gz", "plan"} {
		t.Run(route, func(t *testing.T) {
			f, id, token, data, store := setupBlobRecoveryClaim(t, false)
			group := f.router.Group("/api/v2/runner", middleware.RunnerAuth(repository.NewRunnerRepository(f.db), nil))
			group.GET("/jobs/:id/plan", middleware.JobData(), f.handler.DownloadPlan)
			type contextKey struct{}
			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), contextKey{}, true))
			defer cancel()
			observed := false
			store.read = func(readCtx context.Context, _ string) ([]byte, error) {
				cancel()
				observed = readCtx.Value(contextKey{}) == true && errors.Is(readCtx.Err(), context.Canceled)
				return nil, errors.New("storage request canceled")
			}
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/runner/jobs/"+id+"/"+route, nil)
			req.Header.Set("Authorization", "Bearer "+token.Token)
			req.Header.Set("If-Match", "\""+sha256Hex(data)+"\"")
			req.Header.Set(runnercontract.ArtifactSequenceHeader, "1")
			rec := httptest.NewRecorder()
			f.router.ServeHTTP(rec, req)
			if !observed || rec.Code != http.StatusInternalServerError {
				t.Errorf("storage cancellation observed %v, HTTP %d", observed, rec.Code)
			}
		})
	}
}

func TestRequiredInputs_VariableQueriesUseRequestContext(t *testing.T) {
	for _, occurrence := range []int{1, 2} {
		t.Run(strconv.Itoa(occurrence), func(t *testing.T) {
			f, id, token, _, _ := setupBlobRecoveryClaim(t, false)
			f.handler.variableService = variable.NewServiceWithVariableSetsAndWorkspace(repository.NewVariableRepository(f.db), nil, nil, []byte("0123456789abcdef0123456789abcdef"))
			type contextKey struct{}
			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), contextKey{}, true))
			defer cancel()
			seen, observed := 0, false
			name := "required-variable-context"
			if err := f.db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
				if tx.Statement.Table == "variables" {
					seen++
					if seen == occurrence {
						observed = tx.Statement.Context.Value(contextKey{}) == true
						cancel()
					}
				}
			}); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.db.Callback().Query().Remove(name) }()
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/runner/jobs/"+id+"/artifacts", nil)
			req.Header.Set("Authorization", "Bearer "+token.Token)
			req.Header.Set(runnercontract.ArtifactSequenceHeader, "1")
			rec := httptest.NewRecorder()
			f.router.ServeHTTP(rec, req)
			if !observed || rec.Code != http.StatusInternalServerError {
				t.Errorf("variable cancellation observed %v at query %d, HTTP %d", observed, seen, rec.Code)
			}
		})
	}
}

func TestBlobRecovery_SlowStorageBeforeHeaders(t *testing.T) {
	for _, route := range []string{"artifacts", "blob"} {
		t.Run(route, func(t *testing.T) {
			f, id, token, data, store := setupBlobRecoveryClaim(t, false)
			store.read = func(ctx context.Context, key string) ([]byte, error) {
				timer := time.NewTimer(30 * time.Second)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-timer.C:
					return store.Client.Get(ctx, key)
				}
			}
			server := httptest.NewServer(f.router)
			defer server.Close()
			client := executor.NewClient(server.URL, token.Token, f.runnerA1.ID.String())
			started := time.Now()
			if route == "blob" {
				got, err := client.Blob(t.Context(), runnercontract.BlobRef{Path: "/api/v2/runner/jobs/" + id + "/blob/config.tar.gz", SHA256: sha256Hex(data), SizeBytes: int64(len(data))})
				if err != nil || !bytes.Equal(got, data) {
					t.Fatalf("slow storage read = %v, %d bytes", err, len(got))
				}
			} else {
				var artifacts runnercontract.TofuArtifacts
				if err := client.Artifacts(t.Context(), id, &artifacts, nil); err != nil {
					t.Fatal(err)
				}
				ref := artifacts.ConfigTarballBlob
				if ref == nil || ref.SHA256 != sha256Hex(data) || ref.SizeBytes != int64(len(data)) || artifacts.ConfigTarball != "" {
					t.Fatalf("slow required artifacts returned an incomplete blob reference: %+v", ref)
				}
			}
			if elapsed := time.Since(started); elapsed < 30*time.Second {
				t.Errorf("storage delay was skipped: %s", elapsed)
			}
		})
	}
}

func TestBlobRecovery_ActualClientRetriesLostResponse(t *testing.T) {
	f, id, token, data, _ := setupBlobRecoveryClaim(t, false)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if calls.Add(1) == 1 {
			rec := httptest.NewRecorder()
			f.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("discarded response = HTTP %d", rec.Code)
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		f.router.ServeHTTP(w, req)
	}))
	defer server.Close()
	client := executor.NewClient(server.URL, token.Token, f.runnerA1.ID.String())
	got, err := client.Blob(t.Context(), runnercontract.BlobRef{Path: "/api/v2/runner/jobs/" + id + "/blob/config.tar.gz", SHA256: sha256Hex(data), SizeBytes: int64(len(data))})
	if err != nil || !bytes.Equal(got, data) || calls.Load() != 2 {
		t.Fatalf("lost HTTP response recovery = %v, %d bytes, %d requests", err, len(got), calls.Load())
	}
}

func TestBlobRecovery_ActualClientRetriesStorageFailure(t *testing.T) {
	f, id, token, data, store := setupBlobRecoveryClaim(t, false)
	var calls atomic.Int32
	store.read = func(ctx context.Context, key string) ([]byte, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("transient storage outage")
		}
		return store.Client.Get(ctx, key)
	}
	server := httptest.NewServer(f.router)
	defer server.Close()
	client := executor.NewClient(server.URL, token.Token, f.runnerA1.ID.String())
	got, err := client.Blob(t.Context(), runnercontract.BlobRef{Path: "/api/v2/runner/jobs/" + id + "/blob/config.tar.gz", SHA256: sha256Hex(data), SizeBytes: int64(len(data))})
	if err != nil || !bytes.Equal(got, data) || calls.Load() != 2 {
		t.Fatalf("storage recovery = %v, %d bytes, %d storage reads", err, len(got), calls.Load())
	}
}
