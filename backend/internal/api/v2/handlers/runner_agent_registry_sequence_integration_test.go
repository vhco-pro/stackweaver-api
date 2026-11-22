// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/executor"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
)

func setupOrderedRegistryClaim(t *testing.T, legacy bool) (*claimRouteFixture, string, runnercontract.JobToken) {
	t.Helper()
	f := setupClaimRouteFixture(t)
	f.handler.registryHost = "registry.example.test"
	group := f.router.Group("/api/v2/runner", middleware.RunnerAuth(repository.NewRunnerRepository(f.db), nil))
	group.GET("/jobs/:id/artifacts", middleware.JobData(), f.handler.GetJobArtifacts)
	if !legacy {
		id, _, token := f.startCompletion(t, startRouteCases[2])
		return f, id, token
	}
	id, _ := f.seedStart(t, startRouteCases[2])
	if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String()}); rec.Code != http.StatusOK {
		t.Fatalf("legacy registry claim = HTTP %d", rec.Code)
	}
	rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/token", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy registry job token = HTTP %d", rec.Code)
	}
	var token runnercontract.JobToken
	if err := json.Unmarshal(rec.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	// Claims and tokens minted by the previous API predate this additive column.
	if err := f.db.Model(&models.Run{}).Where("id = ?", id).UpdateColumn("claimed_run_type", "").Error; err != nil {
		t.Fatal(err)
	}
	return f, id, token
}

func registryCredential(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("registry artifacts = HTTP %d", rec.Code)
	}
	var artifacts runnercontract.TofuArtifacts
	if err := json.Unmarshal(rec.Body.Bytes(), &artifacts); err != nil {
		t.Fatal(err)
	}
	if artifacts.Registry == nil || len(artifacts.Registry.Hosts) != 1 || artifacts.Registry.Hosts[0].Token == "" {
		t.Fatal("registry artifact response has no complete credential")
	}
	return artifacts.Registry.Hosts[0].Token
}

func TestRegistrySequence_FixedClaimRejectsInvalidOrMissingSequence(t *testing.T) {
	for _, test := range []struct {
		name    string
		headers map[string]string
	}{
		{name: "missing"},
		{name: "empty", headers: map[string]string{runnercontract.ArtifactSequenceHeader: ""}},
		{name: "zero", headers: map[string]string{runnercontract.ArtifactSequenceHeader: "0"}},
		{name: "negative", headers: map[string]string{runnercontract.ArtifactSequenceHeader: "-1"}},
		{name: "malformed", headers: map[string]string{runnercontract.ArtifactSequenceHeader: "not-a-number"}},
		{name: "overflow", headers: map[string]string{runnercontract.ArtifactSequenceHeader: "9223372036854775808"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, id, token := setupOrderedRegistryClaim(t, false)
			before := f.completionSnapshot(t, "runs", id)
			rec := f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/artifacts", nil, test.headers)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("invalid fixed artifact sequence = HTTP %d, want 400", rec.Code)
			}
			if after := f.completionSnapshot(t, "runs", id); before != after {
				t.Error("invalid artifact sequence changed credentials or claim metadata")
			}
		})
	}
}

func TestRegistrySequence_OrderedLegacyClaimCannotDowngrade(t *testing.T) {
	f, id, token := setupOrderedRegistryClaim(t, true)
	path := "/jobs/" + id + "/artifacts"
	first := registryCredential(t, f.do(t, token.Token, http.MethodGet, path, nil))
	second := registryCredential(t, f.do(t, token.Token, http.MethodGet, path, nil))
	if _, err := f.keys.VerifyAPIKey(first); err == nil {
		t.Error("legacy replacement left its earlier registry credential valid")
	}
	if _, err := f.keys.VerifyAPIKey(second); err != nil {
		t.Error("legacy replacement credential does not verify")
	}
	ordered := registryCredential(t, f.do(t, token.Token, http.MethodGet, path, nil, map[string]string{runnercontract.ArtifactSequenceHeader: "1"}))
	before := f.completionSnapshot(t, "runs", id)
	if rec := f.do(t, token.Token, http.MethodGet, path, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("omitted sequence after ordered issuance = HTTP %d, want 400", rec.Code)
	}
	if after := f.completionSnapshot(t, "runs", id); before != after {
		t.Error("header omission downgraded an ordered legacy claim")
	}
	if _, err := f.keys.VerifyAPIKey(ordered); err != nil {
		t.Error("attempted downgrade revoked the accepted ordered credential")
	}
}

func TestRegistrySequence_DelayedOriginalPreservesRetryCredential(t *testing.T) {
	f, id, token := setupOrderedRegistryClaim(t, false)
	path := "/jobs/" + id + "/artifacts"
	reached, resume := make(chan struct{}), make(chan struct{})
	var entered atomic.Bool
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(resume) }) }
	name := "delayed-registry-read-" + uuid.NewString()
	if err := f.db.Callback().Query().After("gorm:after_query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table == "runs" && entered.CompareAndSwap(false, true) {
			close(reached)
			<-resume
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.db.Callback().Query().Remove(name) }()
	original := make(chan *httptest.ResponseRecorder, 1)
	joined := false
	defer func() {
		release()
		if !joined {
			<-original
		}
	}()
	go func() {
		// The original context stays live to model delayed cancellation delivery.
		original <- f.do(t, token.Token, http.MethodGet, path, nil, map[string]string{runnercontract.ArtifactSequenceHeader: "1"})
	}()
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("original artifact read did not reach its pre-issuance snapshot")
	}
	retry := registryCredential(t, f.do(t, token.Token, http.MethodGet, path, nil, map[string]string{runnercontract.ArtifactSequenceHeader: "2"}))
	release()
	rec := <-original
	joined = true
	code, _ := runnercontract.DecodeError(rec.Body.Bytes())
	if rec.Code != http.StatusConflict || code != runnercontract.ErrorCodeArtifactReadSuperseded || rec.Header().Get(runnercontract.ArtifactSequenceHeader) != "2" {
		t.Errorf("delayed original = HTTP %d code %s, want superseded409/latest2", rec.Code, code)
	}
	if _, err := f.keys.VerifyAPIKey(retry); err != nil {
		t.Error("late original artifact handler revoked the successful retry credential")
	}
	var count int64
	if err := f.db.Model(&models.APIKey{}).Where("scopes::text LIKE ?", "%job-registry:tofu_run:"+id+"%").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("registry credentials after retry interleaving = %d, want 1", count)
	}
}

func TestRegistrySequence_ReplacementFailuresPreserveAcceptedCredential(t *testing.T) {
	for _, operation := range []string{"sequence", "revoke", "mint"} {
		t.Run(operation, func(t *testing.T) {
			f, id, token := setupOrderedRegistryClaim(t, false)
			path := "/jobs/" + id + "/artifacts"
			accepted := registryCredential(t, f.do(t, token.Token, http.MethodGet, path, nil, map[string]string{runnercontract.ArtifactSequenceHeader: "1"}))
			before := f.completionSnapshot(t, "runs", id)
			name := "registry-failure-" + uuid.NewString()
			callback := f.db.Callback().Update()
			table, gormOperation := "runs", "update"
			if operation == "revoke" {
				callback, table, gormOperation = f.db.Callback().Delete(), "api_keys", "delete"
			}
			if operation == "mint" {
				callback, table, gormOperation = f.db.Callback().Create(), "api_keys", "create"
			}
			seen := false
			if err := callback.Before("gorm:"+gormOperation).Register(name, func(tx *gorm.DB) {
				if tx.Statement.Table == table {
					seen = true
					_ = tx.AddError(errors.New("injected registry replacement failure"))
				}
			}); err != nil {
				t.Fatal(err)
			}
			rec := f.do(t, token.Token, http.MethodGet, path, nil, map[string]string{runnercontract.ArtifactSequenceHeader: "2"})
			if err := callback.Remove(name); err != nil {
				t.Fatal(err)
			}
			if !seen {
				t.Errorf("replacement did not reach its %s write", operation)
			}
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("failed replacement = HTTP %d, want 500", rec.Code)
			}
			if after := f.completionSnapshot(t, "runs", id); before != after {
				t.Error("failed replacement changed sequence or credential state")
			}
			if _, err := f.keys.VerifyAPIKey(accepted); err != nil {
				t.Error("failed replacement invalidated the accepted credential")
			}
			registryCredential(t, f.do(t, token.Token, http.MethodGet, path, nil, map[string]string{runnercontract.ArtifactSequenceHeader: "2"}))
		})
	}
}

// holdOriginalRegistryRead pauses after the original parent snapshot, before credential
// issuance. Its context remains live so correctness cannot depend on cancellation delivery.
func holdOriginalRegistryRead(t *testing.T, f *claimRouteFixture) (<-chan struct{}, func()) {
	t.Helper()
	reached, resume := make(chan struct{}), make(chan struct{})
	var entered atomic.Bool
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	name := "held-registry-snapshot-" + uuid.NewString()
	if err := f.db.Callback().Query().After("gorm:after_query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table == "runs" && entered.CompareAndSwap(false, true) {
			close(reached)
			<-resume
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		release()
		_ = f.db.Callback().Query().Remove(name)
	})
	return reached, release
}

func TestRegistrySequence_LateArtifactCannotRecreateCompletedCredential(t *testing.T) {
	f, id, token := setupOrderedRegistryClaim(t, false)
	reached, release := holdOriginalRegistryRead(t, f)
	original := make(chan *httptest.ResponseRecorder, 1)
	joined := false
	defer func() {
		release()
		if !joined {
			<-original
		}
	}()
	go func() {
		original <- f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/artifacts", nil, map[string]string{runnercontract.ArtifactSequenceHeader: "1"})
	}()
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("artifact request did not reach its snapshot")
	}
	if rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", runnercontract.JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Attempt: 1, Phase: "plan", Status: "completed"}); rec.Code != http.StatusOK {
		t.Fatalf("winning completion = HTTP %d", rec.Code)
	}
	before := f.completionSnapshot(t, "runs", id)
	release()
	rec := <-original
	joined = true
	code, _ := runnercontract.DecodeError(rec.Body.Bytes())
	if rec.Code != http.StatusForbidden || (code != runnercontract.ErrorCodeJobTerminal && code != runnercontract.ErrorCodeJobTokenRevoked) {
		t.Errorf("late artifact after completion = HTTP %d code %s", rec.Code, code)
	}
	if after := f.completionSnapshot(t, "runs", id); before != after {
		t.Error("late artifact recreated credentials or changed completed claim")
	}
}

func TestRegistrySequence_OldClaimCannotReplaceNextApplyCredential(t *testing.T) {
	f, id, token := setupOrderedRegistryClaim(t, false)
	if err := f.db.Model(&models.Run{}).Where("id = ?", id).Update("auto_apply", true).Error; err != nil {
		t.Fatal(err)
	}
	reached, release := holdOriginalRegistryRead(t, f)
	original := make(chan *httptest.ResponseRecorder, 1)
	joined := false
	defer func() {
		release()
		if !joined {
			<-original
		}
	}()
	go func() {
		original <- f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/artifacts", nil, map[string]string{runnercontract.ArtifactSequenceHeader: "9223372036854775807"})
	}()
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("old artifact request did not reach its snapshot")
	}
	if rec := f.do(t, token.Token, http.MethodPost, "/jobs/"+id+"/complete", runnercontract.JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Attempt: 1, Phase: "plan", Status: "completed", HasChanges: true, ResourceAdditions: 1}); rec.Code != http.StatusOK {
		t.Fatalf("plan completion = HTTP %d", rec.Code)
	}
	if rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/start", runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String(), Attempt: 2, Phase: "apply", RunType: "apply"}); rec.Code != http.StatusOK {
		t.Fatalf("next apply start = HTTP %d", rec.Code)
	}
	rec := f.do(t, f.token, http.MethodPost, "/jobs/"+id+"/token", runnercontract.JobTokenRequest{Attempt: 2, Phase: "apply", RunType: "apply"})
	if rec.Code != http.StatusOK {
		t.Fatalf("next apply token = HTTP %d", rec.Code)
	}
	var next runnercontract.JobToken
	if err := json.Unmarshal(rec.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	accepted := registryCredential(t, f.do(t, next.Token, http.MethodGet, "/jobs/"+id+"/artifacts", nil, map[string]string{runnercontract.ArtifactSequenceHeader: "1"}))
	before := f.completionSnapshot(t, "runs", id)
	release()
	rec = <-original
	joined = true
	code, _ := runnercontract.DecodeError(rec.Body.Bytes())
	if rec.Code != http.StatusForbidden || code != runnercontract.ErrorCodeJobTokenRevoked {
		t.Errorf("old claim with larger sequence = HTTP %d code %s", rec.Code, code)
	}
	if after := f.completionSnapshot(t, "runs", id); before != after {
		t.Error("old claim changed next apply credential or sequence")
	}
	if _, err := f.keys.VerifyAPIKey(accepted); err != nil {
		t.Error("old claim revoked next apply credential")
	}
}

func TestRegistrySequence_CredentialScopeAndLifetime(t *testing.T) {
	f, id, token := setupOrderedRegistryClaim(t, false)
	var run models.Run
	if err := f.db.First(&run, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", run.WorkspaceID).Update("run_timeout", 3600).Error; err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	raw := registryCredential(t, f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/artifacts", nil, map[string]string{runnercontract.ArtifactSequenceHeader: "1"}))
	finished := time.Now()
	key, err := f.keys.VerifyAPIKey(raw)
	if err != nil {
		t.Fatal("issued registry credential does not verify")
	}
	if key.ExpiresAt == nil || key.ExpiresAt.Before(started.Add(time.Hour+apikey.JobTokenGrace)) || key.ExpiresAt.After(finished.Add(time.Hour+apikey.JobTokenGrace)) {
		t.Error("registry credential lifetime differs from workspace timeout plus existing grace")
	}
	authService := auth.NewService(repository.NewUserRepository(f.db))
	authService.SetAPIKeyService(f.keys)
	for _, org := range []uuid.UUID{f.orgA, f.runnerB1.OrgID()} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/modules/x", nil)
		c.Request.Header.Set("Authorization", "Bearer "+raw)
		if got := authorizeRegistryRead(c, authService, repository.NewOrganizationRepository(f.db), nil, org, false); got != (org == f.orgA) {
			t.Errorf("private registry authorization for own organization %t = %t", org == f.orgA, got)
		}
	}
}

func TestRegistrySequence_CapabilityRequiresOrderingOnLegacyClaim(t *testing.T) {
	f, id, token := setupOrderedRegistryClaim(t, true)
	before := f.completionSnapshot(t, "runs", id)
	rec := f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/artifacts", nil, map[string]string{runnercontract.CapabilitiesHeader: runnercontract.CapabilityClaimRecovery})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("fixed request without sequence on legacy claim = HTTP %d, want 400", rec.Code)
	}
	if after := f.completionSnapshot(t, "runs", id); before != after {
		t.Error("invalid fixed request changed legacy claim or credentials")
	}
}

func TestRegistrySequence_EqualSequencePreservesAcceptedCredential(t *testing.T) {
	f, id, token := setupOrderedRegistryClaim(t, false)
	path := "/jobs/" + id + "/artifacts"
	headers := map[string]string{runnercontract.ArtifactSequenceHeader: "9223372036854775807"}
	accepted := registryCredential(t, f.do(t, token.Token, http.MethodGet, path, nil, headers))
	before := f.completionSnapshot(t, "runs", id)
	rec := f.do(t, token.Token, http.MethodGet, path, nil, headers)
	code, _ := runnercontract.DecodeError(rec.Body.Bytes())
	if rec.Code != http.StatusConflict || code != runnercontract.ErrorCodeArtifactReadSuperseded || rec.Header().Get(runnercontract.ArtifactSequenceHeader) != "9223372036854775807" {
		t.Errorf("equal maximum sequence = HTTP %d code %s", rec.Code, code)
	}
	if after := f.completionSnapshot(t, "runs", id); before != after {
		t.Error("equal sequence changed accepted credential or counter")
	}
	if _, err := f.keys.VerifyAPIKey(accepted); err != nil {
		t.Error("equal sequence revoked accepted credential")
	}
}

func TestRegistrySequence_UnknownOriginalPhaseRetainsClaim(t *testing.T) {
	for _, protocol := range []struct {
		name   string
		legacy bool
	}{
		{name: "fixed"},
		{name: "legacy", legacy: true},
	} {
		t.Run(protocol.name, func(t *testing.T) {
			for _, test := range []struct {
				name     string
				metadata map[string]any
			}{
				{name: "missing phase", metadata: map[string]any{"claimed_phase": ""}},
				{name: "unknown phase", metadata: map[string]any{"claimed_phase": "unknown"}},
				{name: "inconsistent type", metadata: map[string]any{"claimed_run_type": "apply-destroy"}},
			} {
				t.Run(test.name, func(t *testing.T) {
					f, id, token := setupOrderedRegistryClaim(t, protocol.legacy)
					if err := f.db.Model(&models.Run{}).Where("id = ?", id).Updates(test.metadata).Error; err != nil {
						t.Fatal(err)
					}
					before := f.completionSnapshot(t, "runs", id)
					rec := f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/artifacts", nil, map[string]string{runnercontract.ArtifactSequenceHeader: "1"})
					if rec.Code != http.StatusInternalServerError {
						t.Errorf("unknown original artifact phase = HTTP %d, want 500", rec.Code)
					}
					if after := f.completionSnapshot(t, "runs", id); before != after {
						t.Error("unknown original phase changed credentials or claim state")
					}
				})
			}
		})
	}
}

func TestRegistrySequence_CommitFailurePreservesAcceptedCredential(t *testing.T) {
	f, id, token := setupOrderedRegistryClaim(t, false)
	path := "/jobs/" + id + "/artifacts"
	accepted := registryCredential(t, f.do(t, token.Token, http.MethodGet, path, nil, map[string]string{runnercontract.ArtifactSequenceHeader: "1"}))
	before := f.completionSnapshot(t, "runs", id)
	original := f.handler.db
	scoped := original.Session(&gorm.Session{NewDB: true, Context: t.Context()})
	seen := false
	scoped.Statement.ConnPool = &completionCommitPool{ConnPool: original.Statement.ConnPool, seen: &seen}
	f.handler.db = scoped
	rec := f.do(t, token.Token, http.MethodGet, path, nil, map[string]string{runnercontract.ArtifactSequenceHeader: "2"})
	f.handler.db = original
	if !seen {
		t.Error("registry replacement did not reach final transaction commit")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("registry failed commit = HTTP %d, want 500", rec.Code)
	}
	if after := f.completionSnapshot(t, "runs", id); before != after {
		t.Error("failed registry commit changed credential or sequence state")
	}
	if _, err := f.keys.VerifyAPIKey(accepted); err != nil {
		t.Error("failed registry commit revoked accepted credential")
	}
	registryCredential(t, f.do(t, token.Token, http.MethodGet, path, nil, map[string]string{runnercontract.ArtifactSequenceHeader: "2"}))
}

func TestRegistrySequence_FixedClaimValidatesHeadersWithoutRegistry(t *testing.T) {
	f, id, token := setupOrderedRegistryClaim(t, false)
	f.handler.registryHost = ""
	path := "/jobs/" + id + "/artifacts"
	before := f.completionSnapshot(t, "runs", id)
	for _, headers := range []map[string]string{nil, {runnercontract.ArtifactSequenceHeader: "invalid"}} {
		if rec := f.do(t, token.Token, http.MethodGet, path, nil, headers); rec.Code != http.StatusBadRequest {
			t.Errorf("invalid fixed artifact header without registry = HTTP %d, want 400", rec.Code)
		}
	}
	rec := f.do(t, token.Token, http.MethodGet, path, nil, map[string]string{runnercontract.ArtifactSequenceHeader: "1"})
	var artifacts runnercontract.TofuArtifacts
	if err := json.Unmarshal(rec.Body.Bytes(), &artifacts); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || artifacts.Registry != nil {
		t.Errorf("valid fixed artifact read without registry = HTTP %d, registry present %t", rec.Code, artifacts.Registry != nil)
	}
	if after := f.completionSnapshot(t, "runs", id); before != after {
		t.Error("registry-disabled artifact read changed claim or credential state")
	}
}

func TestRegistrySequence_UnavailableCredentialServiceIsRetryable(t *testing.T) {
	f, id, token := setupOrderedRegistryClaim(t, false)
	f.handler.apiKeyService = nil
	before := f.completionSnapshot(t, "runs", id)
	rec := f.do(t, token.Token, http.MethodGet, "/jobs/"+id+"/artifacts", nil, map[string]string{runnercontract.ArtifactSequenceHeader: "1"})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("configured registry without credential service = HTTP %d, want 500", rec.Code)
	}
	if after := f.completionSnapshot(t, "runs", id); before != after {
		t.Error("unavailable registry credential service changed claim or credentials")
	}
}

func TestRegistrySequence_NormalClientRetryPreservesCredentialAfterDelayedOriginal(t *testing.T) {
	f, id, token := setupOrderedRegistryClaim(t, false)
	reached, release := holdOriginalRegistryRead(t, f)
	original := make(chan *httptest.ResponseRecorder, 1)
	var pending sync.WaitGroup
	var attempts atomic.Int64
	var sequenceMu sync.Mutex
	var sequences []string
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sequenceMu.Lock()
		sequences = append(sequences, r.Header.Get(runnercontract.ArtifactSequenceHeader))
		sequenceMu.Unlock()
		if attempts.Add(1) != 1 {
			f.router.ServeHTTP(w, r)
			return
		}
		pending.Add(1)
		go func(ctx context.Context) {
			defer pending.Done()
			rec := httptest.NewRecorder()
			// Only the fault injector detaches cancellation. The real original handler stays
			// live, allowing the retry to finish before the original reaches issuance.
			f.router.ServeHTTP(rec, r.Clone(context.WithoutCancel(ctx)))
			original <- rec
		}(r.Context())
		select {
		case <-reached:
		case <-time.After(10 * time.Second):
			t.Error("original read did not reach pre-issuance hold")
			return
		}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	}))
	defer func() {
		release()
		gateway.Close()
		pending.Wait()
	}()
	client := executor.NewClient(gateway.URL, token.Token, f.runnerA1.ID.String())
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	var artifacts runnercontract.TofuArtifacts
	if err := client.Artifacts(ctx, id, &artifacts, func() int { return artifacts.ContractVersion }); err != nil {
		t.Fatalf("normal client artifact retry = %v", err)
	}
	if artifacts.Registry == nil || len(artifacts.Registry.Hosts) != 1 {
		t.Fatal("retried artifacts have no complete registry credential")
	}
	raw := artifacts.Registry.Hosts[0].Token
	release()
	var rec *httptest.ResponseRecorder
	select {
	case rec = <-original:
	case <-ctx.Done():
		t.Fatal("original handler did not finish after retry")
	}
	code, _ := runnercontract.DecodeError(rec.Body.Bytes())
	if rec.Code != http.StatusConflict || code != runnercontract.ErrorCodeArtifactReadSuperseded || rec.Header().Get(runnercontract.ArtifactSequenceHeader) != "2" {
		t.Errorf("late original = %d code %s, want superseded409/latest2", rec.Code, code)
	}
	sequenceMu.Lock()
	if len(sequences) != 2 || sequences[0] != "1" || sequences[1] != "2" {
		t.Errorf("normal client sequences = %v, want [1 2]", sequences)
	}
	sequenceMu.Unlock()
	if _, err := f.keys.VerifyAPIKey(raw); err != nil {
		t.Fatal("late original revoked the actual client retry credential")
	}
	var count int64
	if err := f.db.Model(&models.APIKey{}).Where("scopes::text LIKE ?", "%job-registry:tofu_run:"+id+"%").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("current registry credentials = %d, want 1", count)
	}
	authService := auth.NewService(repository.NewUserRepository(f.db))
	authService.SetAPIKeyService(f.keys)
	for _, org := range []uuid.UUID{f.orgA, f.runnerB1.OrgID()} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/modules/x", nil)
		c.Request.Header.Set("Authorization", "Bearer "+raw)
		if got := authorizeRegistryRead(c, authService, repository.NewOrganizationRepository(f.db), nil, org, false); got != (org == f.orgA) {
			t.Errorf("retried credential private registry organization match %t = %t", org == f.orgA, got)
		}
	}
}
