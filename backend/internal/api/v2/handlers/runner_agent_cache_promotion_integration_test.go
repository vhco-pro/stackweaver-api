// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for cache promotion (#933, D7, AC35): what a successful job reports installing
// beyond its descriptor becomes a pending promotion of its organization's cache, handed to the
// runner that ran it with its heartbeat; the runner's populator settles it by uploading the verified
// entry under it or by dropping it, and a drop it marks as a poisoning leaves an event on the job and
// a pool-level audit record.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestCachePromotion

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

func (f *agentPrepFixture) promotionRouter(store *snapshotStore) (*gin.Engine, *apikey.Service) {
	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	h := &RunnerAgentHandler{
		db:             f.db,
		runnerRepo:     repository.NewRunnerRepository(f.db),
		jobExecRepo:    repository.NewRunnerJobExecutionRepository(f.db),
		apiKeyService:  svc,
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
		playbookRepo:   repository.NewAnsiblePlaybookRepository(f.db),
		storageClient:  store,
		mirror:         &runnercontract.Mirror{TofuReleasesURL: "https://releases.mirror.test"},
	}
	return f.router(func(authed *gin.RouterGroup) {
		authed.POST("/heartbeat", middleware.RequireRunnerToken(), h.Heartbeat)
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.POST("/jobs/:id/complete", middleware.JobData(), h.JobComplete)
		authed.PUT("/cache/:kind/:sha256", middleware.RequireRunnerToken(), h.PutCacheEntry)
		authed.POST("/cache/promotions/:id/drop", middleware.RequireRunnerToken(), h.DropCachePromotion)
	}), svc
}

func (f *agentPrepFixture) heartbeatPromotions(t *testing.T, r *gin.Engine, key string, runner *models.Runner) runnercontract.HeartbeatResponse {
	t.Helper()
	rec := runnerDo(t, r, key, http.MethodPost, "/api/v2/runner/heartbeat", runnercontract.HeartbeatRequest{RunnerID: runner.ID.String(), Status: "online"})
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String())
	}
	var resp runnercontract.HeartbeatResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp
}

// completeWithManifest runs an Ansible job of runner a1 to completion with manifest.
func (f *agentPrepFixture) completeWithManifest(t *testing.T, r *gin.Engine, svc *apikey.Service, status string, manifest *runnercontract.CacheManifest) *models.AnsibleJob {
	t.Helper()
	job := f.seedJob(t, nil, f.runnerA1)
	if err := f.db.Create(&models.RunnerJobExecution{RunnerID: f.runnerA1.ID, JobType: models.JobTypeAnsibleJob, JobID: job.ID, Status: models.JobExecutionStatusRunning}).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("job_id = ?", job.ID).Delete(&models.RunnerJobExecution{}) })
	if code, _ := f.mintJobToken(t, r, svc, "a1", job.ID.String(), "job-"+job.ID.String()); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	body := runnercontract.JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Status: status, CacheManifest: manifest}
	if rec := runnerDo(t, r, "job-"+job.ID.String(), http.MethodPost, "/api/v2/runner/jobs/"+job.ID.String()+"/complete", body); rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	return job
}

func (f *agentPrepFixture) cleanupPromotions(t *testing.T) {
	t.Cleanup(func() {
		f.db.Where("organization_id = ?", f.orgA).Delete(&models.CachePromotion{})
		f.db.Where("organization_id = ?", f.orgA).Delete(&models.CacheEntry{})
		f.db.Where("organization_id = ? AND action LIKE ?", f.orgA, "cache.%").Delete(&models.AuditLog{})
	})
}

func TestCachePromotion_ReportedEntriesReachTheRunnerThatRanTheJob(t *testing.T) {
	f := setupAgentPrepFixture(t)
	f.cleanupPromotions(t)
	store := newSnapshotStore()
	r, svc := f.promotionRouter(store)
	already := f.seedNamedCacheEntry(t, store, f.orgA, "collection", "ansible.posix", "2.2.2", "", []byte("posix"), time.Now())

	manifest := &runnercontract.CacheManifest{Entries: []runnercontract.CacheEntry{
		{Kind: runnercontract.CacheKindCollection, Name: "community.general", Version: "9.4.0"},
		{Kind: runnercontract.CacheKindCollection, Name: already.Name, Version: already.Version},
		{Kind: "bogus", Name: "x", Version: "1"},
	}}
	f.completeWithManifest(t, r, svc, "completed", manifest)

	resp := f.heartbeatPromotions(t, r, "a1", f.runnerA1)
	if len(resp.CachePromotions) != 1 {
		t.Fatalf("promotions = %+v, want community.general alone (posix is cached, bogus is no kind)", resp.CachePromotions)
	}
	p := resp.CachePromotions[0]
	if p.Entry.Name != "community.general" || p.Entry.Version != "9.4.0" || p.OrganizationID != f.orgA.String() {
		t.Errorf("promotion = %+v", p)
	}
	if resp.Mirror == nil || resp.Mirror.TofuReleasesURL != "https://releases.mirror.test" {
		t.Errorf("a heartbeat carrying promotions carries the mirror block too: %+v", resp.Mirror)
	}
	if other := f.heartbeatPromotions(t, r, "a2", f.runnerA2); len(other.CachePromotions) != 0 {
		t.Errorf("another runner of the pool was handed %+v", other.CachePromotions)
	}

	// Uploading the verified entry under the promotion settles it.
	body := []byte("community.general 9.4.0 tarball")
	q := url.Values{"name": {"community.general"}, "version": {"9.4.0"}, "promotion": {p.ID}}
	if rec := cacheDo(t, r, "a1", http.MethodPut, cachePath("collection", sha256Hex(body), q), body); rec.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	var row models.CachePromotion
	f.db.First(&row, "id = ?", p.ID)
	if row.Status != models.CachePromotionPromoted {
		t.Errorf("promotion status = %s, want promoted", row.Status)
	}
	if again := f.heartbeatPromotions(t, r, "a1", f.runnerA1); len(again.CachePromotions) != 0 {
		t.Errorf("a settled promotion was handed out again: %+v", again.CachePromotions)
	}
}

func TestCachePromotion_FailedJobReportsNothing(t *testing.T) {
	f := setupAgentPrepFixture(t)
	f.cleanupPromotions(t)
	r, svc := f.promotionRouter(newSnapshotStore())
	f.completeWithManifest(t, r, svc, "failed", &runnercontract.CacheManifest{Entries: []runnercontract.CacheEntry{{Kind: runnercontract.CacheKindCollection, Name: "community.general", Version: "9.4.0"}}})
	var n int64
	f.db.Model(&models.CachePromotion{}).Where("organization_id = ?", f.orgA).Count(&n)
	if n != 0 {
		t.Errorf("a failed job left %d promotions", n)
	}
}

func TestCachePromotion_APoisonedDropIsRecordedOnTheJobAndThePool(t *testing.T) {
	f := setupAgentPrepFixture(t)
	f.cleanupPromotions(t)
	r, svc := f.promotionRouter(newSnapshotStore())
	job := f.completeWithManifest(t, r, svc, "completed", &runnercontract.CacheManifest{Entries: []runnercontract.CacheEntry{{Kind: runnercontract.CacheKindCollection, Name: "community.general", Version: "9.4.0"}}})
	p := f.heartbeatPromotions(t, r, "a1", f.runnerA1).CachePromotions[0]

	drop := map[string]any{"reason": "the source's tarball hashes to aaaa, the server's artifact.sha256 is bbbb", "poisoned": true}
	if rec := runnerDo(t, r, "a2", http.MethodPost, "/api/v2/runner/cache/promotions/"+p.ID+"/drop", drop); rec.Code != http.StatusForbidden {
		t.Errorf("another runner dropping the promotion: %d, want 403", rec.Code)
	}
	if rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/cache/promotions/"+p.ID+"/drop", drop); rec.Code != http.StatusOK {
		t.Fatalf("drop: %d %s", rec.Code, rec.Body.String())
	}
	var row models.CachePromotion
	f.db.First(&row, "id = ?", p.ID)
	if row.Status != models.CachePromotionDropped || !row.Poisoned || row.Reason == "" {
		t.Errorf("promotion = %+v, want dropped, poisoned, with its reason", row)
	}
	var events []models.AnsibleJobEvent
	f.db.Where("job_id = ? AND event = ?", job.ID, "cache_entry_dropped").Find(&events)
	if len(events) != 1 {
		t.Errorf("the job carries %d cache_entry_dropped events, want 1", len(events))
	}
	var audits []models.AuditLog
	f.db.Where("organization_id = ? AND action = ?", f.orgA, "cache.poisoning_refused").Find(&audits)
	if len(audits) != 1 || audits[0].ResourceType != "agent_pool" || audits[0].ResourceID == nil || *audits[0].ResourceID != f.poolA {
		t.Errorf("audit records = %+v, want one on the job's pool", audits)
	}
	if again := f.heartbeatPromotions(t, r, "a1", f.runnerA1); len(again.CachePromotions) != 0 {
		t.Errorf("a dropped promotion was handed out again: %+v", again.CachePromotions)
	}
}
