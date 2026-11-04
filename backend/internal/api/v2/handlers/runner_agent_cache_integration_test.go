// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the per-organization cache routes (#933, D7, AC34): a job token reads only
// its organization's entries through the blob route and writes none; a launcher writes through
// PUT /runner/cache/:kind/:sha256 only for an organization it serves, and the API re-hashes the
// body and refuses a mismatch with the key; GET /runner/cache/:kind/:sha256 serves a customer
// launcher its pool's organization and a hosted launcher the organizations whose work it holds.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestCache

//go:build integration

package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func (f *agentPrepFixture) cacheRouter(store *snapshotStore) (*gin.Engine, *apikey.Service) {
	r, svc, _ := f.cacheRouterWithHandler(store)
	return r, svc
}

func (f *agentPrepFixture) cacheRouterWithHandler(store *snapshotStore) (*gin.Engine, *apikey.Service, *RunnerAgentHandler) {
	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	h := &RunnerAgentHandler{
		db:             f.db,
		runnerRepo:     repository.NewRunnerRepository(f.db),
		apiKeyService:  svc,
		jobExecRepo:    repository.NewRunnerJobExecutionRepository(f.db),
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
		playbookRepo:   repository.NewAnsiblePlaybookRepository(f.db),
		storageClient:  store,
	}
	return f.router(func(authed *gin.RouterGroup) {
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.GET("/jobs/:id/blob/*name", middleware.JobData(), h.GetJobBlob)
		authed.GET("/jobs/:id/artifacts", middleware.JobData(), h.GetJobArtifacts)
		authed.GET("/cache/:kind/:sha256", middleware.RequireRunnerToken(), h.GetCacheEntry)
		authed.PUT("/cache/:kind/:sha256", middleware.RequireRunnerToken(), h.PutCacheEntry)
	}), svc, h
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// seedCacheEntry stores content as an entry of org's cache, object and row.
func (f *agentPrepFixture) seedCacheEntry(t *testing.T, store *snapshotStore, org uuid.UUID, kind string, content []byte) *models.CacheEntry {
	t.Helper()
	sum := sha256Hex(content)
	entry := &models.CacheEntry{
		OrganizationID: org, Kind: kind, SHA256: sum, Name: "tofu", Version: "1.10.0", Platform: "linux_amd64",
		SizeBytes: int64(len(content)), Verification: models.CacheVerified, LastUsedAt: time.Now().Add(-time.Hour),
	}
	if err := f.db.Create(entry).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", entry.ID).Delete(&models.CacheEntry{}) })
	if err := store.Put(t.Context(), models.CacheObjectKey(org, kind, sum), content); err != nil {
		t.Fatal(err)
	}
	return entry
}

// cleanupCacheRows removes the cache rows a test's uploads created, by organization.
func (f *agentPrepFixture) cleanupCacheRows(t *testing.T, orgs ...uuid.UUID) {
	t.Cleanup(func() { f.db.Where("organization_id IN ?", orgs).Delete(&models.CacheEntry{}) })
}

func cacheDo(t *testing.T, r *gin.Engine, key, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Test-Key", key)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func cachePath(kind, sum string, q url.Values) string {
	p := "/api/v2/runner/cache/" + kind + "/" + sum
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	return p
}

func TestCache_JobTokenReadsOnlyItsOrganization(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc := f.cacheRouter(store)
	run := f.seedRun(t, f.runnerA1)
	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	orgB := *f.runnerB1.OrganizationID
	mine := f.seedCacheEntry(t, store, f.orgA, "tofu", []byte("organization A's tofu zip"))
	theirs := f.seedCacheEntry(t, store, orgB, "tofu", []byte("organization B's tofu zip"))

	path := "/api/v2/runner/jobs/" + run.ID + "/blob/cache/tofu/" + mine.SHA256
	for i := range 2 {
		got := cacheDo(t, r, "job", http.MethodGet, path, nil)
		if got.Code != http.StatusOK || got.Body.String() != "organization A's tofu zip" {
			t.Fatalf("fetch %d of its own organization's entry: %d %q", i+1, got.Code, got.Body.String())
		}
	}
	var after models.CacheEntry
	f.db.First(&after, "id = ?", mine.ID)
	if !after.LastUsedAt.After(mine.LastUsedAt) {
		t.Errorf("a read left last_used_at at %v", after.LastUsedAt)
	}

	if got := cacheDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/blob/cache/tofu/"+theirs.SHA256, nil); got.Code != http.StatusForbidden {
		t.Errorf("organization A's job token on organization B's entry: %d, want 403", got.Code)
	}
	if got := cacheDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/blob/cache/tofu/"+sha256Hex([]byte("nobody's")), nil); got.Code != http.StatusForbidden {
		t.Errorf("an entry no organization holds: %d, want 403", got.Code)
	}
	if got := cacheDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/blob/cache/bogus/"+mine.SHA256, nil); got.Code != http.StatusNotFound {
		t.Errorf("an unknown kind: %d, want 404", got.Code)
	}
	if got := cacheDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/blob/cache/tofu/../../etc", nil); got.Code != http.StatusNotFound && got.Code != http.StatusBadRequest {
		t.Errorf("a malformed key: %d, want 400 or 404", got.Code)
	}
}

func TestCache_NoJobTokenWrites(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc := f.cacheRouter(store)
	f.cleanupCacheRows(t, f.orgA)
	run := f.seedRun(t, f.runnerA1)
	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	body := []byte("a job's attempt at poisoning")
	if got := cacheDo(t, r, "job", http.MethodPut, cachePath("tofu", sha256Hex(body), nil), body); got.Code != http.StatusForbidden {
		t.Errorf("a job token writing the cache: %d, want 403", got.Code)
	}
	var n int64
	f.db.Model(&models.CacheEntry{}).Where("organization_id = ?", f.orgA).Count(&n)
	if n != 0 {
		t.Errorf("%d cache rows after a refused write", n)
	}
	if got := cacheDo(t, r, "job", http.MethodGet, cachePath("tofu", sha256Hex(body), nil), nil); got.Code != http.StatusForbidden {
		t.Errorf("a job token on the launcher read route: %d, want 403", got.Code)
	}
}

func TestCache_PutRehashesTheBody(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, _ := f.cacheRouter(store)
	orgB := *f.runnerB1.OrganizationID
	f.cleanupCacheRows(t, f.orgA, orgB)
	body := []byte("terraform-provider-null_3.2.4_linux_amd64.zip contents")
	sum := sha256Hex(body)
	meta := url.Values{"name": {"registry.opentofu.org/hashicorp/null"}, "version": {"3.2.4"}, "platform": {"linux_amd64"}, "source": {"https://registry.opentofu.org/v1/providers/hashicorp/null/3.2.4/download/linux/amd64"}}

	if got := cacheDo(t, r, "a1", http.MethodPut, cachePath("provider", sha256Hex([]byte("something else")), meta), body); got.Code != http.StatusUnprocessableEntity {
		t.Errorf("a body that does not hash to its key: %d, want 422 (%s)", got.Code, got.Body.String())
	}
	if _, err := store.Get(t.Context(), models.CacheObjectKey(f.orgA, "provider", sha256Hex([]byte("something else")))); err == nil {
		t.Error("the mismatching body was stored")
	}
	if got := cacheDo(t, r, "a1", http.MethodPut, cachePath("provider", "not-a-sha", meta), body); got.Code != http.StatusBadRequest {
		t.Errorf("a malformed key: %d, want 400", got.Code)
	}
	if got := cacheDo(t, r, "a1", http.MethodPut, cachePath("bogus", sum, meta), body); got.Code != http.StatusNotFound {
		t.Errorf("an unknown kind: %d, want 404", got.Code)
	}

	got := cacheDo(t, r, "a1", http.MethodPut, cachePath("provider", sum, meta), body)
	if got.Code != http.StatusCreated {
		t.Fatalf("a verified upload: %d (%s)", got.Code, got.Body.String())
	}
	stored, err := store.Get(t.Context(), models.CacheObjectKey(f.orgA, "provider", sum))
	if err != nil || !bytes.Equal(stored, body) {
		t.Fatalf("the object under cache/<org>/provider/<sha>: %v", err)
	}
	var row models.CacheEntry
	if err := f.db.First(&row, "organization_id = ? AND kind = ? AND sha256 = ?", f.orgA, "provider", sum).Error; err != nil {
		t.Fatalf("the cache row: %v", err)
	}
	if row.Name != "registry.opentofu.org/hashicorp/null" || row.Version != "3.2.4" || row.Platform != "linux_amd64" || row.SizeBytes != int64(len(body)) || row.Verification != models.CacheVerified {
		t.Errorf("the cache row = %+v", row)
	}
	if again := cacheDo(t, r, "a1", http.MethodPut, cachePath("provider", sum, meta), body); again.Code != http.StatusOK {
		t.Errorf("uploading an entry the organization already holds: %d, want 200", again.Code)
	}

	// A customer launcher writes only its pool's organization's prefix.
	q := url.Values{"organization": {orgB.String()}}
	for k, v := range meta {
		q[k] = v
	}
	if got := cacheDo(t, r, "a1", http.MethodPut, cachePath("provider", sum, q), body); got.Code != http.StatusForbidden {
		t.Errorf("organization A's launcher writing organization B's cache: %d, want 403", got.Code)
	}
	var n int64
	f.db.Model(&models.CacheEntry{}).Where("organization_id = ?", orgB).Count(&n)
	if n != 0 {
		t.Errorf("organization B holds %d rows after a refused write", n)
	}
	// An offline verification is recorded as such.
	off := url.Values{"verification": {models.CacheVerifiedOffline}}
	for k, v := range meta {
		off[k] = v
	}
	other := []byte("another provider zip")
	if got := cacheDo(t, r, "a1", http.MethodPut, cachePath("provider", sha256Hex(other), off), other); got.Code != http.StatusCreated {
		t.Fatalf("an offline-verified upload: %d", got.Code)
	}
	var offRow models.CacheEntry
	f.db.First(&offRow, "organization_id = ? AND sha256 = ?", f.orgA, sha256Hex(other))
	if offRow.Verification != models.CacheVerifiedOffline {
		t.Errorf("verification = %q, want offline", offRow.Verification)
	}
	bad := url.Values{"verification": {"trust-me"}}
	if got := cacheDo(t, r, "a1", http.MethodPut, cachePath("provider", sum, bad), body); got.Code != http.StatusBadRequest {
		t.Errorf("an unknown verification: %d, want 400", got.Code)
	}
}

func TestCache_LauncherReadsOnlyOrganizationsItServes(t *testing.T) {
	hf := setupHostedRunnerFixture(t)
	f := hf.agentPrepFixture
	store := newSnapshotStore()
	r, _ := f.cacheRouter(store)
	orgB := *f.runnerB1.OrganizationID
	entryA := f.seedCacheEntry(t, store, f.orgA, "collection", []byte("ansible.posix 2.2.2"))

	if got := cacheDo(t, r, "a1", http.MethodGet, cachePath("collection", entryA.SHA256, nil), nil); got.Code != http.StatusOK || got.Body.String() != "ansible.posix 2.2.2" {
		t.Errorf("a customer launcher reading its organization's entry: %d", got.Code)
	}
	if got := cacheDo(t, r, "a1", http.MethodGet, cachePath("collection", entryA.SHA256, url.Values{"organization": {orgB.String()}}), nil); got.Code != http.StatusForbidden {
		t.Errorf("a customer launcher naming another organization: %d, want 403", got.Code)
	}
	if got := cacheDo(t, r, "b1", http.MethodGet, cachePath("collection", entryA.SHA256, nil), nil); got.Code != http.StatusNotFound {
		t.Errorf("organization B's launcher on organization A's entry: %d, want 404 (its own organization lacks it)", got.Code)
	}

	// A hosted launcher reads and writes the organizations whose work it holds, and no other.
	heldOrg, runID := hf.hostedOrgRun(t, "cache")
	f.cleanupCacheRows(t, heldOrg)
	held := f.seedCacheEntry(t, store, heldOrg, "tofu", []byte("held organization's tofu"))
	if got := cacheDo(t, r, "hosted", http.MethodGet, cachePath("tofu", held.SHA256, url.Values{"organization": {heldOrg.String()}}), nil); got.Code != http.StatusForbidden {
		t.Errorf("a hosted launcher before it holds any of the organization's work: %d, want 403", got.Code)
	}
	if err := f.db.Model(&models.Run{}).Where("id = ?", runID).Updates(map[string]any{"runner_id": hf.runner.ID, "status": models.RunStatusPlanning}).Error; err != nil {
		t.Fatal(err)
	}
	if got := cacheDo(t, r, "hosted", http.MethodGet, cachePath("tofu", held.SHA256, url.Values{"organization": {heldOrg.String()}}), nil); got.Code != http.StatusOK {
		t.Errorf("a hosted launcher holding the organization's run: %d, want 200 (%s)", got.Code, got.Body.String())
	}
	if got := cacheDo(t, r, "hosted", http.MethodGet, cachePath("collection", entryA.SHA256, url.Values{"organization": {f.orgA.String()}}), nil); got.Code != http.StatusForbidden {
		t.Errorf("a hosted launcher on an organization it holds nothing of: %d, want 403", got.Code)
	}
	if got := cacheDo(t, r, "hosted", http.MethodGet, cachePath("tofu", held.SHA256, nil), nil); got.Code != http.StatusBadRequest {
		t.Errorf("a hosted launcher naming no organization: %d, want 400", got.Code)
	}
	body := []byte("a hosted populator's verified upload")
	if got := cacheDo(t, r, "hosted", http.MethodPut, cachePath("tofu", sha256Hex(body), url.Values{"organization": {heldOrg.String()}, "name": {"tofu"}, "version": {"1.10.0"}}), body); got.Code != http.StatusCreated {
		t.Errorf("a hosted launcher writing a held organization's cache: %d (%s)", got.Code, got.Body.String())
	}
	if got := cacheDo(t, r, "hosted", http.MethodPut, cachePath("tofu", sha256Hex(body), url.Values{"organization": {f.orgA.String()}}), body); got.Code != http.StatusForbidden {
		t.Errorf("a hosted launcher writing an organization it holds nothing of: %d, want 403", got.Code)
	}
}

// A hosted launcher's populator uploads an entry after the job that reported it has finished, so
// a pending promotion handed to that launcher authorizes the write of its organization's cache;
// another runner's promotion, a settled one, or a read authorizes nothing (#933, D7, AC33, AC35).
func TestCache_HostedPopulatorUploadsUnderItsPromotion(t *testing.T) {
	hf := setupHostedRunnerFixture(t)
	f := hf.agentPrepFixture
	store := newSnapshotStore()
	r, _ := f.cacheRouter(store)
	org, _ := hf.hostedOrgRun(t, "promo")
	f.cleanupCacheRows(t, org)
	promo := &models.CachePromotion{
		ID: uuid.New(), OrganizationID: org, RunnerID: hf.runner.ID, JobKind: string(models.JobTypeTofuRun), JobID: "run-promo-" + uuid.NewString()[:8],
		Entry: models.JSONB{"kind": "tofu", "name": "tofu", "version": "1.10.0"}, Status: models.CachePromotionPending,
	}
	others := &models.CachePromotion{
		ID: uuid.New(), OrganizationID: org, RunnerID: f.runnerA1.ID, JobKind: string(models.JobTypeTofuRun), JobID: "run-promo-x",
		Entry: models.JSONB{"kind": "tofu", "name": "tofu", "version": "1.10.0"}, Status: models.CachePromotionPending,
	}
	for _, p := range []*models.CachePromotion{promo, others} {
		if err := f.db.Create(p).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { f.db.Where("id IN ?", []uuid.UUID{promo.ID, others.ID}).Delete(&models.CachePromotion{}) })

	body := []byte("tofu 1.10.0, verified after the run ended")
	q := func(id uuid.UUID) url.Values {
		return url.Values{"organization": {org.String()}, "name": {"tofu"}, "version": {"1.10.0"}, "promotion": {id.String()}}
	}
	if got := cacheDo(t, r, "hosted", http.MethodPut, cachePath("tofu", sha256Hex(body), q(others.ID)), body); got.Code != http.StatusForbidden {
		t.Errorf("an upload under another runner's promotion: %d, want 403", got.Code)
	}
	if got := cacheDo(t, r, "hosted", http.MethodGet, cachePath("tofu", sha256Hex(body), q(promo.ID)), nil); got.Code != http.StatusForbidden {
		t.Errorf("a read naming a promotion: %d, want 403 (a promotion authorizes its upload only)", got.Code)
	}
	if got := cacheDo(t, r, "hosted", http.MethodPut, cachePath("tofu", sha256Hex(body), q(promo.ID)), body); got.Code != http.StatusCreated {
		t.Fatalf("an upload under the launcher's own promotion: %d (%s)", got.Code, got.Body.String())
	}
	var row models.CachePromotion
	f.db.First(&row, "id = ?", promo.ID)
	if row.Status != models.CachePromotionPromoted {
		t.Errorf("promotion status = %s, want promoted", row.Status)
	}
	if got := cacheDo(t, r, "hosted", http.MethodPut, cachePath("tofu", sha256Hex(body), q(promo.ID)), body); got.Code != http.StatusForbidden {
		t.Errorf("a second upload under a settled promotion: %d, want 403", got.Code)
	}
}
