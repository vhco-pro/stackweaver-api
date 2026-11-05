// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the cache janitor (#933, D7, AC36): an organization's cache stays under its
// resolved cache_size_limit (the organization's own, else the deployment's), losing its least
// recently used entries first, object and row; an organization under its limit keeps everything;
// settled promotions past their retention are removed.
//
//	go test -tags integration ./internal/services/cachejanitor/

//go:build integration

package cachejanitor

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/storage/storagetest"
	"gorm.io/gorm"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	db, err := dbtest.Open(t, dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		t.Fatal(err)
	}
	return db
}

func seedOrg(t *testing.T, db *gorm.DB, limit int64) uuid.UUID {
	t.Helper()
	org := &models.Organization{ID: uuid.New(), Name: "cachejanitor-" + uuid.NewString()[:8], CacheSizeLimit: limit}
	if err := db.Create(org).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Where("organization_id = ?", org.ID).Delete(&models.CacheEntry{})
		db.Where("organization_id = ?", org.ID).Delete(&models.CachePromotion{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
	})
	return org.ID
}

func seedEntry(t *testing.T, db *gorm.DB, store *storagetest.Memory, org uuid.UUID, name string, size int64, used time.Time) *models.CacheEntry {
	t.Helper()
	sha := uuid.NewString() + uuid.NewString()
	sha = sha[:64]
	e := &models.CacheEntry{OrganizationID: org, Kind: "collection", SHA256: sha, Name: name, SizeBytes: size, LastUsedAt: used}
	if err := db.Create(e).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Put(t.Context(), models.CacheObjectKey(org, e.Kind, e.SHA256), make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	return e
}

func remaining(t *testing.T, db *gorm.DB, org uuid.UUID) map[string]bool {
	t.Helper()
	var rows []models.CacheEntry
	db.Where("organization_id = ?", org).Find(&rows)
	out := map[string]bool{}
	for _, r := range rows {
		out[r.Name] = true
	}
	return out
}

func TestSweep_KeepsEachOrganizationUnderItsLimit(t *testing.T) {
	db := testDB(t)
	store := storagetest.NewMemory()
	now := time.Now()

	// Its own limit of 250 bytes: four 100-byte entries lose the two least recently used.
	small := seedOrg(t, db, 250)
	oldest := seedEntry(t, db, store, small, "oldest", 100, now.Add(-4*time.Hour))
	seedEntry(t, db, store, small, "older", 100, now.Add(-3*time.Hour))
	seedEntry(t, db, store, small, "recent", 100, now.Add(-2*time.Hour))
	seedEntry(t, db, store, small, "newest", 100, now.Add(-time.Hour))
	// No limit of its own: the deployment's 1000 bytes leave its 300 bytes alone.
	roomy := seedOrg(t, db, 0)
	kept := seedEntry(t, db, store, roomy, "kept", 300, now.Add(-100*time.Hour))

	j := &Janitor{DB: db, Store: store, DefaultLimit: 1000, PromotionRetention: 7 * 24 * time.Hour}
	if err := j.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := remaining(t, db, small); len(got) != 2 || !got["recent"] || !got["newest"] {
		t.Errorf("the small organization keeps %v, want the two most recently used", got)
	}
	if _, err := store.Get(t.Context(), models.CacheObjectKey(small, oldest.Kind, oldest.SHA256)); err == nil {
		t.Error("an evicted entry's object is still stored")
	}
	if got := remaining(t, db, roomy); !got["kept"] {
		t.Errorf("an organization under its limit lost entries: %v", got)
	}
	if _, err := store.Get(t.Context(), models.CacheObjectKey(roomy, kept.Kind, kept.SHA256)); err != nil {
		t.Errorf("the kept entry's object is gone: %v", err)
	}
}

func TestSweep_RemovesOldPromotions(t *testing.T) {
	db := testDB(t)
	org := seedOrg(t, db, 0)
	old := &models.CachePromotion{OrganizationID: org, RunnerID: uuid.New(), JobKind: "tofu_run", JobID: "run-old", Entry: models.JSONB{"kind": "tofu"}, Status: models.CachePromotionPromoted}
	fresh := &models.CachePromotion{OrganizationID: org, RunnerID: uuid.New(), JobKind: "tofu_run", JobID: "run-fresh", Entry: models.JSONB{"kind": "tofu"}, Status: models.CachePromotionPending}
	for _, p := range []*models.CachePromotion{old, fresh} {
		if err := db.Create(p).Error; err != nil {
			t.Fatal(err)
		}
	}
	db.Model(&models.CachePromotion{}).Where("id = ?", old.ID).Update("created_at", time.Now().Add(-8*24*time.Hour))
	j := &Janitor{DB: db, Store: storagetest.NewMemory(), DefaultLimit: 1 << 30, PromotionRetention: 7 * 24 * time.Hour}
	if err := j.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	var n int64
	db.Model(&models.CachePromotion{}).Where("id = ?", old.ID).Count(&n)
	if n != 0 {
		t.Error("a promotion past its retention was kept")
	}
	db.Model(&models.CachePromotion{}).Where("id = ?", fresh.ID).Count(&n)
	if n != 1 {
		t.Error("a fresh promotion was removed")
	}
}

// TestSweep_RemovesTheCacheOfADeletedOrganization: entries whose organization is gone, left by a
// delete before it removed them, are swept with their objects whatever the limit.
func TestSweep_RemovesTheCacheOfADeletedOrganization(t *testing.T) {
	db := testDB(t)
	store := storagetest.NewMemory()
	org := seedOrg(t, db, 0)
	orphan := seedEntry(t, db, store, org, "orphan", 100, time.Now())
	if err := db.Where("id = ?", org).Delete(&models.Organization{}).Error; err != nil {
		t.Fatal(err)
	}

	j := &Janitor{DB: db, Store: store, DefaultLimit: 1 << 30}
	if err := j.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := remaining(t, db, org); len(got) != 0 {
		t.Errorf("a deleted organization keeps cache entries %v", got)
	}
	if _, err := store.Get(t.Context(), models.CacheObjectKey(org, orphan.Kind, orphan.SHA256)); err == nil {
		t.Error("the deleted organization's cache object is still stored")
	}
}
