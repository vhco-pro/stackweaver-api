// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package cachejanitor bounds the per-organization caches (#933, D7, AC36): each organization's
// entries are kept under its resolved cache_size_limit, least recently used first out, and settled
// promotions are removed once past their retention.
package cachejanitor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/settings"
	"github.com/michielvha/stackweaver/core/storage"
	"gorm.io/gorm"
)

// Janitor sweeps the caches.
type Janitor struct {
	DB    *gorm.DB
	Store storage.Client
	// DefaultLimit is the deployment's per-organization bound (CACHE_SIZE_LIMIT).
	DefaultLimit int64
	// PromotionRetention is how long a promotion is kept once created.
	PromotionRetention time.Duration
}

// Sweep runs one pass over every organization holding cache entries.
func (j *Janitor) Sweep(ctx context.Context) error {
	var totals []struct {
		OrganizationID uuid.UUID
		Total          int64
	}
	if err := j.DB.WithContext(ctx).Model(&models.CacheEntry{}).
		Select("organization_id, SUM(size_bytes) AS total").Group("organization_id").Scan(&totals).Error; err != nil {
		return fmt.Errorf("summing the caches: %w", err)
	}
	var errs []error
	for _, t := range totals {
		var org models.Organization
		if err := j.DB.WithContext(ctx).Select("id", "cache_size_limit").First(&org, "id = ?", t.OrganizationID).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			errs = append(errs, err)
			continue
		}
		limit := settings.EffectiveCacheSizeLimit(&org, j.DefaultLimit).Value
		if t.Total <= limit {
			continue
		}
		if err := j.evict(ctx, t.OrganizationID, t.Total, limit); err != nil {
			errs = append(errs, err)
		}
	}
	if j.PromotionRetention > 0 {
		if err := j.DB.WithContext(ctx).Where("created_at < ?", time.Now().Add(-j.PromotionRetention)).Delete(&models.CachePromotion{}).Error; err != nil {
			errs = append(errs, fmt.Errorf("removing old promotions: %w", err))
		}
	}
	return errors.Join(errs...)
}

// evict removes an organization's least recently used entries, object first, until it is under
// limit.
func (j *Janitor) evict(ctx context.Context, org uuid.UUID, total, limit int64) error {
	const batch = 200
	for total > limit {
		var entries []models.CacheEntry
		if err := j.DB.WithContext(ctx).Where("organization_id = ?", org).Order("last_used_at").Limit(batch).Find(&entries).Error; err != nil {
			return fmt.Errorf("listing the cache of %s: %w", org, err)
		}
		if len(entries) == 0 {
			return nil
		}
		for _, e := range entries {
			if total <= limit {
				return nil
			}
			if err := j.Store.Delete(ctx, models.CacheObjectKey(e.OrganizationID, e.Kind, e.SHA256)); err != nil && !errors.Is(err, storage.ErrNotFound) {
				return fmt.Errorf("deleting the cache object %s: %w", e.SHA256, err)
			}
			if err := j.DB.WithContext(ctx).Delete(&models.CacheEntry{}, "id = ?", e.ID).Error; err != nil {
				return fmt.Errorf("deleting the cache entry %s: %w", e.ID, err)
			}
			total -= e.SizeBytes
			logger.Infof("Cache janitor: evicted %s %s %s of organization %s (%d bytes)", e.Kind, e.Name, e.Version, org, e.SizeBytes)
		}
	}
	return nil
}

// Start sweeps every interval until ctx ends, the first sweep a minute after start.
func (j *Janitor) Start(ctx context.Context, interval time.Duration) {
	go func() {
		timer := time.NewTimer(time.Minute)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			if err := j.Sweep(ctx); err != nil && ctx.Err() == nil {
				logger.Warnf("Cache janitor: %v", err)
			}
			timer.Reset(interval)
		}
	}()
}
