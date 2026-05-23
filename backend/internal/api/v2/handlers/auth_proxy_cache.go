// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// settingsCacheEntry is the value stored in the settings cache.
//
// Each entry keeps the fresh payload and expiry so hot reads need no I/O, plus
// a separate stalePayload copy that survives past expiry. When Zitadel returns
// a 5xx we'd rather hand the SPA a slightly stale set of flags than a 502 — a
// cached loginSettings from 20 minutes ago still renders the login form; a 502
// bricks it. The stale copy is trimmed back to a ceiling so we don't serve
// arbitrarily old data.
type settingsCacheEntry struct {
	key          string
	payload      []byte
	expiresAt    time.Time
	stalePayload []byte
	staleUntil   time.Time
}

// settingsCache is a small in-memory TTL cache for the settings-proxy endpoints.
//
// Round 25 hardening (item 22 / R25c H-1): the cache is now LRU-bounded.
// The previous version had no eviction beyond TTL on the assumption that
// the key space was fixed (8 endpoints × low-cardinality org scope).
// But the cache key includes `ctx.orgId`, which is read from a query
// parameter on unauthenticated `/auth/settings/*` endpoints — so an
// attacker can mint unique `ctx.orgId` values to fill the cache. The
// LRU cap prevents memory exhaustion.
//
// Single-flight on misses (F-chaos-2 hardening item 1) is still
// deferred — the thundering-herd test hasn't shown it matters in
// practice, and the LRU eviction is orthogonal to that work.
//
// The full reject-unknown-`ctx.orgId` half of R25c H-1 is deferred
// until item 21 (LookupOrgByDomain TTL cache) lands — without a known-
// org set, the only fail-closed option is "reject every ctx.orgId
// from unauth callers," which would break the SPA's per-org branding
// lookup. The LRU cap alone bounds the attacker's blast radius.
//
// Memory: defaultSettingsCacheCap × ~few KB per entry ≈ tens of MB
// worst case, bounded.
const defaultSettingsCacheCap = 10_000

type settingsCache struct {
	mu      sync.Mutex
	entries map[string]*list.Element // key → list element holding *settingsCacheEntry
	lru     *list.List               // MRU at front; LRU at back
	cap     int

	// Round 25 Wave 8 (item 1 / F-chaos-2): singleflight deduplicates
	// concurrent cache misses for the same key. Without it, 50
	// concurrent cold-cache requests for `/v2/settings/login` produced
	// 50 upstream Zitadel fetches — a thundering-herd amplifier.
	// `singleflight.Group.Do` ensures all concurrent callers for the
	// same key wait on a single in-flight upstream fetch and share
	// the result.
	flight singleflight.Group

	hits            atomic.Uint64
	misses          atomic.Uint64
	staleServed     atomic.Uint64
	evictions       atomic.Uint64
	upstreamFetches atomic.Uint64
	dedupedFetches  atomic.Uint64
}

// staleWindow is how long past the normal TTL we're willing to keep a
// stale copy around to serve if Zitadel 5xxs. Longer than any individual
// TTL in the table below, so any cached entry can survive a Zitadel outage
// of up to this duration.
const staleWindow = 6 * time.Hour

func newSettingsCache() *settingsCache {
	return &settingsCache{
		entries: make(map[string]*list.Element),
		lru:     list.New(),
		cap:     defaultSettingsCacheCap,
	}
}

// get returns the cached fresh payload for key if one exists and hasn't
// expired. The returned bool is true when the caller should use the payload
// and skip the outbound request entirely.
func (s *settingsCache) get(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.entries[key]
	if !ok {
		s.misses.Add(1)
		return nil, false
	}
	entry := el.Value.(*settingsCacheEntry)
	if time.Now().After(entry.expiresAt) {
		s.misses.Add(1)
		return nil, false
	}
	// Touch — a cache hit moves the entry to the MRU front.
	s.lru.MoveToFront(el)
	s.hits.Add(1)
	return entry.payload, true
}

// stale returns the stored stale payload for key if one exists and is still
// within the stale window. Used when Zitadel returns 5xx.
func (s *settingsCache) stale(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.entries[key]
	if !ok {
		return nil, false
	}
	entry := el.Value.(*settingsCacheEntry)
	if len(entry.stalePayload) == 0 || time.Now().After(entry.staleUntil) {
		return nil, false
	}
	// Touch — serving the stale entry indicates it's still useful.
	s.lru.MoveToFront(el)
	s.staleServed.Add(1)
	return entry.stalePayload, true
}

// set records payload as the fresh value for key with the given TTL and
// shadows it to the stale slot so it remains available after expiry.
// On insert overflow, the LRU entry is evicted.
func (s *settingsCache) set(key string, payload []byte, ttl time.Duration) {
	now := time.Now()
	// Defensive copy — callers pass slices that may be reused.
	buf := make([]byte, len(payload))
	copy(buf, payload)

	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.entries[key]; ok {
		// In-place update: same key, refresh payload + TTL, move to MRU.
		entry := el.Value.(*settingsCacheEntry)
		entry.payload = buf
		entry.expiresAt = now.Add(ttl)
		entry.stalePayload = buf
		entry.staleUntil = now.Add(ttl + staleWindow)
		s.lru.MoveToFront(el)
		return
	}
	entry := &settingsCacheEntry{
		key:          key,
		payload:      buf,
		expiresAt:    now.Add(ttl),
		stalePayload: buf,
		staleUntil:   now.Add(ttl + staleWindow),
	}
	el := s.lru.PushFront(entry)
	s.entries[key] = el

	if s.lru.Len() > s.cap {
		victim := s.lru.Back()
		if victim != nil {
			s.lru.Remove(victim)
			delete(s.entries, victim.Value.(*settingsCacheEntry).key)
			s.evictions.Add(1)
		}
	}
}

// SettingsCacheMetrics is the public view of the cache counters.
type SettingsCacheMetrics struct {
	Hits            uint64
	Misses          uint64
	StaleServed     uint64
	Evictions       uint64
	UpstreamFetches uint64 // Round 25 Wave 8 (item 1): unique upstream fetches (singleflight deduplicated)
	DedupedFetches  uint64 // concurrent miss-callers that piggy-backed on an in-flight fetch
}

// Metrics returns a snapshot of the cache counters for logging / observability.
func (s *settingsCache) Metrics() SettingsCacheMetrics {
	return SettingsCacheMetrics{
		Hits:            s.hits.Load(),
		Misses:          s.misses.Load(),
		StaleServed:     s.staleServed.Load(),
		Evictions:       s.evictions.Load(),
		UpstreamFetches: s.upstreamFetches.Load(),
		DedupedFetches:  s.dedupedFetches.Load(),
	}
}

// fetchOrShare runs `fn` exactly once for a given key while concurrent
// callers for the same key wait and receive the shared result. Round
// 25 Wave 8 (item 1 / F-chaos-2). The returned error is whatever `fn`
// returned (or a singleflight forwarding error). The boolean reports
// whether the caller was the leader (true) or a piggy-backer (false)
// — used by the metrics counters.
func (s *settingsCache) fetchOrShare(key string, fn func() (any, error)) (any, bool, error) {
	leader := false
	v, err, shared := s.flight.Do(key, func() (any, error) {
		leader = true
		s.upstreamFetches.Add(1)
		return fn()
	})
	if shared && !leader {
		// Concurrent caller piggy-backed on the leader's fetch.
		s.dedupedFetches.Add(1)
	}
	return v, leader, err
}

// settingsTTL maps each settings-proxy zitadel path to its cache TTL per the
// plan's D3 table. Paths not in this map are treated as uncacheable.
//
// The exact paths here are the ones Zitadel v4 actually exposes (verified
// against a live v4.13 instance). An earlier plan iteration used
// camelCase variants (`passwordComplexitySettings`, `legalAndSupportSettings`)
// that returned 404 — fixed during Phase-A re-verification.
var settingsTTL = map[string]time.Duration{
	"/v2/settings/login":               15 * time.Minute,
	"/v2/settings/branding":            1 * time.Hour,
	"/v2/settings/password/complexity": 15 * time.Minute,
	"/v2/settings/password/expiry":     15 * time.Minute,
	"/v2/settings/lockout":             15 * time.Minute,
	"/v2/settings/legal_support":       1 * time.Hour,
	"/v2/settings/security":            15 * time.Minute,
}
