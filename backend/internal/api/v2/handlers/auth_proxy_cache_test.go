// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// TestSettingsCache_HitMissCycle verifies the basic TTL cache contract:
// the first read is a miss and hits Zitadel; the second read is a hit and
// doesn't; once the entry expires we go back to missing.
func TestSettingsCache_HitMissCycle(t *testing.T) {
	c := newSettingsCache()
	key := "/v2/settings/login"
	payload := []byte(`{"allowRegister":true}`)

	if _, ok := c.get(key); ok {
		t.Fatal("expected miss on empty cache")
	}
	c.set(key, payload, 50*time.Millisecond)
	got, ok := c.get(key)
	if !ok || string(got) != string(payload) {
		t.Fatalf("expected cache hit with payload, got ok=%v got=%q", ok, got)
	}

	// Let the TTL expire.
	time.Sleep(60 * time.Millisecond)
	if _, ok := c.get(key); ok {
		t.Fatal("expected miss after TTL expiry")
	}

	// But the stale copy should still be available until staleUntil.
	if _, ok := c.stale(key); !ok {
		t.Fatal("expected stale to be available after TTL, before staleWindow")
	}

	m := c.Metrics()
	if m.Hits != 1 || m.Misses != 2 || m.StaleServed != 1 {
		t.Errorf("unexpected metrics: %+v", m)
	}
}

// TestSettingsCache_DefensiveCopy asserts that callers mutating the slice they
// passed to set() don't accidentally corrupt the cached entry.
func TestSettingsCache_DefensiveCopy(t *testing.T) {
	c := newSettingsCache()
	key := "/v2/settings/branding"
	src := []byte(`{"logoUrl":"a"}`)
	c.set(key, src, time.Minute)
	src[len(src)-2] = 'Z' // mutate caller's buffer

	got, _ := c.get(key)
	if strings.Contains(string(got), "Z") {
		t.Errorf("cache did not make a defensive copy: %q", got)
	}
}

// TestSettingsProxy_StaleOnUpstream5xx verifies the SPA keeps receiving the
// last-good settings when Zitadel falls over. Prevents a Zitadel outage from
// bricking the login page. Mirrors the F-chaos-5 spec intent.
func TestSettingsProxy_StaleOnUpstream5xx(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var callCount atomic.Int64
	fresh := `{"settings":{"allowRegister":true}}`
	mockZitadel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(fresh))
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"code":13,"message":"upstream down"}`))
	}))
	defer mockZitadel.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: mockZitadel.URL, PAT: "pat"})

	// First request populates the cache with the fresh value.
	w1 := httptest.NewRecorder()
	c1, _ := gin.CreateTestContext(w1)
	c1.Request = newTestRequest(http.MethodGet, "/auth/settings/login")
	proxy.settingsProxy(c1, "/v2/settings/login", "settings")

	if w1.Code != http.StatusOK {
		t.Fatalf("first call: expected 200, got %d: %s", w1.Code, w1.Body.String())
	}
	if !strings.Contains(w1.Body.String(), `"allowRegister":true`) {
		t.Errorf("first response lost unwrapped payload: %s", w1.Body.String())
	}

	// Expire the entry so the next request goes back to Zitadel.
	// Round 25 Wave 3 (item 22): entries map is now an LRU
	// `map[string]*list.Element`; unwrap to the underlying entry.
	proxy.settingsCache.mu.Lock()
	el := proxy.settingsCache.entries["/v2/settings/login"]
	entry := el.Value.(*settingsCacheEntry)
	entry.expiresAt = time.Now().Add(-time.Second) // mark expired but keep stale
	proxy.settingsCache.mu.Unlock()

	// Second call hits Zitadel, Zitadel 5xxs, and we should fall back to stale.
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = newTestRequest(http.MethodGet, "/auth/settings/login")
	proxy.settingsProxy(c2, "/v2/settings/login", "settings")

	if w2.Code != http.StatusOK {
		t.Fatalf("stale fallback: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), `"allowRegister":true`) {
		t.Errorf("stale fallback didn't serve prior payload: %s", w2.Body.String())
	}

	m := proxy.SettingsCacheMetrics()
	if m.StaleServed == 0 {
		t.Errorf("expected StaleServed > 0, got %+v", m)
	}
}

// TestSettingsProxy_CacheShortCircuitsUpstream asserts that a warm cache
// prevents outbound requests entirely — the stampede protection this buys us
// only works if we actually skip the upstream call.
func TestSettingsProxy_CacheShortCircuitsUpstream(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var hits atomic.Int64
	mockZitadel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"settings":{"x":1}}`))
	}))
	defer mockZitadel.Close()

	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: mockZitadel.URL, PAT: "pat"})

	for range 5 {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequest(http.MethodGet, "/auth/settings/login")
		proxy.settingsProxy(c, "/v2/settings/login", "settings")
		if w.Code != http.StatusOK {
			t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
		}
	}

	if got := hits.Load(); got != 1 {
		t.Errorf("expected upstream to be called exactly once across 5 reads, got %d", got)
	}
	m := proxy.SettingsCacheMetrics()
	if m.Hits != 4 {
		t.Errorf("expected 4 cache hits, got %d (misses=%d)", m.Hits, m.Misses)
	}
}

// Round 25 Wave 3 (item 22 / R25c H-1): the settings cache is LRU-
// bounded. An attacker minting unique `ctx.orgId` values to fill the
// cache must NOT exhaust memory — overflow evicts the LRU entry.
func TestSettingsCache_LRUEvictionOnOverflow(t *testing.T) {
	c := newSettingsCache()
	c.cap = 3 // shrink for the test

	c.set("a", []byte("payloadA"), time.Minute)
	c.set("b", []byte("payloadB"), time.Minute)
	c.set("c", []byte("payloadC"), time.Minute)
	c.set("d", []byte("payloadD"), time.Minute) // evicts "a"

	if _, ok := c.entries["a"]; ok {
		t.Errorf("LRU should have evicted 'a' on overflow")
	}
	if c.lru.Len() != 3 {
		t.Errorf("LRU list length: want 3, got %d", c.lru.Len())
	}
	m := c.Metrics()
	if m.Evictions != 1 {
		t.Errorf("evictions counter: want 1, got %d", m.Evictions)
	}
}

// Round 25 Wave 3 (item 22 / R25c H-1): a cache hit must move the
// entry to MRU front so it survives subsequent overflows.
func TestSettingsCache_HitPromotesToMRU(t *testing.T) {
	c := newSettingsCache()
	c.cap = 3

	c.set("a", []byte("A"), time.Minute) // [a]
	c.set("b", []byte("B"), time.Minute) // [b, a]
	c.set("c", []byte("C"), time.Minute) // [c, b, a]

	// Touch "a" — moves to front.
	if _, ok := c.get("a"); !ok {
		t.Fatal("a should be a cache hit")
	}
	// LRU order is now [a, c, b]; next set evicts "b".
	c.set("d", []byte("D"), time.Minute)

	if _, ok := c.entries["b"]; ok {
		t.Errorf("b should have been evicted (was LRU after a's promotion)")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := c.entries[k]; !ok {
			t.Errorf("expected %q to remain", k)
		}
	}
}

// Round 25 Wave 3 (item 22 / R25c H-1): re-set on an existing key must
// refresh the entry in place (no eviction, no leak) and move to MRU.
func TestSettingsCache_RefreshKeepsKey(t *testing.T) {
	c := newSettingsCache()
	c.cap = 3

	c.set("a", []byte("v1"), time.Minute)
	c.set("a", []byte("v2"), time.Minute) // refresh in place

	if c.lru.Len() != 1 {
		t.Errorf("LRU list length after refresh: want 1, got %d", c.lru.Len())
	}
	if got, ok := c.get("a"); !ok || string(got) != "v2" {
		t.Errorf("refresh did not update payload: got %q ok=%v", got, ok)
	}
	if c.Metrics().Evictions != 0 {
		t.Errorf("refresh must not count as eviction")
	}
}

// Round 25 Wave 8 (item 1 / F-chaos-2): settingsProxy must dedupe
// concurrent cache misses for the same key via singleflight. 50
// concurrent cold-cache requests for `/auth/settings/login` must
// trigger exactly ONE upstream Zitadel fetch.
func TestSettingsProxy_SingleFlightDeduplication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var fetches atomic.Int64
	mockZitadel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		// Add a small delay so concurrent callers actually overlap
		// in the singleflight window. Without it the leader could
		// finish before any waiter even started.
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"settings":{"allowRegister":true}}`))
	}))
	defer mockZitadel.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: mockZitadel.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	const concurrent = 50
	var wg sync.WaitGroup
	wg.Add(concurrent)
	for range concurrent {
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = newTestRequest(http.MethodGet, "/auth/settings/login")
			proxy.settingsProxy(c, "/v2/settings/login", "settings")
		}()
	}
	wg.Wait()

	if got := fetches.Load(); got != 1 {
		t.Errorf("expected singleflight to dedupe 50 concurrent miss-callers to 1 upstream fetch, got %d", got)
	}
	m := proxy.SettingsCacheMetrics()
	if m.UpstreamFetches != 1 {
		t.Errorf("metrics: UpstreamFetches: want 1, got %d", m.UpstreamFetches)
	}
	if m.DedupedFetches < 40 {
		// Expect ~49 deduped (49 piggybackers + 1 leader). Allow
		// some scheduling slack — racing schedulers could let some
		// callers see the populated cache directly. >=40 is plenty
		// to pin the singleflight behaviour.
		t.Errorf("metrics: DedupedFetches: want ≥40, got %d", m.DedupedFetches)
	}
}

// Round 26 Wave 9 (HIGH-2): the singleflight upstream fetch MUST use a
// detached context, not the leader's request context. Without this, a
// leader whose client disconnects mid-fetch poisons every piggy-backing
// waiter via context.Canceled — turning a single client misbehaviour
// into a fan-out outage.
func TestSettingsProxy_SingleFlightSurvivesLeaderContextCancel(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var fetches atomic.Int64
	releaseUpstream := make(chan struct{})
	mockZitadel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		// Block until released so we can fire the cancel before the
		// upstream returns.
		<-releaseUpstream
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"settings":{"allowRegister":true}}`))
	}))
	defer mockZitadel.Close()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: mockZitadel.URL, PAT: "pat"})
	defer proxy.StopDecoyOrgIDsSweeper()

	// Leader's request — context will be cancelled BEFORE the upstream
	// returns. With the fix in place, the singleflight callback uses
	// a detached context so the fetch completes and the waiter sees
	// the result.
	leaderCtx, leaderCancel := context.WithCancel(context.Background())
	leaderDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequestWithContext(leaderCtx, http.MethodGet, "/auth/settings/login", nil)
		c.Request = req
		proxy.settingsProxy(c, "/v2/settings/login", "settings") //nolint:contextcheck // intentional: testing that the singleflight callback is detached from this context
		leaderDone <- w
	}()

	// Give the leader a moment to enter singleflight.
	time.Sleep(20 * time.Millisecond)

	// Waiter — separate context, alive.
	waiterDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/settings/login", nil)
		proxy.settingsProxy(c, "/v2/settings/login", "settings")
		waiterDone <- w
	}()

	// Now cancel the leader's context, then release upstream.
	time.Sleep(20 * time.Millisecond)
	leaderCancel()
	close(releaseUpstream)

	// The waiter MUST see a successful response — the upstream fetch
	// completed despite the leader's context cancellation.
	select {
	case w := <-waiterDone:
		if w.Code != http.StatusOK {
			t.Errorf("waiter must succeed despite leader cancel; got status %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"allowRegister":true`) {
			t.Errorf("waiter got wrong body: %s", w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter timed out — singleflight blocked on cancelled leader context (regression)")
	}

	<-leaderDone // drain
	if fetches.Load() != 1 {
		t.Errorf("expected exactly 1 upstream fetch (singleflight), got %d", fetches.Load())
	}
}
