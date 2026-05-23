// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"sync"
	"testing"
	"time"
)

// fakeClock returns a controllable time source for sliding-window tests.
// Tests advance `now` directly to exercise expiry without sleeping.
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }

func TestLoginNameRateLimiter_NotLockedInitially(t *testing.T) {
	rl := NewLoginNameRateLimiter(5, 5*time.Minute)
	if rl.IsLocked("alice") {
		t.Error("user should not be locked with no recorded failures")
	}
}

func TestLoginNameRateLimiter_LocksAtThreshold(t *testing.T) {
	rl := NewLoginNameRateLimiter(3, 5*time.Minute)
	for i := range 2 {
		rl.RecordFailure("alice")
		if rl.IsLocked("alice") {
			t.Errorf("locked at count=%d but threshold=3", i+1)
		}
	}
	rl.RecordFailure("alice")
	if !rl.IsLocked("alice") {
		t.Error("expected lock at count=3 == threshold")
	}
	rl.RecordFailure("alice")
	if !rl.IsLocked("alice") {
		t.Error("expected to remain locked beyond threshold")
	}
}

func TestLoginNameRateLimiter_PerUserIsolation(t *testing.T) {
	rl := NewLoginNameRateLimiter(3, 5*time.Minute)
	for range 5 {
		rl.RecordFailure("alice")
	}
	if !rl.IsLocked("alice") {
		t.Error("alice should be locked")
	}
	if rl.IsLocked("bob") {
		t.Error("bob should NOT be locked — failures must be per-user")
	}
}

func TestLoginNameRateLimiter_ResetClearsLock(t *testing.T) {
	rl := NewLoginNameRateLimiter(3, 5*time.Minute)
	for range 5 {
		rl.RecordFailure("alice")
	}
	if !rl.IsLocked("alice") {
		t.Fatal("alice should be locked before Reset")
	}
	rl.Reset("alice")
	if rl.IsLocked("alice") {
		t.Error("Reset should clear the lock (F-sec-6 contract)")
	}
	// Post-reset, the next failure starts a fresh count.
	rl.RecordFailure("alice")
	if rl.IsLocked("alice") {
		t.Error("single failure after Reset should NOT immediately re-lock")
	}
}

func TestLoginNameRateLimiter_WindowExpiry(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	rl := NewLoginNameRateLimiter(3, 5*time.Minute)
	rl.now = clock.Now

	for range 5 {
		rl.RecordFailure("alice")
	}
	if !rl.IsLocked("alice") {
		t.Fatal("alice should be locked initially")
	}

	// Advance past the window — IsLocked should auto-purge and report
	// unlocked. This is the sliding-window contract: an attacker who
	// stops trying for the window's duration gets a fresh budget.
	clock.now = clock.now.Add(6 * time.Minute)
	if rl.IsLocked("alice") {
		t.Error("expected unlock after window expiry")
	}

	// And a fresh failure should start a NEW window.
	rl.RecordFailure("alice")
	if rl.IsLocked("alice") {
		t.Error("first failure in new window should NOT lock immediately")
	}
}

func TestLoginNameRateLimiter_ResetAllClearsEverything(t *testing.T) {
	rl := NewLoginNameRateLimiter(3, 5*time.Minute)
	for _, u := range []string{"alice", "bob", "carol"} {
		for range 5 {
			rl.RecordFailure(u)
		}
	}
	for _, u := range []string{"alice", "bob", "carol"} {
		if !rl.IsLocked(u) {
			t.Fatalf("%s should be locked before ResetAll", u)
		}
	}
	rl.ResetAll()
	for _, u := range []string{"alice", "bob", "carol"} {
		if rl.IsLocked(u) {
			t.Errorf("%s should be unlocked after ResetAll", u)
		}
	}
}

func TestLoginNameRateLimiter_DisabledByZeroThreshold(t *testing.T) {
	rl := NewLoginNameRateLimiter(0, 5*time.Minute)
	for range 100 {
		rl.RecordFailure("alice")
	}
	if rl.IsLocked("alice") {
		t.Error("threshold=0 must disable locking entirely")
	}
}

func TestLoginNameRateLimiter_EmptyLoginNameNoOp(t *testing.T) {
	// Defense-in-depth: empty loginName must not corrupt the map or
	// accidentally lock all empty-loginName attempts together.
	rl := NewLoginNameRateLimiter(3, 5*time.Minute)
	for range 10 {
		rl.RecordFailure("")
	}
	if rl.IsLocked("") {
		t.Error("empty loginName must never enter the failure map")
	}
}

// --- Audit Round 20: BeginAttempt + RollbackAttempt ---

// TestBeginAttempt_AllowsUpToThresholdSequentially proves the gate
// shape matches the F-sec-5 contract: the first `threshold` calls
// succeed (each reserves one failure slot), and the (threshold+1)-th
// call is refused.
func TestBeginAttempt_AllowsUpToThresholdSequentially(t *testing.T) {
	rl := NewLoginNameRateLimiter(5, 5*time.Minute)
	for i := 1; i <= 5; i++ {
		if !rl.BeginAttempt("alice") {
			t.Errorf("attempt %d should be allowed (under threshold)", i)
		}
	}
	if rl.BeginAttempt("alice") {
		t.Error("attempt 6 must be refused — 5 failures already reserved")
	}
}

// TestBeginAttempt_RaceSafe is the regression test for Audit Round 20
// Finding 3: under N parallel callers, no more than `threshold` attempts
// are allowed through. The legacy IsLocked + RecordFailure pair would
// let all N pass.
func TestBeginAttempt_RaceSafe(t *testing.T) {
	const (
		threshold = 5
		parallel  = 100
	)
	rl := NewLoginNameRateLimiter(threshold, 5*time.Minute)

	results := make(chan bool, parallel)
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(parallel)
	for range parallel {
		go func() {
			defer done.Done()
			start.Wait()
			results <- rl.BeginAttempt("alice")
		}()
	}
	start.Done()
	done.Wait()
	close(results)

	allowed := 0
	for r := range results {
		if r {
			allowed++
		}
	}
	if allowed != threshold {
		t.Errorf("parallel BeginAttempt allowed %d through; threshold=%d", allowed, threshold)
	}
}

// TestRollbackAttempt_ReturnsSlot ensures a transport-error path
// (Zitadel 5xx, network failure) doesn't accumulate phantom failures
// that lock honest users on retry.
func TestRollbackAttempt_ReturnsSlot(t *testing.T) {
	rl := NewLoginNameRateLimiter(3, 5*time.Minute)
	rl.BeginAttempt("alice") // count=1
	rl.BeginAttempt("alice") // count=2
	if !rl.BeginAttempt("alice") {
		t.Fatal("3rd attempt should reserve a slot at the threshold edge")
	}
	rl.RollbackAttempt("alice") // count back to 2

	if !rl.BeginAttempt("alice") {
		t.Error("post-rollback the next attempt must be allowed (count was 2)")
	}
	// Now at threshold (3) — the 4th attempt must be refused.
	if rl.BeginAttempt("alice") {
		t.Error("attempt past threshold must be refused after the rollback dance")
	}
}

// TestRollbackAttempt_BoundedAtZero guards against an unmatched
// rollback: rollback on a counter at 0 must not underflow.
func TestRollbackAttempt_BoundedAtZero(t *testing.T) {
	rl := NewLoginNameRateLimiter(3, 5*time.Minute)
	rl.RollbackAttempt("alice") // no prior attempt — must be a no-op
	if !rl.BeginAttempt("alice") {
		t.Error("rollback-with-no-prior-attempt corrupted the map")
	}
}

// Round 25 Wave 3 (item 23 / R25c H-2): the failures map is LRU-bounded
// at `defaultLoginNameLimiterCap`. An attacker probing many distinct
// loginNames must NOT grow memory unbounded — overflow evicts the LRU
// entry. We size the test cap down to 3 so we can exercise the eviction
// path without minting 100k entries.
func TestLoginNameRateLimiter_LRUEvictionOnOverflow(t *testing.T) {
	rl := NewLoginNameRateLimiter(5, 5*time.Minute)
	rl.cap = 3 // shrink for the test

	// Insert 4 distinct loginNames; the first should be evicted.
	rl.RecordFailure("alice")
	rl.RecordFailure("bob")
	rl.RecordFailure("carol")
	rl.RecordFailure("dave") // pushes alice out

	if _, ok := rl.failures["alice"]; ok {
		t.Errorf("LRU should have evicted alice on overflow")
	}
	for _, name := range []string{"bob", "carol", "dave"} {
		if _, ok := rl.failures[name]; !ok {
			t.Errorf("expected %q to remain in the limiter map", name)
		}
	}
	if rl.lru.Len() != 3 {
		t.Errorf("LRU list length: want 3, got %d", rl.lru.Len())
	}
}

// Round 25 Wave 3 (item 23 / R25c H-2): touching an entry (via
// RecordFailure or BeginAttempt) must move it to MRU front so it
// survives subsequent overflows. Pin the LRU semantics.
func TestLoginNameRateLimiter_LRUTouchPromotesEntry(t *testing.T) {
	rl := NewLoginNameRateLimiter(5, 5*time.Minute)
	rl.cap = 3

	rl.RecordFailure("alice") // [alice]
	rl.RecordFailure("bob")   // [bob, alice]
	rl.RecordFailure("carol") // [carol, bob, alice]
	rl.RecordFailure("alice") // [alice, carol, bob] — alice promoted, count++
	rl.RecordFailure("dave")  // [dave, alice, carol] — bob evicted (LRU)

	if _, ok := rl.failures["bob"]; ok {
		t.Errorf("bob should have been evicted (was LRU after alice's promotion)")
	}
	for _, name := range []string{"alice", "carol", "dave"} {
		if _, ok := rl.failures[name]; !ok {
			t.Errorf("expected %q to remain", name)
		}
	}
}

// Round 25 Wave 3 (item 23 / R25c H-2): the background sweeper must
// prune entries whose firstFailureAt is older than `window`. We use
// the injectable `now` to fast-forward time without sleeping.
func TestLoginNameRateLimiter_SweeperPrunesExpired(t *testing.T) {
	rl := NewLoginNameRateLimiter(5, 100*time.Millisecond)
	defer rl.Stop()

	base := time.Now()
	rl.now = func() time.Time { return base }

	// Seed three entries at t=0.
	rl.RecordFailure("alice")
	rl.RecordFailure("bob")
	rl.RecordFailure("carol")

	// Fast-forward past the window.
	rl.now = func() time.Time { return base.Add(200 * time.Millisecond) }

	// Manually invoke the sweeper (deterministic — don't rely on the
	// background ticker's timing).
	rl.sweepExpired()

	if len(rl.failures) != 0 {
		t.Errorf("sweeper should have pruned all expired entries; still have %d", len(rl.failures))
	}
	if rl.lru.Len() != 0 {
		t.Errorf("LRU list should be empty after sweep; len=%d", rl.lru.Len())
	}
}

// Round 25 Wave 3 (item 23 / R25c H-2): Stop() halts the sweeper
// without panic and is idempotent.
func TestLoginNameRateLimiter_StopIsIdempotent(t *testing.T) {
	rl := NewLoginNameRateLimiter(5, time.Minute)
	rl.Stop()
	rl.Stop() // must not panic on double-close
}
