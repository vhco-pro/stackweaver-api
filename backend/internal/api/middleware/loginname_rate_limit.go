// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"container/list"
	"sync"
	"time"
)

// defaultLoginNameLimiterCap bounds the LoginNameRateLimiter map. Round 25
// hardening (item 23 / R25c H-2): the previous implementation grew the
// map unbounded, with comments noting "entries older than `window` are
// purged opportunistically on each call (no background goroutine)" —
// so an attacker probing many distinct loginNames fills the map with
// entries that won't be purged until each one is touched again.
// Memory grows unbounded under sustained credential-spraying.
//
// 100k entries ≈ a few MB of `loginNameFailure` state; generous for
// legitimate traffic but caps the worst case.
const defaultLoginNameLimiterCap = 100_000

// LoginNameRateLimiter tracks failed-password attempts per loginName and
// locks accounts that exceed `threshold` failures within `window`.
// Defends against password-spraying — an attacker hitting many usernames
// from rotating IPs would slip past the per-IP `IPRateLimiter` because
// each attempt costs the bucket only one token; the per-loginName
// counter accumulates across IPs.
//
// The limiter uses a sliding window: the first failure within the window
// stamps `firstFailureAt`, subsequent failures bump `count`, and once
// `count >= threshold` the user is "locked" for the remainder of the
// window. A successful auth (`Reset(loginName)`) clears the entry, so
// honest users who mistyped a few times aren't permanently stuck after
// they finally type the right password.
//
// Thread-safe under sync.Mutex. Memory grows with the number of distinct
// loginNames seen within the window — entries older than `window` are
// purged opportunistically on each call (no background goroutine).
//
// **Loginname-key canonicalisation invariant (Round 25 item 28 / R25b F7):**
// All public methods (`IsLocked`, `BeginAttempt`, `RollbackAttempt`,
// `RecordFailure`, `Reset`) key on the raw `loginName` string the
// caller passes in. Two callers that disagree on case-folding (e.g.
// `Alice@x.com` vs `alice@x.com`) produce two distinct entries — one
// would lock the user, the other wouldn't. The limiter does NOT
// canonicalise on its own behalf because it has no domain knowledge
// about which case-folding rule is correct (loginName domain part is
// case-insensitive per RFC 5321, but the local part may be either).
// CALLERS MUST canonicalise (typically `strings.ToLower(loginName)`)
// before passing in. Today every Stackweaver call site reads the
// loginName from the same canonicalised source (`extractLoginName…`
// helpers in `auth_proxy.go`), so the invariant holds — but a future
// caller adding a new code path must follow the same convention.
type LoginNameRateLimiter struct {
	mu        sync.Mutex
	failures  map[string]*list.Element // loginName → list element holding *loginNameFailure
	lru       *list.List               // MRU at front; LRU at back
	cap       int
	threshold int
	window    time.Duration
	now       func() time.Time // injectable for unit tests

	// stopSweeper closes when Stop() is called to halt the background
	// sweeper goroutine. nil if no sweeper was started (zero-config /
	// tests).
	stopSweeper chan struct{}
	sweeperOnce sync.Once
}

type loginNameFailure struct {
	loginName      string
	count          int
	firstFailureAt time.Time
}

// NewLoginNameRateLimiter creates a per-loginName failure tracker. A
// non-positive `threshold` disables the limiter (every IsLocked call
// returns false; RecordFailure is a no-op) — useful for STACKWEAVER_ENV=
// dev setups where password-spraying lockout would be a footgun.
//
// Round 25 hardening (item 23 / R25c H-2): the failures map is now LRU-
// bounded (cap `defaultLoginNameLimiterCap`). A background sweeper
// goroutine prunes expired entries every `window/2` so memory bounded
// under sustained credential-spraying even when no future probe touches
// an old entry. The sweeper starts lazily when `threshold > 0`; the
// disabled-limiter case skips it entirely.
func NewLoginNameRateLimiter(threshold int, window time.Duration) *LoginNameRateLimiter {
	rl := &LoginNameRateLimiter{
		failures:  make(map[string]*list.Element),
		lru:       list.New(),
		cap:       defaultLoginNameLimiterCap,
		threshold: threshold,
		window:    window,
		now:       time.Now,
	}
	if threshold > 0 && window > 0 {
		rl.startSweeper()
	}
	return rl
}

// startSweeper launches the background goroutine that periodically
// prunes expired entries from the failures map. Idempotent — guarded
// by sync.Once so callers don't have to track whether they've started
// it. The sweeper exits when stopSweeper is closed (Stop()).
func (rl *LoginNameRateLimiter) startSweeper() {
	rl.sweeperOnce.Do(func() {
		rl.stopSweeper = make(chan struct{})
		// Tick at half the window so an expired entry never lives more
		// than window+window/2 = 1.5×window before being reaped.
		interval := rl.window / 2
		if interval < time.Second {
			interval = time.Second
		}
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					rl.sweepExpired()
				case <-rl.stopSweeper:
					return
				}
			}
		}()
	})
}

// sweepExpired walks the LRU and prunes every entry whose first-failure
// timestamp is older than `window`. Holding the mutex for the duration
// is fine because the map is bounded by `cap` (≤100k) and the prune is
// O(N). Future enhancement: walk only the LRU back tail to short-circuit.
func (rl *LoginNameRateLimiter) sweepExpired() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	// Walk back-to-front so we evict cold entries first; stop as soon
	// as we hit a non-expired entry (LRU semantics: the back is oldest
	// by *touch*, but firstFailureAt is what TTL is measured against,
	// so we can't short-circuit safely. Walk all entries.)
	for el := rl.lru.Back(); el != nil; {
		entry := el.Value.(*loginNameFailure)
		prev := el.Prev()
		if now.Sub(entry.firstFailureAt) > rl.window {
			rl.lru.Remove(el)
			delete(rl.failures, entry.loginName)
		}
		el = prev
	}
}

// Stop halts the background sweeper goroutine. Idempotent — safe to
// call multiple times. Intended for graceful shutdown / test cleanup;
// production deployments don't need to call it because the goroutine
// exits when the process exits anyway.
func (rl *LoginNameRateLimiter) Stop() {
	if rl.stopSweeper != nil {
		select {
		case <-rl.stopSweeper:
			// already closed
		default:
			close(rl.stopSweeper)
		}
	}
}

// loadEntry returns the loginNameFailure for loginName if present,
// without touching LRU position. Caller MUST hold the mutex.
func (rl *LoginNameRateLimiter) loadEntry(loginName string) (*loginNameFailure, bool) {
	el, ok := rl.failures[loginName]
	if !ok {
		return nil, false
	}
	return el.Value.(*loginNameFailure), true
}

// touchEntry returns the loginNameFailure and moves its element to the
// MRU front of the LRU list. Caller MUST hold the mutex.
func (rl *LoginNameRateLimiter) touchEntry(loginName string) (*loginNameFailure, bool) {
	el, ok := rl.failures[loginName]
	if !ok {
		return nil, false
	}
	rl.lru.MoveToFront(el)
	return el.Value.(*loginNameFailure), true
}

// putEntry inserts a fresh failure entry, evicting the LRU on overflow.
// Caller MUST hold the mutex.
func (rl *LoginNameRateLimiter) putEntry(entry *loginNameFailure) {
	el := rl.lru.PushFront(entry)
	rl.failures[entry.loginName] = el
	if rl.lru.Len() > rl.cap {
		victim := rl.lru.Back()
		if victim != nil {
			rl.lru.Remove(victim)
			delete(rl.failures, victim.Value.(*loginNameFailure).loginName)
		}
	}
}

// removeEntry deletes the entry for loginName from both the map and
// the LRU list. Caller MUST hold the mutex.
func (rl *LoginNameRateLimiter) removeEntry(loginName string) {
	if el, ok := rl.failures[loginName]; ok {
		rl.lru.Remove(el)
		delete(rl.failures, loginName)
	}
}

// IsLocked reports whether `loginName` has accumulated enough recent
// failures to be locked. Window-expired entries are purged inline and
// reported as unlocked.
//
// NOTE: `IsLocked` alone is NOT race-safe under parallel attempts —
// concurrent callers can each see `count < threshold`, all forward
// upstream, then all RecordFailure, blowing past the threshold by N
// in-flight attempts. Use `BeginAttempt` for the password-attempt
// gate; `IsLocked` is kept for read-only inspection (tests, metrics).
func (rl *LoginNameRateLimiter) IsLocked(loginName string) bool {
	if rl.threshold <= 0 || loginName == "" {
		return false
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	entry, ok := rl.loadEntry(loginName)
	if !ok {
		return false
	}
	if rl.now().Sub(entry.firstFailureAt) > rl.window {
		// Window expired — clear and treat as unlocked.
		rl.removeEntry(loginName)
		return false
	}
	return entry.count >= rl.threshold
}

// BeginAttempt atomically checks the lockout threshold AND tentatively
// reserves a failure slot. Returns true if the caller may proceed with
// the upstream password check, false if the user is locked.
//
// This closes the parallel-attempt race that `IsLocked` + post-flight
// `RecordFailure` allows: with N concurrent PATCHes, all N pass the
// IsLocked gate (count < threshold), all N forward to Zitadel, then
// all N record their failures — blowing past `threshold` by N. Audit
// Round 20 surfaced this; the fix is to claim the slot pre-flight.
//
// Caller contract:
//   - On a successful upstream auth (HTTP 200): call `Reset(loginName)`
//     to clear the tentative bump (and any prior failures).
//   - On a confirmed upstream failure (HTTP 4xx): do NOTHING — the slot
//     is already counted.
//   - On a transport-layer error or upstream 5xx: call `RollbackAttempt(loginName)`
//     so an outage doesn't silently lock honest users.
func (rl *LoginNameRateLimiter) BeginAttempt(loginName string) bool {
	if rl.threshold <= 0 || loginName == "" {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	entry, ok := rl.touchEntry(loginName)
	if !ok || now.Sub(entry.firstFailureAt) > rl.window {
		// Fresh window. Reserve the first slot and proceed.
		rl.removeEntry(loginName) // no-op if not present
		rl.putEntry(&loginNameFailure{loginName: loginName, count: 1, firstFailureAt: now})
		return true
	}
	if entry.count >= rl.threshold {
		// Already locked — refuse before forwarding upstream.
		return false
	}
	// Tentatively reserve another slot. If the caller's upstream auth
	// succeeds, they'll Reset and clear the bump.
	entry.count++
	return true
}

// RollbackAttempt undoes a tentative slot reservation when the upstream
// call could not produce a definitive auth verdict (5xx, transport
// error). Without this, a transient Zitadel outage would count failed
// retries as real lockout failures and brick honest users.
//
// Decrements the entry count by one; deletes the entry if count drops
// to zero (so the next attempt starts a fresh window). Bounded below
// at zero — a stray rollback can never go negative.
//
// Round 21 Finding 5 (DEFERRED, documented at design-time): under a
// SUSTAINED Zitadel outage that 5xxs every attempt, an attacker can
// farm rollbacks indefinitely — each cycle returns their full budget.
// The honest-user protection is the priority and the IPRateLimiter
// caps absolute volume per source. A future hardening could track
// 5xx events separately and treat them as confirmed failures after a
// small grace count (e.g. 3 5xxs in window → switch to RecordFailure
// semantics). Not fixed today because the current behavior is
// asymmetrically helpful to honest users (transient blip → no lock)
// and the abuse case requires a Zitadel-outage-class event that
// dominates other failure modes anyway.
func (rl *LoginNameRateLimiter) RollbackAttempt(loginName string) {
	if rl.threshold <= 0 || loginName == "" {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	entry, ok := rl.loadEntry(loginName)
	if !ok {
		return
	}
	if entry.count <= 1 {
		rl.removeEntry(loginName)
		return
	}
	entry.count--
}

// RecordFailure increments the failure counter for `loginName`. The
// first failure within a window stamps `firstFailureAt`; subsequent
// failures inside the window only bump count. Once the window expires,
// the next failure resets both fields (sliding window semantics).
//
// Prefer `BeginAttempt` for the password-attempt gate (see Audit Round
// 20). RecordFailure is kept for callers that need the legacy
// post-flight semantics — currently only the unit-test harness.
func (rl *LoginNameRateLimiter) RecordFailure(loginName string) {
	if rl.threshold <= 0 || loginName == "" {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	entry, ok := rl.touchEntry(loginName)
	if !ok || now.Sub(entry.firstFailureAt) > rl.window {
		rl.removeEntry(loginName) // no-op if not present
		rl.putEntry(&loginNameFailure{loginName: loginName, count: 1, firstFailureAt: now})
		return
	}
	entry.count++
}

// Reset clears the failure tracking for a single loginName. Called after
// a successful password verification so honest users who fat-fingered a
// few attempts aren't penalized after they finally get it right (F-sec-6
// contract).
func (rl *LoginNameRateLimiter) Reset(loginName string) {
	if loginName == "" {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.removeEntry(loginName)
}

// ResetAll clears every loginName failure entry. Intended for E2E test
// harnesses (`/auth/testing/reset`) to restore a clean slate between
// specs — never call from production code paths.
func (rl *LoginNameRateLimiter) ResetAll() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.failures = make(map[string]*list.Element)
	rl.lru = list.New()
}
