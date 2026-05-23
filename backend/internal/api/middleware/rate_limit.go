// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"container/list"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type RateLimiter struct {
	limiter *rate.Limiter
}

func NewRateLimiter(rps int, burst int) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(rps), burst),
	}
}

func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rl.limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// defaultIPLimiterCap bounds the IPRateLimiter map. Round 25c Finding
// C-3: the previous implementation grew the map unbounded, so an
// attacker spoofing X-Forwarded-For (or simply traffic from a large
// IPv6 address space) could exhaust API memory by minting fresh
// buckets. 100k entries ≈ a few MB of `rate.Limiter` state, which is
// generous for legitimate traffic but caps the worst case.
const defaultIPLimiterCap = 100_000

// Per-IP rate limiter with LRU-bounded entry map. The entries list
// holds *ipLimiterEntry in MRU-front order; on overflow we evict from
// the back (least-recently-touched IP).
type IPRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*list.Element
	entries  *list.List
	cap      int
	rps      int
	burst    int
}

type ipLimiterEntry struct {
	ip      string
	limiter *rate.Limiter
}

func NewIPRateLimiter(rps int, burst int) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*list.Element),
		entries:  list.New(),
		cap:      defaultIPLimiterCap,
		rps:      rps,
		burst:    burst,
	}
}

func (rl *IPRateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if el, ok := rl.limiters[ip]; ok {
		rl.entries.MoveToFront(el)
		return el.Value.(*ipLimiterEntry).limiter
	}
	entry := &ipLimiterEntry{ip: ip, limiter: rate.NewLimiter(rate.Limit(rl.rps), rl.burst)}
	el := rl.entries.PushFront(entry)
	rl.limiters[ip] = el
	if rl.entries.Len() > rl.cap {
		victim := rl.entries.Back()
		if victim != nil {
			rl.entries.Remove(victim)
			delete(rl.limiters, victim.Value.(*ipLimiterEntry).ip)
		}
	}
	return entry.limiter
}

// Reset clears all per-IP rate-limit state. Intended for E2E test harnesses
// to restore a clean slate between specs — never call from production code
// paths. Guarded at the call site by the `e2e` build tag + runtime env check.
func (rl *IPRateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.limiters = make(map[string]*list.Element)
	rl.entries = list.New()
}

func (rl *IPRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		limiter := rl.getLimiter(ip)

		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
