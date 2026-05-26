// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"bytes"
	"container/list"
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
)

// NotificationMode controls how verification/OTP codes are delivered.
type NotificationMode string

const (
	NotificationModeReturnCode NotificationMode = "return_code"
	NotificationModeEmail      NotificationMode = "email"
)

// SessionCookieName is the name of the httpOnly cookie that stores Zitadel session entries.
const SessionCookieName = "sessions"

// SessionCookieMaxBytes is the maximum size for the sessions cookie (2KB, with 4KB browser limit as hard cap).
const SessionCookieMaxBytes = 2048

// sessionEntry represents a single session stored in the sessions cookie array.
type sessionEntry struct {
	ID    string `json:"id"`
	Token string `json:"token"`
	// UserID is the Zitadel internal user id this session is bound to.
	// `userScopedProxyWithMethod` checks this against URL :id params to
	// enforce DR-4: a cookie minted for user A must NOT be usable to
	// register / read user B's authenticators. Populated post-createSession
	// via `populateUserIDFromZitadel` (one extra GET /v2/sessions/{id}
	// round-trip — F-sec-9 caught the gap on 2026-04-28). Preserved across
	// `UpdateSession` so password/MFA checks don't lose the binding.
	UserID       string `json:"userId,omitempty"`
	LoginName    string `json:"loginName,omitempty"`
	Organization string `json:"organization,omitempty"`
	CreationTs   string `json:"creationTs,omitempty"`
	ExpirationTs string `json:"expirationTs,omitempty"`
	ChangeTs     string `json:"changeTs,omitempty"`
	RequestID    string `json:"requestId,omitempty"`
	// Decoy marks an F-sec-7 anti-enumeration session: CreateSession
	// returned a fake success for an unknown loginName when the org's
	// login policy has `ignoreUnknownUsernames: true`. UpdateSession
	// short-circuits with a canonical password-invalid response for
	// these so the decoy never leaves the proxy. Internal-only — the
	// cookie ships in an httpOnly cookie scoped to /auth and the
	// browser can't read it.
	Decoy bool `json:"decoy,omitempty"`
}

// AuthProxyConfig holds configuration for the auth proxy.
type AuthProxyConfig struct {
	// ZitadelInternalURL is the internal URL for Zitadel (e.g. http://localhost:8080).
	ZitadelInternalURL string
	// ZitadelIssuer is the external issuer URL Zitadel puts in the `iss` claim of
	// tokens (e.g. https://zitadel.example.com). Used by the backchannel-logout
	// verifier to accept logout_tokens and by the Host: override when fetching
	// JWKS via the internal address.
	ZitadelIssuer string
	// PAT is the service account personal access token for Zitadel Session API calls.
	PAT string
	// ClientID is the OIDC client_id this RP is registered under at Zitadel.
	// Used by the backchannel-logout verifier to enforce that incoming
	// logout_tokens carry our client_id in their `aud` claim per OIDC
	// Back-Channel Logout 1.0 §2.6 step 4 (Round 23 Finding 1). Empty value
	// disables audience binding — production callers MUST set this.
	ClientID string
	// NotificationMode controls code delivery (return_code or email).
	NotificationMode NotificationMode
	// DefaultRedirectURI is the fallback redirect URI when none is specified.
	DefaultRedirectURI string
	// AutoSubmitCode enables auto-submit UX for OTP fields.
	AutoSubmitCode bool
	// CustomRequestHeaders is a comma-separated list of key:value headers to add to Zitadel requests.
	// Parsed from the CUSTOM_REQUEST_HEADERS env var (same format as the old login-ui).
	CustomRequestHeaders string
	// IsProduction controls the Secure flag on cookies.
	IsProduction bool
	// PublicFrontendURL is the browser-visible base URL of the SPA (e.g.
	// "https://app.example.com"). Used by IdP success/failure URL construction
	// in StartIdP — the SPA frequently lives on a different host than the api
	// (split-domain deployments: api.example.com vs app.example.com), and
	// without this the IdP-intent callback lands on the wrong host and 404s.
	// Empty → fall back to the api's own publicBaseURL (correct for
	// same-origin deployments like network_mode: host on localhost). Read from
	// STACKWEAVER_APP_URL in main.go.
	PublicFrontendURL string
	// PostLogoutAllowedHosts is a list of host names that the
	// EndSession redirect-host allowlist will accept on top of
	// PublicFrontendURL's host. Round 25 Wave 5 (item 5 / Round 23
	// Finding 5): defense-in-depth against a misconfigured Zitadel
	// `post_logout_redirect_uri` allowlist. The browser sees us as
	// the redirect issuer (same origin) so we don't want to forward
	// a Zitadel-supplied redirect to an attacker-controlled host
	// even if Zitadel itself accepts it. Empty list → only
	// PublicFrontendURL's host is allowed (relative paths always
	// allowed). Read from STACKWEAVER_POST_LOGOUT_HOSTS in main.go.
	PostLogoutAllowedHosts []string
	// DecoySecret is the HMAC key used by the F-sec-7 decoy-id
	// derivation (Round 21 Finding 1). Round 25 Wave 6 (item 6 /
	// Round 22 OOS): in HA deployments, every replica MUST share the
	// same secret so decoy ids are stable across replicas — otherwise
	// an attacker round-robin'd across replicas sees divergent fake
	// ids while a real user's ids stay stable, distinguishing real
	// vs decoy. Single-replica deployments can leave this nil and
	// `NewAuthProxy` will generate a per-process random secret. Read
	// from `STACKWEAVER_DECOY_SECRET` (base64-encoded ≥32 bytes) in
	// main.go.
	DecoySecret []byte
	// LoginNameLockoutThreshold is the number of failed password
	// attempts per loginName within `LoginNameLockoutWindow` that
	// triggers a per-user lockout (defense against password-spraying
	// across rotating IPs that the per-IP `IPRateLimiter` doesn't
	// catch on its own — F-sec-5/6). 0 disables the limiter (useful
	// for dev). Read from STACKWEAVER_LOGINNAME_LOCKOUT_THRESHOLD in
	// main.go; default 5.
	LoginNameLockoutThreshold int
	// LoginNameLockoutWindow is the sliding-window duration over which
	// `LoginNameLockoutThreshold` failures must accumulate to trigger
	// a lockout. Read from STACKWEAVER_LOGINNAME_LOCKOUT_WINDOW in
	// main.go; default 15 minutes.
	LoginNameLockoutWindow time.Duration
}

// AuthProxy handles proxying authentication requests to Zitadel.
// It sits between the SPA frontend and Zitadel, adding the service account PAT
// to every request so the PAT never reaches the browser.
type AuthProxy struct {
	config        AuthProxyConfig
	client        *http.Client
	headers       map[string]string // parsed custom headers
	headerOnce    sync.Once
	settingsCache *settingsCache

	backchannelVerifier     *backchannelVerifier
	backchannelVerifierOnce sync.Once

	// LoginNameLimiter exposed (uppercase L) so test reset / observability
	// hooks (e.g. `/auth/testing/reset` in routes.go) can call ResetAll
	// without reaching into private state.
	LoginNameLimiter *middleware.LoginNameRateLimiter

	// decoySecret is the per-process HMAC key used to derive deterministic
	// fake user/org ids for F-sec-7 anti-enumeration responses (Round 21
	// Finding 1). The same loginName probed twice MUST produce the same
	// fake `factors.user.id` and `organizationId` — random ids per call
	// would diverge across two probes for the same unknown user, while
	// a real user always returns the same ids. Keyed on a randomly-
	// generated 32-byte secret at AuthProxy construction so the fake-
	// id space can't be precomputed by an attacker without server
	// access. Process restart rotates the keyspace — acceptable since
	// the decoy contract is per-session, not durable.
	//
	// HA caveat: each replica generates its own decoySecret, so the
	// same loginName probed via two replicas yields different fake
	// ids — distinguishable from a real user (whose ids are stable
	// across replicas). Round 22 OOS note. Deferred: needs a shared
	// cluster secret (env var or KMS-derived) for HA correctness.
	decoySecret []byte

	// decoyOrgIDs tracks every fake organization id the proxy has
	// issued via `deriveDecoySnowflake(secret, "org:"+loginName)` in
	// a CreateSession decoy response. Round 22 Finding 3:
	// `GetLoginSettings ?ctx.orgId=<decoyOrgId>` would otherwise
	// forward to Zitadel and either 404 or fall back to the
	// instance-default — both of which are wire-distinguishable from
	// a real org's custom policy response, recreating the F-sec-7
	// enumeration leak from a different angle. When this map
	// contains the requested orgId, the settings proxy strips
	// `ctx.orgId` and serves the unscoped (instance-default)
	// response instead.
	//
	// Round 25 hardening (item 24 / R25c H-3): formerly a `sync.Map`
	// pruned opportunistically on lookup. Entries that were never
	// touched again — the common case for an attacker probing once
	// then moving on — accumulated forever. Now stored as a bounded
	// LRU map (cap `defaultDecoyOrgIDsCap`) with a background sweeper
	// goroutine that prunes expired entries every `decoyOrgTTL/2`.
	decoyOrgIDsMu        sync.Mutex
	decoyOrgIDsEntries   map[string]*list.Element // orgId → list element holding *decoyOrgIDEntry
	decoyOrgIDsLRU       *list.List               // MRU at front
	decoyOrgIDsCap       int
	decoyOrgIDsStop      chan struct{}
	decoyOrgIDsSweepOnce sync.Once
}

// decoyOrgIDEntry is the value stored in the bounded LRU. Round 25
// hardening (item 24 / R25c H-3).
type decoyOrgIDEntry struct {
	orgID  string
	expiry time.Time
}

// defaultDecoyOrgIDsCap bounds the decoyOrgIDs map. Round 25 hardening
// (item 24 / R25c H-3): caps the worst case at attack-rate-independent
// memory. 100k entries × ~64 bytes/entry ≈ <10MB.
const defaultDecoyOrgIDsCap = 100_000

// decoyOrgTTL is how long an issued decoy orgID stays in the
// `decoyOrgIDs` map. Should comfortably exceed a normal login flow's
// duration (CreateSession → GetLoginSettings) but not so long that a
// sustained attack accumulates unbounded memory. 30 minutes balances
// honest-user grace period vs attack-rate × memory.
const decoyOrgTTL = 30 * time.Minute

// NewAuthProxy creates a new AuthProxy instance.
func NewAuthProxy(config AuthProxyConfig) *AuthProxy {
	// Resolve loginName-lockout defaults. Threshold 0 disables the
	// limiter entirely (helpful for dev / unit-test setups that want
	// deterministic behavior). Sane production defaults: 5 attempts
	// per 15 minutes — same shape as common bank / SaaS lockout
	// policies, well above the typing-mistake threshold but
	// uncomfortably tight for a brute-force attempt.
	lockoutThreshold := config.LoginNameLockoutThreshold
	if lockoutThreshold == 0 {
		lockoutThreshold = 5
	}
	lockoutWindow := config.LoginNameLockoutWindow
	if lockoutWindow == 0 {
		lockoutWindow = 15 * time.Minute
	}

	// Decoy-id HMAC key (Round 21 Finding 1).
	//
	// Round 25 Wave 6 (item 6 / Round 22 OOS): if the operator
	// provided one via STACKWEAVER_DECOY_SECRET, use it so HA
	// replicas produce identical decoy ids. Otherwise generate a
	// per-process random secret (correct for single-replica). 32
	// bytes is overkill for HMAC-SHA256 but matches the OWASP
	// recommendation; crypto/rand failure here is catastrophic
	// — we'd rather panic at startup than ship without a decoy
	// secret (decoy ids would otherwise collide trivially).
	var secret []byte
	if len(config.DecoySecret) > 0 {
		secret = config.DecoySecret
	} else {
		secret = make([]byte, 32)
		if _, err := cryptorand.Read(secret); err != nil {
			panic(fmt.Sprintf("auth proxy: cannot generate decoy secret: %v", err))
		}
	}

	p := &AuthProxy{
		config: config,
		client: &http.Client{
			Timeout: 30 * time.Second,
			// Don't follow redirects — we intercept 302s from Zitadel (DR-2).
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		settingsCache:      newSettingsCache(),
		LoginNameLimiter:   middleware.NewLoginNameRateLimiter(lockoutThreshold, lockoutWindow),
		decoySecret:        secret,
		decoyOrgIDsEntries: make(map[string]*list.Element),
		decoyOrgIDsLRU:     list.New(),
		decoyOrgIDsCap:     defaultDecoyOrgIDsCap,
	}
	p.startDecoyOrgIDsSweeper()
	return p
}

// storeDecoyOrgID inserts orgID with the given expiry, evicting the
// LRU entry on overflow. Idempotent: existing entries are refreshed
// (touched + new expiry).
func (p *AuthProxy) storeDecoyOrgID(orgID string, expiry time.Time) {
	if orgID == "" {
		return
	}
	p.decoyOrgIDsMu.Lock()
	defer p.decoyOrgIDsMu.Unlock()
	if el, ok := p.decoyOrgIDsEntries[orgID]; ok {
		el.Value.(*decoyOrgIDEntry).expiry = expiry
		p.decoyOrgIDsLRU.MoveToFront(el)
		return
	}
	entry := &decoyOrgIDEntry{orgID: orgID, expiry: expiry}
	el := p.decoyOrgIDsLRU.PushFront(entry)
	p.decoyOrgIDsEntries[orgID] = el
	if p.decoyOrgIDsLRU.Len() > p.decoyOrgIDsCap {
		victim := p.decoyOrgIDsLRU.Back()
		if victim != nil {
			p.decoyOrgIDsLRU.Remove(victim)
			delete(p.decoyOrgIDsEntries, victim.Value.(*decoyOrgIDEntry).orgID)
		}
	}
}

// loadDecoyOrgIDExpiry returns the expiry timestamp for orgID, or the
// zero time + false if not present. Touches the LRU on hit.
func (p *AuthProxy) loadDecoyOrgIDExpiry(orgID string) (time.Time, bool) {
	p.decoyOrgIDsMu.Lock()
	defer p.decoyOrgIDsMu.Unlock()
	el, ok := p.decoyOrgIDsEntries[orgID]
	if !ok {
		return time.Time{}, false
	}
	p.decoyOrgIDsLRU.MoveToFront(el)
	return el.Value.(*decoyOrgIDEntry).expiry, true
}

// deleteDecoyOrgID removes orgID from both the map and the LRU list.
func (p *AuthProxy) deleteDecoyOrgID(orgID string) {
	p.decoyOrgIDsMu.Lock()
	defer p.decoyOrgIDsMu.Unlock()
	if el, ok := p.decoyOrgIDsEntries[orgID]; ok {
		p.decoyOrgIDsLRU.Remove(el)
		delete(p.decoyOrgIDsEntries, orgID)
	}
}

// startDecoyOrgIDsSweeper launches the background goroutine that
// periodically prunes expired entries. Runs every decoyOrgTTL/2 so an
// expired entry never lives more than 1.5×decoyOrgTTL before reaping.
// Idempotent under sync.Once. Round 25 hardening (item 24 / R25c H-3).
func (p *AuthProxy) startDecoyOrgIDsSweeper() {
	p.decoyOrgIDsSweepOnce.Do(func() {
		p.decoyOrgIDsStop = make(chan struct{})
		interval := decoyOrgTTL / 2
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					p.sweepDecoyOrgIDs()
				case <-p.decoyOrgIDsStop:
					return
				}
			}
		}()
	})
}

// sweepDecoyOrgIDs walks the LRU list and removes expired entries. The
// map is bounded so this is O(N) but N ≤ defaultDecoyOrgIDsCap.
func (p *AuthProxy) sweepDecoyOrgIDs() {
	p.decoyOrgIDsMu.Lock()
	defer p.decoyOrgIDsMu.Unlock()
	now := time.Now()
	for el := p.decoyOrgIDsLRU.Back(); el != nil; {
		entry := el.Value.(*decoyOrgIDEntry)
		prev := el.Prev()
		if now.After(entry.expiry) {
			p.decoyOrgIDsLRU.Remove(el)
			delete(p.decoyOrgIDsEntries, entry.orgID)
		}
		el = prev
	}
}

// StopDecoyOrgIDsSweeper halts the background sweeper. Idempotent.
// Intended for graceful shutdown / test cleanup.
func (p *AuthProxy) StopDecoyOrgIDsSweeper() {
	if p.decoyOrgIDsStop != nil {
		select {
		case <-p.decoyOrgIDsStop:
		default:
			close(p.decoyOrgIDsStop)
		}
	}
}

// SettingsCacheMetrics returns a snapshot of the settings-cache counters so
// callers (e.g. a metrics endpoint or periodic log) can observe cache behaviour.
func (p *AuthProxy) SettingsCacheMetrics() SettingsCacheMetrics {
	return p.settingsCache.Metrics()
}

// getBackchannelVerifier returns the lazily-constructed backchannel-logout
// verifier for this proxy. Lazy construction keeps NewAuthProxy cheap and
// lets tests inject their own verifier by setting p.backchannelVerifier
// before calling the handler.
//
// Round 24 Finding 8: emit a WARN log on first use when `ClientID` is
// empty. Round 23 Finding 1 added the audience-binding check to
// `verifyLogoutToken` but kept an empty-string fallback (legacy
// compat for existing test fixtures that don't know an `aud`). That
// fallback silently disables the cross-RP forced-logout DoS guard —
// any Zitadel-signed `logout_token` from another RP on the same
// instance terminates sessions in this app. The warning makes the
// degraded mode operationally visible so a misconfigured deployment
// doesn't ship undetected.
func (p *AuthProxy) getBackchannelVerifier() *backchannelVerifier {
	p.backchannelVerifierOnce.Do(func() {
		if p.backchannelVerifier != nil {
			return
		}
		jwksURL := strings.TrimRight(p.config.ZitadelInternalURL, "/") + "/oauth/v2/keys"
		hostOverride := ""
		if u, err := url.Parse(p.config.ZitadelIssuer); err == nil && u.Host != "" {
			hostOverride = u.Host
		}
		if p.config.ClientID == "" {
			// Round 25 hardening (item 15): in production, an empty
			// ClientID is a fatal misconfiguration — the backchannel-
			// logout audience binding silently disables and any
			// Zitadel-signed logout_token from any other RP on the
			// same instance can terminate sessions in this app. Fail
			// loudly at first use rather than ship the degraded mode.
			// Dev keeps the WARN so test fixtures that don't know an
			// `aud` need not be rewritten.
			if p.config.IsProduction {
				logger.Errorf("auth proxy: ZITADEL_API_CLIENT_ID is empty in production — refusing to construct backchannel verifier. Set ZITADEL_API_CLIENT_ID to the OIDC client_id this RP is registered under at Zitadel.")
				panic("auth proxy: ZITADEL_API_CLIENT_ID required in production (Round 25 item 15 / Round 23 Finding 1)")
			}
			logger.Warn("auth proxy: ZITADEL_API_CLIENT_ID is empty — backchannel-logout audience binding is DISABLED. Any Zitadel-signed logout_token (including from other RPs on the same instance) will terminate sessions. Set ZITADEL_API_CLIENT_ID to enable cross-RP forced-logout DoS protection (Round 23 Finding 1).")
		}
		p.backchannelVerifier = newBackchannelVerifier(jwksURL, hostOverride, p.config.ClientID, p.client, p.config.ZitadelIssuer)
	})
	return p.backchannelVerifier
}

// IsBackchannelRevoked reports whether a session sid has been invalidated by
// a prior backchannel logout_token. Other handlers (e.g. session refresh) can
// call this to reject requests that reference a revoked sid.
func (p *AuthProxy) IsBackchannelRevoked(sid string) bool {
	return p.getBackchannelVerifier().IsSIDRevoked(sid)
}

// HealthAuthProxy exposes a small JSON probe of safety-critical auth-proxy
// configuration toggles so the E2E suite (and any external uptime probe)
// can verify them at runtime without scraping container logs. Round 27
// Wave 15: replaces the `docker logs | grep ZITADEL_API_CLIENT_ID` flow
// the Round 24 Finding 8 verification used to require.
//
// Response shape (stable contract — bump a field rather than change shape):
//
//	{
//	  "backchannel_binding_active": bool,  // true iff p.config.ClientID is non-empty (R24-8)
//	  "production_mode": bool              // mirrors p.config.IsProduction
//	}
//
// Intentionally NOT a health check in the liveness/readiness sense — it
// reports CONFIG state, not service availability. Returns 200 always so
// uptime probes don't get confused; the consumer reads the JSON to make
// a verdict.
func (p *AuthProxy) HealthAuthProxy(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"backchannel_binding_active": p.config.ClientID != "",
		"production_mode":            p.config.IsProduction,
	})
}

// --- Helper methods ---

// parsedHeaders returns the parsed custom request headers (lazy-init, thread-safe).
func (p *AuthProxy) parsedHeaders() map[string]string {
	p.headerOnce.Do(func() {
		p.headers = parseCustomHeaders(p.config.CustomRequestHeaders)
	})
	return p.headers
}

// parseCustomHeaders parses a comma-separated "key:value,key2:value2" string.
//
// Defense-in-depth: rejects pairs whose name or value contain CR/LF/NUL to
// prevent header-injection if the env var source is ever compromised. Go's
// net/http already validates on Set() in recent versions, but stopping bad
// input at the parse boundary keeps the logic obvious.
func parseCustomHeaders(raw string) map[string]string {
	result := make(map[string]string)
	if raw == "" {
		return result
	}
	for pair := range strings.SplitSeq(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if name == "" || strings.ContainsAny(name, "\r\n\x00") || strings.ContainsAny(value, "\r\n\x00") {
			logger.Warnf("parseCustomHeaders: rejecting header %q — contains control characters", name)
			continue
		}
		result[name] = value
	}
	return result
}

// zitadelURL builds a full URL to the internal Zitadel instance.
func (p *AuthProxy) zitadelURL(path string) string {
	return strings.TrimRight(p.config.ZitadelInternalURL, "/") + path
}

// proxyRequest makes an HTTP request to Zitadel with the service account PAT.
// It returns the response body and status code, or an error.
func (p *AuthProxy) proxyRequest(ctx context.Context, method, path string, body io.Reader, contentType string) ([]byte, int, http.Header, error) {
	reqURL := p.zitadelURL(path)
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to create request to %s: %w", path, err)
	}

	// Add PAT authorization
	req.Header.Set("Authorization", "Bearer "+p.config.PAT)

	// Set content type
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Add custom headers (multi-header support per D4)
	for k, v := range p.parsedHeaders() {
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to proxy request to %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("failed to read response from %s: %w", path, err)
	}

	return respBody, resp.StatusCode, resp.Header, nil
}

// proxyJSON makes a JSON request to Zitadel and returns the parsed response.
func (p *AuthProxy) proxyJSON(ctx context.Context, method, path string, requestBody any) (json.RawMessage, int, error) {
	var bodyReader io.Reader
	contentType := "application/json"

	if requestBody != nil {
		bodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	respBody, statusCode, _, err := p.proxyRequest(ctx, method, path, bodyReader, contentType)
	if err != nil {
		return nil, 0, err
	}

	return json.RawMessage(respBody), statusCode, nil
}

// proxyFormPost forwards a form-encoded POST to Zitadel (used for token exchange).
func (p *AuthProxy) proxyFormPost(ctx context.Context, path string, formData url.Values) ([]byte, int, http.Header, error) {
	return p.proxyRequest(ctx, http.MethodPost, path, strings.NewReader(formData.Encode()), "application/x-www-form-urlencoded")
}

// getPublicHost resolves the browser-visible host for building callback URLs (per D4).
// Priority: x-zitadel-public-host → x-zitadel-forward-host → x-forwarded-host → host header.
func getPublicHost(c *gin.Context) string {
	for _, header := range []string{
		"X-Zitadel-Public-Host",
		"X-Zitadel-Forward-Host",
		"X-Forwarded-Host",
	} {
		if v := c.GetHeader(header); v != "" {
			return v
		}
	}
	return c.Request.Host
}

// getPublicBaseURL returns the scheme+host for the current request.
//
// Scheme priority:
//  1. X-Forwarded-Proto header (set by reverse proxies / Cloudflare Tunnel).
//     The api typically runs behind TLS termination so Request.TLS is nil
//     even when the browser-visible URL is https — without honouring this
//     header first the discovery doc / IdP successUrl land on the wrong
//     scheme and the SPA redirect chain breaks.
//  2. Direct TLS on the request (TLS == nil → http, else https).
func getPublicBaseURL(c *gin.Context) string {
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		return proto + "://" + getPublicHost(c)
	}
	scheme := "https"
	if c.Request.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + getPublicHost(c)
}

// getFrontendBaseURL returns the SPA's public base URL for IdP redirect
// construction. Prefers the configured PublicFrontendURL (split-domain
// deployments where api and SPA differ); falls back to the api's own
// publicBaseURL when unset (same-origin deployments).
func (p *AuthProxy) getFrontendBaseURL(c *gin.Context) string {
	if u := strings.TrimRight(p.config.PublicFrontendURL, "/"); u != "" {
		return u
	}
	return getPublicBaseURL(c)
}

// respondError sends a JSON error response matching Zitadel's error shape.
func respondError(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{
		"code":    status,
		"message": message,
	})
}

// --- Session cookie management (D6) ---

// sessionCookieHMACDomain is the domain-separation tag prepended to the
// HMAC input so the session-cookie HMAC tag can never be confused with
// any other HMAC use of the same `decoySecret`. Round 25 Wave 6 (item 19
// / R25a #3).
const sessionCookieHMACDomain = "stackweaver-session-cookie-v1:"

// signSessionCookie computes the HMAC-SHA256 tag for `payload` using
// `decoySecret` (which is the shared HA-aware secret per item 6 when
// configured, or a per-process random one otherwise). The tag is
// returned as base64url-no-padding so it's a fixed 43 chars, separated
// from the payload by a `.` (which never appears in base64url). Round
// 25 Wave 6 (item 19 / R25a #3).
func (p *AuthProxy) signSessionCookie(payload []byte) string {
	mac := hmac.New(sha256.New, p.decoySecret)
	mac.Write([]byte(sessionCookieHMACDomain))
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifySessionCookie returns the JSON payload of `cookieVal` if the
// HMAC tag is valid. Returns (nil, false) if the format is malformed,
// the tag is missing, or the HMAC doesn't match. The caller must treat
// a `false` return identically to "no cookie present" — never as a 4xx
// — so a tampered cookie just makes the user re-authenticate. Round 25
// Wave 6 (item 19 / R25a #3).
func (p *AuthProxy) verifySessionCookie(cookieVal string) ([]byte, bool) {
	idx := strings.IndexByte(cookieVal, '.')
	if idx <= 0 || idx >= len(cookieVal)-1 {
		return nil, false
	}
	tag := cookieVal[:idx]
	payload := cookieVal[idx+1:]
	expected, err := base64.RawURLEncoding.DecodeString(tag)
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, p.decoySecret)
	mac.Write([]byte(sessionCookieHMACDomain))
	mac.Write([]byte(payload))
	if !hmac.Equal(expected, mac.Sum(nil)) {
		return nil, false
	}
	return []byte(payload), true
}

// readSessionCookie reads the session entries from the httpOnly cookie.
//
// Round 25 Wave 6 (item 19 / R25a #3): the cookie value is now signed
// with HMAC-SHA256(decoySecret, "stackweaver-session-cookie-v1:"+json).
// A bad MAC (tampered cookie, attacker-overwritten via shared-apex XSS,
// stale legacy unsigned cookie) is treated identically to "no cookie"
// so the user is silently re-authenticated rather than 4xx'd.
func (p *AuthProxy) readSessionCookie(c *gin.Context) []sessionEntry {
	cookieVal, err := c.Cookie(SessionCookieName)
	if err != nil || cookieVal == "" {
		return nil
	}

	payload, ok := p.verifySessionCookie(cookieVal)
	if !ok {
		// Either malformed, unsigned (legacy), or HMAC mismatch.
		// Treat as absent — caller will issue a fresh empty cookie
		// on next write.
		logger.Debugf("session cookie failed HMAC verification — treating as absent")
		return nil
	}

	var entries []sessionEntry
	if err := json.Unmarshal(payload, &entries); err != nil {
		logger.Warnf("Failed to parse sessions cookie: %v", err)
		return nil
	}
	return entries
}

// writeSessionCookie writes the session entries to an httpOnly cookie with FIFO eviction.
//
// Budget accounting MUST measure the URL-encoded size, not the raw JSON
// length: Gin's `c.SetCookie` runs `url.QueryEscape` on the value before
// emitting the Set-Cookie header (because cookie values can't contain
// `"`, `,`, `;`, or control chars verbatim). Raw JSON of ~2 KB expands
// to ~2.4 KB encoded — checking the raw size lets the encoded cookie
// blow past the 2 KB browser-budget guardrail. Round 16 (2026-04-28)
// caught this against F-sec-19; before the fix, a 30-session cookie was
// 2468 bytes on the wire despite the in-Go check claiming 2000.
//
// Round 25 Wave 6 (item 19 / R25a #3): the JSON payload is signed with
// HMAC-SHA256 and the on-the-wire format is `<43-char-base64url-tag>.<json>`.
// Signing adds a fixed 44 bytes (43-char tag + `.` separator) to the
// budget — accounted for in the budget loop below.
func (p *AuthProxy) writeSessionCookie(c *gin.Context, entries []sessionEntry) {
	for {
		data, err := json.Marshal(entries)
		if err != nil {
			logger.Warnf("Failed to marshal sessions cookie: %v", err)
			return
		}
		signed := p.signSessionCookie(data) + "." + string(data)
		if len(url.QueryEscape(signed)) <= SessionCookieMaxBytes || len(entries) <= 1 {
			break
		}
		// Remove the oldest entry (first element).
		entries = entries[1:]
	}

	data, err := json.Marshal(entries)
	if err != nil {
		logger.Warnf("Failed to marshal sessions cookie: %v", err)
		return
	}
	signed := p.signSessionCookie(data) + "." + string(data)

	maxAge := 0 // session-only (DR-7)
	secure := p.config.IsProduction
	sameSite := http.SameSiteLaxMode

	c.SetSameSite(sameSite)
	c.SetCookie(SessionCookieName, signed, maxAge, "/auth", "", secure, true)
}

// clearSessionEntry removes a specific session entry from the cookie by session ID.
func (p *AuthProxy) clearSessionEntry(c *gin.Context, sessionID string) {
	entries := p.readSessionCookie(c)
	filtered := make([]sessionEntry, 0, len(entries))
	for _, e := range entries {
		if e.ID != sessionID {
			filtered = append(filtered, e)
		}
	}
	p.writeSessionCookie(c, filtered)
}

// upsertSessionEntry adds or updates a session entry in the cookie.
func (p *AuthProxy) upsertSessionEntry(c *gin.Context, entry sessionEntry) {
	entries := p.readSessionCookie(c)
	found := false
	for i, e := range entries {
		if e.ID == entry.ID {
			entries[i] = entry
			found = true
			break
		}
	}
	if !found {
		entries = append(entries, entry)
	}
	p.writeSessionCookie(c, entries)
}

// findSessionEntry finds a session entry by session ID.
func (p *AuthProxy) findSessionEntry(c *gin.Context, sessionID string) *sessionEntry {
	for _, e := range p.readSessionCookie(c) {
		if e.ID == sessionID {
			return &e
		}
	}
	return nil
}

// requireOwningSession is middleware that validates the caller owns the session referenced in the URL.
// Used on user-scoped endpoints per DR-4.
func (p *AuthProxy) requireOwningSession(c *gin.Context, sessionID string) bool {
	entry := p.findSessionEntry(c, sessionID)
	if entry == nil {
		respondError(c, http.StatusForbidden, "no valid session for this resource")
		return false
	}
	return true
}

// --- OIDC Proxy Endpoints (A2) ---

// Authorize handles GET /auth/oidc/authorize.
// Intercepts Zitadel's 302 redirect, extracts the authRequest ID, and returns JSON (DR-2 Option A).
func (p *AuthProxy) Authorize(c *gin.Context) {
	// Build the query string to forward to Zitadel
	params := c.Request.URL.Query()

	// Dispatch on auth-request ID prefix (A2.1)
	// At this point we don't have the auth-request ID yet — prefix dispatch happens
	// after Zitadel returns the redirect. We validate in the response parsing below.

	// Forward the authorize request to Zitadel
	zitadelPath := "/oauth/v2/authorize?" + params.Encode()
	_, statusCode, respHeaders, err := p.proxyRequest(c.Request.Context(), http.MethodGet, zitadelPath, nil, "")
	if err != nil {
		logger.Errorf("Failed to proxy authorize request: %v", err)
		respondError(c, http.StatusBadGateway, "failed to reach identity provider")
		return
	}

	// DR-2: Intercept the 302 redirect from Zitadel
	if statusCode == http.StatusFound || statusCode == http.StatusSeeOther {
		location := respHeaders.Get("Location")
		if location == "" {
			respondError(c, http.StatusBadGateway, "identity provider returned redirect without Location header")
			return
		}

		parsedLocation, err := url.Parse(location)
		if err != nil {
			respondError(c, http.StatusBadGateway, "identity provider returned invalid redirect URL")
			return
		}

		authRequestID := parsedLocation.Query().Get("authRequest")
		if authRequestID == "" {
			// Might be an error redirect or an unsupported flow
			respondError(c, http.StatusBadRequest, "no auth request ID in redirect")
			return
		}

		// A2.1: Prefix dispatch — reject SAML and Device flows
		if strings.HasPrefix(authRequestID, "saml_") {
			respondError(c, http.StatusBadRequest, "SAML authentication is not supported by this login UI")
			return
		}
		if strings.HasPrefix(authRequestID, "device_") {
			respondError(c, http.StatusBadRequest, "Device Authorization Grant is not supported by this login UI")
			return
		}

		// Extract OIDC parameters from the original request to return to the SPA
		response := gin.H{
			"authRequest": authRequestID,
		}

		// Pass through relevant parameters the SPA needs
		if loginHint := params.Get("login_hint"); loginHint != "" {
			response["loginHint"] = loginHint
		}
		if prompt := params.Get("prompt"); prompt != "" {
			response["prompt"] = prompt
		}
		if scope := params.Get("scope"); scope != "" {
			response["scope"] = scope
		}

		// Parse org scope from scope parameter or organization query param
		if org := params.Get("organization"); org != "" {
			response["organization"] = org
		} else if scope := params.Get("scope"); scope != "" {
			// Check for urn:zitadel:iam:org:id: or urn:zitadel:iam:org:domain:primary: scopes
			for s := range strings.FieldsSeq(scope) {
				if orgID, found := strings.CutPrefix(s, "urn:zitadel:iam:org:id:"); found {
					response["organizationId"] = orgID
				} else if domain, found := strings.CutPrefix(s, "urn:zitadel:iam:org:domain:primary:"); found {
					response["organizationDomain"] = domain
				}
			}
		}

		c.JSON(http.StatusOK, response)
		return
	}

	// If Zitadel returned something other than a redirect, return a sanitized error.
	// Don't pass through raw Zitadel responses — they may contain internal hostnames or HTML.
	respondError(c, statusCode, "authorization request failed")
}

// TokenExchange handles POST /auth/oidc/token.
// Proxies the token exchange request to Zitadel, passing form data through unchanged.
// The redirect_uri must match what was used in the authorize request (PKCE requirement).
func (p *AuthProxy) TokenExchange(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		respondError(c, http.StatusBadRequest, "invalid form data")
		return
	}

	respBody, statusCode, respHeaders, err := p.proxyFormPost(c.Request.Context(), "/oauth/v2/token", c.Request.PostForm)
	if err != nil {
		logger.Errorf("Failed to proxy token exchange: %v", err)
		respondError(c, http.StatusBadGateway, "failed to exchange token with identity provider")
		return
	}

	// Pass through content type from Zitadel
	contentType := respHeaders.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}
	c.Data(statusCode, contentType, respBody)
}

// JWKSProxy handles GET /auth/oidc/keys.
// Proxies the JWKS endpoint from Zitadel.
func (p *AuthProxy) JWKSProxy(c *gin.Context) {
	respBody, statusCode, _, err := p.proxyRequest(c.Request.Context(), http.MethodGet, "/oauth/v2/keys", nil, "")
	if err != nil {
		logger.Errorf("Failed to proxy JWKS: %v", err)
		respondError(c, http.StatusBadGateway, "failed to fetch keys from identity provider")
		return
	}
	c.Data(statusCode, "application/json", respBody)
}

// UserinfoProxy handles GET /auth/oidc/userinfo.
// Proxies the userinfo endpoint — note this one passes the Bearer token from the client,
// not the PAT, since it returns info about the authenticated user.
func (p *AuthProxy) UserinfoProxy(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	reqURL := p.zitadelURL("/oidc/v1/userinfo")
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, reqURL, nil)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "failed to create userinfo request")
		return
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	for k, v := range p.parsedHeaders() {
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		logger.Errorf("Failed to proxy userinfo: %v", err)
		respondError(c, http.StatusBadGateway, "failed to fetch userinfo from identity provider")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("Failed to read userinfo response: %v", err)
		respondError(c, http.StatusBadGateway, "failed to read userinfo from identity provider")
		return
	}
	c.Data(resp.StatusCode, "application/json", body)
}

// EndSession handles both GET and POST /auth/oidc/end-session.
// GET: OIDC RP-Initiated Logout (browser redirect with query params — per OIDC spec).
// POST: either form-encoded RP-initiated logout, OR OIDC Back-Channel Logout 1.0
// when the body contains a `logout_token` (A6.1, AC-38). Back-channel logouts
// are verified locally against Zitadel's JWKS and do NOT get forwarded upstream;
// the OP is telling the RP to invalidate its own session state.
func (p *AuthProxy) EndSession(c *gin.Context) {
	var formData url.Values

	if c.Request.Method == http.MethodGet {
		// OIDC spec uses GET with query params for RP-initiated logout
		formData = c.Request.URL.Query()
	} else {
		if err := c.Request.ParseForm(); err != nil {
			respondError(c, http.StatusBadRequest, "invalid form data")
			return
		}
		formData = c.Request.PostForm

		// Backchannel logout path: presence of logout_token signals the OP is
		// notifying the RP that a session was terminated server-side. Verify
		// the JWT locally; do not forward to Zitadel.
		if token := formData.Get("logout_token"); token != "" {
			p.handleBackchannelLogout(c, token)
			return
		}
	}

	// End session uses id_token_hint for session identification — do NOT add the PAT
	// (PAT identifies the service account, not the end user's session).
	reqURL := p.zitadelURL("/oidc/v1/end_session")
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, reqURL, strings.NewReader(formData.Encode()))
	if err != nil {
		respondError(c, http.StatusInternalServerError, "failed to create end session request")
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range p.parsedHeaders() {
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		logger.Errorf("Failed to proxy end session: %v", err)
		respondError(c, http.StatusBadGateway, "failed to end session with identity provider")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	statusCode := resp.StatusCode
	respHeaders := resp.Header

	// If Zitadel returns a redirect (302), follow it (redirect the browser).
	// Round 25 Wave 5 (item 5 / Round 23 Finding 5): defense-in-depth
	// host allowlist. The primary control is Zitadel's
	// `post_logout_redirect_uri` allowlist, but a misconfigured
	// allowlist (wildcard / accidentally permissive) would let an
	// attacker craft a logout URL that bounces the browser to an
	// arbitrary host with our origin as the redirect issuer. We
	// validate the host before forwarding.
	if statusCode == http.StatusFound || statusCode == http.StatusSeeOther {
		location := respHeaders.Get("Location")
		if location != "" {
			if p.allowPostLogoutRedirect(location) {
				c.Redirect(statusCode, location)
				return
			}
			// Refuse the redirect — return a benign success body so
			// the SPA can render its own logout-done page.
			logger.Warnf("EndSession: refusing post-logout redirect to disallowed host (%q)", location)
			c.JSON(http.StatusOK, gin.H{"loggedOut": true})
			return
		}
	}

	c.Data(statusCode, "application/json", respBody)
}

// allowPostLogoutRedirect reports whether the given absolute or
// relative URL is on the post-logout host allowlist. Relative paths
// are always allowed (same-origin). Absolute URLs must match either
// PublicFrontendURL's host or a host listed in PostLogoutAllowedHosts.
// Round 25 Wave 5 (item 5 / Round 23 Finding 5).
func (p *AuthProxy) allowPostLogoutRedirect(location string) bool {
	if location == "" {
		return false
	}
	// Round 27 (HIGH-4 / Round 26 HIGH-4 re-confirmed): reject any
	// Location containing backslash, leading `//`, or other shape that
	// browsers normalise to a scheme-relative cross-origin redirect.
	// `url.Parse("/\\evil.com/x")` returns Scheme="" Host="" so the
	// relative-path branch below would accept it; browsers (Chrome,
	// Firefox) then collapse `\` → `/` in the Location header and
	// navigate to `//evil.com/...` which is scheme-relative cross-origin.
	// Same hazard for `///foo` (three or more leading slashes):
	// browsers may treat the first two slashes as protocol-relative.
	if strings.ContainsRune(location, '\\') {
		return false
	}
	if strings.HasPrefix(location, "//") {
		return false
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return false
	}
	// Relative path (no scheme + no host) is always same-origin.
	if parsed.Scheme == "" && parsed.Host == "" {
		return true
	}
	target := strings.ToLower(parsed.Host)
	if target == "" {
		return false
	}
	// Allowed: PublicFrontendURL's host.
	if pf := strings.TrimRight(p.config.PublicFrontendURL, "/"); pf != "" {
		if pfu, err := url.Parse(pf); err == nil && pfu.Host != "" {
			if strings.ToLower(pfu.Host) == target {
				return true
			}
		}
	}
	// Allowed: anything in the configured extra-hosts list.
	for _, h := range p.config.PostLogoutAllowedHosts {
		if strings.ToLower(strings.TrimSpace(h)) == target {
			return true
		}
	}
	return false
}

// OIDCDiscovery handles GET /.well-known/openid-configuration for the auth proxy.
// Rewrites Zitadel's discovery document to point to the proxy endpoints.
func (p *AuthProxy) OIDCDiscovery(c *gin.Context) {
	respBody, statusCode, _, err := p.proxyRequest(c.Request.Context(), http.MethodGet, "/.well-known/openid-configuration", nil, "")
	if err != nil {
		logger.Errorf("Failed to proxy OIDC discovery: %v", err)
		respondError(c, http.StatusBadGateway, "failed to fetch OIDC configuration from identity provider")
		return
	}

	if statusCode != http.StatusOK {
		c.Data(statusCode, "application/json", respBody)
		return
	}

	// Rewrite the issuer and endpoint URLs to point to the proxy
	var discovery map[string]any
	if err := json.Unmarshal(respBody, &discovery); err != nil {
		c.Data(statusCode, "application/json", respBody)
		return
	}

	publicBase := getPublicBaseURL(c)
	discovery["issuer"] = publicBase
	discovery["authorization_endpoint"] = publicBase + "/auth/oidc/authorize"
	discovery["token_endpoint"] = publicBase + "/auth/oidc/token"
	discovery["jwks_uri"] = publicBase + "/auth/oidc/keys"
	discovery["userinfo_endpoint"] = publicBase + "/auth/oidc/userinfo"
	discovery["end_session_endpoint"] = publicBase + "/auth/oidc/end-session"

	c.JSON(http.StatusOK, discovery)
}

// --- Auth Request Endpoints (A3) ---

// GetAuthRequest handles GET /auth/oidc/auth-requests/:id.
// Returns the auth request details from Zitadel.
func (p *AuthProxy) GetAuthRequest(c *gin.Context) {
	authRequestID := c.Param("id")
	if authRequestID == "" {
		respondError(c, http.StatusBadRequest, "auth request ID is required")
		return
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodGet, "/v2/oidc/auth_requests/"+authRequestID, nil)
	if err != nil {
		logger.Errorf("Failed to get auth request: %v", err)
		respondError(c, http.StatusBadGateway, "failed to get auth request from identity provider")
		return
	}
	c.Data(statusCode, "application/json", respBody)
}

// FinalizeAuthRequest handles POST /auth/oidc/finalize.
// Links a session to an auth request and returns the callback URL.
func (p *AuthProxy) FinalizeAuthRequest(c *gin.Context) {
	var req struct {
		AuthRequestID string `json:"authRequestId"`
		SessionID     string `json:"sessionId"`
		SessionToken  string `json:"sessionToken"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	// If session token not provided in body, try to get it from the cookie
	cookieEntry := p.findSessionEntry(c, req.SessionID)
	if req.SessionToken == "" && cookieEntry != nil {
		req.SessionToken = cookieEntry.Token
	}

	if req.SessionToken == "" {
		respondError(c, http.StatusBadRequest, "session token is required")
		return
	}

	// F-sec-7 (Audit Round 20): a decoy session must not progress
	// through finalize. Forwarding to Zitadel would 404 (the decoy id
	// has no real session), and that 404 is distinguishable from a
	// real session-without-password's 412 PreconditionFailed — an
	// attacker who skipped UpdateSession and called finalize directly
	// could enumerate users by status divergence. Mirror Zitadel's
	// "session not authenticated" precondition shape.
	if cookieEntry != nil && cookieEntry.Decoy {
		c.Data(http.StatusPreconditionFailed, "application/json", buildDecoyFinalizePreconditionResponse())
		return
	}

	zitadelReq := map[string]any{
		"session": map[string]any{
			"sessionId":    req.SessionID,
			"sessionToken": req.SessionToken,
		},
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPost, "/v2/oidc/auth_requests/"+req.AuthRequestID, zitadelReq)
	if err != nil {
		logger.Errorf("Failed to finalize auth request: %v", err)
		respondError(c, http.StatusBadGateway, "failed to finalize auth request with identity provider")
		return
	}
	c.Data(statusCode, "application/json", respBody)
}

// --- Session API Proxy (A4) ---

// CreateSession handles POST /auth/sessions.
// Creates a new Zitadel session (user check, challenges).
func (p *AuthProxy) CreateSession(c *gin.Context) {
	var reqBody map[string]any
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	// Notification mode handling (P1/DR-6 + Wave 14):
	//
	//   - return_code mode: force `returnCode: {}` on OTP challenges so
	//     Zitadel echoes the code in the response (homelab/dev default;
	//     no SMTP required).
	//   - email mode: strip any `returnCode` the SPA sent so Zitadel
	//     delivers via the configured SMTP backend instead of echoing.
	//     Wave 14 caught this: the SPA's Otp.tsx unconditionally sends
	//     `returnCode: {}` because it doesn't know which mode the proxy
	//     is in — without the proxy stripping it, every email-mode
	//     challenge stays as "return-the-code" and no email is ever sent.
	switch p.config.NotificationMode {
	case NotificationModeReturnCode:
		p.injectReturnCodeFlags(reqBody)
	case NotificationModeEmail:
		p.stripReturnCodeFlags(reqBody)
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPost, "/v2/sessions", reqBody)
	if err != nil {
		logger.Errorf("Failed to create session: %v", err)
		respondError(c, http.StatusBadGateway, "failed to create session with identity provider")
		return
	}

	// Round 25 Wave 8 (item 3 / F-sec-8): timing parity. The unknown-
	// user branch (404 → shouldFakeUnknownUser) makes a SECOND
	// upstream call to `/v2/settings/login` to read
	// `ignoreUnknownUsernames`. The known-user (200) branch makes
	// only ONE call. Without balancing, paired-request medians
	// diverge at the network-RTT scale — observable as a username-
	// enumeration timing oracle. Issue the same `/v2/settings/login`
	// call sequentially on the known-user path so both branches
	// take ≈ 2 RTT. The result is discarded; the only purpose is
	// to balance work. Only fires on the success path because the
	// failure paths (transport error, 5xx) already short-circuit
	// before any decoy logic.
	if statusCode == http.StatusOK || statusCode == http.StatusCreated {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		_, _, _ = p.proxyJSON(ctx, http.MethodGet, "/v2/settings/login", nil)
		cancel()
	}

	// F-sec-7: anti-enumeration. When the org's login policy has
	// `ignoreUnknownUsernames: true` AND the request is a loginName
	// check (not a userId / sessionId reference), Zitadel's 404 leaks
	// "this user does not exist" to anyone hitting the API directly.
	// The hosted Zitadel login UI hides this by routing everyone to
	// the password page; we replicate that defense at the api layer
	// by faking a successful session response with a `decoy-` prefixed
	// id. UpdateSession-with-password later detects the prefix and
	// fakes the canonical "Password is invalid" rejection without
	// forwarding (so an attacker can't distinguish the decoy by
	// observing the password response either).
	if statusCode == http.StatusNotFound && p.shouldFakeUnknownUser(c, reqBody) {
		// Capture the probed loginName so subsequent decoy responses
		// (GetSession, lockout key) can mirror real-user behaviour
		// deterministically — Round 21 Finding 1 / Finding 2.
		probedLoginName, _ := extractLoginNameFromCheck(reqBody)

		// Round 25 Wave 5 (item 25 / R25b F3): collision check between
		// the freshly-generated decoy id and any existing session id
		// in the cookie. The collision space is ~10^18 so this is
		// astronomically rare in practice (1 in 10^18 per generation),
		// but a bare upsertSessionEntry would silently mark an existing
		// real session as a decoy on collision and drop it from the
		// account picker. Retry up to 5 times; if every attempt
		// collides (probabilistically impossible) bail to upstream.
		existingIDs := make(map[string]bool)
		for _, e := range p.readSessionCookie(c) {
			existingIDs[e.ID] = true
		}
		var fakeBody []byte
		var decoyID string
		for range 5 {
			fakeBody, decoyID = buildDecoySessionResponse()
			if !existingIDs[decoyID] {
				break
			}
			fakeBody, decoyID = nil, ""
		}
		if decoyID == "" {
			logger.Warnf("auth proxy: 5 decoy-id collision retries exhausted (probabilistically impossible — investigate the cookie state) — falling through to upstream 404")
			c.Data(statusCode, "application/json", respBody)
			return
		}

		// Round 25 hardening (item 29 / R25b F8): build-then-publish.
		// `buildDecoySessionResponse` returns an empty body on marshal
		// failure — if we publish that we leak the decoy state via
		// the empty-body wire shape AND register a decoyOrg + cookie
		// for a session the client never received. Bail out to the
		// natural 404 path instead — the client sees Zitadel's real
		// 404 (a known F-sec-7 leak this anti-enumeration code path
		// is meant to mask, but a fail-closed degradation is better
		// than half-state).
		if len(fakeBody) == 0 {
			logger.Warnf("auth proxy: buildDecoySessionResponse returned empty body — falling through to upstream 404 (loginName=%q)", probedLoginName)
			c.Data(statusCode, "application/json", respBody)
			return
		}
		// Stage all derived state locally before publishing any of
		// it. `decoyOrgID` is HMAC-derived and infallible; the cookie
		// payload only depends on values we already have.
		var resp struct {
			SessionToken string `json:"sessionToken"`
		}
		_ = json.Unmarshal(fakeBody, &resp)
		entry := sessionEntry{
			ID:        decoyID,
			Token:     resp.SessionToken,
			LoginName: probedLoginName,
			Decoy:     true,
		}
		var decoyOrgID string
		if probedLoginName != "" {
			decoyOrgID = deriveDecoySnowflake(p.decoySecret, "org:"+probedLoginName)
		}

		// Publish: cookie + decoyOrg registry + response body.
		// Store the decoy in the cookie so the SPA's follow-up
		// UpdateSession passes `requireOwningSession` (otherwise it
		// would 403, which is a different shape from a real session
		// hitting password-invalid). The Decoy flag stays inside the
		// httpOnly cookie — UpdateSession uses it to short-circuit
		// without forwarding upstream. UserID is intentionally empty,
		// so userScopedProxy refuses to forward calls bound to a
		// decoy (Round 21 ruled the userScoped surface out — the
		// 403-vs-Zitadel divergence is scoped to a follow-up).
		p.upsertSessionEntry(c, entry)
		// Round 22 Finding 3: register the decoy orgId so a follow-
		// up `GetLoginSettings ?ctx.orgId=<this>` doesn't leak via
		// Zitadel-404-vs-real-org-policy divergence.
		if decoyOrgID != "" {
			p.storeDecoyOrgID(decoyOrgID, time.Now().Add(decoyOrgTTL))
		}
		c.Data(http.StatusCreated, "application/json", fakeBody)
		return
	}

	// If session was created successfully, store it in the cookie
	if statusCode == http.StatusOK || statusCode == http.StatusCreated {
		p.storeSessionFromResponse(c, respBody)
	}

	c.Data(statusCode, "application/json", respBody)
}

// shouldFakeUnknownUser decides whether a 404 from Zitadel's
// createSession should be masked by a decoy session. Two conditions
// must both hold: (a) the request was a `checks.user.loginName` check
// (faking userId/sessionId checks would just delay a downstream error
// without hiding anything), and (b) the org's login policy has
// `ignoreUnknownUsernames: true`. Reads the policy via the cached
// settings proxy so per-request cost is amortized.
func (p *AuthProxy) shouldFakeUnknownUser(c *gin.Context, reqBody map[string]any) bool {
	// (a) only fake when the check was a loginName lookup. A userId
	// or sessionId-based createSession failing 404 is a different
	// shape of error that doesn't reveal user existence anyway.
	checks, ok := reqBody["checks"].(map[string]any)
	if !ok {
		return false
	}
	user, ok := checks["user"].(map[string]any)
	if !ok {
		return false
	}
	loginName, ok := user["loginName"].(string)
	if !ok || loginName == "" {
		return false
	}

	// (b) read the login policy. Unscoped — we don't know the org
	// because the user doesn't exist; the instance-default policy is
	// what applies in that case.
	//
	// Cache deliberately bypassed: this is a security-critical
	// decision and the only way the policy goes stale is operator
	// action, which is rare. A stale `false` cache hit while the
	// operator has switched the policy to `true` would leak existence
	// for up to 15 minutes — exactly the leak we're closing. The cost
	// is one extra Zitadel call per unknown-user 404, gated by the
	// per-IP rate limiter (so attacker-volume is bounded).
	body, status, err := p.proxyJSON(c.Request.Context(), http.MethodGet, "/v2/settings/login", nil)
	if err != nil || status != http.StatusOK {
		return false
	}
	// settings response is wrapped in `{"settings": {...}}` —
	// unwrap before checking. Same shape as settingsProxy.
	var wrapper struct {
		Settings json.RawMessage `json:"settings"`
	}
	var raw []byte
	if err := json.Unmarshal(body, &wrapper); err == nil && len(wrapper.Settings) > 0 {
		raw = wrapper.Settings
	}
	if len(raw) == 0 {
		return false
	}
	var policy struct {
		IgnoreUnknownUsernames bool `json:"ignoreUnknownUsernames"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return false
	}
	return policy.IgnoreUnknownUsernames
}

// buildDecoySessionResponse synthesizes a Zitadel-shaped createSession
// success response with a decoy id and token. Shape MUST match the
// real response (same JSON keys, same status code path) AND the id
// must look like a real Zitadel session id (numeric snowflake) so a
// client can't tell from the response that it got a fake. The decoy
// is tracked via the `Decoy` flag on the cookie's sessionEntry — that
// flag is internal to the proxy (httpOnly cookie scoped to /auth) and
// never leaves the wire. UpdateSession reads the flag to short-circuit
// the decoy with a canonical password-invalid response.
//
// Returns the body and the freshly-minted sessionId so the caller can
// stash it in the cookie with Decoy=true.
func buildDecoySessionResponse() ([]byte, string) {
	id := randomDecoySessionID() // pure-numeric, mirrors Zitadel's snowflake id format
	token := randomDecoyToken(70)
	type decoyDetails struct {
		Sequence      string `json:"sequence"`
		ChangeDate    string `json:"changeDate"`
		ResourceOwner string `json:"resourceOwner"`
	}
	type decoyBody struct {
		Details      decoyDetails `json:"details"`
		SessionID    string       `json:"sessionId"`
		SessionToken string       `json:"sessionToken"`
	}
	body := decoyBody{
		Details: decoyDetails{
			Sequence:      "1",
			ChangeDate:    time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
			ResourceOwner: "0",
		},
		SessionID:    id,
		SessionToken: token,
	}
	// gosec G117: SessionToken is a fake (random bytes), not a real
	// credential — the whole point of the decoy is that there is no
	// secret to leak.
	out, err := json.Marshal(body) //nolint:gosec
	if err != nil {
		// Marshaling a fully-typed struct should never fail; if it
		// does, returning an empty body keeps callers from leaking a
		// half-formed response.
		return []byte{}, id
	}
	return out, id
}

// randomDecoySessionID returns an 18-digit numeric string that mirrors
// the shape of a real Zitadel snowflake-style session id. Using only
// digits removes any visible "decoy-" tell from the response wire.
func randomDecoySessionID() string {
	const digits = 18
	buf := make([]byte, digits)
	if _, err := cryptorand.Read(buf); err != nil {
		return ""
	}
	out := make([]byte, digits)
	for i, b := range buf {
		out[i] = '0' + (b % 10)
	}
	// Avoid a leading zero — Zitadel session ids never start with 0.
	if out[0] == '0' {
		out[0] = '1'
	}
	return string(out)
}

// buildDecoyGetSessionResponse mimics Zitadel's GET /v2/sessions/{id}
// response for a session that has only a loginName check (no password
// factor yet). Captured shape from a live Zitadel v4.13 instance:
//
//	{"session":{"id","creationDate","changeDate","sequence",
//	  "factors":{"user":{"verifiedAt","id","loginName","organizationId"}}}}
//
// Round 21 Finding 1 caught the previous version emitting an empty
// `factors: {}` — wire-distinguishable from the real shape, which
// fully populates `factors.user.{verifiedAt, id, loginName,
// organizationId}`. The fake user/org ids are derived deterministically
// from the cookie's captured loginName via HMAC(decoySecret) so two
// probes of the same unknown loginName produce the same ids — mirroring
// what real users do (their Zitadel ids are stable). The HMAC secret
// is per-process (rotated on restart) so an attacker can't precompute
// the fake-id space.
func buildDecoyGetSessionResponse(entry *sessionEntry, decoySecret []byte) []byte {
	type userFactor struct {
		VerifiedAt     string `json:"verifiedAt"`
		ID             string `json:"id"`
		LoginName      string `json:"loginName"`
		OrganizationID string `json:"organizationId"`
	}
	type factors struct {
		User userFactor `json:"user"`
	}
	type decoySession struct {
		ID           string  `json:"id"`
		CreationDate string  `json:"creationDate"`
		ChangeDate   string  `json:"changeDate"`
		Sequence     string  `json:"sequence"`
		Factors      factors `json:"factors"`
	}
	type wrapper struct {
		Session decoySession `json:"session"`
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	loginName := entry.LoginName
	body := wrapper{
		Session: decoySession{
			ID:           entry.ID,
			CreationDate: now,
			ChangeDate:   now,
			// Round 25 hardening (item 27 / R25b F6): HMAC-derived in
			// [1, 50] to defeat "always 1" statistical fingerprinting.
			// Determinism preserved per loginName.
			Sequence: deriveDecoySequence(decoySecret, loginName),
			Factors: factors{
				User: userFactor{
					VerifiedAt:     now,
					ID:             deriveDecoySnowflake(decoySecret, "user:"+loginName),
					LoginName:      loginName,
					OrganizationID: deriveDecoySnowflake(decoySecret, "org:"+loginName),
				},
			},
		},
	}
	out, err := json.Marshal(body)
	if err != nil {
		return []byte{}
	}
	return out
}

// deriveDecoySnowflake maps an arbitrary input string to a stable
// 18-digit numeric id that mirrors the shape of a Zitadel snowflake.
// Used by the F-sec-7 decoy machinery (Round 21 Finding 1) to ensure
// two probes of the same unknown loginName produce the same fake
// user/org id — without this stability, a real-vs-decoy comparison on
// repeated probes would diverge instantly. HMAC-SHA256 is overkill for
// the security needs (we just want unforgeable + deterministic) but
// matches the OWASP recipe.
//
// Round 22 Finding 5 (DEFERRED, documented at design-time): real
// Zitadel snowflakes encode a creation timestamp in the high bits
// (custom epoch). Hash-derived ids are uniformly distributed in
// [10^17, 10^18), so an attacker who has seen a legitimate snowflake
// from this Zitadel instance can fingerprint the "real" range and
// flag ids outside it as decoys. Mitigation would be to derive a
// Zitadel-shaped snowflake (timestamp = quantized now, machine-id =
// stable hash, sequence = remaining HMAC bytes). Deferred — the
// statistical detection requires many probes against the same
// instance, and the IPRateLimiter caps probe volume. Tradeoff vs
// the engineering cost of mirroring Zitadel's snowflake encoding.
func deriveDecoySnowflake(secret []byte, key string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(key))
	digest := mac.Sum(nil)
	// Take the first 8 bytes as a uint64; mod into the 18-digit
	// snowflake range (10^17 to 10^18-1) so leading-zero suppression
	// isn't needed and the shape is byte-indistinguishable from a
	// real snowflake.
	const lo uint64 = 100000000000000000  // 10^17
	const hi uint64 = 1000000000000000000 // 10^18
	n := binary.BigEndian.Uint64(digest[:8])
	n = lo + (n % (hi - lo))
	return fmt.Sprintf("%d", n)
}

// deriveDecoySequence maps an HMAC-derived value into [1, 50] for use
// as the `details.sequence` field on decoy session responses. Round 25
// hardening (item 27 / R25b F6): the previous implementation hardcoded
// `Sequence: "1"` on every decoy GET response, so an attacker who
// statistically samples real-vs-decoy session sequences can flag
// "always 1" as a decoy fingerprint. A real Zitadel session's
// `sequence` is a positive integer that increments per session-state
// write — fresh sessions carry low numbers (1-5 typical), older /
// MFA-touched sessions trend higher. [1, 50] is a realistic range for
// the loginName-only sessions the GetSession decoy mirrors.
//
// Determinism contract is preserved: same key → same sequence, so two
// probes of the same loginName never see divergent decoy responses.
func deriveDecoySequence(secret []byte, key string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("sequence:" + key))
	digest := mac.Sum(nil)
	// Use the next 8 bytes (offset 8) so this doesn't share entropy
	// with `deriveDecoySnowflake` — even though they take different
	// `key` prefixes already, separating the byte ranges keeps the
	// per-field derivations independent.
	n := binary.BigEndian.Uint64(digest[8:16])
	return fmt.Sprintf("%d", 1+(n%50))
}

// isIssuedDecoyOrgID reports whether `orgID` is a fake org id this
// proxy issued via a CreateSession decoy response within the TTL.
// Round 22 Finding 3: used by `settingsProxy` to strip `ctx.orgId`
// when the caller is probing a decoy org, so the upstream response
// is the unscoped instance-default rather than the wire-distinguishable
// "404" or "real-org policy" that would leak via shape divergence.
//
// Round 25 Wave 3 (item 24 / R25c H-3): expired entries are still
// pruned inline on lookup AS WELL AS by the background sweeper. The
// LRU cap and sweeper bound memory; inline pruning gives prompt
// cleanup on the hot path. Belt-and-braces.
func (p *AuthProxy) isIssuedDecoyOrgID(orgID string) bool {
	expiry, ok := p.loadDecoyOrgIDExpiry(orgID)
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		// Expired — prune inline.
		p.deleteDecoyOrgID(orgID)
		return false
	}
	return true
}

// extractLoginNameFromCheck pulls `checks.user.loginName` out of a
// `POST /auth/sessions` request body. Round 21 Finding 1: the decoy
// path needs the loginName to derive deterministic fake ids and to
// key the per-decoy lockout. Returns "" + false if the body shape
// doesn't carry a loginName check (e.g. userId-based check).
//
// Round 27 (CRITICAL, Round 27b): the returned value is lowercased
// to canonicalise. Wave 9 fixed the lockout-key derivation site
// only; the decoy SNOWFLAKE derivations (`deriveDecoySnowflake(secret,
// "user:"+loginName)` etc.) ALSO use this loginName — case-sensitive
// HMAC input meant `Alice@x.com` and `alice@x.com` produced
// DIFFERENT fake user/org ids while a real user with case-insensitive
// resolution returned the SAME real ids on both probes. Comparing
// the two probes' returned ids was a real-vs-decoy oracle that
// re-opened F-sec-7 from a different angle. Lowercasing at the
// extraction site is the single-source-of-truth fix: every
// downstream HMAC derivation, cookie storage, and lockout key sees
// the canonical value automatically. RFC 5321 §2.4 says the local
// part of an email address MAY be case-sensitive, but Zitadel
// itself resolves usernames case-insensitively, so the canonicalisation
// here matches Zitadel's behaviour.
func extractLoginNameFromCheck(reqBody map[string]any) (string, bool) {
	checks, ok := reqBody["checks"].(map[string]any)
	if !ok {
		return "", false
	}
	user, ok := checks["user"].(map[string]any)
	if !ok {
		return "", false
	}
	loginName, ok := user["loginName"].(string)
	if !ok || loginName == "" {
		return "", false
	}
	return strings.ToLower(loginName), true
}

// buildDecoyDeleteSessionResponse mimics Zitadel's DELETE response so
// an attacker probing `DELETE /auth/sessions/{decoyId}` can't distinguish
// the decoy from a real session by the deletion outcome (Audit Round 20).
// Zitadel returns 200 with a `details` envelope on successful delete.
func buildDecoyDeleteSessionResponse() []byte {
	type decoyDetails struct {
		Sequence      string `json:"sequence"`
		ChangeDate    string `json:"changeDate"`
		ResourceOwner string `json:"resourceOwner"`
	}
	type wrapper struct {
		Details decoyDetails `json:"details"`
	}
	body := wrapper{
		Details: decoyDetails{
			Sequence:      "2",
			ChangeDate:    time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
			ResourceOwner: "0",
		},
	}
	out, err := json.Marshal(body)
	if err != nil {
		return []byte{}
	}
	return out
}

// buildDecoyFinalizePreconditionResponse mimics Zitadel's
// 412 PreconditionFailed shape for `POST /v2/oidc/auth_requests/{id}`
// when the supplied session lacks a password factor. A real
// loginName-only session hits this path; the decoy must mirror it
// rather than 404 from Zitadel (Audit Round 20).
func buildDecoyFinalizePreconditionResponse() []byte {
	type decoyError struct {
		Code    int      `json:"code"`
		Message string   `json:"message"`
		Details []string `json:"details"`
	}
	body := decoyError{
		// gRPC code 9 (FailedPrecondition) → HTTP 412.
		Code:    9,
		Message: "Errors.User.NotMatchingUserID (COMMAND-3M9fs)",
		Details: []string{},
	}
	out, err := json.Marshal(body)
	if err != nil {
		return []byte{}
	}
	return out
}

// buildDecoyUserScopedResponse synthesizes a Zitadel-shaped response
// for a userScopedProxy endpoint hit on a decoy session. Round 22
// Finding 1: forwarding a decoy through `userScopedProxyWithMethod`
// would 403 (cookie UserID="" doesn't match URL :id), while a real
// loginName-only session would forward to Zitadel and 200 with
// endpoint-specific content. The 403-vs-200 divergence is itself an
// enumeration oracle.
//
// Per-endpoint synthesis is keyed off the upstream Zitadel path:
//   - `/authentication_methods` → empty `authMethodTypes` array (a
//     fresh user with no MFA enrolled)
//   - everything else → generic `details` envelope success (matches
//     Zitadel's shape for register-MFA, register-passkey, password-
//     reset, change-password, verify-email, etc.)
//
// The synthesized response is a "no-op success" — appropriate for
// the read endpoint and for register-side endpoints, less so for
// destructive actions, but those aren't reachable on a decoy in the
// SPA flow anyway.
//
// Round 22 Finding 6: the generic-path `details.resourceOwner` was
// previously hardcoded to "0", which is wire-distinguishable from a
// real Zitadel response (which carries the org's snowflake id). The
// SPA can't reach this branch in normal flow (decoys 4xx at the
// password check before any register-MFA call), but a directly-
// crafted attacker probe with a forged decoy cookie + decoy-hash
// URL could. Closes the leak by deriving the same fake org
// snowflake we use elsewhere — `deriveDecoySnowflake(secret,
// "org:"+loginName)` — so it matches the GetSession decoy's
// `factors.user.organizationId` for the same loginName.
func buildDecoyUserScopedResponse(zitadelPath string, entry *sessionEntry, decoySecret []byte) []byte {
	if strings.Contains(zitadelPath, "/authentication_methods") {
		// SPA's `Password.tsx::checkForcedFlows` reads
		// `authMethodTypes` to decide whether to prompt for MFA. An
		// empty array is the canonical "no factors enrolled yet" shape.
		out, err := json.Marshal(map[string]any{
			"details":         searchSessionsListDetails{TotalResult: "0", Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")},
			"authMethodTypes": []string{},
		})
		if err != nil {
			return []byte(`{"authMethodTypes":[]}`)
		}
		return out
	}
	// Generic Zitadel-shaped success envelope. `sequence` and
	// `resourceOwner` are stringified per the JSON-mapping convention.
	type genericDetails struct {
		Sequence      string `json:"sequence"`
		ChangeDate    string `json:"changeDate"`
		ResourceOwner string `json:"resourceOwner"`
	}
	resourceOwner := "0"
	sequence := "1"
	if entry != nil && entry.LoginName != "" && len(decoySecret) > 0 {
		resourceOwner = deriveDecoySnowflake(decoySecret, "org:"+entry.LoginName)
		// Round 25 hardening (item 27 / R25b F6): HMAC-derived sequence
		// in the keyed branch. Unkeyed branch (entry == nil) keeps "1"
		// — those reach this code only via a forged-cookie probe with
		// no loginName context, so there's nothing to anchor to.
		sequence = deriveDecoySequence(decoySecret, entry.LoginName)
	}
	body := struct {
		Details genericDetails `json:"details"`
	}{
		Details: genericDetails{
			Sequence:      sequence,
			ChangeDate:    time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
			ResourceOwner: resourceOwner,
		},
	}
	out, err := json.Marshal(body)
	if err != nil {
		return []byte{}
	}
	return out
}

// isLikelyUnknownUserResponse heuristically detects a Zitadel
// response that indicates the requested user doesn't exist. Used by
// Round 23 Findings 2/3 (F-sec-7 from-a-different-angle) to canonicalize
// PasswordReset / ChangePassword / VerifyEmail responses so direct
// (non-SPA) probing can't enumerate user IDs derived from F-sec-7
// decoy sessions. Zitadel signals "unknown user" via gRPC code 5
// (NOT_FOUND) → HTTP 404 with a body containing `Errors.User.NotFound`.
//
// We match on both the status code AND the body to avoid swallowing
// legitimate 404s that happen to share the status (e.g. an unknown
// route — wouldn't carry the User.NotFound marker).
func isLikelyUnknownUserResponse(statusCode int, body []byte) bool {
	if statusCode != http.StatusNotFound {
		return false
	}
	return bytes.Contains(body, []byte("User.NotFound")) ||
		bytes.Contains(body, []byte("NOT_FOUND"))
}

// canonicalDetailsEnvelope returns a Zitadel-shaped `{"details":{
// "sequence","changeDate","resourceOwner"}}` body suitable for
// stand-in success responses on user-scoped endpoints. Used by the
// Round 23 unknown-user canonicalization to make a synthesized 200
// shape-indistinguishable from a real Zitadel success.
func canonicalDetailsEnvelope() []byte {
	type details struct {
		Sequence      string `json:"sequence"`
		ChangeDate    string `json:"changeDate"`
		ResourceOwner string `json:"resourceOwner"`
	}
	body := struct {
		Details details `json:"details"`
	}{
		Details: details{
			Sequence:      "1",
			ChangeDate:    time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
			ResourceOwner: "0",
		},
	}
	out, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"details":{}}`)
	}
	return out
}

// canonicalCodeInvalidResponse returns a Zitadel-shaped 4xx body that
// matches what Zitadel emits for a wrong verification code on a real
// user. Used by Round 23 unknown-user canonicalization on VerifyEmail
// and ChangePassword's reset-flow branch — a real user with a wrong
// code 4xxs with this shape, so an unknown user must produce the
// same shape to avoid enumeration.
func canonicalCodeInvalidResponse() []byte {
	type errBody struct {
		Code    int      `json:"code"`
		Message string   `json:"message"`
		Details []string `json:"details"`
	}
	body := errBody{
		Code:    9, // gRPC FailedPrecondition (= HTTP 400)
		Message: "Code is invalid (CODE-3M9fs)",
		Details: []string{},
	}
	out, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"code":9,"message":"Code is invalid"}`)
	}
	return out
}

// buildDecoyPasswordInvalidResponse mimics Zitadel's password-failure
// response shape so a decoy session's PATCH rejection is byte-shape
// indistinguishable from a real password-mismatch on a known user.
// Zitadel returns gRPC code 7 (FailedPrecondition) → HTTP 400, with
// `code`, `message`, `details` keys. The message uses Zitadel's
// canonical error string + an alphanumeric suffix that real failures
// also carry (so a regex matcher in the SPA fires either way).
func buildDecoyPasswordInvalidResponse() []byte {
	type decoyError struct {
		Code    int      `json:"code"`
		Message string   `json:"message"`
		Details []string `json:"details"`
	}
	body := decoyError{
		Code:    7,
		Message: "Password is invalid (COMMAND-3M9fs)",
		Details: []string{},
	}
	out, err := json.Marshal(body)
	if err != nil {
		return []byte{}
	}
	return out
}

// randomDecoyToken returns a base64url-shaped string of approximately
// `n` characters. Uses crypto/rand under the hood (via the rand
// package's reader); the exact length is approximate because base64
// encoding rounds up. Good enough for "looks like a real Zitadel
// id/token" — an attacker examining the structure can't distinguish.
func randomDecoyToken(n int) string {
	// n bytes → ceil(n*4/3) base64 chars. We want ~n output chars,
	// so request 3n/4 bytes.
	byteCount := max((n*3)/4, 1)
	buf := make([]byte, byteCount)
	if _, err := cryptorand.Read(buf); err != nil {
		// crypto/rand failure is catastrophic; fallback to a
		// time-based seed isn't acceptable for a security-critical
		// surface. Bail and the caller's empty string is logged
		// upstream.
		return ""
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(buf), "=")
}

// UpdateSession handles PATCH /auth/sessions/:id.
// Updates a session (password check, MFA check, etc.).
func (p *AuthProxy) UpdateSession(c *gin.Context) {
	sessionID := c.Param("id")
	if sessionID == "" {
		respondError(c, http.StatusBadRequest, "session ID is required")
		return
	}

	// Verify the caller owns this session (DR-4)
	if !p.requireOwningSession(c, sessionID) {
		return
	}

	var reqBody map[string]any
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	// Verify session exists in cookie — fail-fast if not found
	entry := p.findSessionEntry(c, sessionID)
	if entry == nil {
		respondError(c, http.StatusForbidden, "session not found — please sign in again")
		return
	}
	// NOTE: sessionToken on PATCH is DEPRECATED in Zitadel v4.13+ and will be ignored.
	// The token is only needed for finalizeAuthRequest. We do NOT inject it here.

	// Notification mode handling (P1/DR-6 + Wave 14):
	//
	//   - return_code mode: force `returnCode: {}` on OTP challenges so
	//     Zitadel echoes the code in the response (homelab/dev default;
	//     no SMTP required).
	//   - email mode: strip any `returnCode` the SPA sent so Zitadel
	//     delivers via the configured SMTP backend instead of echoing.
	//     Wave 14 caught this: the SPA's Otp.tsx unconditionally sends
	//     `returnCode: {}` because it doesn't know which mode the proxy
	//     is in — without the proxy stripping it, every email-mode
	//     challenge stays as "return-the-code" and no email is ever sent.
	switch p.config.NotificationMode {
	case NotificationModeReturnCode:
		p.injectReturnCodeFlags(reqBody)
	case NotificationModeEmail:
		p.stripReturnCodeFlags(reqBody)
	}

	// F-sec-5/6: detect password-attempt PATCHes. The limiter applies
	// to BOTH real and decoy sessions — Round 21 Finding 2 caught the
	// decoy lockout gap: real users hit 429 at threshold but decoys
	// returned 400 forever, giving an attacker a single-bit oracle
	// for "user exists" by counting consecutive 400s.
	//
	// Limiter key: real users key on `entry.UserID` (server-derived,
	// authoritative — Round 17 populates it via `fetchSessionUserID`).
	// Decoys have UserID="" and key on `decoy:` + `entry.LoginName`
	// (the loginName captured at decoy createSession time). Different
	// keyspaces, but both produce identical 429-at-threshold behaviour
	// from the client's perspective. The "decoy:" prefix prevents
	// collision with a real loginName-shaped UserID.
	//
	// Round 21 Finding 4: the request must be a PURE password attempt
	// (`checks.password.password` set AND no other factor checks in
	// the same body). A mixed body — e.g. `password + totp` — that
	// 4xxs upstream might 4xx because of the totp validation, not
	// password mismatch; counting it as a password failure would let
	// an attacker (or a transient SPA bug) accidentally lock a
	// victim. By gating on a single-factor body shape, the post-flight
	// "any 4xx is a password failure" rule is sound: with no other
	// factor in play, the only meaningful 4xx is a password failure.
	isPasswordAttempt := isPureSinglePasswordCheck(reqBody)
	limiterKey := ""
	if isPasswordAttempt && p.LoginNameLimiter != nil {
		switch {
		case entry.Decoy && entry.LoginName != "":
			// Round 26 Wave 9 (HIGH-1): lowercase the loginName before
			// keying the lockout. Without this, an attacker probing
			// `Admin@x.com`, `ADMIN@x.com`, `aDmin@x.com` (etc.) gets
			// a separate counter per casing and bypasses the per-user
			// lockout entirely on the decoy path. The Wave 2 doc-block
			// on `LoginNameRateLimiter` declares the canonicalisation
			// invariant — caller must canonicalise — and this is the
			// caller's responsibility.
			limiterKey = "decoy:" + strings.ToLower(entry.LoginName)
		case !entry.Decoy && entry.UserID != "":
			// UserID is a Zitadel snowflake (numeric, no case
			// ambiguity) — already canonical.
			limiterKey = entry.UserID
		}
	}
	if limiterKey != "" {
		// BeginAttempt atomically gates AND reserves a tentative
		// failure slot. Race-safe under parallel PATCHes (Round 20).
		if !p.LoginNameLimiter.BeginAttempt(limiterKey) {
			// Round 27 Wave 15 — observability: emit a WARN log so an
			// on-call grepping API logs can see lockouts as they
			// happen ("yes, X is being attacked"). Structured
			// `event=` field for easy filtering; the loginName/UserID
			// is embedded in the key with the `decoy:` / bare
			// namespace already prefixed by the caller.
			logger.Warnf("event=loginname_lockout_denied key=%q reason=too_many_failed_password_attempts", limiterKey)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"code":    http.StatusTooManyRequests,
				"message": "too many failed password attempts — try again later",
			})
			return
		}
	}

	// F-sec-7: short-circuit decoy sessions. The decoy never forwards
	// to Zitadel (which would 404 the fake id and leak by status
	// divergence). Always return the canonical "Password is invalid"
	// 4xx — the limiter above already turned the threshold-th attempt
	// into a 429, mirroring the real path.
	if entry.Decoy {
		c.Data(http.StatusBadRequest, "application/json", buildDecoyPasswordInvalidResponse())
		return
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPatch, "/v2/sessions/"+sessionID, reqBody)
	if err != nil {
		// Transport-level error — no auth verdict. Roll back the
		// tentative slot so an outage doesn't silently lock honest
		// users on retry. (Round 20 Finding 5 documents the budget-
		// farming risk during sustained Zitadel outages — accepted
		// tradeoff vs locking honest users out.)
		if limiterKey != "" {
			p.LoginNameLimiter.RollbackAttempt(limiterKey)
		}
		logger.Errorf("Failed to update session: %v", err)
		respondError(c, http.StatusBadGateway, "failed to update session with identity provider")
		return
	}

	// Update the session token in the cookie (tokens change on every update)
	if statusCode == http.StatusOK {
		p.storeSessionFromResponse(c, respBody)
	}

	// F-sec-5/6: post-flight bookkeeping. Round 21 Finding 4 moved the
	// "is this a password attempt?" guard into the request-body shape
	// (see isPureSinglePasswordCheck above); given that, ANY 4xx from
	// Zitadel for a single-factor password body counts as a password
	// failure (the request had no other check that could have caused
	// the rejection). 5xx/transport rolls back so a Zitadel outage
	// doesn't lock honest users.
	//
	//   - 200 → Reset (clears the bump + any prior failures).
	//   - 4xx (any) → leave the bump in place; with a single-factor
	//     body, 4xx implies password mismatch.
	//   - 5xx (or transport) → Rollback.
	if limiterKey != "" {
		switch {
		case statusCode == http.StatusOK:
			p.LoginNameLimiter.Reset(limiterKey)
		case statusCode >= 500:
			p.LoginNameLimiter.RollbackAttempt(limiterKey)
		}
		// 4xx falls through — bump stays.
	}

	c.Data(statusCode, "application/json", respBody)
}

// isPureSinglePasswordCheck reports whether the request body is
// EXACTLY a `{checks: {password: {password: "<non-whitespace>"}}}`
// shape — no other top-level keys, no other check siblings, no empty
// or whitespace-only password. The post-flight lockout-bookkeeping
// rule then treats any 4xx upstream as a real password failure
// (with no other thing in the body, the only thing that could fail
// is the password).
//
// Round 21 Finding 4 closed the `checks` siblings gap (`password +
// totp` bundle). Round 22 Finding 4 tightens the gate further: the
// previous version allowed top-level siblings (`lifetime`,
// `metadata`, `challenges`) which Zitadel's UpdateSession also
// validates and could 4xx on, letting an attacker (or transient
// bug) trigger lockout on non-password code paths. Now the request
// body must contain ONLY the `checks` key.
//
// Whitespace-only passwords are also rejected — they'd be forwarded
// to Zitadel and 4xx as "password is invalid", but the attempt was
// trivially malformed and shouldn't burn a slot.
func isPureSinglePasswordCheck(reqBody map[string]any) bool {
	if len(reqBody) != 1 {
		return false
	}
	checks, ok := reqBody["checks"].(map[string]any)
	if !ok {
		return false
	}
	if len(checks) != 1 {
		return false
	}
	pw, ok := checks["password"].(map[string]any)
	if !ok {
		return false
	}
	pwStr, ok := pw["password"].(string)
	if !ok || strings.TrimSpace(pwStr) == "" {
		return false
	}
	return true
}

// GetSession handles GET /auth/sessions/:id.
func (p *AuthProxy) GetSession(c *gin.Context) {
	sessionID := c.Param("id")
	if sessionID == "" {
		respondError(c, http.StatusBadRequest, "session ID is required")
		return
	}

	if !p.requireOwningSession(c, sessionID) {
		return
	}

	// F-sec-7 (Audit Round 20 + Round 21 Finding 1): a decoy GetSession
	// must mirror a real loginName-only session's full shape — the
	// divergence between a 404 and a populated 200 is what lets an
	// attacker enumerate users. The synthesized response carries a
	// fully-populated `factors.user.{id, loginName, organizationId}`
	// with deterministic hash-derived ids so repeated probes of the
	// same unknown loginName look identical to a real user.
	if entry := p.findSessionEntry(c, sessionID); entry != nil && entry.Decoy {
		c.Data(http.StatusOK, "application/json", buildDecoyGetSessionResponse(entry, p.decoySecret))
		return
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodGet, "/v2/sessions/"+sessionID, nil)
	if err != nil {
		logger.Errorf("Failed to get session: %v", err)
		respondError(c, http.StatusBadGateway, "failed to get session from identity provider")
		return
	}
	c.Data(statusCode, "application/json", respBody)
}

// DeleteSession handles DELETE /auth/sessions/:id.
func (p *AuthProxy) DeleteSession(c *gin.Context) {
	sessionID := c.Param("id")
	if sessionID == "" {
		respondError(c, http.StatusBadRequest, "session ID is required")
		return
	}

	if !p.requireOwningSession(c, sessionID) {
		return
	}

	// Get session token from cookie
	var sessionToken string
	cookieEntry := p.findSessionEntry(c, sessionID)
	if cookieEntry != nil {
		sessionToken = cookieEntry.Token
	}

	// F-sec-7 (Audit Round 20): a decoy DELETE must not 404 upstream.
	// Clear the cookie entry locally and synthesize a Zitadel-shaped
	// 200 with `details` so an attacker can't distinguish a decoy by
	// the delete-time error shape.
	if cookieEntry != nil && cookieEntry.Decoy {
		p.clearSessionEntry(c, sessionID)
		c.Data(http.StatusOK, "application/json", buildDecoyDeleteSessionResponse())
		return
	}

	reqBody := map[string]any{
		"sessionToken": sessionToken,
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodDelete, "/v2/sessions/"+sessionID, reqBody)
	if err != nil {
		logger.Errorf("Failed to delete session: %v", err)
		respondError(c, http.StatusBadGateway, "failed to delete session with identity provider")
		return
	}

	// Remove from cookie on Zitadel success — the canonical happy path.
	if statusCode == http.StatusOK {
		p.clearSessionEntry(c, sessionID)
		c.Data(statusCode, "application/json", respBody)
		return
	}

	// F20 multi-session UI: gracefully smooth over the case where Zitadel
	// rejects the cookie-stored sessionToken as invalid. The token gets
	// consumed by `finalizeAuthRequest` during normal login completion,
	// so by the time the user reaches `/login/logout` the stored token
	// can no longer prove ownership to Zitadel — but the user's intent
	// ("remove this session from my browser's session list") is still
	// valid from the cookie's perspective. We honour the local cleanup,
	// surface a 200, and leave the upstream session to expire on its
	// own TTL. Without this, the multi-session picker is stuck rendering
	// sessions the user can't actually remove (Round-22 RP-side parity
	// follow-up to F20).
	//
	// Narrowly scoped to "Session Token is invalid" (Zitadel COMMAND-sGr42
	// → 403) so genuine errors (network failures, real authorization
	// rejections) still bubble up. Any other 4xx/5xx returns Zitadel's
	// shape verbatim — the SPA's `data-testid="logout-session-remove"`
	// click handler swallows non-2xx and refetches the list, so honest
	// errors degrade into "the session stays and you can try again."
	if statusCode == http.StatusForbidden && bytes.Contains(respBody, []byte("Session Token is invalid")) {
		p.clearSessionEntry(c, sessionID)
		c.Data(http.StatusOK, "application/json", buildDecoyDeleteSessionResponse())
		return
	}

	c.Data(statusCode, "application/json", respBody)
}

// SearchSessions handles POST /auth/sessions/search.
//
// The proxy uses the service-account PAT, which Zitadel treats as privileged
// for session queries. To prevent a caller from enumerating sessions that
// don't belong to them, this handler hard-constrains the outgoing query to
// only the session IDs recorded in the caller's own sessions cookie. Any
// client-supplied sessionIds / userIds / creator queries are discarded.
//
// F-sec-7 (Round 21 Finding 3): if the cookie holds decoy entries, the
// upstream query MUST exclude them — Zitadel returns 0 rows for the fake
// ids, and the resulting row-count divergence (0 for decoy vs 1+ for a
// real session in the same loginName-only state) is itself an
// enumeration oracle. We forward only the real ids upstream, then
// splice synthesized decoy session rows back into the response so the
// client sees a row-count + per-row shape that mirrors a real result.
func (p *AuthProxy) SearchSessions(c *gin.Context) {
	var reqBody map[string]any
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	entries := p.readSessionCookie(c)
	if len(entries) == 0 {
		c.JSON(http.StatusOK, gin.H{"sessions": []any{}})
		return
	}

	realIDs := make([]string, 0, len(entries))
	decoyEntries := make([]sessionEntry, 0, len(entries))
	for _, e := range entries {
		if e.Decoy {
			decoyEntries = append(decoyEntries, e)
			continue
		}
		realIDs = append(realIDs, e.ID)
	}

	// All entries are decoys → no upstream call needed; synthesize the
	// whole response.
	if len(realIDs) == 0 {
		body := buildDecoySearchSessionsResponse(decoyEntries, p.decoySecret)
		c.Data(http.StatusOK, "application/json", body)
		return
	}

	// Overwrite any caller-supplied filters with a single IdsQuery
	// scoped to the REAL cookie sessions (decoys excluded — Round 21).
	reqBody["queries"] = []map[string]any{
		{"idsQuery": map[string]any{"ids": realIDs}},
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPost, "/v2/sessions/search", reqBody)
	if err != nil {
		logger.Errorf("Failed to search sessions: %v", err)
		respondError(c, http.StatusBadGateway, "failed to search sessions with identity provider")
		return
	}

	// Splice decoy rows into the upstream result so the client sees
	// one row per cookie session, matching the row count + shape of a
	// real all-real result.
	if statusCode == http.StatusOK && len(decoyEntries) > 0 {
		spliced := spliceDecoyRowsIntoSearchResponse(respBody, decoyEntries, p.decoySecret)
		if spliced != nil {
			c.Data(http.StatusOK, "application/json", spliced)
			return
		}
		// Fall through if splicing failed — better to return Zitadel's
		// real response than a half-formed mix.
	}

	c.Data(statusCode, "application/json", respBody)
}

// searchSessionsListDetails mirrors Zitadel's `ListDetails` envelope
// on `/v2/sessions/search`. Captured shape from a live tunnel:
//
//	{"details":{"totalResult":"1","timestamp":"<rfc3339>"},
//	 "sessions":[ ... ]}
//
// `processedSequence` exists in the proto but is omitted from the
// HTTP-JSON wire response when zero, so we don't include it here.
type searchSessionsListDetails struct {
	TotalResult string `json:"totalResult"`
	Timestamp   string `json:"timestamp"`
}

// extractDecoyRows builds the synthesized session rows for a list of
// decoy cookie entries. Returns the inner session objects (NOT the
// `{"session": ...}` wrapper) ready for splicing into a `sessions`
// array. Round 22 Finding 2: the previous splicer stripped Zitadel's
// `details` envelope; this helper is now reused by both the all-decoy
// and mixed paths so the envelope handling is consistent.
func extractDecoyRows(decoys []sessionEntry, secret []byte) []json.RawMessage {
	rows := make([]json.RawMessage, 0, len(decoys))
	for i := range decoys {
		body := buildDecoyGetSessionResponse(&decoys[i], secret)
		var wrapped struct {
			Session json.RawMessage `json:"session"`
		}
		if err := json.Unmarshal(body, &wrapped); err != nil || len(wrapped.Session) == 0 {
			continue
		}
		rows = append(rows, wrapped.Session)
	}
	return rows
}

// buildDecoySearchSessionsResponse synthesizes a Zitadel-shaped
// SearchSessions response (including the `details` envelope) from a
// list of decoy cookie entries. Used when the cookie carries ONLY
// decoys (no real sessions to query upstream).
//
// Round 22 Finding 2: the prior version emitted just `{"sessions":
// [...]}`, dropping Zitadel's `details: {totalResult, timestamp}`
// envelope — wire-distinguishable from a real-only response.
func buildDecoySearchSessionsResponse(decoys []sessionEntry, secret []byte) []byte {
	rows := extractDecoyRows(decoys, secret)
	body := struct {
		Details  searchSessionsListDetails `json:"details"`
		Sessions []json.RawMessage         `json:"sessions"`
	}{
		Details: searchSessionsListDetails{
			TotalResult: fmt.Sprintf("%d", len(rows)),
			Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
		},
		Sessions: rows,
	}
	out, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"details":{"totalResult":"0","timestamp":"1970-01-01T00:00:00Z"},"sessions":[]}`)
	}
	return out
}

// spliceDecoyRowsIntoSearchResponse takes Zitadel's real search
// response and prepends synthesized decoy rows. Preserves the
// upstream `details` envelope but updates `totalResult` to reflect
// the merged row count (Round 22 Finding 2). Returns nil on
// unmarshal failure so the caller can fall back to the upstream
// response unchanged — but with the all-real `details` count
// preserved (the row-count divergence vs the cookie size IS still a
// secondary leak; reaching this branch requires an upstream JSON
// parse failure which would itself indicate a bigger problem).
func spliceDecoyRowsIntoSearchResponse(realBody []byte, decoys []sessionEntry, secret []byte) []byte {
	var parsed struct {
		Details  json.RawMessage   `json:"details"`
		Sessions []json.RawMessage `json:"sessions"`
	}
	if err := json.Unmarshal(realBody, &parsed); err != nil {
		return nil
	}
	decoyRows := extractDecoyRows(decoys, secret)
	// Bound check the cap argument to `make` so CodeQL's
	// go/allocation-size-overflow query is satisfied and a malicious
	// upstream cannot trigger an oversized allocation (Wave 8 / D4).
	// 65536 rows is far more than any realistic session listing.
	const maxRows = 1 << 16
	if len(parsed.Sessions) > maxRows || len(decoyRows) > maxRows {
		return nil
	}
	merged := make([]json.RawMessage, 0, len(parsed.Sessions)+len(decoyRows))
	merged = append(merged, decoyRows...)
	merged = append(merged, parsed.Sessions...)

	// Update the `details.totalResult` to reflect the merged count
	// while preserving the upstream `timestamp` (and any other
	// fields Zitadel might add). If we can't parse `details`,
	// synthesize a fresh envelope rather than dropping it (dropping
	// would be the original Round 22 Finding 2 leak).
	var details map[string]any
	if len(parsed.Details) > 0 {
		_ = json.Unmarshal(parsed.Details, &details)
	}
	if details == nil {
		details = map[string]any{
			"timestamp": time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
		}
	}
	details["totalResult"] = fmt.Sprintf("%d", len(merged))

	out, err := json.Marshal(map[string]any{
		"details":  details,
		"sessions": merged,
	})
	if err != nil {
		return nil
	}
	return out
}

// --- IdP Proxy (A5) ---

// StartIdP handles POST /auth/idp/start.
func (p *AuthProxy) StartIdP(c *gin.Context) {
	var reqBody map[string]any
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	// IdP success/failure pages live on the SPA, not the api. Build URLs from
	// the frontend base (config.PublicFrontendURL or, in same-origin
	// deployments, the api's own host) — using the api host directly here
	// would 404 the user when the SPA is on a different domain.
	frontendBase := p.getFrontendBaseURL(c)
	idpID, _ := reqBody["idpId"].(string)
	if idpID == "" {
		respondError(c, http.StatusBadRequest, "idpId is required")
		return
	}

	reqBody["urls"] = map[string]string{
		"successUrl": frontendBase + "/login/idp/" + idpID + "/process",
		"failureUrl": frontendBase + "/login/idp/" + idpID + "/failure",
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPost, "/v2/idp_intents", reqBody)
	if err != nil {
		logger.Errorf("Failed to start IdP flow: %v", err)
		respondError(c, http.StatusBadGateway, "failed to start identity provider flow")
		return
	}
	c.Data(statusCode, "application/json", respBody)
}

// CompleteIdP handles POST /auth/idp/complete/:intentId.
func (p *AuthProxy) CompleteIdP(c *gin.Context) {
	intentID := c.Param("intentId")
	if intentID == "" {
		respondError(c, http.StatusBadRequest, "intent ID is required")
		return
	}

	var reqBody map[string]any
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPost, "/v2/idp_intents/"+intentID, reqBody)
	if err != nil {
		logger.Errorf("Failed to complete IdP flow: %v", err)
		respondError(c, http.StatusBadGateway, "failed to complete identity provider flow")
		return
	}
	c.Data(statusCode, "application/json", respBody)
}

// ListIdpProviders handles GET /auth/idp/providers.
//
// Returns the set of identity providers that should be rendered as login buttons.
// Zitadel's canonical endpoint for this is GET /v2/settings/login/idps (part of
// the settings service) — it returns `{details, identityProviders:[...]}`. The
// earlier plan entry that targeted POST /v2/idps/search was wrong for v4 (that
// path returns 405). The response is adapted to `{result: [...]}` so the
// frontend reader (which expects a `result` array) doesn't need to track the
// Zitadel response-key naming.
func (p *AuthProxy) ListIdpProviders(c *gin.Context) {
	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodGet, "/v2/settings/login/idps", nil)
	if err != nil {
		logger.Errorf("Failed to list IdP providers: %v", err)
		respondError(c, http.StatusBadGateway, "failed to list identity providers")
		return
	}

	if statusCode != http.StatusOK {
		c.Data(statusCode, "application/json", respBody)
		return
	}

	// Rewrite {identityProviders:[...]} → {result:[...]} for the frontend.
	var wrapper struct {
		IdentityProviders json.RawMessage `json:"identityProviders"`
	}
	if err := json.Unmarshal(respBody, &wrapper); err != nil {
		// Unexpected shape — forward unchanged and let the frontend handle it.
		c.Data(statusCode, "application/json", respBody)
		return
	}
	if len(wrapper.IdentityProviders) == 0 {
		c.JSON(http.StatusOK, gin.H{"result": []any{}})
		return
	}
	c.Data(http.StatusOK, "application/json",
		[]byte(`{"result":`+string(wrapper.IdentityProviders)+`}`))
}

// --- User Management Proxy (A6) ---

// CreateUser handles POST /auth/users.
func (p *AuthProxy) CreateUser(c *gin.Context) {
	var reqBody map[string]any
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	// In return_code mode, inject email.returnCode (DR-6).
	// SetHumanEmail.verification is a Zitadel proto `oneof` — only ONE branch
	// (returnCode | sendCode | isVerified) may be set per message. Register.tsx
	// pre-fills `isVerified: false` for email-mode parity, so we strip the
	// other branches before injecting returnCode; otherwise Zitadel's
	// unmarshaller rejects the message with "oneof … verification is already
	// set".
	if p.config.NotificationMode == NotificationModeReturnCode {
		if email, ok := reqBody["email"].(map[string]any); ok {
			delete(email, "isVerified")
			delete(email, "sendCode")
			email["returnCode"] = map[string]any{}
		}
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPost, "/v2/users/human", reqBody)
	if err != nil {
		logger.Errorf("Failed to create user: %v", err)
		respondError(c, http.StatusBadGateway, "failed to create user with identity provider")
		return
	}
	c.Data(statusCode, "application/json", respBody)
}

// PasswordReset handles POST /auth/users/:id/password-reset.
// This endpoint is public but rate-limited per DR-4.
func (p *AuthProxy) PasswordReset(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		respondError(c, http.StatusBadRequest, "user ID is required")
		return
	}

	var reqBody map[string]any
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		reqBody = make(map[string]any)
	}

	// In return_code mode, set top-level returnCode as empty object (DR-6).
	// CRITICAL: password_reset uses "returnCode": {} (empty object), NOT boolean true.
	// Using boolean true causes Zitadel to silently fall back to email delivery.
	if p.config.NotificationMode == NotificationModeReturnCode {
		reqBody["returnCode"] = map[string]any{}
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPost, "/v2/users/"+userID+"/password_reset", reqBody)
	if err != nil {
		logger.Errorf("Failed to request password reset: %v", err)
		respondError(c, http.StatusBadGateway, "failed to request password reset")
		return
	}
	// Round 23 Finding 2 (MODERATE): canonicalize unknown-user 404
	// to a 200 success shape so the F-sec-7 anti-enumeration shield
	// extends to direct (non-SPA) probing. The SPA's password-reset
	// flow goes loginName → createSession (decoy-aware) → getSession
	// → password_reset. With F-sec-7 the createSession step returns a
	// fake userId for unknown loginNames; without canonicalization
	// here, the password_reset call distinguishes real vs decoy via
	// 200 vs 404 — recreating the enumeration leak from a different
	// angle. The actual reset code is only emitted by Zitadel for
	// real users (in returnCode mode) or via SMTP (in email mode);
	// the canonical empty-success body for unknown users is harmless.
	if isLikelyUnknownUserResponse(statusCode, respBody) {
		statusCode = http.StatusOK
		respBody = canonicalDetailsEnvelope()
	}
	c.Data(statusCode, "application/json", respBody)
}

// ChangePassword handles POST /auth/users/:id/password.
// Requires verification code — Zitadel enforces server-side (DR-4).
func (p *AuthProxy) ChangePassword(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		respondError(c, http.StatusBadRequest, "user ID is required")
		return
	}

	var reqBody map[string]any
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPost, "/v2/users/"+userID+"/password", reqBody)
	if err != nil {
		logger.Errorf("Failed to change password: %v", err)
		respondError(c, http.StatusBadGateway, "failed to change password")
		return
	}
	// Round 23 Finding 2 (MODERATE): canonicalize unknown-user 404
	// to a "code is invalid" 4xx — same shape Zitadel emits for a
	// wrong verificationCode (reset flow) or wrong currentPassword
	// (in-app change flow) on a REAL user. Without this, an attacker
	// can probe `/auth/users/<guessedId>/password` with a bogus body
	// and read 404 (unknown user) vs 4xx-with-different-shape (known
	// user with wrong creds) → enumeration leak.
	if isLikelyUnknownUserResponse(statusCode, respBody) {
		statusCode = http.StatusBadRequest
		respBody = canonicalCodeInvalidResponse()
	}
	c.Data(statusCode, "application/json", respBody)
}

// userScopedProxy is a generic handler for user-scoped endpoints that require session ownership.
// Used for TOTP, passkey, U2F, and OTP registration endpoints.
// Per DR-4: requires a valid session cookie before forwarding to Zitadel.
// Zitadel's server-side enforcement + the PAT ensures the session token is
// user-bound, but we validate at the proxy layer too to prevent cross-user access.
func (p *AuthProxy) userScopedProxy(c *gin.Context, zitadelPath string) {
	p.userScopedProxyWithMethod(c, http.MethodPost, zitadelPath)
}

// userScopedProxyWithMethod is the generalized form of userScopedProxy that
// honors the request's HTTP method. POST endpoints reuse `userScopedProxy`;
// GET endpoints (e.g. `/auth/users/{id}/authentication_methods`, used by
// `Password.tsx::checkForcedFlows` to discover user-level MFA enrollment)
// route through here so the body-binding path is skipped.
//
// DR-4 enforcement: the URL `:id` (target user) MUST match at least one
// session's bound UserID in the caller's cookie. Round 17 (F-sec-9)
// added this — pre-fix, any logged-in user could mutate any other user's
// authenticators (TOTP, passkey, etc.) just by swapping the id in the
// URL. The `userId` URL parameter name comes from the route definition
// in `routes.go` (e.g. `users.GET("/:id/authentication_methods", ...)`).
func (p *AuthProxy) userScopedProxyWithMethod(c *gin.Context, method, zitadelPath string) {
	entries := p.readSessionCookie(c)
	if len(entries) == 0 {
		respondError(c, http.StatusForbidden, "no valid session for this resource")
		return
	}

	// Bind the request to one of the caller's cookie sessions. If the
	// route doesn't carry an `:id` param (none of today's user-scoped
	// routes lack one, but the helper is generalized) we skip the
	// match check — the session-presence check above is sufficient
	// for those.
	//
	// Round 22 Finding 1 (F-sec-7 leak): a decoy session has UserID="",
	// so the legacy match below always 403s decoys. A real loginName-
	// only session forwards to Zitadel and returns whatever Zitadel
	// says about the user — DIFFERENT shape from the decoy 403.
	// Match decoys via their hash-derived fake user id: the decoy's
	// `factors.user.id` (returned by GetSession) equals
	// `deriveDecoySnowflake(secret, "user:"+entry.LoginName)`. If the
	// URL `:id` matches that hash for any decoy entry, short-circuit
	// the upstream call with a Zitadel-shaped success response so a
	// decoy probe is indistinguishable from a real loginName-only
	// session probe.
	if targetUserID := c.Param("id"); targetUserID != "" {
		matchedReal := false
		var matchedDecoy *sessionEntry
		for i := range entries {
			e := &entries[i]
			if !e.Decoy && e.UserID != "" && e.UserID == targetUserID {
				matchedReal = true
				break
			}
			if e.Decoy && e.LoginName != "" {
				if deriveDecoySnowflake(p.decoySecret, "user:"+e.LoginName) == targetUserID {
					matchedDecoy = e
				}
			}
		}
		if !matchedReal && matchedDecoy == nil {
			respondError(c, http.StatusForbidden, "session does not authorize this user")
			return
		}
		if matchedDecoy != nil {
			c.Data(http.StatusOK, "application/json", buildDecoyUserScopedResponse(zitadelPath, matchedDecoy, p.decoySecret))
			return
		}
	}

	var reqBody map[string]any
	if method != http.MethodGet {
		if err := c.ShouldBindJSON(&reqBody); err != nil {
			reqBody = make(map[string]any)
		}
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), method, zitadelPath, reqBody)
	if err != nil {
		logger.Errorf("Failed to proxy user-scoped request to %s: %v", zitadelPath, err)
		respondError(c, http.StatusBadGateway, "failed to complete request with identity provider")
		return
	}
	c.Data(statusCode, "application/json", respBody)
}

// GetUserByID handles GET /auth/users/:id — proxies Zitadel's
// `GET /v2/users/{id}` so the SPA can read flags it needs after
// authentication (notably `human.passwordChangeRequired` for F19).
//
// Routed through `userScopedProxyWithMethod` so the URL `:id` MUST
// match the cookie session's `UserID` (Round 17 cross-user gate).
// This keeps the endpoint a pure self-read — a logged-in user can
// only fetch their OWN record. Decoy sessions get a synthesized
// Zitadel-shaped response from the same Round-22 helper, so direct
// probes can't enumerate via this endpoint either.
func (p *AuthProxy) GetUserByID(c *gin.Context) {
	userID := c.Param("id")
	p.userScopedProxyWithMethod(c, http.MethodGet, "/v2/users/"+userID)
}

// ListAuthMethods handles GET /auth/users/:id/authentication_methods.
//
// Returns the list of authentication factors the user has enrolled (TOTP,
// passkey, U2F, OTP-email, OTP-sms, password). The SPA's password page
// reads this to decide whether to route the user to a second-factor prompt
// instead of finalizing the auth request on the password alone — without
// this hop, a TOTP-enrolled user would land on `/dashboard` with only a
// password verified, which silently breaks user-level MFA enforcement.
func (p *AuthProxy) ListAuthMethods(c *gin.Context) {
	userID := c.Param("id")
	p.userScopedProxyWithMethod(c, http.MethodGet, "/v2/users/"+userID+"/authentication_methods")
}

// RegisterTOTP handles POST /auth/users/:id/totp.
func (p *AuthProxy) RegisterTOTP(c *gin.Context) {
	userID := c.Param("id")
	p.userScopedProxy(c, "/v2/users/"+userID+"/totp")
}

// VerifyTOTP handles POST /auth/users/:id/totp/verify.
func (p *AuthProxy) VerifyTOTP(c *gin.Context) {
	userID := c.Param("id")
	p.userScopedProxy(c, "/v2/users/"+userID+"/totp/verify")
}

// RegisterPasskey handles POST /auth/users/:id/passkeys.
func (p *AuthProxy) RegisterPasskey(c *gin.Context) {
	userID := c.Param("id")
	p.userScopedProxy(c, "/v2/users/"+userID+"/passkeys")
}

// VerifyPasskey handles POST /auth/users/:id/passkeys/:pkId.
func (p *AuthProxy) VerifyPasskey(c *gin.Context) {
	userID := c.Param("id")
	pkID := c.Param("pkId")
	p.userScopedProxy(c, "/v2/users/"+userID+"/passkeys/"+pkID)
}

// RegisterU2F handles POST /auth/users/:id/u2f.
func (p *AuthProxy) RegisterU2F(c *gin.Context) {
	userID := c.Param("id")
	p.userScopedProxy(c, "/v2/users/"+userID+"/u2f")
}

// VerifyU2F handles POST /auth/users/:id/u2f/:u2fId.
func (p *AuthProxy) VerifyU2F(c *gin.Context) {
	userID := c.Param("id")
	u2fID := c.Param("u2fId")
	p.userScopedProxy(c, "/v2/users/"+userID+"/u2f/"+u2fID)
}

// EnableOTPEmail handles POST /auth/users/:id/otp-email.
func (p *AuthProxy) EnableOTPEmail(c *gin.Context) {
	userID := c.Param("id")
	p.userScopedProxy(c, "/v2/users/"+userID+"/otp_email")
}

// EnableOTPSMS handles POST /auth/users/:id/otp-sms.
func (p *AuthProxy) EnableOTPSMS(c *gin.Context) {
	userID := c.Param("id")
	p.userScopedProxy(c, "/v2/users/"+userID+"/otp_sms")
}

// VerifyEmail handles POST /auth/users/:id/email.
// Verifies the user's email address with a verification code.
//
// Zitadel exposes two distinct endpoints on the email subresource:
//   - POST /v2/users/{id}/email          → SetEmail (set/update; needs `email`)
//   - POST /v2/users/{id}/email/verify   → VerifyEmail (consumes a code)
//
// The SPA uses the latter — the request body carries `verificationCode` only.
// Calling SetEmail by mistake makes Zitadel reject the request with
// "invalid SetEmailRequest.Email: value length must be between 1 and 200
// runes" because `email` is required there.
//
// Round 25 Wave 6 (item 20 / R25b F1): VerifyEmail previously bypassed
// the cross-user auth gate that `userScopedProxyWithMethod` enforces
// for every other user-scoped endpoint, leaving a timing oracle on
// email verification. Now the URL `:id` MUST match the caller's
// cookie session's UserID OR a decoy hash; mismatched callers get
// 403 (same as the rest of the user-scoped surface).
//
// Round 25 Wave 6 (item 30 / R25b F1 follow-on): per-userId rate cap
// on VerifyEmail attempts via the existing `LoginNameLimiter` keyed
// with a `verify-email:` prefix to prevent brute-force iteration of
// the verification code. The rate-limit-rejection branch adds a
// small randomised delay (jitter) so the timing of the rejection
// can't be used to probe whether the user is rate-limited (which
// would otherwise leak "this user is being attacked").
func (p *AuthProxy) VerifyEmail(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		respondError(c, http.StatusBadRequest, "user ID is required")
		return
	}

	// Round 25 Wave 6 (item 20): cross-user gate. The previous unconditional
	// `requireUserScopedSession` call broke F7 self-registration — a freshly
	// registered user has NO session cookie yet (CreateUser doesn't mint one),
	// so verify-email-after-register always 403'd (Wave 14 fix, 2026-05-10).
	//
	// Apply the gate only when a session cookie IS present:
	//   - No cookie → fall through to Zitadel; security is provided by the
	//     short, single-use verification code and the per-userId rate cap
	//     below + Round 23 F3 canonical unknown-user response.
	//   - Cookie present and matches URL :id → real user verifying own email.
	//   - Cookie present and matches a decoy hash → decoy short-circuit.
	//   - Cookie present and matches NEITHER → 403 (cross-user attack).
	var matchedDecoy *sessionEntry
	if entries := p.readSessionCookie(c); len(entries) > 0 {
		matchedReal := false
		for i := range entries {
			e := &entries[i]
			if !e.Decoy && e.UserID != "" && e.UserID == userID {
				matchedReal = true
				break
			}
			if e.Decoy && e.LoginName != "" {
				if deriveDecoySnowflake(p.decoySecret, "user:"+e.LoginName) == userID {
					matchedDecoy = e
				}
			}
		}
		if !matchedReal && matchedDecoy == nil {
			respondError(c, http.StatusForbidden, "session does not authorize this user")
			return
		}
	}

	// Decoy short-circuit: synthesise the canonical "Code is invalid"
	// 4xx so an attacker can't distinguish a decoy from a real user
	// with a wrong code. Same shape used by the unknown-user
	// canonicalization in the real-Zitadel branch below (Round 23 F3).
	if matchedDecoy != nil {
		c.Data(http.StatusBadRequest, "application/json", canonicalCodeInvalidResponse())
		return
	}

	var reqBody map[string]any
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	// Round 25 Wave 6 (item 30): per-userId rate cap. A captured
	// verification code is short and brute-forcible without this gate.
	// Reuse the existing LoginNameLimiter with a `verify-email:`
	// namespace so a flood of bad codes for a single user trips the
	// shared lockout machinery without crossing into the loginName
	// counter.
	rateLimitKey := "verify-email:" + userID
	if !p.LoginNameLimiter.BeginAttempt(rateLimitKey) {
		// Wave 15 observability mirror of the password-attempt path.
		logger.Warnf("event=loginname_lockout_denied key=%q reason=too_many_failed_email_verification_attempts", rateLimitKey)
		// Add jitter (10-50ms) so the rate-limit branch isn't a
		// timing oracle for "this user is locked out".
		jitterMs := 10 + (time.Now().UnixNano() % 41) // 10..50 ms
		time.Sleep(time.Duration(jitterMs) * time.Millisecond)
		c.Data(http.StatusBadRequest, "application/json", canonicalCodeInvalidResponse())
		return
	}

	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPost, "/v2/users/"+userID+"/email/verify", reqBody)
	if err != nil {
		// Transport error / 5xx — roll back the rate-limit slot so
		// honest users aren't penalised for a Zitadel outage.
		p.LoginNameLimiter.RollbackAttempt(rateLimitKey)
		logger.Errorf("Failed to verify email: %v", err)
		respondError(c, http.StatusBadGateway, "failed to verify email with identity provider")
		return
	}
	// Round 23 Finding 3 (MODERATE): canonicalize unknown-user 404
	// to a "code is invalid" 4xx so direct (non-SPA) probing can't
	// enumerate user IDs derived from F-sec-7 decoy sessions. Same
	// shape Zitadel emits for a wrong verification code on a REAL
	// user, so the attacker can't distinguish "this id doesn't
	// exist" from "this id exists but the code is wrong".
	if isLikelyUnknownUserResponse(statusCode, respBody) {
		statusCode = http.StatusBadRequest
		respBody = canonicalCodeInvalidResponse()
	}
	// On confirmed success (200), clear the failure counter so an
	// honest user who fat-fingered a few codes isn't penalised after
	// they get it right.
	if statusCode == http.StatusOK {
		p.LoginNameLimiter.Reset(rateLimitKey)
	}
	c.Data(statusCode, "application/json", respBody)
}

// --- Settings Proxy (A7) ---
// These proxy Zitadel's settings endpoints with a small TTL cache (A7-cache).
// Zitadel wraps settings responses in a container object (e.g., {"settings": {...}});
// we unwrap before caching so the cached payload is already in the shape the
// frontend expects — no repeated unwrap work on cache hits.
//
// Cache semantics:
//   - Per-path TTL from settingsTTL (login 15m, branding 1h, etc.)
//   - Cache key includes the safelisted query string (currently only
//     `ctx.orgId=<id>` is honored). Org-scoped reads exist because login
//     settings vary per-org when an org has its own policy override
//     (force-MFA / allow-register / domain-discovery overrides). Without
//     forwarding the org context, the SPA would see the instance default
//     even for users in orgs with stricter policies — silently bypassing
//     forceMfa / allow-register etc.
//   - If Zitadel 5xxs and a stale entry exists within staleWindow, serve stale
//     rather than propagate the outage to the SPA. The SPA is dead without
//     login settings, so stale here is strictly better than a 502.

// allowedSettingsQueryParams limits which incoming query params the settings
// proxy forwards to Zitadel. Anything outside this set is ignored — the
// alternative (forwarding everything) lets a hostile SPA tweak inject
// queries that change the cache key in ways we never tested.
var allowedSettingsQueryParams = map[string]struct{}{
	"ctx.orgId": {},
}

func (p *AuthProxy) settingsProxy(c *gin.Context, zitadelPath string, unwrapKey string) {
	// Filter the query string to the allowlist before building the upstream
	// path / cache key. Empty filtered query means cache-by-path (the common
	// case for instance-default reads); a present `ctx.orgId` makes the key
	// per-org so two orgs with different policies don't share a cache entry.
	filtered := url.Values{}
	for k, vs := range c.Request.URL.Query() {
		if _, ok := allowedSettingsQueryParams[k]; ok {
			for _, v := range vs {
				filtered.Add(k, v)
			}
		}
	}
	// Round 22 Finding 3: if the caller passes `ctx.orgId` matching
	// an issued decoy orgId, strip the param so the upstream call is
	// unscoped (instance-default) — same response shape an unknown
	// real org would produce post-fallback. Without this, the
	// per-org Zitadel response (404 or instance-default with a
	// different cached payload) is wire-distinguishable from a real
	// org's customized policy, recreating the F-sec-7 leak.
	if orgID := filtered.Get("ctx.orgId"); orgID != "" && p.isIssuedDecoyOrgID(orgID) {
		filtered.Del("ctx.orgId")
	}
	upstreamPath := zitadelPath
	cacheKey := zitadelPath
	if encoded := filtered.Encode(); encoded != "" {
		upstreamPath = zitadelPath + "?" + encoded
		cacheKey = upstreamPath
	}

	if cached, ok := p.settingsCache.get(cacheKey); ok {
		c.Data(http.StatusOK, "application/json", cached)
		return
	}

	// Round 25 Wave 8 (item 1 / F-chaos-2): wrap the cold-cache upstream
	// fetch in singleflight so 50 concurrent callers for the same key
	// share a single Zitadel call instead of stampeding. Each caller
	// gets the same result struct back and serves it independently.
	//
	// Round 26 Wave 9 (HIGH-2): the leader's upstream fetch uses a
	// DETACHED context (not the leader's request context). Without
	// detachment, the leader's client disconnecting mid-fetch would
	// poison every piggy-backing waiter via context.Canceled — turning
	// a single client misbehaviour into a fan-out outage. 30s timeout
	// is generous (settings calls typically <1s) but bounds the
	// in-flight goroutine if Zitadel hangs.
	type sfResult struct {
		payload    []byte
		rawBody    []byte // original body for non-200 / non-unwrap paths
		statusCode int
	}
	result, leader, sfErr := p.settingsCache.fetchOrShare(cacheKey, func() (any, error) {
		// Re-check the cache inside the singleflight: a leader might
		// just have populated it for a previous wave of waiters.
		if cached, ok := p.settingsCache.get(cacheKey); ok {
			return &sfResult{payload: cached, statusCode: http.StatusOK}, nil
		}
		fetchCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		respBody, statusCode, err := p.proxyJSON(fetchCtx, http.MethodGet, upstreamPath, nil)
		if err != nil {
			return nil, err
		}
		// Unwrap success responses before caching so hits and misses
		// return byte-identical payloads.
		if statusCode == http.StatusOK && unwrapKey != "" {
			payload := respBody
			var wrapper map[string]json.RawMessage
			if err := json.Unmarshal(respBody, &wrapper); err == nil {
				if inner, ok := wrapper[unwrapKey]; ok {
					payload = inner
				}
			}
			if ttl, ok := settingsTTL[zitadelPath]; ok {
				p.settingsCache.set(cacheKey, payload, ttl)
			}
			return &sfResult{payload: payload, statusCode: statusCode}, nil
		}
		// Non-200 or no-unwrap: pass through without caching.
		return &sfResult{rawBody: respBody, statusCode: statusCode}, nil
	})
	_ = leader

	if sfErr != nil {
		// Transport error / context cancel from upstream fetch.
		// Serve stale on Zitadel outage if we have something to serve.
		if stale, ok := p.settingsCache.stale(cacheKey); ok {
			logger.Warnf("settingsProxy: serving stale for %s (upstream err=%v)", cacheKey, sfErr)
			c.Data(http.StatusOK, "application/json", stale)
			return
		}
		logger.Errorf("Failed to proxy settings from %s: %v", upstreamPath, sfErr)
		respondError(c, http.StatusBadGateway, "failed to fetch settings from identity provider")
		return
	}

	res, ok := result.(*sfResult)
	if !ok {
		// Defensive — singleflight returned something unexpected.
		respondError(c, http.StatusBadGateway, "failed to fetch settings from identity provider")
		return
	}

	if res.statusCode >= 500 {
		// Upstream returned 5xx. Serve stale on Zitadel outage if we have something to serve.
		if stale, ok := p.settingsCache.stale(cacheKey); ok {
			logger.Warnf("settingsProxy: serving stale for %s (upstream status=%d)", cacheKey, res.statusCode)
			c.Data(http.StatusOK, "application/json", stale)
			return
		}
		c.Data(res.statusCode, "application/json", res.rawBody)
		return
	}

	if res.statusCode != http.StatusOK || unwrapKey == "" {
		c.Data(res.statusCode, "application/json", res.rawBody)
		return
	}

	c.Data(http.StatusOK, "application/json", res.payload)
}

// GetLoginSettings handles GET /auth/settings/login.
func (p *AuthProxy) GetLoginSettings(c *gin.Context) {
	p.settingsProxy(c, "/v2/settings/login", "settings")
}

// GetPasswordComplexity handles GET /auth/settings/password-complexity.
// Zitadel v4 exposes this at /v2/settings/password/complexity (not the
// camelCase path our earlier plan entry referenced).
func (p *AuthProxy) GetPasswordComplexity(c *gin.Context) {
	p.settingsProxy(c, "/v2/settings/password/complexity", "settings")
}

// GetBrandingSettings handles GET /auth/settings/branding.
func (p *AuthProxy) GetBrandingSettings(c *gin.Context) {
	p.settingsProxy(c, "/v2/settings/branding", "settings")
}

// GetPasswordExpiry handles GET /auth/settings/password-expiry.
func (p *AuthProxy) GetPasswordExpiry(c *gin.Context) {
	p.settingsProxy(c, "/v2/settings/password/expiry", "settings")
}

// GetLockoutSettings handles GET /auth/settings/lockout.
func (p *AuthProxy) GetLockoutSettings(c *gin.Context) {
	p.settingsProxy(c, "/v2/settings/lockout", "settings")
}

// GetLegalSettings handles GET /auth/settings/legal.
// Zitadel v4 path is /v2/settings/legal_support (not legalAndSupportSettings).
func (p *AuthProxy) GetLegalSettings(c *gin.Context) {
	p.settingsProxy(c, "/v2/settings/legal_support", "settings")
}

// GetSecuritySettings handles GET /auth/settings/security.
func (p *AuthProxy) GetSecuritySettings(c *gin.Context) {
	p.settingsProxy(c, "/v2/settings/security", "settings")
}

// --- Org discovery (A7.1, AC-36) ---

// lookupOrgByDomainTTL is how long a `(domain → result)` lookup is
// cached. Round 25 hardening (item 21 / R23-4 + R25b F5 + R25c H-4):
// the previous implementation hit Zitadel `/_search` on every probe,
// so an attacker scanning 10k domains burned 10k Zitadel queries.
// 60s is short enough that operator changes (allowDomainDiscovery
// flips, new orgs, primary-domain changes) propagate quickly, and
// long enough to amortise repeated probes for the same domain to one
// upstream call per minute.
const lookupOrgByDomainTTL = 60 * time.Second

// orgAllowsDomainDiscovery fetches the matched org's login policy and
// returns true iff `allowDomainDiscovery` is set. Round 25 hardening
// (item 21 / R23-4): the previous implementation didn't check this
// flag, so an unauthenticated caller could enumerate domain → org
// mappings even for orgs that explicitly opted out.
//
// Fail-closed semantics: any upstream error / unparseable response /
// missing flag returns false. The caller treats "false" as "no match"
// (mirror the empty-result branch) so the response is shape-identical
// for "domain doesn't exist" and "domain exists but org opted out" —
// no existence oracle.
func (p *AuthProxy) orgAllowsDomainDiscovery(ctx context.Context, orgID string) bool {
	if orgID == "" {
		return false
	}
	body, status, err := p.proxyJSON(ctx, http.MethodGet, "/v2/settings/login?ctx.orgId="+url.QueryEscape(orgID), nil)
	if err != nil || status != http.StatusOK {
		return false
	}
	// Unwrap the `{"settings": {...}}` envelope, same shape as
	// shouldFakeUnknownUser uses.
	var wrapper struct {
		Settings json.RawMessage `json:"settings"`
	}
	var raw []byte
	if err := json.Unmarshal(body, &wrapper); err == nil && len(wrapper.Settings) > 0 {
		raw = wrapper.Settings
	}
	if len(raw) == 0 {
		return false
	}
	var policy struct {
		AllowDomainDiscovery bool `json:"allowDomainDiscovery"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return false
	}
	return policy.AllowDomainDiscovery
}

// LookupOrgByDomain handles GET /auth/orgs/by-domain?domain=<domain>.
// Supports the allowDomainDiscovery login flow: the SPA extracts the domain
// from a login name like user@example.com and asks which org (if any) that
// domain maps to, so subsequent auth can scope to that org. Returns the
// org's id + name + primaryDomain, nothing else; intentionally does NOT
// expose member lists, settings, or other per-org metadata to unauthenticated
// callers.
//
// Round 25 hardening (item 21): two fixes here.
//
//  1. Per-org `allowDomainDiscovery` enforcement (closes R23-4 + R25b F5):
//     orgs that have explicitly opted out of domain discovery are filtered
//     from the response. From the caller's perspective the response is
//     identical to "no match" (`{"result": []}`) so the gap can't be used
//     as an existence oracle.
//
//  2. TTL cache (closes R25c H-4): the (domain → filtered-response) tuple
//     is cached for `lookupOrgByDomainTTL` (60s) in the LRU-bounded
//     `settingsCache`. An attacker probing 10k domains issues at most 10k
//     Zitadel queries (one per unique domain), and 10k probes for one
//     domain issues exactly one. Empty results are cached too so the
//     negative-result path is also amortised.
func (p *AuthProxy) LookupOrgByDomain(c *gin.Context) {
	domain := strings.TrimSpace(c.Query("domain"))
	if domain == "" {
		respondError(c, http.StatusBadRequest, "domain query parameter is required")
		return
	}

	// Zitadel domain values are lowercase; normalise so the exact-match query
	// returns the same result regardless of how the user typed their email.
	domain = strings.ToLower(domain)

	cacheKey := "orgbydomain:" + domain
	if cached, ok := p.settingsCache.get(cacheKey); ok {
		c.Data(http.StatusOK, "application/json", cached)
		return
	}

	body := map[string]any{
		"queries": []map[string]any{
			{"domainQuery": map[string]any{
				"domain": domain,
				"method": "TEXT_QUERY_METHOD_EQUALS",
			}},
		},
	}
	respBody, statusCode, err := p.proxyJSON(c.Request.Context(), http.MethodPost, "/v2/organizations/_search", body)
	if err != nil {
		logger.Errorf("Failed to look up org by domain: %v", err)
		respondError(c, http.StatusBadGateway, "failed to look up organisation")
		return
	}
	if statusCode != http.StatusOK {
		c.Data(statusCode, "application/json", respBody)
		return
	}

	// Strip the response down to just id/name/primaryDomain so we never leak
	// fields Zitadel might add later (sequence numbers, resource owners, etc.)
	// to the unauthenticated caller.
	var parsed struct {
		Result []struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			PrimaryDomain string `json:"primaryDomain"`
			State         string `json:"state"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		logger.Warnf("LookupOrgByDomain: unable to parse Zitadel response: %v", err)
		// Fail-soft: empty result + cached so a malformed-response
		// blip doesn't cause an amplifier on retry. Static byte
		// literal avoids a Marshal call that would need error
		// handling for an infallible empty-array case.
		empty := []byte(`{"result":[]}`)
		p.settingsCache.set(cacheKey, empty, lookupOrgByDomainTTL)
		c.Data(http.StatusOK, "application/json", empty)
		return
	}

	out := make([]map[string]string, 0, len(parsed.Result))
	for _, org := range parsed.Result {
		if org.State != "ORGANIZATION_STATE_ACTIVE" {
			continue
		}
		// R23-4 + R25b F5: respect the per-org `allowDomainDiscovery`
		// flag. Filter out orgs that have opted out so the unauth caller
		// can't enumerate domain → org mappings against the operator's
		// explicit policy.
		if !p.orgAllowsDomainDiscovery(c.Request.Context(), org.ID) {
			continue
		}
		out = append(out, map[string]string{
			"id":            org.ID,
			"name":          org.Name,
			"primaryDomain": org.PrimaryDomain,
		})
	}

	// Cache the filtered response so subsequent probes for the same
	// domain hit the cache. Empty results are also cached — the whole
	// point of the negative-result amortisation.
	respBytes, err := json.Marshal(gin.H{"result": out})
	if err != nil {
		// Marshal failure on a fully-typed map should never happen.
		// Fall through to direct response without caching.
		c.JSON(http.StatusOK, gin.H{"result": out})
		return
	}
	p.settingsCache.set(cacheKey, respBytes, lookupOrgByDomainTTL)
	c.Data(http.StatusOK, "application/json", respBytes)
}

// --- Notification mode helpers (DR-6) ---

// injectReturnCodeFlags modifies a session request body to use returnCode mode
// for OTP challenges so codes are returned in the API response instead of emailed/SMSed.
//
// Wave 14 (2026-05-11): Zitadel v4 changed the OTPEmailChallenge /
// OTPSMSChallenge oneof shape — `returnCode` is now a message type
// (`{}`), not a boolean. The old boolean shape blows up with
// `proto: syntax error (line 1:N): unexpected token true` at the
// grpc-gateway. Verified empirically against v4.12.3 while wiring
// up F16. The same fix is mirrored in `Otp.tsx` for the email-mode
// passthrough path.
func (p *AuthProxy) injectReturnCodeFlags(body map[string]any) {
	challenges, ok := body["challenges"].(map[string]any)
	if !ok {
		return
	}
	if _, hasOTPEmail := challenges["otpEmail"]; hasOTPEmail {
		challenges["otpEmail"] = map[string]any{"returnCode": map[string]any{}}
	}
	if _, hasOTPSMS := challenges["otpSms"]; hasOTPSMS {
		challenges["otpSms"] = map[string]any{"returnCode": map[string]any{}}
	}
}

// stripReturnCodeFlags removes any `returnCode` field from OTP challenges
// so Zitadel falls back to the default delivery channel — SMTP for email,
// the configured SMS provider for SMS. Used in email-notification mode
// (Wave 14): the SPA always sends `returnCode: {}` because it can't see
// the proxy's mode env, so the proxy strips it on the wire when running
// in email mode. An OTP challenge body with no oneof selector reduces to
// `{}` which Zitadel interprets as "use the default channel".
func (p *AuthProxy) stripReturnCodeFlags(body map[string]any) {
	challenges, ok := body["challenges"].(map[string]any)
	if !ok {
		return
	}
	for _, key := range []string{"otpEmail", "otpSms"} {
		if challenge, hasField := challenges[key].(map[string]any); hasField {
			delete(challenge, "returnCode")
			challenges[key] = challenge
		}
	}
}

// storeSessionFromResponse extracts sessionId and sessionToken from a Zitadel
// session API response and stores them in the session cookie.
//
// On create, the userId binding is fetched via a follow-up `getSession`
// call (Zitadel's createSession response carries only id+token, no user
// factor — and the binding is what userScopedProxy uses for DR-4). On
// update, we preserve any existing UserID rather than overwriting; an
// updateSession call doesn't change the bound user, only adds factors.
func (p *AuthProxy) storeSessionFromResponse(c *gin.Context, respBody json.RawMessage) {
	var resp struct {
		SessionID    string `json:"sessionId"`
		SessionToken string `json:"sessionToken"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil || resp.SessionID == "" {
		return
	}

	// Preserve the UserID on update (find by id in the existing cookie).
	// On a fresh create the entry doesn't exist yet, so we'll fetch the
	// binding below.
	entry := sessionEntry{
		ID:    resp.SessionID,
		Token: resp.SessionToken,
	}

	// F-sec-7: decoy sessions are stored directly by CreateSession's
	// fake-path (it sets Decoy=true on the entry). On a real
	// updateSession the existing cookie entry might be a decoy that
	// somehow round-tripped — preserve the flag and skip the
	// fetchSessionUserID call (the id is fake; the lookup would 404).
	if existing := p.findSessionEntry(c, resp.SessionID); existing != nil && existing.Decoy {
		entry.Decoy = true
		p.upsertSessionEntry(c, entry)
		return
	}

	if existing := p.findSessionEntry(c, resp.SessionID); existing != nil && existing.UserID != "" {
		entry.UserID = existing.UserID
	} else {
		// New session — fetch binding. Failures here MUST NOT silently
		// drop the entry: without a UserID, the cookie still works for
		// non-user-scoped endpoints (sessions/search, finalize, etc.),
		// and the next `userScopedProxy` call will refuse the request
		// rather than open a cross-user hole.
		if uid := p.fetchSessionUserID(c.Request.Context(), resp.SessionID); uid != "" {
			entry.UserID = uid
		}
	}

	p.upsertSessionEntry(c, entry)
}

// fetchSessionUserID returns the user id bound to a Zitadel session, or
// "" on error / empty factor. Used exclusively by storeSessionFromResponse
// to populate the UserID field on cookie entries.
func (p *AuthProxy) fetchSessionUserID(ctx context.Context, sessionID string) string {
	respBody, statusCode, err := p.proxyJSON(ctx, http.MethodGet, "/v2/sessions/"+sessionID, nil)
	if err != nil || statusCode != http.StatusOK {
		return ""
	}
	var parsed struct {
		Session struct {
			Factors struct {
				User struct {
					ID string `json:"id"`
				} `json:"user"`
			} `json:"factors"`
		} `json:"session"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return ""
	}
	return parsed.Session.Factors.User.ID
}
