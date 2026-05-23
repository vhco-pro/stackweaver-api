// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/michielvha/logger"
)

// backchannelLogoutEvent is the OIDC-registered event URI that must appear in
// the logout_token's events claim per OpenID Connect Back-Channel Logout 1.0.
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// logoutTokenMaxAge is the maximum wall-clock age we accept between the
// logout_token's `iat` claim and now. OIDC spec requires the RP to validate
// the token is "recent"; 5 minutes is a conservative compromise between
// clock skew between OP and RP and replay-window risk.
const logoutTokenMaxAge = 5 * time.Minute

// jwksTTL is how long a fetched JWKS set is kept in memory before a re-fetch.
// Too short and we hammer Zitadel on every backchannel call; too long and
// rotated keys take forever to pick up. 10 min matches common defaults.
const jwksTTL = 10 * time.Minute

// revokedSIDTTL is how long a sid from a valid logout_token is remembered
// as revoked. Must be at least as long as the access-token lifetime so any
// in-flight token that references that sid gets rejected on refresh.
const revokedSIDTTL = 24 * time.Hour

// seenJTITTL is how long a successfully-verified backchannel logout_token
// is remembered for replay detection. Round 25 Wave 5 (item 18 / R25a #2):
// must be at least `logoutTokenMaxAge + clockSkewSeconds` so any token
// the iat-too-old check would still accept also gets the dedup short-
// circuit. After this window the token can't be replayed anyway (the
// iat-too-old check rejects it), so the dedup entry is safe to evict.
const seenJTITTL = logoutTokenMaxAge + 60*time.Second

// seenJTICap bounds the in-memory replay-detection set so an attacker
// posting fake jtis can't grow memory unbounded. Round 25 Wave 5
// (item 18 / R25a #2). Real Zitadel jti values are random uuids — 10k
// entries × 36 bytes per uuid + map overhead ≈ ~1 MB, well within the
// per-process budget.
const seenJTICap = 10_000

// logoutTokenClaims is the subset of OIDC backchannel-logout claims we care
// about. `aud` is left as a json.RawMessage because the spec permits it to
// be either a string or an array of strings.
type logoutTokenClaims struct {
	Issuer   string          `json:"iss"`
	Audience json.RawMessage `json:"aud"`
	IssuedAt int64           `json:"iat"`
	Expiry   int64           `json:"exp"`
	JTI      string          `json:"jti"`
	Events   map[string]any  `json:"events"`
	SID      string          `json:"sid"`
	Subject  string          `json:"sub"`
	Nonce    string          `json:"nonce"`
}

// backchannelVerifier is a light-weight JWKS-backed JWT verifier scoped to
// the backchannel logout handler. Intentionally separate from the core auth
// service's verifier: that one is keyed to the API's own issuer/client, while
// this path has slightly different claim requirements (events, no nonce).
type backchannelVerifier struct {
	jwksURL          string          // Zitadel JWKS endpoint, internal address
	hostOverride     string          // external issuer host used as Host: header
	httpClient       *http.Client    // shared proxy client
	acceptedIss      map[string]bool // set of issuer values we accept
	expectedClientID string          // Round 23 Finding 1: must appear in `aud`

	mu         sync.RWMutex
	keys       []jose.JSONWebKey
	keysExpiry time.Time

	// revokedSIDs tracks sids seen in valid logout_tokens. Values are the
	// expiry time after which the entry can be reaped. A real deployment
	// would back this with Redis so multiple API replicas share state —
	// noted as a follow-up; single-replica dev is correct with the map.
	revokedSIDs sync.Map // map[string]time.Time

	// seenJTIs is the LRU-bounded jti dedup cache. Round 25 Wave 5
	// (item 18 / R25a #2): a captured valid logout_token can be
	// replayed to amplify CPU work (signature verify) on the verifier.
	// We record jti on successful verify and short-circuit subsequent
	// replays of the same jti as a fast-path success (backchannel
	// logout is idempotent — re-seeing a known-good logout token
	// should always be treated the same way).
	seenJTIsMu  sync.Mutex
	seenJTIs    map[string]*list.Element // jti → list element with expiry
	seenJTIsLRU *list.List               // MRU at front
	seenJTIsCap int
}

// seenJTIEntry is the value stored in the seenJTIs LRU. Round 25 Wave 5
// (item 18 / R25a #2): we cache sid + sub alongside jti so a replay
// short-circuit can return the original claims rather than synthetic
// empty ones — RevokeSID gets called again (idempotent), logging stays
// accurate, and the contract ("logout_token returned valid claims")
// holds for callers that inspect SID/Subject.
type seenJTIEntry struct {
	jti     string
	sid     string
	subject string
	expiry  time.Time
}

// newBackchannelVerifier constructs the verifier. `expectedClientID` is the
// OIDC client_id this RP is registered under at Zitadel — Round 23 Finding 1
// requires that any accepted logout_token's `aud` contain this value, per
// OIDC Back-Channel Logout 1.0 §2.6 step 4. Empty string DISABLES audience
// binding (legacy behaviour, retained only so existing tests that don't
// know an `aud` need not be rewritten — production callers MUST pass the
// real client id).
//
// Round 25 hardening (item 26): all accepted issuers are canonicalised
// at construction time (TrimSpace, TrimRight `/`, lowercase host
// portion) so issuer comparison at verify-time is symmetric. RFC 3986
// §3.2.2 says host components are case-insensitive, and an operator
// typo (trailing space, mixed-case host) shouldn't bork verification.
// `expectedClientID` is canonicalised the same way.
func newBackchannelVerifier(jwksURL, hostOverride, expectedClientID string, client *http.Client, acceptedIssuers ...string) *backchannelVerifier {
	iss := make(map[string]bool, len(acceptedIssuers))
	for _, s := range acceptedIssuers {
		if c := canonicalIssuer(s); c != "" {
			iss[c] = true
		}
	}
	return &backchannelVerifier{
		jwksURL:          jwksURL,
		hostOverride:     hostOverride,
		httpClient:       client,
		acceptedIss:      iss,
		expectedClientID: strings.TrimSpace(expectedClientID),
		seenJTIs:         make(map[string]*list.Element),
		seenJTIsLRU:      list.New(),
		seenJTIsCap:      seenJTICap,
	}
}

// rememberJTI records jti + sid + sub in the seen-set so future replays
// of the same token are short-circuited and surfaced with the original
// claims. Caller MUST hold no other locks. Round 25 Wave 5 (item 18 /
// R25a #2).
func (b *backchannelVerifier) rememberJTI(jti, sid, sub string) {
	if jti == "" || b.seenJTIsCap <= 0 {
		return
	}
	b.seenJTIsMu.Lock()
	defer b.seenJTIsMu.Unlock()
	if el, ok := b.seenJTIs[jti]; ok {
		// Already recorded; just bump expiry + MRU.
		entry := el.Value.(*seenJTIEntry)
		entry.expiry = time.Now().Add(seenJTITTL)
		entry.sid = sid
		entry.subject = sub
		b.seenJTIsLRU.MoveToFront(el)
		return
	}
	entry := &seenJTIEntry{jti: jti, sid: sid, subject: sub, expiry: time.Now().Add(seenJTITTL)}
	el := b.seenJTIsLRU.PushFront(entry)
	b.seenJTIs[jti] = el
	if b.seenJTIsLRU.Len() > b.seenJTIsCap {
		victim := b.seenJTIsLRU.Back()
		if victim != nil {
			b.seenJTIsLRU.Remove(victim)
			delete(b.seenJTIs, victim.Value.(*seenJTIEntry).jti)
		}
	}
}

// lookupJTI returns the cached entry if jti is in the dedup set and
// still within its TTL. Returns nil (and prunes the entry) if expired.
func (b *backchannelVerifier) lookupJTI(jti string) *seenJTIEntry {
	if jti == "" {
		return nil
	}
	b.seenJTIsMu.Lock()
	defer b.seenJTIsMu.Unlock()
	el, ok := b.seenJTIs[jti]
	if !ok {
		return nil
	}
	entry := el.Value.(*seenJTIEntry)
	if time.Now().After(entry.expiry) {
		b.seenJTIsLRU.Remove(el)
		delete(b.seenJTIs, jti)
		return nil
	}
	b.seenJTIsLRU.MoveToFront(el)
	return entry
}

// peekJTI extracts the `jti` claim from a JWS payload without verifying
// the signature. Used as a fast-path replay-detection check before the
// expensive signature verify. The unverified jti is only used as an
// LRU lookup key — an attacker forging a jti that happens to collide
// with a real cached one would simply trigger a benign short-circuit
// success response (backchannel logout is idempotent), not a security
// bypass. The LRU bound prevents cache poisoning.
func peekJTIUnverified(jws *jose.JSONWebSignature) string {
	if jws == nil || len(jws.Signatures) == 0 {
		return ""
	}
	// jose's `UnsafePayloadWithoutVerification` returns the payload
	// bytes without checking the signature — exactly what we want
	// here, where we only need a non-trust-load lookup key.
	payload := jws.UnsafePayloadWithoutVerification()
	if len(payload) == 0 {
		return ""
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.JTI
}

// canonicalIssuer normalises an issuer URL for symmetric comparison.
// Strips surrounding whitespace, trailing slashes, and lowercases the
// scheme + host portion (RFC 3986 §3.2.2 — host is case-insensitive).
// Path is preserved verbatim because some IdPs use case-sensitive path
// segments (Zitadel's default `/oauth/v2` is lowercase, but the
// canonicalisation can't safely assume that for every operator).
func canonicalIssuer(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "/")
	if s == "" {
		return ""
	}
	// Find the path boundary so we only lowercase scheme+host.
	// Format is `<scheme>://<host>[:port][/path]`.
	schemeEnd := strings.Index(s, "://")
	if schemeEnd < 0 {
		// Doesn't look like a URL — best-effort lowercase the whole thing.
		return strings.ToLower(s)
	}
	hostStart := schemeEnd + 3
	pathStart := strings.IndexByte(s[hostStart:], '/')
	if pathStart < 0 {
		// scheme://host[:port] only.
		return strings.ToLower(s)
	}
	pathStart += hostStart
	return strings.ToLower(s[:pathStart]) + s[pathStart:]
}

// verifyLogoutToken parses and validates a backchannel logout_token per OIDC
// Back-Channel Logout 1.0 §2.6. Returns the validated claims on success; any
// non-nil error means the token must be rejected and no action taken.
//
// Round 25 Wave 5 (item 18 / R25a #2): a fast-path replay-detection
// gate runs after JWS parse but BEFORE signature verify. A repeated
// jti returns the previously-cached claims as a synthetic success
// (backchannel logout is idempotent — we already RevokeSID'd the
// session on the first call, so a replay is a no-op anyway). The
// unverified jti is only used as an LRU lookup key; an attacker
// forging a jti can at most trigger a benign short-circuit, not
// bypass auth. The LRU bound prevents cache poisoning by attacker-
// controlled jti values, since real jtis recently in the cache get
// promoted on each replay.
func (b *backchannelVerifier) verifyLogoutToken(ctx context.Context, raw string) (*logoutTokenClaims, error) {
	if strings.Count(raw, ".") != 2 {
		return nil, fmt.Errorf("logout_token is not a JWS")
	}

	supported := []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256}
	jws, err := jose.ParseSigned(raw, supported)
	if err != nil {
		return nil, fmt.Errorf("parse logout_token: %w", err)
	}

	// Round 25 Wave 5 (item 18 / R25a #2): replay-detection fast-path.
	// Read the unverified jti and short-circuit if we've already seen
	// it. The cached entry carries sid + sub from the original verify,
	// so the synthetic claims surfaced to handleBackchannelLogout
	// preserve the contract (RevokeSID is called again — idempotent —
	// and logging stays accurate). The peek is "unverified" but the
	// jti is only used as an LRU lookup key, not for any trust
	// decision.
	if jti := peekJTIUnverified(jws); jti != "" {
		if cached := b.lookupJTI(jti); cached != nil {
			return &logoutTokenClaims{JTI: cached.jti, SID: cached.sid, Subject: cached.subject}, nil
		}
	}

	payload, err := b.verifySignature(ctx, jws)
	if err != nil {
		return nil, err
	}

	var claims logoutTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decode logout_token claims: %w", err)
	}

	// §2.6 checks — these run in order of cheapest-to-most-expensive and each
	// returns a distinct error so tests can pin the exact rejection reason.
	// Round 25 hardening (item 26): canonicalise the claim-side issuer the
	// same way the accepted-set was canonicalised so trivial whitespace /
	// case differences in the host portion don't bork verification.
	if !b.acceptedIss[canonicalIssuer(claims.Issuer)] {
		return nil, fmt.Errorf("logout_token issuer %q not accepted", claims.Issuer)
	}
	if len(claims.Audience) == 0 {
		return nil, fmt.Errorf("logout_token missing audience")
	}
	// Round 23 Finding 1 (HIGH): OIDC Back-Channel Logout 1.0 §2.6
	// step 4 requires the RP to verify its own client_id is in the
	// audience set. Without this, any Zitadel-signed logout_token
	// issued for ANY other registered RP on the same Zitadel instance
	// would terminate sessions in this app — cross-RP forced-logout
	// DoS. The `aud` claim per spec may be either a JSON string or a
	// JSON array of strings; handle both.
	if b.expectedClientID != "" {
		auds, err := parseAudienceClaim(claims.Audience)
		if err != nil {
			return nil, fmt.Errorf("logout_token audience: %w", err)
		}
		matched := false
		for _, a := range auds {
			if a == b.expectedClientID {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("logout_token audience does not contain this RP's client_id")
		}
	}
	if claims.IssuedAt == 0 {
		return nil, fmt.Errorf("logout_token missing iat")
	}
	now := time.Now().Unix()
	if claims.IssuedAt > now+int64(clockSkewSeconds) {
		return nil, fmt.Errorf("logout_token issued in the future")
	}
	if now-claims.IssuedAt > int64(logoutTokenMaxAge/time.Second) {
		return nil, fmt.Errorf("logout_token too old")
	}
	if claims.Expiry != 0 && now > claims.Expiry+int64(clockSkewSeconds) {
		return nil, fmt.Errorf("logout_token expired")
	}
	if _, ok := claims.Events[backchannelLogoutEvent]; !ok {
		return nil, fmt.Errorf("logout_token missing backchannel-logout event")
	}
	if claims.Nonce != "" {
		// §2.4: logout_token MUST NOT include a nonce claim.
		return nil, fmt.Errorf("logout_token must not contain nonce claim")
	}
	if claims.SID == "" && claims.Subject == "" {
		return nil, fmt.Errorf("logout_token must contain sid or sub")
	}

	// Round 25 Wave 5 (item 18 / R25a #2): record the jti + sid + sub
	// on success so subsequent replays of this token short-circuit
	// the signature verify AND surface the original claims to the
	// caller. Empty jti is a no-op (older Zitadel versions may not
	// emit one — we simply don't dedup those tokens).
	b.rememberJTI(claims.JTI, claims.SID, claims.Subject)

	return &claims, nil
}

// clockSkewSeconds tolerates ±30s between the OP and RP clocks. Matches the
// same tolerance used elsewhere in the proxy (e.g. max_age enforcement).
const clockSkewSeconds = 30

// parseAudienceClaim handles JWT's `aud` shape ambiguity per RFC 7519 §4.1.3:
// the value may be a single string OR an array of strings. Round 23 Finding 1
// uses this for client-id binding on logout_tokens. Returns a normalized
// []string so callers can do a flat membership check.
func parseAudienceClaim(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty audience")
	}
	// Try the array shape first — most common from Zitadel.
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	// Fall back to single string.
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}, nil
	}
	return nil, fmt.Errorf("audience is neither string nor array of strings")
}

// verifySignature returns the JWS payload if and only if the signature is
// valid under one of Zitadel's currently published JWKS keys.
//
// Round 25 hardening (item 17 / R25a #1): on signature failure, if the
// JWS's `kid` header references a key not in our cached JWKS, force one
// JWKS refresh and retry exactly once. Without this, a Zitadel key
// rotation triggers up to a `jwksTTL` window (10 min) of failed
// verifications until the cache expires naturally. The single-retry
// guard + kid-not-cached gate together prevent an attacker posting
// garbage tokens from farming JWKS refreshes — a token whose kid IS
// in the cache and still fails verify is a real bad signature, not a
// rotation, so we don't refresh on it.
func (b *backchannelVerifier) verifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	payload, lastErr, err := b.tryVerify(ctx, jws, false)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		return payload, nil
	}

	// First pass failed. Decide whether to force-refresh.
	if !b.kidUnknown(jws) {
		if lastErr != nil {
			return nil, fmt.Errorf("signature invalid: %w", lastErr)
		}
		return nil, fmt.Errorf("no usable JWKS keys")
	}

	logger.Infof("backchannelVerifier: kid not in cached JWKS — forcing one refresh and retrying")
	payload, lastErr, err = b.tryVerify(ctx, jws, true)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		return payload, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("signature invalid (post-refresh): %w", lastErr)
	}
	return nil, fmt.Errorf("no usable JWKS keys (post-refresh)")
}

// tryVerify runs one verification pass. `forceRefresh=true` bypasses
// the JWKS TTL cache and re-fetches from Zitadel. Returns (payload,
// lastVerifyErr, fetchErr) — `payload != nil` means success; both nil
// means "no key matched, no verify error captured" (empty JWKS edge).
func (b *backchannelVerifier) tryVerify(ctx context.Context, jws *jose.JSONWebSignature, forceRefresh bool) ([]byte, error, error) {
	keys, err := b.getKeys(ctx, forceRefresh)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	var lastErr error
	for _, key := range keys {
		if key.Key == nil {
			continue
		}
		if payload, vErr := jws.Verify(key.Key); vErr == nil {
			return payload, nil, nil
		} else {
			lastErr = vErr
		}
	}
	return nil, lastErr, nil
}

// kidUnknown reports whether the JWS references a kid that is NOT in
// the currently cached JWKS. Returns true when the kid header is empty
// (we treat unknown-kid and missing-kid the same — both warrant a
// refresh attempt). Read-only on the cache; safe to call after
// tryVerify failed.
//
// Reads the kid from the PROTECTED header — go-jose's `Signature.Header`
// is the merged (protected + unprotected) view and is documented as
// "may or may not have been signed and in general should not be
// trusted." For OIDC backchannel logout JWTs (compact serialization)
// the kid is always in the protected header per JWS spec, so falling
// through `Protected.KeyID` is correct AND safer than the merged view.
func (b *backchannelVerifier) kidUnknown(jws *jose.JSONWebSignature) bool {
	if len(jws.Signatures) == 0 {
		return true
	}
	kid := jws.Signatures[0].Protected.KeyID
	if kid == "" {
		// Defense in depth: fall through to the merged header in case
		// a future Zitadel change moves kid to the unprotected header.
		// Worst case is we attempt a refresh on a token that doesn't
		// warrant one — bounded by the single-retry guard.
		kid = jws.Signatures[0].Header.KeyID
	}
	if kid == "" {
		return true
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, k := range b.keys {
		if k.KeyID == kid {
			return false
		}
	}
	return true
}

// getKeys returns the cached JWKS or re-fetches from Zitadel if stale.
// `forceRefresh=true` bypasses the TTL check (Round 25 item 17 /
// R25a #1 — used by tryVerify to recover from a Zitadel key rotation
// that happened before the natural cache expiry).
func (b *backchannelVerifier) getKeys(ctx context.Context, forceRefresh bool) ([]jose.JSONWebKey, error) {
	if !forceRefresh {
		b.mu.RLock()
		if len(b.keys) > 0 && time.Now().Before(b.keysExpiry) {
			keys := b.keys
			b.mu.RUnlock()
			return keys, nil
		}
		b.mu.RUnlock()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	if b.hostOverride != "" {
		req.Host = b.hostOverride
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("backchannelVerifier: close JWKS body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS returned HTTP %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("empty JWKS")
	}

	b.mu.Lock()
	b.keys = jwks.Keys
	b.keysExpiry = time.Now().Add(jwksTTL)
	b.mu.Unlock()

	return jwks.Keys, nil
}

// RevokeSID records sid as revoked until its revocation TTL elapses. Look-ups
// via IsSIDRevoked will return true in that window.
func (b *backchannelVerifier) RevokeSID(sid string) {
	if sid == "" {
		return
	}
	b.revokedSIDs.Store(sid, time.Now().Add(revokedSIDTTL))
}

// IsSIDRevoked reports whether sid has been backchannel-logged-out and still
// has revocation remaining.
func (b *backchannelVerifier) IsSIDRevoked(sid string) bool {
	v, ok := b.revokedSIDs.Load(sid)
	if !ok {
		return false
	}
	expiry, _ := v.(time.Time)
	if time.Now().After(expiry) {
		b.revokedSIDs.Delete(sid)
		return false
	}
	return true
}

// handleBackchannelLogout validates an incoming OIDC backchannel logout_token
// and, if valid, records the referenced sid as revoked so subsequent session
// refresh attempts referencing it are rejected. Per OIDC Back-Channel Logout
// 1.0 §2.8 the RP returns:
//   - 200 with Cache-Control: no-store on success
//   - 400 Bad Request with a JSON error object on failure
//
// Method is on AuthProxy (not backchannelVerifier) so it can touch the Gin
// context and gain future access to shared state (metrics, session cache).
func (p *AuthProxy) handleBackchannelLogout(c *gin.Context, token string) {
	claims, err := p.getBackchannelVerifier().verifyLogoutToken(c.Request.Context(), token)
	if err != nil {
		logger.Warnf("backchannel logout rejected: %v", err)
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	if claims.SID != "" {
		p.getBackchannelVerifier().RevokeSID(claims.SID)
		logger.Infof("backchannel logout accepted: sid=%s sub=%s", claims.SID, claims.Subject)
	} else {
		// Subject-only logout is a hint to invalidate all sessions for that user
		// across this RP. We don't maintain a sub→sid map yet; log and move on.
		// Treating this as success matches OIDC guidance ("RP MUST make a best
		// effort") — the JWT was valid, we just can't act on it.
		logger.Infof("backchannel logout accepted (sub-only): sub=%s", claims.Subject)
	}

	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
}
