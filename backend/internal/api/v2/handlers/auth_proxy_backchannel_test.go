// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// backchannelTestRig wires a test JWKS server, a signing key, and a
// preconfigured verifier. Returned components let each test drop in its own
// claims and toggle headers without rebuilding the fixture from scratch.
type backchannelTestRig struct {
	issuer       string
	clientID     string
	signer       jose.Signer
	jwksServer   *httptest.Server
	verifier     *backchannelVerifier
	signingKeyID string
}

func newBackchannelTestRig(t *testing.T) *backchannelTestRig {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}

	keyID := "test-key-1"
	pubJWK := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(jwksServer.Close)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: priv, KeyID: keyID}},
		(&jose.SignerOptions{}).WithType("logout+jwt"),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	const issuer = "https://zitadel.example.com"
	const clientID = "test-client"
	verifier := newBackchannelVerifier(jwksServer.URL, "", clientID, http.DefaultClient, issuer)

	return &backchannelTestRig{
		issuer:       issuer,
		clientID:     clientID,
		signer:       signer,
		jwksServer:   jwksServer,
		verifier:     verifier,
		signingKeyID: keyID,
	}
}

// sign encodes claims as a signed JWT using the rig's key.
func (r *backchannelTestRig) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	raw, err := jwt.Signed(r.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

// validClaims returns a baseline claim set the tests can mutate.
func (r *backchannelTestRig) validClaims() map[string]any {
	return map[string]any{
		"iss": r.issuer,
		"aud": r.clientID,
		"iat": time.Now().Unix(),
		"jti": "test-jti",
		"sub": "user-1",
		"sid": "sess-abc",
		"events": map[string]any{
			backchannelLogoutEvent: map[string]any{},
		},
	}
}

func TestBackchannel_Verify_HappyPath(t *testing.T) {
	r := newBackchannelTestRig(t)
	token := r.sign(t, r.validClaims())

	claims, err := r.verifier.verifyLogoutToken(context.Background(), token)
	if err != nil {
		t.Fatalf("expected valid logout_token, got error: %v", err)
	}
	if claims.SID != "sess-abc" {
		t.Errorf("expected sid=sess-abc, got %q", claims.SID)
	}
}

// Each of these negative cases tests a distinct spec-required rejection. The
// table pattern makes it cheap to add new ones when we harden further.
func TestBackchannel_Verify_RejectsMalformedTokens(t *testing.T) {
	r := newBackchannelTestRig(t)

	// Separate signer with a different key — used for "forged signature" case.
	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	otherSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: otherPriv, KeyID: "evil-key"}},
		(&jose.SignerOptions{}).WithType("logout+jwt"),
	)
	if err != nil {
		t.Fatalf("other signer: %v", err)
	}
	forged, err := jwt.Signed(otherSigner).Claims(r.validClaims()).Serialize()
	if err != nil {
		t.Fatalf("forge: %v", err)
	}

	// Build the unsigned version by mutating the algorithm in the header — a
	// real attacker would try `alg: none`. The library refuses to construct
	// such tokens; we synthesize the JWS manually.
	unsigned := strings.Join([]string{
		// {"alg":"none","typ":"JWT"}
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
		// base64url-encode the baseline claims inline would make this test
		// brittle; "" is sufficient — the parser rejects non-3-part tokens
		// before claim parsing.
		"",
		"",
	}, ".")

	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"empty", "", "not a JWS"},
		{"not a jwt", "not.a.jwt.at.all", "not a JWS"},
		{"two segments", "a.b", "not a JWS"},
		{"unsigned (alg=none)", unsigned, "parse logout_token"},
		{"forged signature", forged, "signature"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.verifier.verifyLogoutToken(context.Background(), tc.token)
			if err == nil {
				t.Fatal("expected rejection, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestBackchannel_Verify_RejectsClaimViolations(t *testing.T) {
	r := newBackchannelTestRig(t)

	cases := []struct {
		name    string
		mutate  func(c map[string]any)
		wantSub string
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://evil.example.com" }, "issuer"},
		{"missing iat", func(c map[string]any) { delete(c, "iat") }, "missing iat"},
		{"iat in future", func(c map[string]any) { c["iat"] = time.Now().Add(10 * time.Minute).Unix() }, "future"},
		{"iat too old", func(c map[string]any) { c["iat"] = time.Now().Add(-1 * time.Hour).Unix() }, "too old"},
		{"expired", func(c map[string]any) {
			c["iat"] = time.Now().Add(-90 * time.Second).Unix()
			c["exp"] = time.Now().Add(-2 * time.Minute).Unix()
		}, "expired"},
		{"no events", func(c map[string]any) { c["events"] = map[string]any{"other:event": map[string]any{}} }, "event"},
		{"has nonce", func(c map[string]any) { c["nonce"] = "don't put a nonce in a logout token" }, "nonce"},
		{"no sid or sub", func(c map[string]any) { delete(c, "sid"); delete(c, "sub") }, "sid or sub"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := r.validClaims()
			tc.mutate(c)
			token := r.sign(t, c)

			_, err := r.verifier.verifyLogoutToken(context.Background(), token)
			if err == nil {
				t.Fatal("expected rejection, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

// TestBackchannel_EndSessionDispatch verifies that a POST to /auth/oidc/end-session
// with a valid logout_token is handled locally (SID recorded, 200 returned)
// and does NOT get forwarded to the Zitadel mock.
func TestBackchannel_EndSessionDispatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := newBackchannelTestRig(t)

	zitadelCalled := false
	mockZitadel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		zitadelCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer mockZitadel.Close()

	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: mockZitadel.URL,
		ZitadelIssuer:      r.issuer,
		PAT:                "pat",
	})
	// Inject the test verifier so we don't need to wire a JWKS server at the
	// proxy's ZitadelInternalURL.
	proxy.backchannelVerifier = r.verifier
	proxy.backchannelVerifierOnce.Do(func() {})

	token := r.sign(t, r.validClaims())

	body := fmt.Sprintf("logout_token=%s", token)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/oidc/end-session", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	proxy.EndSession(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if zitadelCalled {
		t.Error("backchannel logout must NOT be forwarded to Zitadel")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("expected Cache-Control: no-store, got %q", w.Header().Get("Cache-Control"))
	}
	if !proxy.IsBackchannelRevoked("sess-abc") {
		t.Error("sid should have been recorded as revoked")
	}
}

// TestBackchannel_EndSessionDispatch_Forged verifies a forged/bad JWT is
// rejected (400) without being forwarded to Zitadel and without revoking
// any sid.
func TestBackchannel_EndSessionDispatch_Forged(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := newBackchannelTestRig(t)

	mockZitadel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("Zitadel must not be called when logout_token is bad")
		w.WriteHeader(http.StatusOK)
	}))
	defer mockZitadel.Close()

	proxy := NewAuthProxy(AuthProxyConfig{
		ZitadelInternalURL: mockZitadel.URL,
		ZitadelIssuer:      r.issuer,
		PAT:                "pat",
	})
	proxy.backchannelVerifier = r.verifier
	proxy.backchannelVerifierOnce.Do(func() {})

	// Forged: bad issuer.
	bad := r.validClaims()
	bad["iss"] = "https://evil.example.com"
	token := r.sign(t, bad)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/oidc/end-session",
		strings.NewReader("logout_token="+token))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	proxy.EndSession(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if proxy.IsBackchannelRevoked("sess-abc") {
		t.Error("sid must NOT be revoked when token is forged")
	}
}

// --- Audit Round 23 ---

// TestBackchannel_RejectsWrongAudience: Round 23 Finding 1 (HIGH).
// A logout_token whose `aud` does NOT contain THIS RP's client_id
// must be rejected, even if signed by the trusted Zitadel JWKS and
// otherwise well-formed. Previously the verifier only checked
// `len(aud) > 0` — any logout_token issued for ANY other RP on the
// same Zitadel instance would have terminated sessions in this app.
func TestBackchannel_RejectsWrongAudience(t *testing.T) {
	r := newBackchannelTestRig(t)

	cases := []struct {
		name string
		aud  any
	}{
		{"single string, wrong client", "some-other-client"},
		{"array of strings, all other clients", []string{"some-other-client", "yet-another-client"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := r.validClaims()
			c["aud"] = tc.aud
			token := r.sign(t, c)

			_, err := r.verifier.verifyLogoutToken(context.Background(), token)
			if err == nil {
				t.Fatal("expected rejection (wrong audience), got nil")
			}
			if !strings.Contains(err.Error(), "audience") {
				t.Errorf("error %q does not mention audience binding", err)
			}
		})
	}
}

// TestBackchannel_AcceptsAudienceArrayContainingClientID: positive case
// for the array shape — when this RP's client_id IS in the audience
// list (alongside others), the token is still accepted. Pins that
// the new audience check doesn't break the legitimate multi-aud
// scenario (some IdPs include both the RP's client_id AND a service
// audience).
func TestBackchannel_AcceptsAudienceArrayContainingClientID(t *testing.T) {
	r := newBackchannelTestRig(t)
	c := r.validClaims()
	c["aud"] = []string{"another-client", r.clientID, "third-aud"}
	token := r.sign(t, c)

	if _, err := r.verifier.verifyLogoutToken(context.Background(), token); err != nil {
		t.Fatalf("audience array containing client_id must be accepted, got: %v", err)
	}
}

// TestBackchannel_EmptyExpectedClientIDDisablesAudienceBinding: belt-
// and-braces test for the legacy fallback. When `expectedClientID`
// is empty (e.g. dev configurations that haven't wired the client
// id), the verifier reverts to the pre-Round-23 behaviour of just
// checking `aud` is non-empty. Production configurations MUST set
// the client id; this test pins the explicit opt-out semantics so
// a future refactor can't silently re-enable binding when the
// caller forgot to set it.
func TestBackchannel_EmptyExpectedClientIDDisablesAudienceBinding(t *testing.T) {
	r := newBackchannelTestRig(t)
	r.verifier.expectedClientID = "" // simulate legacy/unconfigured caller

	c := r.validClaims()
	c["aud"] = "some-other-client"
	token := r.sign(t, c)

	if _, err := r.verifier.verifyLogoutToken(context.Background(), token); err != nil {
		t.Errorf("with empty expectedClientID, any non-empty aud must be accepted; got: %v", err)
	}
}

// TestParseAudienceClaim covers the JWT `aud` shape ambiguity per
// RFC 7519 §4.1.3 (string OR array of strings). The audience-binding
// check depends on this normalization.
func TestParseAudienceClaim(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{"single string", `"client-1"`, []string{"client-1"}, false},
		{"array of one", `["client-1"]`, []string{"client-1"}, false},
		{"array of multiple", `["client-1","client-2"]`, []string{"client-1", "client-2"}, false},
		{"empty array", `[]`, []string{}, false},
		{"empty raw", ``, nil, true},
		{"object (invalid shape)", `{"client":"a"}`, nil, true},
		{"number (invalid)", `123`, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAudienceClaim([]byte(tc.raw))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("length: want %d, got %d (%v)", len(tc.want), len(got), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("[%d]: want %q, got %q", i, tc.want[i], got[i])
				}
			}
		})
	}
}

func TestBackchannel_RevokedSIDTTL(t *testing.T) {
	v := newBackchannelVerifier("", "", "", http.DefaultClient, "https://issuer")
	if v.IsSIDRevoked("x") {
		t.Fatal("unrevoked sid reported revoked")
	}
	v.RevokeSID("x")
	if !v.IsSIDRevoked("x") {
		t.Fatal("freshly-revoked sid not reported")
	}
	// Force-expire the entry and confirm the lazy cleanup kicks in.
	v.revokedSIDs.Store("x", time.Now().Add(-time.Minute))
	if v.IsSIDRevoked("x") {
		t.Fatal("expired revocation should no longer be reported")
	}
}

// Round 25 hardening (item 26 / R25b F4): pin canonicalIssuer's
// behaviour so the verifier accepts trivial whitespace / case
// differences in the host portion without false rejections, but
// preserves path case (some IdPs use case-sensitive paths).
func TestCanonicalIssuer(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"just whitespace", "   ", ""},
		{"trailing slash stripped", "https://zitadel.example.com/", "https://zitadel.example.com"},
		{"surrounding whitespace stripped", "  https://zitadel.example.com  ", "https://zitadel.example.com"},
		{"mixed-case host lowercased", "https://ZITADEL.Example.com", "https://zitadel.example.com"},
		{"scheme lowercased", "HTTPS://zitadel.example.com", "https://zitadel.example.com"},
		{"path case preserved", "https://Zitadel.example.com/Oauth/V2", "https://zitadel.example.com/Oauth/V2"},
		{"port preserved", "HTTPS://EXAMPLE.com:8443/path", "https://example.com:8443/path"},
		{"no scheme falls back to whole-string lowercase", "ZITADEL.EXAMPLE.COM", "zitadel.example.com"},
		{"trailing slash + uppercase host together", "HTTPS://ZITADEL.EXAMPLE.COM/", "https://zitadel.example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := canonicalIssuer(tc.in); got != tc.want {
				t.Errorf("canonicalIssuer(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Round 25 hardening (item 26 / R25b F4): the verifier must accept a
// claim-side issuer that differs from the configured value by trivial
// whitespace / case in the host portion. Pre-fix this would have been
// rejected for asymmetric canonicalisation; post-fix the canonical
// comparison normalises both sides.
func TestBackchannel_Verify_AcceptsCanonicallyEquivalentIssuer(t *testing.T) {
	r := newBackchannelTestRig(t)
	claims := r.validClaims()
	// Same issuer the rig configured, but with mixed-case host + a
	// trailing slash. Pre-Round-25 this would have rejected on
	// `acceptedIss` lookup miss; post-fix canonicalIssuer normalises.
	claims["iss"] = "HTTPS://ZITADEL.Example.com/"
	token := r.sign(t, claims)
	if _, err := r.verifier.verifyLogoutToken(context.Background(), token); err != nil {
		t.Errorf("expected canonically-equivalent issuer to be accepted, got: %v", err)
	}
}

// Round 25 hardening (item 17 / R25a #1): when a JWS references a
// `kid` not in the cached JWKS (Zitadel rotated keys mid-cache-TTL),
// the verifier must force one JWKS refresh and retry exactly once.
// Without this, key rotation triggers up to a `jwksTTL` window of
// failed verifications.
func TestBackchannel_Verify_KidRotation_ForceRefreshAndRetry(t *testing.T) {
	// Stand up a JWKS server that initially serves key-A, then after
	// a flag flip serves key-B. Sign the token with key-B (the new
	// rotated key) so the cached key-A fails verify and the kid
	// (key-B) is not in the cache → force-refresh path triggers.
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate keyA: %v", err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate keyB: %v", err)
	}

	jwksA := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &keyA.PublicKey, KeyID: "key-a", Algorithm: string(jose.RS256), Use: "sig"},
	}}
	jwksB := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &keyB.PublicKey, KeyID: "key-b", Algorithm: string(jose.RS256), Use: "sig"},
	}}

	rotated := false
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if rotated {
			_ = json.NewEncoder(w).Encode(jwksB)
		} else {
			_ = json.NewEncoder(w).Encode(jwksA)
		}
	}))
	defer jwksServer.Close()

	const issuer = "https://zitadel.example.com"
	const clientID = "test-client"
	v := newBackchannelVerifier(jwksServer.URL, "", clientID, http.DefaultClient, issuer)

	// Warm the cache with keyA.
	if _, err := v.getKeys(context.Background(), false); err != nil {
		t.Fatalf("initial getKeys: %v", err)
	}

	// Now rotate to keyB on the JWKS server side and sign with keyB.
	rotated = true
	signerB, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: keyB, KeyID: "key-b"}},
		(&jose.SignerOptions{}).WithType("logout+jwt"),
	)
	if err != nil {
		t.Fatalf("signerB: %v", err)
	}
	claims := map[string]any{
		"iss": issuer,
		"aud": clientID,
		"iat": time.Now().Unix(),
		"jti": "rot-1",
		"sub": "user-1",
		"sid": "sess-rot",
		"events": map[string]any{
			backchannelLogoutEvent: map[string]any{},
		},
	}
	token, err := jwt.Signed(signerB).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify must succeed via the force-refresh path: cached key-A
	// fails verify → kid `key-b` not in cache → refresh → key-b
	// fetched → verify succeeds on retry.
	got, err := v.verifyLogoutToken(context.Background(), token)
	if err != nil {
		t.Fatalf("expected verify to succeed via force-refresh, got: %v", err)
	}
	if got.SID != "sess-rot" {
		t.Errorf("sid: want sess-rot, got %q", got.SID)
	}
}

// Round 25 hardening (item 17 / R25a #1): the force-refresh guard MUST
// only fire when the kid is unknown — a known kid that fails verify is
// a real bad signature, not a rotation, and must NOT trigger a refresh
// (or an attacker posting garbage tokens with the right kid could farm
// JWKS refreshes).
func TestBackchannel_Verify_KnownKidBadSig_DoesNotRefresh(t *testing.T) {
	// Track JWKS fetch count.
	var fetches int
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate keyA: %v", err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate keyB: %v", err)
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &keyA.PublicKey, KeyID: "key-a", Algorithm: string(jose.RS256), Use: "sig"},
	}}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	const issuer = "https://zitadel.example.com"
	v := newBackchannelVerifier(jwksServer.URL, "", "test-client", http.DefaultClient, issuer)

	// Warm cache (1 fetch).
	if _, err := v.getKeys(context.Background(), false); err != nil {
		t.Fatalf("initial getKeys: %v", err)
	}
	wantInitial := fetches

	// Sign a token with keyB but advertise kid `key-a` (which IS in
	// the cache). Verify will fail — but kidUnknown returns false,
	// so we MUST NOT refresh.
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: keyB, KeyID: "key-a"}},
		(&jose.SignerOptions{}).WithType("logout+jwt"),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	claims := map[string]any{
		"iss": issuer,
		"aud": "test-client",
		"iat": time.Now().Unix(),
		"jti": "bad-1",
		"sub": "user-1",
		"sid": "sess-bad",
		"events": map[string]any{
			backchannelLogoutEvent: map[string]any{},
		},
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := v.verifyLogoutToken(context.Background(), token); err == nil {
		t.Fatal("expected forged-but-known-kid token to be rejected")
	}
	if fetches != wantInitial {
		t.Errorf("known-kid bad-sig must not trigger JWKS refresh: fetches=%d, want=%d", fetches, wantInitial)
	}
}

// Round 25 Wave 5 (item 18 / R25a #2): replaying a previously-verified
// logout_token must short-circuit the signature verify (CPU-amplifier
// guard) AND surface the original sid + sub (idempotent contract).
// We track JWKS fetches as a proxy for "did we re-verify".
func TestBackchannel_Verify_JTIReplayShortCircuitsVerify(t *testing.T) {
	r := newBackchannelTestRig(t)

	claims := r.validClaims()
	claims["jti"] = "replay-jti-1"
	token := r.sign(t, claims)

	// First verify: full signature check, jti recorded.
	first, err := r.verifier.verifyLogoutToken(context.Background(), token)
	if err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if first.SID != "sess-abc" {
		t.Errorf("first verify sid: want sess-abc, got %q", first.SID)
	}

	// Replay: must short-circuit. We can't directly count signature
	// verifies (no instrumentation), so we instead verify that the
	// dedup machinery returned the cached entry — which carries
	// the same sid/sub even after we mutate the verifier's accepted
	// issuer set to one that would normally REJECT this token.
	r.verifier.acceptedIss = map[string]bool{"https://only-this.example.com": true}

	second, err := r.verifier.verifyLogoutToken(context.Background(), token)
	if err != nil {
		t.Fatalf("replay verify rejected after issuer mutation — dedup did NOT short-circuit: %v", err)
	}
	if second.SID != "sess-abc" || second.Subject != "user-1" {
		t.Errorf("replay must surface cached sid+sub; got sid=%q sub=%q", second.SID, second.Subject)
	}
}

// Round 25 Wave 5 (item 18 / R25a #2): the seenJTIs LRU has a bound.
// We can't easily exhaust 10k entries in a unit test, so we shrink the
// cap and verify eviction.
func TestBackchannel_SeenJTIs_LRUEviction(t *testing.T) {
	r := newBackchannelTestRig(t)
	r.verifier.seenJTIsCap = 3

	// Record 4 distinct jtis; the first should be evicted.
	r.verifier.rememberJTI("jti-a", "sid-a", "sub-a")
	r.verifier.rememberJTI("jti-b", "sid-b", "sub-b")
	r.verifier.rememberJTI("jti-c", "sid-c", "sub-c")
	r.verifier.rememberJTI("jti-d", "sid-d", "sub-d")

	if e := r.verifier.lookupJTI("jti-a"); e != nil {
		t.Errorf("jti-a should have been evicted")
	}
	for _, jti := range []string{"jti-b", "jti-c", "jti-d"} {
		if e := r.verifier.lookupJTI(jti); e == nil {
			t.Errorf("expected %q to remain in dedup set", jti)
		}
	}
}

// Round 25 Wave 5 (item 18 / R25a #2): an empty jti is a no-op (older
// Zitadel versions may not emit one). The replay never gets cached
// and full verify happens every time.
func TestBackchannel_SeenJTIs_EmptyJTINotCached(t *testing.T) {
	r := newBackchannelTestRig(t)
	r.verifier.rememberJTI("", "sid-x", "sub-x")
	if r.verifier.seenJTIsLRU.Len() != 0 {
		t.Errorf("empty jti must not enter the dedup set")
	}
	if e := r.verifier.lookupJTI(""); e != nil {
		t.Errorf("empty jti must not be reported as seen")
	}
}
