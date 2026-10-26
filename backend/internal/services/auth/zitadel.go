// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

// Reference: https://zitadel.com/docs/guides/integrate/login/oidc/login-users
// Using Zitadel OIDC library for proper token verification: https://github.com/zitadel/oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/go-jose/go-jose/v4"
	"github.com/michielvha/logger"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

// remoteKeySet implements oidc.KeySet for remote JWKS
type remoteKeySet struct {
	httpClient   *http.Client
	jwksURL      string
	hostOverride string       // Host header override for in-cluster requests to Zitadel
	mu           sync.RWMutex // guards keys - read on every verify, written on refresh (AUD-040)
	keys         []jose.JSONWebKey
}

func (r *remoteKeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	// Fast path: verify against the currently cached keys.
	if payload, ok := r.tryVerify(jws); ok {
		return payload, nil
	}

	// AUD-040: the JWKS was fetched once and never refreshed, so after Zitadel rotates its
	// signing keys every token fails until restart. If the token's `kid` isn't one we have
	// cached (or the cache is cold), refresh once and retry. Gating on kid-not-cached stops
	// an attacker posting garbage tokens from farming JWKS refreshes.
	if r.shouldRefresh(jws) {
		if err := r.fetchKeys(ctx); err != nil {
			return nil, fmt.Errorf("failed to refresh JWKS: %w", err)
		}
		if payload, ok := r.tryVerify(jws); ok {
			return payload, nil
		}
	}
	return nil, fmt.Errorf("signature verification failed against JWKS")
}

// tryVerify attempts verification against the cached keys under a read lock.
func (r *remoteKeySet) tryVerify(jws *jose.JSONWebSignature) ([]byte, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, key := range r.keys {
		if key.Key == nil {
			continue
		}
		if payload, err := jws.Verify(key.Key); err == nil {
			return payload, true
		}
	}
	return nil, false
}

// shouldRefresh reports whether a verify failure warrants a one-shot JWKS refresh: the cache
// is cold, or the token carries a `kid` we don't have (a plausible key rotation). A token
// whose `kid` is already cached, or that carries no `kid`, does not trigger a refresh.
func (r *remoteKeySet) shouldRefresh(jws *jose.JSONWebSignature) bool {
	kid := ""
	if len(jws.Signatures) > 0 {
		kid = jws.Signatures[0].Header.KeyID
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.keys) == 0 {
		return true
	}
	if kid == "" {
		return false
	}
	for _, key := range r.keys {
		if key.KeyID == kid {
			return false
		}
	}
	return true
}

func (r *remoteKeySet) fetchKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", r.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// When fetching JWKS via an internal K8s service address, Zitadel uses the
	// Host header to identify the instance. Override it with the external issuer
	// hostname so Zitadel can route to the correct tenant.
	if r.hostOverride != "" {
		req.Host = r.hostOverride
	}

	resp, err := r.httpClient.Do(req) //nolint:gosec // G704: URL is the operator-configured Zitadel JWKS endpoint, not user-controlled
	if err != nil {
		return fmt.Errorf("failed to fetch keys: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch keys: status %d", resp.StatusCode)
	}

	// Use go-jose's built-in JWKS parsing
	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	if len(jwks.Keys) == 0 {
		return fmt.Errorf("no keys found in JWKS")
	}

	r.mu.Lock()
	r.keys = jwks.Keys
	r.mu.Unlock()
	return nil
}

// ZitadelVerifier handles JWT token verification for Zitadel using the OIDC library
type ZitadelVerifier struct {
	issuer       string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	keySet       oidc.KeySet
	internalAddr string   // K8s-internal service address (e.g. "zitadel:8080"), bypasses TLS
	hostOverride string   // External issuer hostname sent as Host header for tenant routing
	acceptedAuds []string // client_ids a token's `aud` may contain (AUD-012); empty disables enforcement
}

// AcceptAudience registers a client_id that an access token's `aud` may contain. Real user
// access tokens are issued to the frontend PKCE client, so their `aud` carries the frontend
// client id - not the API client id the verifier is otherwise configured with. Call this for
// every Stackweaver client (API + frontend) so audience enforcement (AUD-012) accepts real
// tokens while rejecting tokens minted for other clients on the same Zitadel instance.
func (v *ZitadelVerifier) AcceptAudience(clientID string) {
	if clientID != "" {
		v.acceptedAuds = append(v.acceptedAuds, clientID)
	}
}

// audienceAccepted reports whether the token's `aud` intersects the configured set of
// Stackweaver client_ids. When no audiences are configured it returns true, preserving
// availability for unconfigured deployments (enforcement is opt-in via AcceptAudience).
func (v *ZitadelVerifier) audienceAccepted(aud []string) bool {
	if len(v.acceptedAuds) == 0 {
		return true
	}
	for _, want := range v.acceptedAuds {
		if slices.Contains(aud, want) {
			return true
		}
	}
	return false
}

// NewZitadelVerifier creates a new Zitadel JWT verifier using the OIDC library.
// If internalAddr is provided (e.g. "localhost:8080"), JWKS keys are fetched from
// http://{internalAddr}/oauth/v2/keys instead of the external issuer URL.
// This allows the API to validate JWTs issued with an external domain as issuer
// while fetching keys internally without going through the public internet.
func NewZitadelVerifier(issuer, clientID, clientSecret, internalAddr string) (*ZitadelVerifier, error) {
	// Create HTTP client
	httpClient := oauth2.NewClient(context.Background(), nil)

	// Use internal address for JWKS if provided, otherwise fall back to issuer.
	// When using an internal address (e.g. K8s service name), we must also send
	// the external issuer hostname as the Host header so Zitadel can identify
	// the correct instance (Zitadel routes tenants by the Host header).
	jwksURL := issuer + "/oauth/v2/keys"
	var hostOverride string
	if internalAddr != "" {
		jwksURL = "http://" + internalAddr + "/oauth/v2/keys"
		if u, err := url.Parse(issuer); err == nil {
			hostOverride = u.Host
		}
	}

	// Create remote key set that implements oidc.KeySet
	keySet := &remoteKeySet{
		httpClient:   httpClient,
		jwksURL:      jwksURL,
		hostOverride: hostOverride,
	}

	return &ZitadelVerifier{
		issuer:       issuer,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   httpClient,
		keySet:       keySet,
		internalAddr: internalAddr,
		hostOverride: hostOverride,
	}, nil
}

// VerifyToken verifies a JWT token and returns the claims using the OIDC library
// Returns both the validated claims and the raw claims map (for custom Zitadel fields)
func (v *ZitadelVerifier) VerifyToken(ctx context.Context, tokenString string) (*oidc.AccessTokenClaims, map[string]interface{}, error) {
	// Verify that token is a JWT (has dots separating header.payload.signature)
	if !strings.Contains(tokenString, ".") {
		return nil, nil, fmt.Errorf("token is not a JWT (expected JWT format, got opaque token). Please configure Zitadel to issue JWT tokens")
	}

	// Parse JWS to get signature info - needed for CheckSignature
	supportedAlgs := []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256}
	jws, err := jose.ParseSigned(tokenString, supportedAlgs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	// Verify signature using the KeySet to get the payload
	payload, err := v.keySet.VerifySignature(ctx, jws)
	if err != nil {
		return nil, nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Unmarshal payload into a map FIRST to preserve all claims (including custom Zitadel fields)
	var claimsMap map[string]interface{}
	if err := json.Unmarshal(payload, &claimsMap); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal claims map: %w", err)
	}

	// Create claims object and unmarshal payload into it for validation
	claims := &oidc.AccessTokenClaims{}
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	// Validate issuer
	if err := oidc.CheckIssuerWithISSVerifier(claims, v.issuer, nil); err != nil {
		return nil, nil, fmt.Errorf("issuer validation failed: %w", err)
	}

	// AUD-012: enforce that the token is intended for a Stackweaver client. Previously the
	// audience error was discarded ("lenient"), so any token signed by the same Zitadel
	// instance - for any client/project - authenticated and auto-provisioned a user. Real
	// user access tokens are issued to the frontend PKCE client, so we accept the frontend
	// client id (registered via AcceptAudience) as well as the API client id, and reject
	// tokens whose `aud` names only other clients.
	if !v.audienceAccepted(claims.GetAudience()) {
		return nil, nil, fmt.Errorf("token audience %v does not include a Stackweaver client", claims.GetAudience())
	}

	// Validate expiration
	if err := oidc.CheckExpiration(claims, 0); err != nil {
		return nil, nil, fmt.Errorf("token expired: %w", err)
	}

	return claims, claimsMap, nil
}
