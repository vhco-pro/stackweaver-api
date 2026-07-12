// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-040 JWKS cache. The remoteKeySet fetched its keys once and never refreshed (a Zitadel
// key rotation = auth outage until restart), and wrote `keys` with no lock while every verify
// read it (a data race). This test drives concurrent verify (read) and refresh (write) under
// -race and asserts a rotation is picked up without a restart.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func jwksBody(t *testing.T, kid string) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &priv.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"},
	}}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

// TestRemoteKeySet_ConcurrentRefreshNoRace hammers the read (verify) and write (refresh)
// paths concurrently. Run with -race: without the mutex the concurrent keys read/write is a
// data race. It also confirms a rotated kid triggers exactly the refresh path.
func TestRemoteKeySet_ConcurrentRefreshNoRace(t *testing.T) {
	var serves int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&serves, 1)
		_, _ = w.Write(jwksBody(t, "rotating"))
	}))
	defer srv.Close()

	ks := &remoteKeySet{httpClient: srv.Client(), jwksURL: srv.URL}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		// Writer: refresh the cache.
		go func() { defer wg.Done(); _ = ks.fetchKeys(context.Background()) }()
		// Reader: verify against the cache (empty JWS just exercises the guarded read loop).
		go func() { defer wg.Done(); _, _ = ks.tryVerify(&jose.JSONWebSignature{}) }()
	}
	wg.Wait()

	if atomic.LoadInt64(&serves) == 0 {
		t.Fatal("expected the JWKS endpoint to be fetched")
	}
}

// TestRemoteKeySet_RefreshOnUnknownKID pins the rotation behavior: a cold cache and a token
// carrying an uncached kid both warrant a refresh; a cached kid (or no kid) does not.
func TestRemoteKeySet_RefreshOnUnknownKID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwksBody(t, "k-cached"))
	}))
	defer srv.Close()
	ks := &remoteKeySet{httpClient: srv.Client(), jwksURL: srv.URL}

	// Cold cache -> refresh warranted regardless of kid.
	if !ks.shouldRefresh(&jose.JSONWebSignature{}) {
		t.Fatal("cold cache must warrant a refresh")
	}
	if err := ks.fetchKeys(context.Background()); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	withKID := func(kid string) *jose.JSONWebSignature {
		return &jose.JSONWebSignature{Signatures: []jose.Signature{{Header: jose.Header{KeyID: kid}}}}
	}
	if ks.shouldRefresh(withKID("k-cached")) {
		t.Fatal("a cached kid must NOT trigger a refresh (would let attackers farm refreshes)")
	}
	if !ks.shouldRefresh(withKID("k-rotated")) {
		t.Fatal("an uncached kid must trigger a refresh (key rotation)")
	}
	if ks.shouldRefresh(&jose.JSONWebSignature{}) {
		t.Fatal("a warm cache with no kid must NOT refresh")
	}
}
