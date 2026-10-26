// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth/authtest"
	"github.com/michielvha/stackweaver/core/models"
)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// A minted identifier is 32 random bytes in base64url, different every time; only its hash reaches
// the store, so the store never holds a usable cookie value.
func TestNewSessionToken_RandomAndHashedOnly(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		raw, hash, err := NewSessionToken()
		if err != nil {
			t.Fatalf("NewSessionToken: %v", err)
		}
		b, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || len(b) != 32 {
			t.Fatalf("token must be 32 bytes of base64url, got %d bytes (%v)", len(b), err)
		}
		if seen[raw] {
			t.Fatalf("NewSessionToken repeated a value")
		}
		seen[raw] = true
		if hash == raw || hash != HashSessionToken(raw) {
			t.Fatalf("hash must be the SHA-256 of the raw value, never the value itself")
		}
	}

	store := authtest.NewMemSessions()
	now := time.Now()
	sessions := NewSessions(store, SessionLimits{Idle: time.Hour, Absolute: 12 * time.Hour, Liveness: 5 * time.Minute}, fixedClock(now))
	raw, _, err := sessions.Start(&models.BrowserSession{UserID: uuid.New(), ZitadelSID: "sid-1"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	for _, h := range store.Created() {
		if h == raw {
			t.Fatalf("the store received the raw cookie value; it must receive only the hash")
		}
	}
	if created := store.Created(); len(created) != 1 || created[0] != HashSessionToken(raw) {
		t.Fatalf("the store must receive exactly the hash of the minted value")
	}
}

// Two Sessions over one store (two API replicas over one database) see each other's sessions.
func TestSessions_SharedAcrossInstances(t *testing.T) {
	store := authtest.NewMemSessions()
	now := time.Now()
	limits := SessionLimits{Idle: time.Hour, Absolute: 12 * time.Hour, Liveness: 5 * time.Minute}
	a := NewSessions(store, limits, fixedClock(now))
	b := NewSessions(store, limits, fixedClock(now))

	raw, _, err := a.Start(&models.BrowserSession{UserID: uuid.New(), ZitadelSID: "sid-1"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := b.Lookup(raw); err != nil {
		t.Fatalf("a session started on one instance must be found on another: %v", err)
	}
}

// Lookup refuses an unknown value, and a session past its idle or absolute limit, with the named
// sentinel errors the middleware maps to 401.
func TestSessions_LookupExpiry(t *testing.T) {
	store := authtest.NewMemSessions()
	start := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	limits := SessionLimits{Idle: time.Hour, Absolute: 12 * time.Hour, Liveness: 5 * time.Minute}
	raw, _, err := NewSessions(store, limits, fixedClock(start)).Start(&models.BrowserSession{UserID: uuid.New(), ZitadelSID: "sid-1"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	cases := []struct {
		name string
		at   time.Time
		want error
	}{
		{"fresh", start.Add(time.Minute), nil},
		{"idle limit reached", start.Add(time.Hour), ErrSessionExpired},
		{"absolute limit reached", start.Add(12 * time.Hour), ErrSessionExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSessions(store, limits, fixedClock(tc.at)).Lookup(raw)
			matched := errors.Is(err, tc.want)
			if tc.want == nil {
				matched = err == nil
			}
			if !matched {
				t.Fatalf("Lookup at %s: got %v, want %v", tc.at.Sub(start), err, tc.want)
			}
		})
	}

	if _, err := NewSessions(store, limits, fixedClock(start)).Lookup("not-a-real-token"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unknown token: got %v, want ErrSessionNotFound", err)
	}
	if _, err := NewSessions(store, limits, fixedClock(start)).Lookup(""); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("empty token: got %v, want ErrSessionNotFound", err)
	}
}
