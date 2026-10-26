// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package authtest holds test doubles for the auth service's stores.
package authtest

import (
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// MemSessions is an in-memory auth.SessionStore: the browser-session table without a database.
type MemSessions struct {
	mu     sync.Mutex
	byHash map[string]*models.BrowserSession
	// created is every token hash Create received, so a test can prove only hashes are stored.
	created []string
	// Fail, when set, is returned by every read and delete, as a database outage would be.
	Fail error
}

func (m *MemSessions) fail() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Fail
}

// NewMemSessions returns an empty store.
func NewMemSessions() *MemSessions {
	return &MemSessions{byHash: map[string]*models.BrowserSession{}}
}

func (m *MemSessions) Create(s *models.BrowserSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *s
	m.byHash[s.TokenHash] = &cp
	m.created = append(m.created, s.TokenHash)
	return nil
}

func (m *MemSessions) GetByTokenHash(hash string) (*models.BrowserSession, error) {
	if err := m.fail(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byHash[hash]
	if !ok {
		return nil, repository.ErrBrowserSessionNotFound
	}
	cp := *s
	return &cp, nil
}

func (m *MemSessions) GetByID(id uuid.UUID) (*models.BrowserSession, error) {
	if err := m.fail(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.byHash {
		if s.ID == id {
			cp := *s
			return &cp, nil
		}
	}
	return nil, repository.ErrBrowserSessionNotFound
}

func (m *MemSessions) DeleteByID(id uuid.UUID) error {
	if err := m.fail(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, s := range m.byHash {
		if s.ID == id {
			delete(m.byHash, h)
		}
	}
	return nil
}

func (m *MemSessions) DeleteByZitadelSID(sid string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for h, s := range m.byHash {
		if s.ZitadelSID == sid {
			delete(m.byHash, h)
			n++
		}
	}
	return n, nil
}

func (m *MemSessions) Touch(id uuid.UUID, at, idleExpiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.byHash {
		if s.ID == id {
			s.LastActivityAt, s.IdleExpiresAt = at, idleExpiresAt
		}
	}
	return nil
}

func expired(s *models.BrowserSession, now time.Time) bool {
	return !now.Before(s.IdleExpiresAt) || !now.Before(s.AbsoluteExpiresAt)
}

func (m *MemSessions) ListExpired(now time.Time, limit int) ([]repository.ExpiredSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []repository.ExpiredSession
	for _, s := range m.byHash {
		if expired(s, now) {
			out = append(out, repository.ExpiredSession{ID: s.ID, ZitadelSID: s.ZitadelSID})
		}
	}
	slices.SortFunc(out, func(a, b repository.ExpiredSession) int { return strings.Compare(a.ID.String(), b.ID.String()) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemSessions) HasLiveSessionForSID(sid string, except uuid.UUID, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.byHash {
		if s.ZitadelSID == sid && s.ID != except && !expired(s, now) {
			return true, nil
		}
	}
	return false, nil
}

// DeleteExpiredLoginTransactions has no transactions to delete; login transactions have their own
// double.
func (m *MemSessions) DeleteExpiredLoginTransactions(time.Time) (int64, error) { return 0, nil }

// Len is how many sessions are stored.
func (m *MemSessions) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byHash)
}

// Created is every token hash Create received, in order.
func (m *MemSessions) Created() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.created)
}

// ByID returns a copy of the stored session with id, or nil.
func (m *MemSessions) ByID(id uuid.UUID) *models.BrowserSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.byHash {
		if s.ID == id {
			cp := *s
			return &cp
		}
	}
	return nil
}

// Only returns the one stored session, failing the test when there is not exactly one.
func (m *MemSessions) Only(t testing.TB) *models.BrowserSession {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.byHash) != 1 {
		t.Fatalf("want exactly one stored session, got %d", len(m.byHash))
	}
	for _, s := range m.byHash {
		cp := *s
		return &cp
	}
	return nil
}
