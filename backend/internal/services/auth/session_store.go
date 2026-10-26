// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// ErrSessionNotFound means no browser session matches the presented cookie value.
var ErrSessionNotFound = errors.New("browser session not found")

// ErrSessionExpired means the session matched but is past its idle or absolute limit.
var ErrSessionExpired = errors.New("browser session expired")

// ErrSessionEnded means the session matched but Zitadel answered that it, its user or its
// organisation is gone, so the liveness check ended it.
var ErrSessionEnded = errors.New("browser session ended")

// SessionCookieName is the browser session cookie. The __Host- prefix makes a browser refuse it
// unless it is Secure, has Path=/ and no Domain, so a sibling subdomain cannot plant it.
const SessionCookieName = "__Host-sw_session"

// sessionTokenBytes is the size of a session identifier before encoding: 256 bits from crypto/rand.
const sessionTokenBytes = 32

// SessionStore is what the browser-session logic needs from storage. It is satisfied by
// *repository.BrowserSessionRepository and by in-memory fakes in tests.
type SessionStore interface {
	Create(s *models.BrowserSession) error
	GetByTokenHash(tokenHash string) (*models.BrowserSession, error)
	GetByID(id uuid.UUID) (*models.BrowserSession, error)
	DeleteByID(id uuid.UUID) error
	DeleteByZitadelSID(sid string) (int64, error)
	Touch(id uuid.UUID, at, idleExpiresAt time.Time) error
	ListExpired(now time.Time, limit int) ([]repository.ExpiredSession, error)
	HasLiveSessionForSID(sid string, except uuid.UUID, now time.Time) (bool, error)
	DeleteExpiredLoginTransactions(now time.Time) (int64, error)
}

// The repository is the production SessionStore.
var _ SessionStore = (*repository.BrowserSessionRepository)(nil)

// SessionLimits are the configured lifetimes of a browser session.
type SessionLimits struct {
	Idle     time.Duration // signed out after this long without user activity
	Absolute time.Duration // signed out this long after sign-in, whatever the activity
	Liveness time.Duration // how often the session is checked against Zitadel
}

// Liveness checks a session against Zitadel when its check is due. It answers ErrSessionEnded
// when Zitadel says the session, its user or its organisation is gone, and nil otherwise,
// including when Zitadel could not be asked (a check that fails open is retried shortly).
type Liveness interface {
	Check(ctx context.Context, s *models.BrowserSession) error
}

// Sessions starts and looks up backend-for-frontend browser sessions.
type Sessions struct {
	store    SessionStore
	limits   SessionLimits
	now      func() time.Time
	liveness Liveness
	// zitadel ends a session's Zitadel session at sign-out and expiry. Without it only the row goes.
	zitadel ZitadelCaller
	// pace spaces the sweeper's Zitadel deletes; see sweepPace.
	pace time.Duration
}

// NewSessions returns Sessions over store. now is the clock; pass time.Now outside tests.
func NewSessions(store SessionStore, limits SessionLimits, now func() time.Time) *Sessions {
	return &Sessions{store: store, limits: limits, now: now, pace: sweepPace}
}

// SetZitadel sets the connection that ends Zitadel sessions, at sign-out and at expiry.
func (ss *Sessions) SetZitadel(z ZitadelCaller) { ss.zitadel = z }

// SetLiveness sets the check Resolve runs on a session whose check is due. Without one, no
// check runs.
func (ss *Sessions) SetLiveness(l Liveness) { ss.liveness = l }

// Limits returns the configured session lifetimes.
func (ss *Sessions) Limits() SessionLimits { return ss.limits }

// DefaultSessionLimits are the lifetimes used when none are configured: NIST SP 800-63B-4 at
// AAL2 for idle (one hour) and an office day for absolute (twelve hours), checked against Zitadel
// every five minutes.
var DefaultSessionLimits = SessionLimits{Idle: time.Hour, Absolute: 12 * time.Hour, Liveness: 5 * time.Minute}

// NewSessionToken mints a session identifier: 32 bytes from crypto/rand, base64url without
// padding for the cookie, and its hash for the store.
func NewSessionToken() (raw, hash string, err error) {
	b := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("reading random bytes: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, HashSessionToken(raw), nil
}

// HashSessionToken is the hex SHA-256 of a cookie value, the only form the store keeps.
func HashSessionToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Start mints a new identifier for s, stamps its timestamps from the configured limits, stores it,
// and returns the raw cookie value. A new value is minted at every sign-in; none is ever reused.
func (ss *Sessions) Start(s *models.BrowserSession) (string, *models.BrowserSession, error) {
	raw, hash, err := NewSessionToken()
	if err != nil {
		return "", nil, err
	}
	now := ss.now()
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	s.TokenHash = hash
	s.CreatedAt = now
	s.LastActivityAt = now
	s.NextCheckAt = now.Add(ss.limits.Liveness)
	s.IdleExpiresAt = now.Add(ss.limits.Idle)
	s.AbsoluteExpiresAt = now.Add(ss.limits.Absolute)
	if err := ss.store.Create(s); err != nil {
		return "", nil, fmt.Errorf("storing browser session: %w", err)
	}
	return raw, s, nil
}

// Lookup returns the session for a cookie value. It answers ErrSessionNotFound for an empty or
// unknown value and ErrSessionExpired for a session past its idle or absolute limit.
func (ss *Sessions) Lookup(raw string) (*models.BrowserSession, error) {
	if raw == "" {
		return nil, ErrSessionNotFound
	}
	s, err := ss.store.GetByTokenHash(HashSessionToken(raw))
	if errors.Is(err, repository.ErrBrowserSessionNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("looking up browser session: %w", err)
	}
	now := ss.now()
	if !now.Before(s.IdleExpiresAt) || !now.Before(s.AbsoluteExpiresAt) {
		return s, ErrSessionExpired
	}
	return s, nil
}

// ResolveID returns the live session with this id: one that exists, is within its idle and absolute
// limits, and passes the liveness check when one is due, exactly as Resolve judges a cookie. A run's
// log token names the session that minted it and reads through this, so it stops working the
// moment the session ends, by sign-out, revoke, back-channel logout, a limit, or a user or
// organisation deactivated in Zitadel. A read is not activity, so it never extends the session.
func (ss *Sessions) ResolveID(ctx context.Context, id uuid.UUID) (*models.BrowserSession, error) {
	s, err := ss.store.GetByID(id)
	if errors.Is(err, repository.ErrBrowserSessionNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("looking up browser session: %w", err)
	}
	now := ss.now()
	if !now.Before(s.IdleExpiresAt) || !now.Before(s.AbsoluteExpiresAt) {
		return nil, ErrSessionExpired
	}
	if ss.liveness == nil || now.Before(s.NextCheckAt) {
		return s, nil
	}
	if err := ss.liveness.Check(ctx, s); err != nil {
		return nil, err
	}
	return s, nil
}

// Resolve is Lookup followed by the liveness check when one is due. A session whose check is not
// due makes no call to Zitadel. It answers ErrSessionNotFound, ErrSessionExpired or
// ErrSessionEnded for a session the request must be refused for.
func (ss *Sessions) Resolve(ctx context.Context, raw string) (*models.BrowserSession, error) {
	s, err := ss.Lookup(raw)
	if errors.Is(err, ErrSessionExpired) {
		// The request is refused whatever happens next; ending the session is best effort here, and
		// the sweeper retries a row this leaves behind.
		ss.endExpired(ctx, repository.ExpiredSession{ID: s.ID, ZitadelSID: s.ZitadelSID})
		return s, err
	}
	if err != nil {
		return s, err
	}
	if ss.liveness == nil || ss.now().Before(s.NextCheckAt) {
		return s, nil
	}
	if err := ss.liveness.Check(ctx, s); err != nil {
		return s, err
	}
	return s, nil
}

// Touch records user activity on s, pushing its idle limit out by the configured idle timeout. A
// touch from the SPA and every cookie-authenticated state-changing request count as activity; a GET
// does not, so background polling cannot keep a forgotten tab signed in.
func (ss *Sessions) Touch(s *models.BrowserSession) error {
	now := ss.now()
	if err := ss.store.Touch(s.ID, now, now.Add(ss.limits.Idle)); err != nil {
		return fmt.Errorf("recording activity on session %s: %w", s.ID, err)
	}
	s.LastActivityAt, s.IdleExpiresAt = now, now.Add(ss.limits.Idle)
	return nil
}

// SignOut ends s: its row first, so the browser is refused at once, then its Zitadel session, so
// signing back in needs a credential again. A failed Zitadel delete is logged; the row is gone
// either way.
func (ss *Sessions) SignOut(ctx context.Context, s *models.BrowserSession) error {
	if err := ss.store.DeleteByID(s.ID); err != nil {
		return fmt.Errorf("deleting session %s: %w", s.ID, err)
	}
	if ss.zitadel != nil && s.ZitadelSID != "" {
		if err := deleteZitadelSession(ctx, ss.zitadel, s.ZitadelSID); err != nil {
			logger.Warnf("auth: signed out session %s but could not end its Zitadel session: %v", s.ID, err)
		}
	}
	return nil
}

// EndBySID deletes every session signed in through the Zitadel session sid and reports how many
// there were. A back-channel logout or a Settings > Sessions revoke uses it; the Zitadel session is
// already gone.
func (ss *Sessions) EndBySID(sid string) (int64, error) {
	n, err := ss.store.DeleteByZitadelSID(sid)
	if err != nil {
		return 0, fmt.Errorf("deleting the sessions of Zitadel session %s: %w", sid, err)
	}
	return n, nil
}

// Supersede ends the session a browser presented when it signed in again, once the new session is
// stored, so the browser holds one session whichever account it signed in as. The old Zitadel
// session is ended too, unless the new sign-in reused it (keepSID) or another live session still
// names it. A value that names no session is ignored, as a planted cookie is.
func (ss *Sessions) Supersede(ctx context.Context, raw, keepSID string) {
	if raw == "" {
		return
	}
	old, _ := ss.Lookup(raw)
	if old == nil {
		return
	}
	if err := ss.store.DeleteByID(old.ID); err != nil {
		logger.Warnf("auth: ending the session a new sign-in replaced (%s): %v", old.ID, err)
		return
	}
	if ss.zitadel == nil || old.ZitadelSID == "" || old.ZitadelSID == keepSID {
		return
	}
	if shared, err := ss.store.HasLiveSessionForSID(old.ZitadelSID, old.ID, ss.now()); err != nil || shared {
		return
	}
	if err := deleteZitadelSession(ctx, ss.zitadel, old.ZitadelSID); err != nil {
		logger.Warnf("auth: ending the Zitadel session of the replaced session %s: %v", old.ID, err)
	}
}
