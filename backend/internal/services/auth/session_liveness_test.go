// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the liveness check of a browser session (backend-for-frontend-session-plan.md,
// AC7, AC12, AC25, AC26): the claim runs against the real session table, so concurrency and the
// claim's atomicity are PostgreSQL's, and Zitadel is a fake that answers each of the three reads.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped: every
// user and session created here is deleted by its own id.

//go:build integration
// +build integration

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// fakeLivenessZitadel answers the session, user and organisation reads the way Zitadel's v2 API
// does, with whatever the test sets.
type fakeLivenessZitadel struct {
	mu            sync.Mutex
	sessionStatus int
	userStatus    int
	orgStatus     int
	userState     string
	emailVerified bool
	orgState      string
	orgMissing    bool
	displayName   string
	email         string
	avatar        string
	delay         time.Duration
	hang          bool // wait until the request's context ends
	calls         map[string]int
	callErr       error
	subject       string // the user the Zitadel session names
}

func newFakeLivenessZitadel() *fakeLivenessZitadel {
	return &fakeLivenessZitadel{
		sessionStatus: http.StatusOK, userStatus: http.StatusOK, orgStatus: http.StatusOK,
		userState: "USER_STATE_ACTIVE", emailVerified: true, orgState: "ORGANIZATION_STATE_ACTIVE",
		displayName: "Ada Lovelace", email: "ada@example.com", calls: map[string]int{},
	}
}

func (f *fakeLivenessZitadel) count(kind string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[kind]
}

func (f *fakeLivenessZitadel) CallZitadel(ctx context.Context, method, path string, _ any) (int, []byte, error) {
	kind := ""
	switch {
	case method == http.MethodGet && strings.HasPrefix(path, "/v2/sessions/"):
		kind = "session"
	case method == http.MethodGet && strings.HasPrefix(path, "/v2/users/"):
		kind = "user"
	case method == http.MethodPost && path == "/v2/organizations/_search":
		kind = "org"
	default:
		return http.StatusNotFound, nil, nil
	}
	f.mu.Lock()
	f.calls[kind]++
	delay, hang, callErr := f.delay, f.hang, f.callErr
	f.mu.Unlock()

	if hang {
		<-ctx.Done()
		return 0, nil, ctx.Err()
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		}
	}
	if callErr != nil {
		return 0, nil, callErr
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	var status int
	var body any
	switch kind {
	case "session":
		status = f.sessionStatus
		body = map[string]any{"session": map[string]any{"id": "sid", "factors": map[string]any{"user": map[string]any{"id": f.subject, "organizationId": "org-1"}}}}
	case "user":
		status = f.userStatus
		body = map[string]any{"user": map[string]any{
			"userId": "zitadel-sub", "state": f.userState,
			"human": map[string]any{
				"profile": map[string]any{"givenName": "Ada", "familyName": "Lovelace", "displayName": f.displayName, "avatarUrl": f.avatar},
				"email":   map[string]any{"email": f.email, "isVerified": f.emailVerified},
			},
		}}
	case "org":
		status = f.orgStatus
		result := []any{map[string]any{"id": "org-1", "state": f.orgState}}
		if f.orgMissing {
			result = []any{}
		}
		body = map[string]any{"result": result}
	}
	raw, _ := json.Marshal(body)
	return status, raw, nil
}

type livenessRig struct {
	db       *gorm.DB
	repo     *repository.BrowserSessionRepository
	sessions *Sessions
	zitadel  *fakeLivenessZitadel
	liveness *ZitadelLiveness
	raw      string
	session  *models.BrowserSession
}

func newLivenessRig(t *testing.T, interval time.Duration) *livenessRig {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dsn, &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.BrowserSession{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	user := &models.User{ID: uuid.New(), ZitadelSubject: "sub-" + uuid.NewString(), Email: "liveness-" + uuid.NewString()[:8] + "@example.com"}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { db.Delete(&models.User{}, "id = ?", user.ID) })

	r := &livenessRig{db: db, repo: repository.NewBrowserSessionRepository(db), zitadel: newFakeLivenessZitadel()}
	r.zitadel.subject = user.ZitadelSubject
	limits := SessionLimits{Idle: time.Hour, Absolute: 12 * time.Hour, Liveness: interval}
	r.sessions = NewSessions(r.repo, limits, time.Now)
	r.liveness = NewZitadelLiveness(r.repo, r.zitadel, interval)
	r.sessions.SetLiveness(r.liveness)

	raw, s, err := r.sessions.Start(&models.BrowserSession{
		UserID: user.ID, ZitadelSubject: user.ZitadelSubject, ZitadelSID: "sid-" + uuid.NewString()[:8],
		OrganizationID: "org-1", Email: "old@example.com", Name: "Old Name",
	})
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	t.Cleanup(func() { db.Delete(&models.BrowserSession{}, "id = ?", s.ID) })
	r.raw, r.session = raw, s
	return r
}

// due makes the session's liveness check due now.
func (r *livenessRig) due(t *testing.T) {
	t.Helper()
	if err := r.repo.SetNextCheck(r.session.ID, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("make the check due: %v", err)
	}
}

func (r *livenessRig) stored(t *testing.T) *models.BrowserSession {
	t.Helper()
	var s models.BrowserSession
	err := r.db.First(&s, "id = ?", r.session.ID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		t.Fatalf("read the session: %v", err)
	}
	return &s
}

// AC12: many concurrent requests from several tabs while a check is due leave the session valid,
// and Zitadel receives one check, not one per request.
func TestLiveness_ConcurrentRequestsMakeOneCheck(t *testing.T) {
	r := newLivenessRig(t, 5*time.Minute)
	r.zitadel.delay = 50 * time.Millisecond
	r.due(t)

	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.sessions.Resolve(context.Background(), r.raw)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a concurrent request was refused: %v", err)
		}
	}
	for _, kind := range []string{"session", "user", "org"} {
		if n := r.zitadel.count(kind); n != 1 {
			t.Errorf("Zitadel received %d %s read(s), want 1", n, kind)
		}
	}
}

// The three reads run in parallel, under one budget.
func TestLiveness_ReadsRunInParallelUnderOneBudget(t *testing.T) {
	r := newLivenessRig(t, 5*time.Minute)
	// Long reads, so the database round trips Resolve also makes, which take a few hundred
	// milliseconds on a loaded host, cannot blur the line: in sequence the three reads take at
	// least 3s, and even two of them in a row take 2s.
	r.zitadel.delay = time.Second
	r.due(t)
	start := time.Now()
	if _, err := r.sessions.Resolve(context.Background(), r.raw); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Errorf("three 1s reads took %s; they are not running in parallel", elapsed)
	}

	r2 := newLivenessRig(t, 5*time.Minute)
	r2.zitadel.hang = true
	r2.liveness.budget = 200 * time.Millisecond
	r2.due(t)
	start = time.Now()
	if _, err := r2.sessions.Resolve(context.Background(), r2.raw); err != nil {
		t.Fatalf("a check that timed out refused the session: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("a hung Zitadel held the request for %s past a 200ms budget", elapsed)
	}
}

// AC7, AC25: a definite answer that the session, the user or the organisation is gone ends the
// session; the row is deleted and the request refused.
func TestLiveness_DefiniteAnswersEndTheSession(t *testing.T) {
	cases := map[string]func(*fakeLivenessZitadel){
		"session deleted at Zitadel": func(f *fakeLivenessZitadel) { f.sessionStatus = http.StatusNotFound },
		"user deleted":               func(f *fakeLivenessZitadel) { f.userStatus = http.StatusNotFound },
		"user deactivated":           func(f *fakeLivenessZitadel) { f.userState = "USER_STATE_INACTIVE" },
		"user locked":                func(f *fakeLivenessZitadel) { f.userState = "USER_STATE_LOCKED" },
		"email no longer verified":   func(f *fakeLivenessZitadel) { f.emailVerified = false },
		"organisation deactivated":   func(f *fakeLivenessZitadel) { f.orgState = "ORGANIZATION_STATE_INACTIVE" },
		"organisation removed":       func(f *fakeLivenessZitadel) { f.orgMissing = true },
		"session names another user": func(f *fakeLivenessZitadel) { f.subject = "someone-else" },
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			r := newLivenessRig(t, 5*time.Minute)
			set(r.zitadel)
			r.due(t)
			if _, err := r.sessions.Resolve(context.Background(), r.raw); !errors.Is(err, ErrSessionEnded) {
				t.Fatalf("Resolve = %v, want ErrSessionEnded", err)
			}
			if r.stored(t) != nil {
				t.Error("an ended session is still stored")
			}
			if _, err := r.sessions.Resolve(context.Background(), r.raw); !errors.Is(err, ErrSessionNotFound) {
				t.Errorf("the next request found the session again: %v", err)
			}
		})
	}
}

// AC25: an outage, a timeout or a refused service-account token keeps the session, and the check
// is retried thirty seconds later rather than at the next interval.
func TestLiveness_NoVerdictKeepsTheSessionAndRetriesSoon(t *testing.T) {
	cases := map[string]func(*fakeLivenessZitadel, *ZitadelLiveness){
		"session read 503":          func(f *fakeLivenessZitadel, _ *ZitadelLiveness) { f.sessionStatus = http.StatusServiceUnavailable },
		"user read 500":             func(f *fakeLivenessZitadel, _ *ZitadelLiveness) { f.userStatus = http.StatusInternalServerError },
		"service account refused":   func(f *fakeLivenessZitadel, _ *ZitadelLiveness) { f.orgStatus = http.StatusUnauthorized },
		"service account forbidden": func(f *fakeLivenessZitadel, _ *ZitadelLiveness) { f.sessionStatus = http.StatusForbidden },
		"network error":             func(f *fakeLivenessZitadel, _ *ZitadelLiveness) { f.callErr = errors.New("connection refused") },
		"timeout": func(f *fakeLivenessZitadel, l *ZitadelLiveness) {
			f.hang = true
			l.budget = 100 * time.Millisecond
		},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			r := newLivenessRig(t, 5*time.Minute)
			set(r.zitadel, r.liveness)
			r.due(t)
			before := time.Now()
			if _, err := r.sessions.Resolve(context.Background(), r.raw); err != nil {
				t.Fatalf("a check with no verdict refused the session: %v", err)
			}
			s := r.stored(t)
			if s == nil {
				t.Fatal("a check with no verdict deleted the session")
			}
			if next := s.NextCheckAt.Sub(before); next < 25*time.Second || next > 35*time.Second {
				t.Errorf("next check in %s, want about 30s", next)
			}
		})
	}
}

// A definite answer wins over a read that failed: a deleted session is ended even while the
// organisation read is down.
func TestLiveness_DefiniteAnswerWinsOverAFailedRead(t *testing.T) {
	r := newLivenessRig(t, 5*time.Minute)
	r.zitadel.sessionStatus = http.StatusNotFound
	r.zitadel.orgStatus = http.StatusServiceUnavailable
	r.due(t)
	if _, err := r.sessions.Resolve(context.Background(), r.raw); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("Resolve = %v, want ErrSessionEnded", err)
	}
}

// AC26: a claimant that crashed after claiming leaves the check to the next interval, when the
// next request runs it.
func TestLiveness_ACrashedClaimantsCheckRunsAgainWithinOneInterval(t *testing.T) {
	const interval = time.Second
	r := newLivenessRig(t, interval)
	r.due(t)
	// A replica claims the check and dies before reading Zitadel.
	if won, err := r.repo.ClaimDueCheck(r.session.ID, interval); err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	if _, err := r.sessions.Resolve(context.Background(), r.raw); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n := r.zitadel.count("session"); n != 0 {
		t.Fatalf("a request checked while another replica held the claim (%d reads)", n)
	}
	time.Sleep(interval + 100*time.Millisecond)
	if _, err := r.sessions.Resolve(context.Background(), r.raw); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n := r.zitadel.count("session"); n != 1 {
		t.Fatalf("the abandoned check did not run again after one interval (%d reads)", n)
	}
}

// A successful check refreshes the profile the session shows.
func TestLiveness_RefreshesTheProfile(t *testing.T) {
	r := newLivenessRig(t, 5*time.Minute)
	r.zitadel.displayName = "Ada King"
	r.zitadel.email = "ada.king@example.com"
	r.zitadel.avatar = "https://img.example/ada-king.png"
	r.due(t)
	got, err := r.sessions.Resolve(context.Background(), r.raw)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Name != "Ada King" || got.Email != "ada.king@example.com" || got.Picture != "https://img.example/ada-king.png" {
		t.Errorf("the request saw the old profile: %+v", got)
	}
	s := r.stored(t)
	if s.Name != "Ada King" || s.Email != "ada.king@example.com" || s.Picture != "https://img.example/ada-king.png" {
		t.Errorf("the stored profile was not refreshed: name=%q email=%q picture=%q", s.Name, s.Email, s.Picture)
	}
}

// AC13: a request with no check due reads nothing from Zitadel.
func TestLiveness_NotDueMakesNoCall(t *testing.T) {
	r := newLivenessRig(t, 5*time.Minute)
	if _, err := r.sessions.Resolve(context.Background(), r.raw); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, kind := range []string{"session", "user", "org"} {
		if n := r.zitadel.count(kind); n != 0 {
			t.Errorf("Zitadel received %d %s read(s) with no check due", n, kind)
		}
	}
}
