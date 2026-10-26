// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth/authtest"
	"github.com/michielvha/stackweaver/core/models"
)

// Ending browser sessions: sign-out, the idle and absolute limits, and the sweeper
// (backend-for-frontend-session-plan.md, AC5, AC8, AC36).

// fakeZitadelSessions records the Zitadel session deletes it receives and answers each with the
// status the test set for that session (200 by default).
type fakeZitadelSessions struct {
	mu      sync.Mutex
	status  map[string]int
	deletes []string
	at      []time.Time
}

func (f *fakeZitadelSessions) CallZitadel(_ context.Context, method, path string, _ any) (int, []byte, error) {
	if method != http.MethodDelete || !strings.HasPrefix(path, "/v2/sessions/") {
		return http.StatusNotFound, nil, nil
	}
	sid := strings.TrimPrefix(path, "/v2/sessions/")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, sid)
	f.at = append(f.at, time.Now())
	if st, ok := f.status[sid]; ok {
		return st, nil, nil
	}
	return http.StatusOK, []byte(`{}`), nil
}

func (f *fakeZitadelSessions) deleted() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.deletes...)
}

type lifecycleRig struct {
	store    *authtest.MemSessions
	sessions *Sessions
	zitadel  *fakeZitadelSessions
	now      time.Time
}

func newLifecycleRig() *lifecycleRig {
	r := &lifecycleRig{
		store:   authtest.NewMemSessions(),
		zitadel: &fakeZitadelSessions{status: map[string]int{}},
		now:     time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC),
	}
	r.sessions = NewSessions(r.store, DefaultSessionLimits, func() time.Time { return r.now })
	r.sessions.SetZitadel(r.zitadel)
	return r
}

func (r *lifecycleRig) start(t *testing.T, sid string) (string, *models.BrowserSession) {
	t.Helper()
	raw, s, err := r.sessions.Start(&models.BrowserSession{UserID: uuid.New(), ZitadelSubject: "sub", ZitadelSID: sid})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	return raw, s
}

// AC5: sign-out deletes the row and the Zitadel session, so the old cookie is refused and
// signing back in needs a credential.
func TestSignOut_EndsTheSessionAndItsZitadelSession(t *testing.T) {
	r := newLifecycleRig()
	raw, s := r.start(t, "sid-out")
	if err := r.sessions.SignOut(context.Background(), s); err != nil {
		t.Fatalf("SignOut: %v", err)
	}
	if _, err := r.sessions.Resolve(context.Background(), raw); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("the signed-out cookie was not refused: %v", err)
	}
	if got := r.zitadel.deleted(); len(got) != 1 || got[0] != "sid-out" {
		t.Errorf("Zitadel session deletes = %v, want [sid-out]", got)
	}
}

// A failed Zitadel delete at sign-out still signs the browser out.
func TestSignOut_ZitadelFailureStillDeletesTheRow(t *testing.T) {
	r := newLifecycleRig()
	r.zitadel.status["sid-down"] = http.StatusServiceUnavailable
	raw, s := r.start(t, "sid-down")
	if err := r.sessions.SignOut(context.Background(), s); err != nil {
		t.Fatalf("SignOut: %v", err)
	}
	if _, err := r.sessions.Resolve(context.Background(), raw); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("the session survived sign-out: %v", err)
	}
}

// AC8: the idle limit and the absolute limit both refuse, and ending the expired session deletes
// its Zitadel session before the row.
func TestExpiry_LimitsRefuseAndEndTheZitadelSession(t *testing.T) {
	for name, after := range map[string]time.Duration{
		"idle":     DefaultSessionLimits.Idle,
		"absolute": DefaultSessionLimits.Absolute,
	} {
		t.Run(name, func(t *testing.T) {
			r := newLifecycleRig()
			raw, _ := r.start(t, "sid-"+name)
			if name == "absolute" {
				// Activity up to the end does not matter to the absolute limit.
				for elapsed := time.Duration(0); elapsed < after; elapsed += 30 * time.Minute {
					r.now = r.now.Add(30 * time.Minute)
					s, err := r.sessions.Resolve(context.Background(), raw)
					if err != nil {
						break
					}
					if err := r.sessions.Touch(s); err != nil {
						t.Fatalf("touch: %v", err)
					}
				}
			} else {
				r.now = r.now.Add(after)
			}
			if _, err := r.sessions.Resolve(context.Background(), raw); !errors.Is(err, ErrSessionExpired) && !errors.Is(err, ErrSessionNotFound) {
				t.Fatalf("Resolve after the %s limit = %v, want a refusal", name, err)
			}
			if r.store.Len() != 0 {
				t.Error("the expired session's row is still stored")
			}
			if got := r.zitadel.deleted(); len(got) != 1 || got[0] != "sid-"+name {
				t.Errorf("Zitadel session deletes = %v, want [sid-%s]", got, name)
			}
		})
	}
}

// AC36: a 404 from Zitadel counts as done; a 5xx leaves the row for the sweeper to retry, and the
// row's timestamps keep refusing the cookie meanwhile.
func TestExpiry_ZitadelAnswerDecidesWhetherTheRowGoes(t *testing.T) {
	cases := map[string]struct {
		status  int
		rowGone bool
	}{
		"2xx": {http.StatusOK, true},
		"404": {http.StatusNotFound, true},
		"5xx": {http.StatusBadGateway, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := newLifecycleRig()
			r.zitadel.status["sid-x"] = tc.status
			raw, _ := r.start(t, "sid-x")
			r.now = r.now.Add(DefaultSessionLimits.Idle)
			if _, err := r.sessions.Resolve(context.Background(), raw); !errors.Is(err, ErrSessionExpired) {
				t.Fatalf("Resolve = %v, want ErrSessionExpired", err)
			}
			if gone := r.store.Len() == 0; gone != tc.rowGone {
				t.Errorf("row gone = %v, want %v", gone, tc.rowGone)
			}
			if !tc.rowGone {
				if _, err := r.sessions.Resolve(context.Background(), raw); !errors.Is(err, ErrSessionExpired) {
					t.Errorf("the left-over row was not refused: %v", err)
				}
				r.zitadel.status["sid-x"] = http.StatusOK
				if err := r.sessions.Sweep(context.Background()); err != nil {
					t.Fatalf("Sweep: %v", err)
				}
				if r.store.Len() != 0 {
					t.Error("the sweeper did not retry the left-over row")
				}
			}
		})
	}
}

// AC36: when another live session names the same Zitadel session, ending the expired one leaves
// the Zitadel session alone.
func TestExpiry_SharedZitadelSessionIsLeftAlone(t *testing.T) {
	r := newLifecycleRig()
	_, old := r.start(t, "sid-shared")
	r.now = r.now.Add(30 * time.Minute)
	_, live := r.start(t, "sid-shared")
	r.now = r.now.Add(31 * time.Minute) // past the first one's idle limit, inside the second's
	if err := r.sessions.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got := r.zitadel.deleted(); len(got) != 0 {
		t.Fatalf("the shared Zitadel session was deleted: %v", got)
	}
	if r.store.ByID(old.ID) != nil {
		t.Error("the expired row is still stored")
	}
	if r.store.ByID(live.ID) == nil {
		t.Error("the live row was removed")
	}
}

// AC8: a touch extends the idle limit.
func TestTouch_ExtendsTheIdleLimit(t *testing.T) {
	r := newLifecycleRig()
	raw, _ := r.start(t, "sid-touch")
	r.now = r.now.Add(50 * time.Minute)
	s, err := r.sessions.Resolve(context.Background(), raw)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := r.sessions.Touch(s); err != nil {
		t.Fatalf("touch: %v", err)
	}
	r.now = r.now.Add(50 * time.Minute) // 100 minutes after sign-in, 50 after the touch
	if _, err := r.sessions.Resolve(context.Background(), raw); err != nil {
		t.Fatalf("a touched session expired at its original idle limit: %v", err)
	}
}

// AC36: the sweeper paces its Zitadel deletes at no more than five a second.
func TestSweep_PacesZitadelDeletes(t *testing.T) {
	r := newLifecycleRig()
	for i := range 4 {
		r.start(t, "sid-sweep-"+string(rune('a'+i)))
	}
	r.now = r.now.Add(DefaultSessionLimits.Idle)
	if err := r.sessions.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n := len(r.zitadel.deleted()); n != 4 {
		t.Fatalf("swept %d Zitadel sessions, want 4", n)
	}
	r.zitadel.mu.Lock()
	defer r.zitadel.mu.Unlock()
	for i := 1; i < len(r.zitadel.at); i++ {
		if gap := r.zitadel.at[i].Sub(r.zitadel.at[i-1]); gap < sweepPace-10*time.Millisecond {
			t.Errorf("deletes %d and %d were %s apart, want at least %s", i-1, i, gap, sweepPace)
		}
	}
	if r.store.Len() != 0 {
		t.Errorf("%d expired rows survived the sweep", r.store.Len())
	}
}

// The sweeper stops when its context ends, so the API shuts down cleanly.
func TestRunSweeper_StopsOnShutdown(t *testing.T) {
	r := newLifecycleRig()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.sessions.RunSweeper(ctx, 10*time.Millisecond)
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the sweeper did not stop after its context ended")
	}
}
