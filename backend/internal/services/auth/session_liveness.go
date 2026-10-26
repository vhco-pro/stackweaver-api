// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// ZitadelCaller makes a request to Zitadel's API as the login service account and returns the
// status and body. The auth proxy implements it over its own connection to Zitadel.
type ZitadelCaller interface {
	CallZitadel(ctx context.Context, method, path string, body any) (status int, respBody []byte, err error)
}

// LivenessStore is what the liveness check needs from the session store.
type LivenessStore interface {
	ClaimDueCheck(id uuid.UUID, interval time.Duration) (bool, error)
	SetNextCheck(id uuid.UUID, at time.Time) error
	DeleteByID(id uuid.UUID) error
	UpdateProfile(id uuid.UUID, p repository.SessionProfile) error
}

// The repository is the production LivenessStore.
var _ LivenessStore = (*repository.BrowserSessionRepository)(nil)

const (
	// livenessBudget bounds the three reads together; a slow Zitadel takes the same path as an
	// unreachable one, so the request is not held for long.
	livenessBudget = 5 * time.Second
	// livenessRetry is when a check that reached no verdict runs again.
	livenessRetry = 30 * time.Second
)

// ZitadelLiveness checks a browser session against Zitadel: the session, its user and the user's
// organisation, read in parallel with the login service account. A definite answer that any of
// them is gone ends the session. Anything else (an outage, a timeout, a refused service-account
// token) keeps it and retries thirty seconds later, so Zitadel trouble never signs users out; the
// idle and absolute limits bound how long that can last.
type ZitadelLiveness struct {
	store    LivenessStore
	zitadel  ZitadelCaller
	interval time.Duration
	budget   time.Duration
	now      func() time.Time
}

// NewZitadelLiveness returns the liveness check, run at most once per interval per session.
func NewZitadelLiveness(store LivenessStore, zitadel ZitadelCaller, interval time.Duration) *ZitadelLiveness {
	return &ZitadelLiveness{store: store, zitadel: zitadel, interval: interval, budget: livenessBudget, now: time.Now}
}

// verdict is what one read concluded.
type verdict int

const (
	alive  verdict = iota
	gone           // Zitadel answered definitely that the thing is gone or no longer allowed in
	unsure         // no answer could be had
)

// Check claims the session's due check and runs it. A request that loses the claim proceeds on the
// current record: another request, on this replica or another, is checking. The claimant waits for
// the verdict.
func (l *ZitadelLiveness) Check(ctx context.Context, s *models.BrowserSession) error {
	won, err := l.store.ClaimDueCheck(s.ID, l.interval)
	if err != nil {
		logger.Warnf("auth: claiming the liveness check of session %s: %v", s.ID, err)
		return nil
	}
	if !won {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, l.budget)
	defer cancel()

	var (
		wg                          sync.WaitGroup
		sessionV, userV, orgV       verdict
		sessionWhy, userWhy, orgWhy string
		profile                     repository.SessionProfile
	)
	wg.Go(func() { sessionV, sessionWhy = l.readSession(ctx, s) })
	wg.Go(func() { userV, userWhy, profile = l.readUser(ctx, s) })
	wg.Go(func() { orgV, orgWhy = l.readOrganization(ctx, s) })
	wg.Wait()

	switch {
	case sessionV == gone || userV == gone || orgV == gone:
		logger.Infof("auth: ending browser session %s: %s", s.ID, firstReason(
			[]verdict{sessionV, userV, orgV}, []string{sessionWhy, userWhy, orgWhy}, gone))
		if err := l.store.DeleteByID(s.ID); err != nil {
			logger.Errorf("auth: deleting ended session %s: %v", s.ID, err)
		}
		return ErrSessionEnded
	case sessionV == unsure || userV == unsure || orgV == unsure:
		logger.Warnf("auth: the liveness check of session %s reached no verdict, retrying in %s: %s", s.ID, livenessRetry,
			firstReason([]verdict{sessionV, userV, orgV}, []string{sessionWhy, userWhy, orgWhy}, unsure))
		if err := l.store.SetNextCheck(s.ID, l.now().Add(livenessRetry)); err != nil {
			logger.Warnf("auth: rescheduling the liveness check of session %s: %v", s.ID, err)
		}
		return nil
	}

	if err := l.store.UpdateProfile(s.ID, profile); err != nil {
		logger.Warnf("auth: refreshing the profile of session %s: %v", s.ID, err)
		return nil
	}
	s.Email, s.Name, s.GivenName, s.FamilyName, s.Picture = profile.Email, profile.Name, profile.GivenName, profile.FamilyName, profile.Picture
	return nil
}

func firstReason(vs []verdict, whys []string, want verdict) string {
	for i, v := range vs {
		if v == want {
			return whys[i]
		}
	}
	return ""
}

// classify turns a read's outcome into a verdict: 404 is a definite "gone", 200 is an answer to
// look into, and anything else (a network error, a timeout, 5xx, or 401 and 403, which are about
// the service account rather than the user) is no answer.
func classify(status int, err error) (verdict, string, bool) {
	switch {
	case err != nil:
		return unsure, err.Error(), false
	case status == http.StatusNotFound:
		return gone, "", false
	case status == http.StatusOK:
		return alive, "", true
	default:
		return unsure, fmt.Sprintf("Zitadel answered %d", status), false
	}
}

func (l *ZitadelLiveness) readSession(ctx context.Context, s *models.BrowserSession) (verdict, string) {
	status, body, err := l.zitadel.CallZitadel(ctx, http.MethodGet, "/v2/sessions/"+url.PathEscape(s.ZitadelSID), nil)
	v, why, ok := classify(status, err)
	if !ok {
		if v == gone {
			why = "the Zitadel session no longer exists"
		}
		return v, "session read: " + why
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
	if err := json.Unmarshal(body, &parsed); err != nil {
		return unsure, "session read: " + err.Error()
	}
	if id := parsed.Session.Factors.User.ID; id != "" && id != s.ZitadelSubject {
		return gone, "the Zitadel session belongs to another user"
	}
	return alive, ""
}

func (l *ZitadelLiveness) readUser(ctx context.Context, s *models.BrowserSession) (verdict, string, repository.SessionProfile) {
	status, body, err := l.zitadel.CallZitadel(ctx, http.MethodGet, "/v2/users/"+url.PathEscape(s.ZitadelSubject), nil)
	v, why, ok := classify(status, err)
	if !ok {
		if v == gone {
			why = "the user no longer exists"
		}
		return v, "user read: " + why, repository.SessionProfile{}
	}
	var parsed struct {
		User struct {
			State string `json:"state"`
			Human *struct {
				Profile struct {
					GivenName   string `json:"givenName"`
					FamilyName  string `json:"familyName"`
					DisplayName string `json:"displayName"`
					AvatarURL   string `json:"avatarUrl"`
				} `json:"profile"`
				Email struct {
					Email      string `json:"email"`
					IsVerified bool   `json:"isVerified"`
				} `json:"email"`
			} `json:"human"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return unsure, "user read: " + err.Error(), repository.SessionProfile{}
	}
	u := parsed.User
	if u.State != "USER_STATE_ACTIVE" {
		return gone, "the user is " + u.State, repository.SessionProfile{}
	}
	if u.Human == nil || !u.Human.Email.IsVerified {
		return gone, "the user's email address is not verified", repository.SessionProfile{}
	}
	p := u.Human.Profile
	name := p.DisplayName
	if name == "" {
		name = s.Name
	}
	return alive, "", repository.SessionProfile{
		Email: u.Human.Email.Email, Name: name, GivenName: p.GivenName, FamilyName: p.FamilyName, Picture: p.AvatarURL,
	}
}

func (l *ZitadelLiveness) readOrganization(ctx context.Context, s *models.BrowserSession) (verdict, string) {
	if s.OrganizationID == "" {
		return alive, ""
	}
	query := map[string]any{"queries": []any{map[string]any{"idQuery": map[string]any{"id": s.OrganizationID}}}}
	status, body, err := l.zitadel.CallZitadel(ctx, http.MethodPost, "/v2/organizations/_search", query)
	v, why, ok := classify(status, err)
	if !ok {
		return v, "organisation read: " + why
	}
	var parsed struct {
		Result []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return unsure, "organisation read: " + err.Error()
	}
	for _, org := range parsed.Result {
		if org.ID == s.OrganizationID {
			if org.State != "ORGANIZATION_STATE_ACTIVE" {
				return gone, "the organisation is " + org.State
			}
			return alive, ""
		}
	}
	return gone, "the organisation no longer exists"
}
