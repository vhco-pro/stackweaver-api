// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/repository"
)

const (
	// sweepPace spaces the sweeper's Zitadel deletes, at most five a second. Each delete makes
	// Zitadel post a logout token back to the API from one address, and those must stay below the
	// per-IP auth rate limit.
	sweepPace = 200 * time.Millisecond
	// sweepBatch is how many expired sessions one sweep takes on.
	sweepBatch = 100
	// SweepInterval is how often the sweeper runs.
	SweepInterval = time.Minute
	// zitadelDeleteTimeout bounds one Zitadel session delete.
	zitadelDeleteTimeout = 5 * time.Second
)

// deleteZitadelSession ends a Zitadel session with the login service account. A 404 counts as done:
// the session is already gone, which is what was wanted.
func deleteZitadelSession(ctx context.Context, z ZitadelCaller, sid string) error {
	ctx, cancel := context.WithTimeout(ctx, zitadelDeleteTimeout)
	defer cancel()
	status, _, err := z.CallZitadel(ctx, http.MethodDelete, "/v2/sessions/"+url.PathEscape(sid), map[string]any{})
	if err != nil {
		return err
	}
	if status/100 == 2 || status == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("zitadel answered %d", status)
}

// endExpired ends an expired session: its Zitadel session first, and its row only once Zitadel has
// answered, so a failed delete leaves the row for the next sweep to retry while its timestamps keep
// refusing it. The Zitadel session is left alone while another live session names it. It reports
// whether it called Zitadel, so the sweeper can pace itself.
func (ss *Sessions) endExpired(ctx context.Context, e repository.ExpiredSession) (calledZitadel bool) {
	if ss.zitadel != nil && e.ZitadelSID != "" {
		shared, err := ss.store.HasLiveSessionForSID(e.ZitadelSID, e.ID, ss.now())
		if err != nil {
			logger.Warnf("auth: checking whether expired session %s shares its Zitadel session: %v", e.ID, err)
			return false
		}
		if !shared {
			calledZitadel = true
			if err := deleteZitadelSession(ctx, ss.zitadel, e.ZitadelSID); err != nil {
				logger.Warnf("auth: ending the Zitadel session of expired session %s, will retry: %v", e.ID, err)
				return calledZitadel
			}
		}
	}
	if err := ss.store.DeleteByID(e.ID); err != nil {
		logger.Warnf("auth: deleting expired session %s: %v", e.ID, err)
	}
	return calledZitadel
}

// Sweep ends the sessions past their idle or absolute limit, at most sweepBatch of them, pacing the
// Zitadel deletes, and removes expired login transactions. It is idempotent across replicas: two
// sweeping one row both see 2xx or 404 from Zitadel, and the second row delete finds nothing.
func (ss *Sessions) Sweep(ctx context.Context) error {
	expired, err := ss.store.ListExpired(ss.now(), sweepBatch)
	if err != nil {
		return fmt.Errorf("listing expired sessions: %w", err)
	}
	for i, e := range expired {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if ss.endExpired(ctx, e) && i < len(expired)-1 {
			select {
			case <-time.After(ss.pace):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if _, err := ss.store.DeleteExpiredLoginTransactions(ss.now()); err != nil {
		return fmt.Errorf("deleting expired login transactions: %w", err)
	}
	return nil
}

// RunSweeper sweeps every interval until ctx ends. main.go owns it and cancels ctx on shutdown.
func (ss *Sessions) RunSweeper(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ss.Sweep(ctx); err != nil && ctx.Err() == nil {
				logger.Warnf("auth: sweeping expired sessions: %v", err)
			}
		}
	}
}
