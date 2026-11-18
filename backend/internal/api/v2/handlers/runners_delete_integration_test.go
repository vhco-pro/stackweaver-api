// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the launcher delete (#856,
// docs/internal/bug-reports/platform/concurrent-runner-delete-returns-500.md): a delete that loses
// a race with another delete of the same launcher answers 404, and a delete removes the
// launcher's own tokens.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run 'TestRunnerDelete_|TestAgentPoolDelete_'

//go:build integration

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// deleteWhileRowLocked makes two overlapping deletes deterministic. A transaction runs lock, which
// deletes the row and so holds its lock; the request is then sent, and the transaction commits
// only once the request is blocked on that lock. The request has passed the handler's lookup by
// then, so its own delete removes no row. It returns the request's response.
func deleteWhileRowLocked(t *testing.T, db *gorm.DB, router http.Handler, path string, as identity, lock func(tx *gorm.DB) error) *httptest.ResponseRecorder {
	t.Helper()
	winner := db.Begin()
	if winner.Error != nil {
		t.Fatal(winner.Error)
	}
	// Registered after the caller's fixtures, so it runs before their cleanups. Releasing the lock
	// lets a request still waiting on it finish, and the join keeps it from outliving the fixture
	// rows and the pool.
	committed := false
	var request sync.WaitGroup
	t.Cleanup(func() {
		if !committed {
			winner.Rollback()
		}
		request.Wait()
	})
	var winnerPID int
	if err := winner.Raw("SELECT pg_backend_pid()").Scan(&winnerPID).Error; err != nil {
		t.Fatal(err)
	}
	if err := lock(winner); err != nil {
		t.Fatal(err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	request.Go(func() {
		done <- platformAdminCall(t, router, http.MethodDelete, path, as, "")
	})

	deadline := time.Now().Add(10 * time.Second)
	poll, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	for {
		var blocked int64
		if err := db.WithContext(poll).Raw("SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))", winnerPID).Scan(&blocked).Error; err != nil {
			t.Fatal(err)
		}
		if blocked > 0 {
			break
		}
		select {
		case rec := <-done:
			t.Fatalf("delete answered %d %s before it waited on the other delete's lock", rec.Code, rec.Body.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the delete request never waited on the other delete's lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := winner.Commit().Error; err != nil {
		t.Fatal(err)
	}
	committed = true

	select {
	case rec := <-done:
		return rec
	case <-time.After(10 * time.Second):
		t.Fatal("the delete request did not finish after the other delete committed")
		return nil
	}
}

// runnerDeleteFixture is a customer pool in orgA with one launcher, and the handler and router
// that serve DELETE /api/v2/runners/:id.
type runnerDeleteFixture struct {
	*platformAdminFixture
	runner  *models.Runner
	handler *RunnerHandlerV2
	router  http.Handler
	keys    *apikey.Service
}

func setupRunnerDeleteFixture(t *testing.T) *runnerDeleteFixture {
	t.Helper()
	f := setupPlatformAdminFixture(t)
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "rdel-" + f.sfx, OrganizationScoped: true}
	if err := f.db.Create(pool).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", pool.ID).Delete(&models.AgentPool{}) })
	runner := &models.Runner{
		ID: uuid.New(), Name: "rdel-" + f.sfx, OrganizationID: &f.orgA.ID, AgentPoolID: &pool.ID,
		Kind: models.RunnerKindCustomer, RunnerType: models.RunnerTypeTofu, Status: models.RunnerStatusOnline,
	}
	if err := f.db.Create(runner).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", runner.ID).Delete(&models.Runner{}) })

	orgs := repository.NewOrganizationRepository(f.db)
	teams := repository.NewTeamRepository(f.db)
	projects := repository.NewProjectRepository(f.db)
	keys := apikey.NewService(repository.NewAPIKeyRepository(f.db), orgs, projects, teams)
	h := NewRunnerHandlerV2(repository.NewRunnerRepository(f.db), repository.NewRunnerJobExecutionRepository(f.db),
		repository.NewAgentPoolRepository(f.db), orgs, rbac.NewServiceWithTeams(orgs, teams, projects))
	h.SetAPIKeyService(keys)
	r := platformAdminRouter()
	r.DELETE("/api/v2/runners/:id", h.Delete)
	return &runnerDeleteFixture{platformAdminFixture: f, runner: runner, handler: h, router: r, keys: keys}
}

// The loser of two overlapping deletes passes the handler's lookup while the winner has not
// committed, then deletes no row. The launcher is gone, which is what the caller asked for, so
// the answer is 404, never 500.
func TestRunnerDelete_LosingConcurrentDeleteIsNotFound(t *testing.T) {
	f := setupRunnerDeleteFixture(t)
	rec := deleteWhileRowLocked(t, f.db, f.router, "/api/v2/runners/"+f.runner.ID.String(), browserAs(f.owner),
		func(tx *gorm.DB) error { return tx.Delete(&models.Runner{}, "id = ?", f.runner.ID).Error })
	if rec.Code != http.StatusNotFound {
		t.Fatalf("losing delete = %d %s, want 404", rec.Code, rec.Body.String())
	}
}

// Registration mints a launcher a `runner-<name>` token with runner:<id>:* scopes. Deleting the
// launcher removes that token, and leaves another launcher's token alone.
func TestRunnerDelete_RemovesTheLaunchersTokens(t *testing.T) {
	f := setupRunnerDeleteFixture(t)
	other := uuid.New()
	own, _, err := f.keys.CreateRunnerToken(f.owner.ID, f.runner.ID, f.orgA.ID, *f.runner.AgentPoolID, "runner-"+f.runner.Name)
	if err != nil {
		t.Fatal(err)
	}
	kept, _, err := f.keys.CreateRunnerToken(f.owner.ID, other, f.orgA.ID, *f.runner.AgentPoolID, "runner-other-"+f.sfx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id IN ?", []uuid.UUID{own.ID, kept.ID}).Delete(&models.APIKey{}) })

	rec := platformAdminCall(t, f.router, http.MethodDelete, "/api/v2/runners/"+f.runner.ID.String(), browserAs(f.owner), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete launcher = %d %s, want 204", rec.Code, rec.Body.String())
	}
	var ownLeft, keptLeft int64
	f.db.Model(&models.APIKey{}).Where("id = ?", own.ID).Count(&ownLeft)
	f.db.Model(&models.APIKey{}).Where("id = ?", kept.ID).Count(&keptLeft)
	if ownLeft != 0 {
		t.Errorf("the deleted launcher's token is still stored")
	}
	if keptLeft != 1 {
		t.Errorf("another launcher's token was removed")
	}
}
