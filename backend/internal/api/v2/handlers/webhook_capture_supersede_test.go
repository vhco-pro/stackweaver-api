//go:build integration

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	terraform "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers/terraform"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// prSpec is a delivery of pull request 71 from branch feature at commit.
func prSpec(commit string) captureSpec {
	return captureSpec{commit: commit, fetchRef: "refs/pull/71/head", sourceBranch: "feature", prNumber: 71, speculative: true}
}

// TestCapturedPRCommitsSupersedeConcurrently holds the older delivery inside its capture
// transaction, after its supersede scan, while the newer commit of the same pull request arrives.
// Only the newer speculative run may stay pending (AC-20, R-20 F-01).
func TestCapturedPRCommitsSupersedeConcurrently(t *testing.T) {
	f := setupCapture(t)
	supersede := func(runs *repository.RunRepository, versions *repository.ConfigurationVersionRepository) {
		terraform.AutoCancelSupersededSpeculativeRuns(runs, versions, f.wsApp.ID, "feature", 71)
	}
	checked, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, _, err := f.handler.queueCapturedRun(t.Context(), f.wsApp, prSpec(captureHead), func(runs *repository.RunRepository, versions *repository.ConfigurationVersionRepository) {
			supersede(runs, versions)
			close(checked)
			<-release
		})
		done <- err
	}()
	select {
	case <-checked:
	case <-time.After(10 * time.Second):
		t.Fatal("the first delivery never reached its supersede scan")
	}
	second := make(chan error, 1)
	go func() {
		_, created, err := f.handler.queueCapturedRun(t.Context(), f.wsApp, prSpec(captureNext), supersede)
		if err == nil && !created {
			t.Error("the second delivery created nothing")
		}
		second <- err
	}()
	// The second delivery must wait for the first; give it time to block before releasing.
	time.Sleep(500 * time.Millisecond)
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second delivery: %v", err)
	}
	var pending []models.Run
	if err := f.db.Where("workspace_id = ? AND status = ?", f.wsApp.ID, models.RunStatusPending).Find(&pending).Error; err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending runs after two concurrent commits of PR 71 = %d, want only the newer one", len(pending))
	}
}

// TestForkPRsSharingABranchNameDoNotSupersede delivers signed pull requests 71 and 72 from two
// forks whose head branches are both main. They are different pull requests, so both runs stay
// pending (AC-20, R-21 F-01).
func TestForkPRsSharingABranchNameDoNotSupersede(t *testing.T) {
	f := setupCapture(t)
	deliver := func(commit string, number int, fork string) {
		body := f.githubPullRequest(commit)
		body["number"] = number
		head := body["pull_request"].(map[string]any)["head"].(map[string]any)
		head["ref"] = "main"
		head["repo"] = map[string]any{"full_name": fork}
		f.github(t, "pull_request", body)
	}
	deliver(captureHead, 71, "alice/repo")
	deliver(captureNext, 72, "bob/repo")
	pairs := f.pairs(t, f.wsApp)
	if len(pairs) != 2 {
		t.Fatalf("%d pull request runs, want 2", len(pairs))
	}
	for _, p := range pairs {
		if p.run.Status != models.RunStatusPending {
			t.Errorf("pull request %d after a delivery from another fork = %s, want pending", p.cv.PRNumber, p.run.Status)
		}
	}
}

// TestCapturedPRSupersedesBeyondFirstPage puts more than one page of newer history between the
// pending run and the next delivery for its pull request; the pending run is still cancelled
// (AC-20, R-20 F-02).
func TestCapturedPRSupersedesBeyondFirstPage(t *testing.T) {
	f := setupCapture(t)
	supersede := func(runs *repository.RunRepository, versions *repository.ConfigurationVersionRepository) {
		terraform.AutoCancelSupersededSpeculativeRuns(runs, versions, f.wsApp.ID, "feature", 71)
	}
	old, created, err := f.handler.queueCapturedRun(t.Context(), f.wsApp, prSpec(captureHead), supersede)
	if err != nil || !created {
		t.Fatalf("first delivery: created=%v err=%v", created, err)
	}
	for i := 0; i < 101; i++ {
		filler := &models.Run{WorkspaceID: f.wsApp.ID, Status: models.RunStatusPlannedAndFinished, Operation: models.RunOperationPlanOnly}
		if err := f.db.Create(filler).Error; err != nil {
			t.Fatal(err)
		}
	}
	if _, created, err = f.handler.queueCapturedRun(t.Context(), f.wsApp, prSpec(captureNext), supersede); err != nil || !created {
		t.Fatalf("second delivery: created=%v err=%v", created, err)
	}
	var got models.Run
	if err := f.db.First(&got, "id = ?", old.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != models.RunStatusCancelled {
		t.Fatalf("older pull request run after a newer delivery = %s, want cancelled", got.Status)
	}
}

// TestAnAbandonedDeliveryStopsWaiting: a signed push that waits for its workspace's capture lock
// stops waiting when its request is canceled, holds no connection and creates nothing (R-28 F-01).
func TestAnAbandonedDeliveryStopsWaiting(t *testing.T) {
	f := setupCapture(t)
	held, release, holder := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		// The workspace's capture lock, held the way CreateCaptured holds it.
		holder <- f.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", "capture:"+f.wsApp.ID).Error; err != nil {
				return err
			}
			close(held)
			<-release
			return nil
		})
	}()
	released := false
	defer func() {
		if !released {
			close(release)
		}
		<-holder
	}()
	<-held
	payload, _ := json.Marshal(f.githubPush(captureHead))
	ctx, cancel := context.WithCancel(t.Context())
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v2/vcs-connections/github/webhook", bytes.NewReader(payload))
	c.Request.Header.Set("X-GitHub-Event", "push")
	c.Request.Header.Set("X-Hub-Signature-256", githubSign(payload, f.secret))
	done := make(chan struct{})
	go func() {
		f.handler.HandleInstallationWebhook(c)
		close(done)
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("an abandoned delivery kept waiting for the capture lock")
	}
	close(release)
	released = true
	<-holder
	holder <- nil
	if pairs := f.pairs(t, f.wsApp); len(pairs) != 0 {
		t.Errorf("an abandoned delivery created %d run(s), want none", len(pairs))
	}
}

// TestAnAbandonedCaptureGivesUpWaitingForAConnection: with the pool's only connection taken, a
// capture whose context ends stops waiting for one, including before its transaction, where it
// looks up the workspace's pool (R-29 F-01).
func TestAnAbandonedCaptureGivesUpWaitingForAConnection(t *testing.T) {
	f := setupCapture(t)
	sqlDB, err := f.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	held, release, holder := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		holder <- f.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("SELECT 1").Error; err != nil {
				return err
			}
			close(held)
			<-release
			return nil
		})
	}()
	released := false
	defer func() {
		if !released {
			close(release)
			<-holder
		}
		sqlDB.SetMaxOpenConns(0)
	}()
	<-held
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, _, err := f.handler.queueCapturedRun(ctx, f.wsApp, prSpec(captureHead), nil)
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("an abandoned capture succeeded without a connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an abandoned capture kept waiting for a database connection")
	}
	close(release)
	released = true
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
}

// queuePR delivers pull request number at commit through the capture path with the production
// supersede step, as the GitHub and Azure DevOps handlers do.
func queuePR(t *testing.T, f *captureFixture, commit string, number int) (*models.Run, bool) {
	t.Helper()
	spec := captureSpec{commit: commit, fetchRef: "refs/pull/71/head", sourceBranch: "feature", prNumber: number, speculative: true}
	run, created, err := f.handler.queueCapturedRun(t.Context(), f.wsApp, spec, func(runs *repository.RunRepository, versions *repository.ConfigurationVersionRepository) {
		terraform.AutoCancelSupersededSpeculativeRuns(runs, versions, f.wsApp.ID, spec.sourceBranch, spec.prNumber)
	})
	if err != nil {
		t.Fatalf("PR %d at %s: %v", number, commit[:7], err)
	}
	return run, created
}

func statusOf(t *testing.T, f *captureFixture, id string) models.RunStatus {
	t.Helper()
	var r models.Run
	if err := f.db.First(&r, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	return r.Status
}

// TestSecondPRAtTheSameCommitGetsItsOwnRun: two pull requests at one commit each get a run, so
// each gets its own pull request status (AC-20, R-23 F-01).
func TestSecondPRAtTheSameCommitGetsItsOwnRun(t *testing.T) {
	f := setupCapture(t)
	first, created := queuePR(t, f, captureHead, 71)
	if !created {
		t.Fatal("PR 71 created nothing")
	}
	second, created := queuePR(t, f, captureHead, 72)
	if !created {
		t.Fatal("PR 72 at the same commit created nothing, want its own run")
	}
	for _, r := range []*models.Run{first, second} {
		if got := statusOf(t, f, r.ID); got != models.RunStatusPending {
			t.Errorf("run %s = %s, want pending", r.ID, got)
		}
	}
	listed, err := f.handler.runRepo.ListPRRunsForStatusChecks(1000)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range listed {
		seen[r.ID] = true
	}
	if !seen[first.ID] || !seen[second.ID] {
		t.Errorf("status checks list PR 71 run %v and PR 72 run %v, want both", seen[first.ID], seen[second.ID])
	}
}

// TestRedeliveryWhileTheRunIsActiveCreatesNothing (AC-20, Q12).
func TestRedeliveryWhileTheRunIsActiveCreatesNothing(t *testing.T) {
	f := setupCapture(t)
	if _, created := queuePR(t, f, captureHead, 71); !created {
		t.Fatal("first delivery created nothing")
	}
	if _, created := queuePR(t, f, captureHead, 71); created {
		t.Fatal("a redelivery while the commit's run is pending created a second run")
	}
}

// TestSupersededCommitIsPlannedAgain: after B supersedes A, the next delivery of A plans it again
// and supersedes B, as TFE plans every pull request event (AC-20, Q12).
func TestSupersededCommitIsPlannedAgain(t *testing.T) {
	f := setupCapture(t)
	a, _ := queuePR(t, f, captureHead, 71)
	b, _ := queuePR(t, f, captureNext, 71)
	if got := statusOf(t, f, a.ID); got != models.RunStatusCancelled {
		t.Fatalf("A after B = %s, want canceled", got)
	}
	again, created := queuePR(t, f, captureHead, 71)
	if !created {
		t.Fatal("the next delivery of superseded commit A created nothing, want a new run")
	}
	if got := statusOf(t, f, again.ID); got != models.RunStatusPending {
		t.Errorf("A again = %s, want pending", got)
	}
	if got := statusOf(t, f, b.ID); got != models.RunStatusCancelled {
		t.Errorf("B after A again = %s, want canceled", got)
	}
}

// TestTheDeliveryProcessedLastWins: in either order, the pull request delivery processed last
// stays pending and the other is canceled (AC-20, Q12).
func TestTheDeliveryProcessedLastWins(t *testing.T) {
	for _, order := range [][2]string{{captureHead, captureNext}, {captureNext, captureHead}} {
		t.Run(order[0][:7]+"-then-"+order[1][:7], func(t *testing.T) {
			f := setupCapture(t)
			earlier, _ := queuePR(t, f, order[0], 71)
			last, _ := queuePR(t, f, order[1], 71)
			if got := statusOf(t, f, earlier.ID); got != models.RunStatusCancelled {
				t.Errorf("earlier delivery = %s, want canceled", got)
			}
			if got := statusOf(t, f, last.ID); got != models.RunStatusPending {
				t.Errorf("last delivery = %s, want pending", got)
			}
		})
	}
}
