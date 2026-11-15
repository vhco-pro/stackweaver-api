//go:build integration

package handlers

import (
	"testing"
	"time"

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
		_, _, err := f.handler.queueCapturedRun(f.wsApp, prSpec(captureHead), func(runs *repository.RunRepository, versions *repository.ConfigurationVersionRepository) {
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
		_, created, err := f.handler.queueCapturedRun(f.wsApp, prSpec(captureNext), supersede)
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
	old, created, err := f.handler.queueCapturedRun(f.wsApp, prSpec(captureHead), supersede)
	if err != nil || !created {
		t.Fatalf("first delivery: created=%v err=%v", created, err)
	}
	for i := 0; i < 101; i++ {
		filler := &models.Run{WorkspaceID: f.wsApp.ID, Status: models.RunStatusPlannedAndFinished, Operation: models.RunOperationPlanOnly}
		if err := f.db.Create(filler).Error; err != nil {
			t.Fatal(err)
		}
	}
	if _, created, err = f.handler.queueCapturedRun(f.wsApp, prSpec(captureNext), supersede); err != nil || !created {
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
