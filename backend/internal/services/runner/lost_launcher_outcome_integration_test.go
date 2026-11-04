// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The lost-launcher outcome (#933, D3, decision 16, AC9): when a launcher goes offline, its plan
// phase is re-dispatched (and claimed again as a new attempt), its apply and its Ansible job end
// with "runner lost", the saved plan is untouched, and every state lock and job token of that work
// is released.

//go:build integration

package runner

import (
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

type recordingRevoker struct{ revoked []string }

func (r *recordingRevoker) RevokeJobTokens(kind models.JobType, jobID string) error {
	r.revoked = append(r.revoked, string(kind)+":"+jobID)
	return nil
}

func TestLostLauncherOutcome(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dsn, &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	sfx := uuid.NewString()[:8]
	var cleanup []any
	create := func(v any) {
		t.Helper()
		if err := db.Create(v).Error; err != nil {
			t.Fatalf("seed %T: %v", v, err)
		}
		cleanup = append([]any{v}, cleanup...)
	}
	t.Cleanup(func() {
		for _, v := range cleanup {
			db.Delete(v)
		}
	})
	org := &models.Organization{ID: uuid.New(), Name: "lost-org-" + sfx}
	create(org)
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: org.ID, Name: "lost-pool-" + sfx}
	create(pool)
	proj := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "lost-proj-" + sfx}
	create(proj)
	inv := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: org.ID, Name: "lost-inv-" + sfx, Type: models.InventoryTypeStatic}
	create(inv)
	stale := time.Now().Add(-10 * time.Minute)
	gone := &models.Runner{ID: uuid.New(), OrganizationID: new(org.ID), AgentPoolID: new(pool.ID), Name: "lost-runner-" + sfx, Status: models.RunnerStatusOnline, LastHeartbeatAt: &stale}
	create(gone)
	now := time.Now()
	run := func(status models.RunStatus) *models.Run {
		ws := &models.Workspace{ProjectID: proj.ID, Name: "lost-ws-" + uuid.NewString()[:8], ExecutionMode: "agent", AgentPoolID: &pool.ID}
		create(ws)
		r := &models.Run{WorkspaceID: ws.ID, Status: status, Operation: models.RunOperationPlanAndApply, AgentPoolID: &pool.ID, RunnerID: &gone.ID, DispatchedAt: &now, Attempt: 1}
		create(r)
		lock := &models.StateLock{WorkspaceID: ws.ID, LockID: repository.RunStateLockID(r.ID), Operation: "plan_and_apply", LockedBy: &r.ID, ExpiresAt: now.Add(time.Hour)}
		create(lock)
		return r
	}
	planning := run(models.RunStatusPlanning)
	applying := run(models.RunStatusApplying)
	job := &models.AnsibleJob{ID: uuid.New(), ProjectID: proj.ID, InventoryID: inv.ID, Status: models.AnsibleJobStatusRunning, AgentPoolID: &pool.ID, RunnerID: &gone.ID, Attempt: 1}
	create(job)
	sync := &models.WorkItem{ID: "wi-" + uuid.NewString()[:16], OrganizationID: org.ID, Kind: models.WorkItemConstructedRebuild, InventoryID: &inv.ID, Status: models.WorkItemStatusRunning, AgentPoolID: &pool.ID, RunnerID: &gone.ID, Attempt: 1}
	create(sync)

	revoker := &recordingRevoker{}
	m := NewMonitorService(repository.NewRunnerRepository(db))
	m.SetLostLauncherHandling(repository.NewRunRepository(db), revoker)
	m.markStaleRunners()

	var p, a models.Run
	db.First(&p, "id = ?", planning.ID)
	db.First(&a, "id = ?", applying.ID)
	if p.Status != models.RunStatusPending || p.RunnerID != nil || p.DispatchedAt != nil {
		t.Errorf("the lost plan is %s (runner %v, dispatched %v), want pending and unclaimed", p.Status, p.RunnerID, p.DispatchedAt)
	}
	if a.Status != models.RunStatusFailed || a.ErrorMessage != repository.LostDuringApply {
		t.Errorf("the lost apply is %s %q, want failed with the runner-lost reason", a.Status, a.ErrorMessage)
	}
	var j models.AnsibleJob
	db.First(&j, "id = ?", job.ID)
	if j.Status != models.AnsibleJobStatusError || j.ErrorMessage != repository.LostDuringJob || j.FinishedAt == nil {
		t.Errorf("the lost job is %s %q, want error with the runner-lost reason", j.Status, j.ErrorMessage)
	}
	// A sync is safe to run twice: it waits again, unclaimed, for a new attempt.
	var w models.WorkItem
	db.First(&w, "id = ?", sync.ID)
	if w.Status != models.WorkItemStatusPending || w.RunnerID != nil {
		t.Errorf("the lost sync is %s (runner %v), want pending and unclaimed", w.Status, w.RunnerID)
	}
	// The lost apply is not re-run on its own: it stays failed until a person re-queues it,
	// which puts it back in its apply phase for a new attempt (decision 16).
	if ok, err := repository.NewRunRepository(db).RequeueLostApply(applying.ID); err != nil || !ok {
		t.Fatalf("re-queuing the lost apply: %v %v", ok, err)
	}
	var rq models.Run
	db.First(&rq, "id = ?", applying.ID)
	if rq.Status != models.RunStatusApplying || rq.RunnerID != nil || rq.DispatchedAt != nil {
		t.Errorf("the re-queued apply is %s (runner %v, dispatched %v), want applying and unclaimed", rq.Status, rq.RunnerID, rq.DispatchedAt)
	}
	if ok, err := repository.NewRunRepository(db).ClaimForDispatch(applying.ID); err != nil || !ok {
		t.Fatalf("claiming the re-queued apply: %v %v", ok, err)
	}
	var claimed models.Run
	db.First(&claimed, "id = ?", applying.ID)
	if claimed.Attempt != 2 {
		t.Errorf("the re-queued apply is attempt %d, want 2", claimed.Attempt)
	}

	var locks int64
	db.Model(&models.StateLock{}).Where("lock_id IN ?", []string{repository.RunStateLockID(planning.ID), repository.RunStateLockID(applying.ID)}).Count(&locks)
	if locks != 0 {
		t.Errorf("%d state locks of lost runs remain", locks)
	}
	for _, want := range []string{"tofu_run:" + planning.ID, "tofu_run:" + applying.ID, "ansible_job:" + job.ID.String()} {
		if !slices.Contains(revoker.revoked, want) {
			t.Errorf("job tokens of %s were not revoked (revoked %v)", want, revoker.revoked)
		}
	}

	// The re-dispatched plan is a new attempt when it is claimed again.
	if ok, err := repository.NewRunRepository(db).ClaimForDispatch(planning.ID); err != nil || !ok {
		t.Fatalf("re-claiming the lost plan: %v %v", ok, err)
	}
	db.First(&p, "id = ?", planning.ID)
	if p.Attempt != 2 {
		t.Errorf("the re-claimed plan is attempt %d, want 2", p.Attempt)
	}
}
