// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a playbook delete does to the jobs that have not finished and to the playbook's objects in
// storage. A job that has not finished is not a past job: it blocks a plain delete, and a force
// delete cancels it. A deleted playbook's objects under playbooks/<id>/ go with it. Builds on the
// fixture in delete_conflict_integration_test.go.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run 'TestPlaybookDelete|TestPlaybookForceDelete'

//go:build integration

package ansible

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"gorm.io/gorm"
)

// unfinishedJobsDetail is the 409 detail for a playbook that n unfinished jobs use.
func unfinishedJobsDetail(n int) string {
	return fmt.Sprintf("Cannot delete playbook: %d job(s) using it have not finished. "+
		"Wait for them to finish or cancel them, then delete the playbook again, or force delete the playbook, which cancels them.", n)
}

// While a job that uses the playbook is pending or running, the delete is refused and the job
// keeps its playbook. A past job beside it does not count.
func TestPlaybookDelete_UnfinishedJobConflicts(t *testing.T) {
	for _, status := range []models.AnsibleJobStatus{models.AnsibleJobStatusPending, models.AnsibleJobStatusRunning} {
		t.Run(string(status), func(t *testing.T) {
			f := setupCredentialDelete(t)
			f.job(t, nil)
			job := f.jobIn(t, nil, status)

			code, body := f.delete(t, "/ansible/playbooks/"+f.playbook.String())
			assertConflict(t, code, body, unfinishedJobsDetail(1))
			if n := f.count(t, "SELECT count(*) FROM ansible_playbooks WHERE id = ?", f.playbook); n != 1 {
				t.Errorf("the playbook was deleted despite the conflict")
			}
			if n := f.count(t, "SELECT count(*) FROM ansible_jobs WHERE id = ? AND playbook_id = ? AND status = ?", job.ID, f.playbook, status); n != 1 {
				t.Errorf("the unfinished job lost its playbook or its status")
			}
		})
	}
}

// A job launched against the playbook while the delete runs is counted, not orphaned: the
// delete's row lock waits for the job's insert, then counts the job as unfinished.
func TestPlaybookDelete_LateJobConflicts(t *testing.T) {
	f := setupCredentialDelete(t)
	job := &models.AnsibleJob{
		ID: uuid.New(), ProjectID: f.project, PlaybookID: &f.playbook, PlaybookName: "creddel-pb-" + f.sfx,
		InventoryID: f.inv, Name: "creddel-late-job-" + f.sfx, Status: models.AnsibleJobStatusPending,
	}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleJob{}, "id = ?", job.ID) })

	code, body := f.deleteWhileInserting(t, "/ansible/playbooks/"+f.playbook.String(), playbookRowLock,
		func(tx *gorm.DB) error { return tx.Create(job).Error })
	assertConflict(t, code, body, unfinishedJobsDetail(1))
	if n := f.count(t, "SELECT count(*) FROM ansible_jobs WHERE id = ? AND playbook_id = ?", job.ID, f.playbook); n != 1 {
		t.Errorf("the late job lost its playbook")
	}
}

// A force delete cancels the unfinished jobs that use the playbook, as the cancel action does, so
// a runner running one stops it. A job that ran the playbook directly is then kept as a past job
// with the link cleared; a job of a force-deleted template goes with its template.
func TestPlaybookForceDelete_CancelsUnfinishedJobs(t *testing.T) {
	f := setupCredentialDelete(t)
	tmplID := f.template(t)
	fromTemplate := f.jobIn(t, &tmplID, models.AnsibleJobStatusRunning)
	running := f.jobIn(t, nil, models.AnsibleJobStatusRunning)
	pending := f.jobIn(t, nil, models.AnsibleJobStatusPending)

	if code, body := f.delete(t, "/ansible/playbooks/"+f.playbook.String()+"?force=true"); code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (%s)", code, body)
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_playbooks WHERE id = ?", f.playbook); n != 0 {
		t.Errorf("the playbook survived its force delete")
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_jobs WHERE id = ?", fromTemplate.ID); n != 0 {
		t.Errorf("the template's job survived the force delete")
	}
	for _, job := range []*models.AnsibleJob{running, pending} {
		if n := f.count(t,
			"SELECT count(*) FROM ansible_jobs WHERE id = ? AND status = ? AND finished_at IS NOT NULL AND playbook_id IS NULL AND playbook_name = ?",
			job.ID, models.AnsibleJobStatusCanceled, job.PlaybookName); n != 1 {
			t.Errorf("the %s job that ran the playbook directly was not kept, canceled, with the link cleared", job.Status)
		}
		if n := f.count(t, "SELECT count(*) FROM ansible_job_events WHERE job_id = ?", job.ID); n != 1 {
			t.Errorf("the canceled job has %d event(s), want 1", n)
		}
	}
}

// putPlaybookObjects stores the objects a playbook has under its prefix (the cached snapshot,
// uploaded content and anything else there) and one of another playbook, and returns the keys.
func (f *credentialDeleteFixture) putPlaybookObjects(t *testing.T) (own []string, other string) {
	t.Helper()
	prefix := "playbooks/" + f.playbook.String() + "/"
	own = []string{prefix + "snapshot.tar.gz", prefix + "content.tar.gz", prefix + "extra/notes.txt"}
	other = "playbooks/" + uuid.NewString() + "/snapshot.tar.gz"
	for _, key := range append(append([]string{}, own...), other) {
		if err := f.store.Put(context.Background(), key, []byte("object")); err != nil {
			t.Fatalf("storing %s: %v", key, err)
		}
	}
	return own, other
}

func (f *credentialDeleteFixture) assertObjects(t *testing.T, keys []string, want bool) {
	t.Helper()
	for _, key := range keys {
		_, err := f.store.Get(context.Background(), key)
		if got := err == nil; got != want {
			t.Errorf("object %s present = %v, want %v", key, got, want)
		}
	}
}

// A deleted playbook's objects in storage go with it once the delete commits. Another playbook's
// objects stay, and a refused delete leaves every object in place.
func TestPlaybookDelete_PrunesItsStorage(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		f := setupCredentialDelete(t)
		f.template(t)
		own, other := f.putPlaybookObjects(t)
		if code, body := f.delete(t, "/ansible/playbooks/"+f.playbook.String()); code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (%s)", code, body)
		}
		f.assertObjects(t, append(own, other), true)
	})
	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprintf("force=%v", force), func(t *testing.T) {
			f := setupCredentialDelete(t)
			f.job(t, nil)
			own, other := f.putPlaybookObjects(t)
			path := "/ansible/playbooks/" + f.playbook.String()
			if force {
				path += "?force=true"
			}
			if code, body := f.delete(t, path); code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204 (%s)", code, body)
			}
			f.assertObjects(t, own, false)
			f.assertObjects(t, []string{other}, true)
		})
	}
}
