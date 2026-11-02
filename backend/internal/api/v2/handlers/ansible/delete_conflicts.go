// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"fmt"
	"strings"

	"github.com/michielvha/stackweaver/core/repository"
)

// deleteConflict pairs a foreign key that refuses a delete with the 409 detail that names what
// holds the row and how to remove it.
type deleteConflict struct {
	constraint string
	detail     string
}

// Each table lists the foreign keys that are NO ACTION toward the resource, so the database
// refuses its delete. Every other reference cascades or is nulled by the reconciled delete rules
// (models.FKDeleteRules) and never surfaces here. A delete that fails on a constraint outside its
// table is an unexpected error and answers 500.

// credentialInUseByJobsDetail: a job keeps the credentials it ran with. A job template's credential
// set, inventory sources and workflow nodes let go of a deleted credential. No route deletes a
// single job, so the detail names the ways a job is removed.
const credentialInUseByJobsDetail = "Cannot delete credential: one or more jobs ran with it. " +
	"It can be deleted once those jobs are removed, by deleting the job templates that launched them or through job retention."

// jobLinkConflicts are the credential's blockers: the link from a job's credential set.
var jobLinkConflicts = []deleteConflict{
	{"fk_ansible_job_credentials_ansible_credential", credentialInUseByJobsDetail},
}

const (
	inventoryUsedByTemplatesDetail = "Cannot delete inventory: one or more job templates use it. " +
		"Change those templates to another inventory or delete them, or force delete the inventory."
	inventoryUsedByJobsDetail = "Cannot delete inventory: one or more jobs ran against it. " +
		"Delete the job templates that launched them, or force delete the inventory."
)

// inventoryConflicts are the inventory's blockers: job templates built on it and jobs run against
// it. Its hosts, groups, sources and sync history cascade; workflows, workflow nodes and workflow
// runs fall back to their template's inventory.
var inventoryConflicts = []deleteConflict{
	{"fk_ansible_job_templates_inventory", inventoryUsedByTemplatesDetail},
	{"fk_ansible_jobs_inventory", inventoryUsedByJobsDetail},
}

const playbookUsedByTemplatesDetail = "Cannot delete playbook: one or more job templates use it. " +
	"Change those templates to another playbook or delete them, or force delete the playbook."

// playbookInUseDetail is the 409 detail for a playbook delete refused by what uses the playbook:
// the job templates built on it first, since those need changing whatever else is true, else the
// jobs that use it and have not finished.
func playbookInUseDetail(inUse *repository.PlaybookInUseError) string {
	if inUse.JobTemplates > 0 {
		return fmt.Sprintf("Cannot delete playbook: it is referenced by %d job template(s). "+
			"Remove the playbook from those resources first", inUse.JobTemplates)
	}
	return fmt.Sprintf("Cannot delete playbook: %d job(s) using it have not finished. "+
		"Wait for them to finish or cancel them, then delete the playbook again, or force delete the playbook, which cancels them.",
		inUse.UnfinishedJobs)
}

// playbookConflicts are the playbook's blockers at the foreign key: the job templates built on
// it. PlaybookRepository.Delete counts those and the unfinished jobs under the playbook's row
// lock, so this mapping is a fallback. Jobs run against it and schedules that target it keep
// their row with the playbook link cleared.
var playbookConflicts = []deleteConflict{
	{"fk_ansible_playbooks_job_templates", playbookUsedByTemplatesDetail},
}

// deleteConflictDetail returns the 409 detail for err when it is a violation of one of conflicts'
// constraints, and false for any other error.
func deleteConflictDetail(err error, conflicts []deleteConflict) (string, bool) {
	if err == nil {
		return "", false
	}
	msg := err.Error()
	if !strings.Contains(msg, "violates foreign key constraint") {
		return "", false
	}
	for _, c := range conflicts {
		if strings.Contains(msg, `"`+c.constraint+`"`) {
			return c.detail, true
		}
	}
	return "", false
}
