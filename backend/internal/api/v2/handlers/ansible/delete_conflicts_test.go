// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"errors"
	"fmt"
	"testing"
)

// fkViolation is the error a Postgres foreign key violation reaches a handler as, wrapped once by
// a repository.
func fkViolation(table, constraint, child string) error {
	return fmt.Errorf("deleting: %w", errors.New(
		`ERROR: update or delete on table "`+table+`" violates foreign key constraint "`+constraint+
			`" on table "`+child+`" (SQLSTATE 23503)`))
}

// TestDeleteConflictDetail holds each delete's 409 to the constraints that really refuse it: the
// NO ACTION foreign keys toward the resource. A violation of any other constraint, or any other
// error, is not a conflict and answers 500.
func TestDeleteConflictDetail(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		conflicts []deleteConflict
		want      string
		wantOK    bool
	}{
		{
			name:      "credential a job ran with",
			err:       fkViolation("ansible_credentials", "fk_ansible_job_credentials_ansible_credential", "ansible_job_credentials"),
			conflicts: jobLinkConflicts, want: credentialInUseByJobsDetail, wantOK: true,
		},
		{
			name:      "credential held by a template link is not a blocker",
			err:       fkViolation("ansible_credentials", "fk_ansible_job_template_credentials_ansible_credential", "ansible_job_template_credentials"),
			conflicts: jobLinkConflicts,
		},
		{
			name:      "inventory used by a job template",
			err:       fkViolation("ansible_inventories", "fk_ansible_job_templates_inventory", "ansible_job_templates"),
			conflicts: inventoryConflicts, want: inventoryUsedByTemplatesDetail, wantOK: true,
		},
		{
			name:      "inventory a job ran against",
			err:       fkViolation("ansible_inventories", "fk_ansible_jobs_inventory", "ansible_jobs"),
			conflicts: inventoryConflicts, want: inventoryUsedByJobsDetail, wantOK: true,
		},
		{
			name:      "inventory source is not a blocker",
			err:       fkViolation("ansible_inventories", "fk_ansible_inventory_sources_inventory", "ansible_inventory_sources"),
			conflicts: inventoryConflicts,
		},
		{
			name:      "playbook used by a job template",
			err:       fkViolation("ansible_playbooks", "fk_ansible_playbooks_job_templates", "ansible_job_templates"),
			conflicts: playbookConflicts, want: playbookUsedByTemplatesDetail, wantOK: true,
		},
		{
			name:      "job run against a playbook is not a blocker",
			err:       fkViolation("ansible_playbooks", "fk_ansible_playbooks_jobs", "ansible_jobs"),
			conflicts: playbookConflicts,
		},
		{
			name:      "a constraint name that only starts with a blocker's",
			err:       fkViolation("ansible_inventories", "fk_ansible_jobs_inventory_override", "ansible_jobs"),
			conflicts: inventoryConflicts,
		},
		{
			name:      "not a foreign key violation",
			err:       errors.New(`ERROR: duplicate key value violates unique constraint "fk_ansible_jobs_inventory" (SQLSTATE 23505)`),
			conflicts: inventoryConflicts,
		},
		{name: "no error", conflicts: inventoryConflicts},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := deleteConflictDetail(tc.err, tc.conflicts)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("deleteConflictDetail = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
