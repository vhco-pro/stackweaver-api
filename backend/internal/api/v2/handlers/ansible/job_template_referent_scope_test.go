// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a job template may name (#915): a playbook, an inventory and credentials of the
// organization of its project. Anything else is a 400 in the JSON:API errors document, and a row
// that exists in another organization gets the very same bytes as an identifier that names
// nothing. The fixture and the assertions are in referent_scope_neighbours_test.go.
//
// The defects these tests were written against, each driven by a member of one organization only:
//
//   - a create attached another organization's credential to the template. The handler did
//     compare organizations, but against the project of a template row it had just built and
//     never loaded, so the comparison was skipped. A launch then put the credential on the job;
//   - a create and an update stored another organization's inventory and playbook. A launch
//     refused them, so nothing ran, and the template sat there naming a row its organization does
//     not have;
//   - an identifier that named nothing failed at the foreign key with a 500, and a credential
//     that named nothing was dropped with a 201.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestJobTemplateReferents

//go:build integration

package ansible

import (
	"net/http"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

// templateWrites is every write that makes a job template name a row: the two creates and the
// update, with the referent each must refuse.
func (f *neighbourScopeFixture) templateWrites() (orgTemplates, projectTemplates, template string, writes []neighbourWrite) {
	orgTemplates = "/api/v2/organizations/" + f.orgName + "/ansible/job-templates"
	projectTemplates = "/api/v2/projects/" + f.project + "/ansible/job-templates"
	template = "/api/v2/ansible/job-templates/" + f.template.String()

	create := func(path, relationship string) func(t *testing.T, id string) (int, []byte) {
		return func(t *testing.T, id string) (int, []byte) {
			t.Helper()
			if relationship == "credentials" {
				return f.call(t, http.MethodPost, path, neighbourDocument(t, "ansible-job-templates", neighbourName(), f.own("", ""), []string{id}))
			}
			return f.call(t, http.MethodPost, path, neighbourDocument(t, "ansible-job-templates", neighbourName(), f.own(relationship, id), nil))
		}
	}
	update := func(relationship string) func(t *testing.T, id string) (int, []byte) {
		return func(t *testing.T, id string) (int, []byte) {
			t.Helper()
			if relationship == "credentials" {
				return f.call(t, http.MethodPatch, template, neighbourDocument(t, "ansible-job-templates", map[string]any{}, nil, []string{id}))
			}
			return f.call(t, http.MethodPatch, template,
				neighbourDocument(t, "ansible-job-templates", map[string]any{}, map[string]string{relationship: id}, nil))
		}
	}
	return orgTemplates, projectTemplates, template, []neighbourWrite{
		{"a job template naming a credential", create(orgTemplates, "credentials"), f.otherSSH, "credential not found"},
		{"a job template naming an inventory", create(orgTemplates, "inventory"), f.otherInventory, "inventory not found"},
		{"a job template naming a playbook", create(orgTemplates, "playbook"), f.otherPlaybook, "playbook not found"},
		{"a project job template naming a credential", create(projectTemplates, "credentials"), f.otherSSH, "credential not found"},
		{"a project job template naming an inventory", create(projectTemplates, "inventory"), f.otherInventory, "inventory not found"},
		{"a project job template naming a playbook", create(projectTemplates, "playbook"), f.otherPlaybook, "playbook not found"},
		{"a job template update naming a credential", update("credentials"), f.otherSSH, "credential not found"},
		{"a job template update naming an inventory", update("inventory"), f.otherInventory, "inventory not found"},
		// The next two did refuse another organization's row before, in words an unknown
		// identifier did not get, which told the caller that the row is there: "Playbook does not
		// belong to this template's organization" against "Playbook not found", and a 400 for a
		// credential of another organization against a 404 for one that does not exist.
		{"a job template update naming a playbook", update("playbook"), f.otherPlaybook, "playbook not found"},
		{"a template credential attach", func(t *testing.T, id string) (int, []byte) {
			t.Helper()
			return f.call(t, http.MethodPost, template+"/credentials", `{"credential_id":"`+id+`"}`)
		}, f.otherSSH, "credential not found"},
	}
}

func TestJobTemplateReferents_AnotherOrganizationReadsAsNotFound(t *testing.T) {
	f := setupNeighbourScope(t)
	var before models.AnsibleJobTemplate
	if err := f.db.First(&before, "id = ?", f.template).Error; err != nil {
		t.Fatalf("loading the template: %v", err)
	}

	_, _, _, writes := f.templateWrites()
	f.assertReadAsNotFound(t, writes)

	// The updates were refused whole: the template still names what it named.
	var after models.AnsibleJobTemplate
	if err := f.db.First(&after, "id = ?", f.template).Error; err != nil {
		t.Fatalf("reloading the template: %v", err)
	}
	if after.PlaybookID != before.PlaybookID || after.InventoryID != before.InventoryID {
		t.Errorf("the refused updates moved the template to playbook %s and inventory %s", after.PlaybookID, after.InventoryID)
	}
}

func TestJobTemplateReferents_OwnOrganizationIsAccepted(t *testing.T) {
	f := setupNeighbourScope(t)
	orgTemplates, projectTemplates, template, _ := f.templateWrites()

	for name, path := range map[string]string{"a job template": orgTemplates, "a project job template": projectTemplates} {
		t.Run(name+" with its organization's playbook, inventory and credential", func(t *testing.T) {
			code, body := f.call(t, http.MethodPost, path,
				neighbourDocument(t, "ansible-job-templates", neighbourName(), f.own("", ""), []string{f.sshCred}))
			created := createdResource(t, code, body)
			var row models.AnsibleJobTemplate
			if err := f.db.First(&row, "id = ?", created.ID).Error; err != nil {
				t.Fatalf("loading the created template: %v", err)
			}
			if row.PlaybookID.String() != f.playbook || row.InventoryID.String() != f.inventoryID {
				t.Errorf("stored playbook %s and inventory %s, want %s and %s", row.PlaybookID, row.InventoryID, f.playbook, f.inventoryID)
			}
			if got := f.credentialsOf(t, "ansible_job_template_credentials", "ansible_job_template_id", created.ID); len(got) != 1 || got[0] != f.sshCred {
				t.Errorf("the template holds credentials %v, want [%s]", got, f.sshCred)
			}
		})
	}
	t.Run("a job template update to its organization's other playbook, inventory and credential", func(t *testing.T) {
		code, body := f.call(t, http.MethodPatch, template,
			neighbourDocument(t, "ansible-job-templates", map[string]any{},
				map[string]string{"playbook": f.playbook2, "inventory": f.inventory2}, []string{f.sshCred}))
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", code, body)
		}
		var row models.AnsibleJobTemplate
		if err := f.db.First(&row, "id = ?", f.template).Error; err != nil {
			t.Fatalf("loading the template: %v", err)
		}
		if row.PlaybookID.String() != f.playbook2 || row.InventoryID.String() != f.inventory2 {
			t.Errorf("stored playbook %s and inventory %s, want %s and %s", row.PlaybookID, row.InventoryID, f.playbook2, f.inventory2)
		}
		if got := f.credentialsOf(t, "ansible_job_template_credentials", "ansible_job_template_id", f.template.String()); len(got) != 1 || got[0] != f.sshCred {
			t.Errorf("the template holds credentials %v, want [%s]", got, f.sshCred)
		}
	})
	t.Run("a job template update that names nothing leaves what the template names alone", func(t *testing.T) {
		code, body := f.call(t, http.MethodPatch, template,
			neighbourDocument(t, "ansible-job-templates", map[string]any{"description": "patched"}, nil, nil))
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", code, body)
		}
		if got := f.credentialsOf(t, "ansible_job_template_credentials", "ansible_job_template_id", f.template.String()); len(got) != 1 {
			t.Errorf("the template holds credentials %v, want the one it held", got)
		}
	})
	t.Run("a template credential attach of its organization's credential", func(t *testing.T) {
		code, body := f.call(t, http.MethodPost, template+"/credentials", `{"credential_id":"`+f.vaultCred+`"}`)
		if code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (%s)", code, body)
		}
		if got := f.credentialsOf(t, "ansible_job_template_credentials", "ansible_job_template_id", f.template.String()); len(got) != 2 {
			t.Errorf("the template holds credentials %v, want the ssh and the vault credential", got)
		}
	})
}

// TestJobTemplateReferents_StoredRowsAreNotTrusted is the point of use over HTTP for the two
// referents a launch has always refused. Each is written onto the template directly, the way a
// row stored before the write was checked would be, and the launch starts nothing. The stored
// credential set is the launch's own case, in TestJobLaunchReferents_StoredCredentialsAreNotTrusted.
func TestJobTemplateReferents_StoredRowsAreNotTrusted(t *testing.T) {
	f := setupNeighbourScope(t)
	launch := "/api/v2/ansible/job-templates/" + f.template.String() + "/launch"

	// Each case puts the template back as it was, whatever the case finds.
	t.Run("a template naming an inventory of another organization is not launched", func(t *testing.T) {
		f.exec(t, "UPDATE ansible_job_templates SET inventory_id = ? WHERE id = ?", f.otherInventory, f.template)
		defer f.exec(t, "UPDATE ansible_job_templates SET inventory_id = ? WHERE id = ?", f.inventoryID, f.template)
		f.assertNotLaunched(t, launch)
	})
	t.Run("a template naming a playbook of another organization is not launched", func(t *testing.T) {
		f.exec(t, "UPDATE ansible_job_templates SET playbook_id = ? WHERE id = ?", f.otherPlaybook, f.template)
		defer f.exec(t, "UPDATE ansible_job_templates SET playbook_id = ? WHERE id = ?", f.playbook, f.template)
		f.assertNotLaunched(t, launch)
	})
	t.Run("the template is launched once it names its own organization's rows again", func(t *testing.T) {
		code, body := f.call(t, http.MethodPost, launch, "")
		createdResource(t, code, body)
	})
}

// TestJobTemplateReferents_AlreadyOneAnswer pins what a job template names beside its playbook,
// inventory and credentials. Each already answered another organization's row and an unknown
// identifier with the same bytes and stored nothing.
func TestJobTemplateReferents_AlreadyOneAnswer(t *testing.T) {
	f := setupNeighbourScope(t)
	orgTemplates, _, template, _ := f.templateWrites()
	createNaming := func(relationship string) func(t *testing.T, id string) (int, []byte) {
		return func(t *testing.T, id string) (int, []byte) {
			t.Helper()
			return f.call(t, http.MethodPost, orgTemplates,
				neighbourDocument(t, "ansible-job-templates", neighbourName(), f.own(relationship, id), nil))
		}
	}
	f.assertOneAnswer(t, []neighbourWrite{
		{name: "a job template naming a project", send: createNaming("project"), foreign: f.otherProject},
		{name: "a job template naming an agent pool", send: createNaming("agent-pool"), foreign: f.otherPool},
		{name: "a job template update naming an agent pool", send: func(t *testing.T, id string) (int, []byte) {
			t.Helper()
			return f.call(t, http.MethodPatch, template,
				neighbourDocument(t, "ansible-job-templates", map[string]any{}, map[string]string{"agent-pool": id}, nil))
		}, foreign: f.otherPool},
	})
}
