// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A job template's timeout and an inventory source's sync timeout are zero (inherit) or a number of
// seconds up to settings.MaxRunTimeoutSeconds: a negative value or one above the bound answers 422
// and changes nothing.
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run 'TestAnsibleTimeouts'

//go:build integration

package ansible

import (
	"net/http"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/settings"
)

func TestAnsibleTimeouts_AreBounded(t *testing.T) {
	f := setupNeighbourScope(t)
	orgTemplates := "/api/v2/organizations/" + f.orgName + "/ansible/job-templates"
	template := "/api/v2/ansible/job-templates/" + f.template.String()
	source := "/api/v2/ansible/inventory-sources/" + f.source.String()

	for _, bad := range []int{-10, settings.MaxRunTimeoutSeconds + 1} {
		attrs := neighbourName()
		attrs["timeout-seconds"] = bad
		if code, body := f.call(t, http.MethodPost, orgTemplates, neighbourDocument(t, "ansible-job-templates", attrs, f.own("", ""), nil)); code != http.StatusUnprocessableEntity {
			t.Errorf("create a template with timeout-seconds %d = %d, want 422 (%s)", bad, code, body)
		}
		if code, body := f.call(t, http.MethodPatch, template, neighbourDocument(t, "ansible-job-templates", map[string]any{"timeout-seconds": bad}, nil, nil)); code != http.StatusUnprocessableEntity {
			t.Errorf("update a template to timeout-seconds %d = %d, want 422 (%s)", bad, code, body)
		}
		if code, body := f.call(t, http.MethodPatch, source, neighbourDocument(t, "ansible-inventory-sources", map[string]any{"sync-timeout": bad}, nil, nil)); code != http.StatusUnprocessableEntity {
			t.Errorf("update a source to sync-timeout %d = %d, want 422 (%s)", bad, code, body)
		}
	}
	var tmpl models.AnsibleJobTemplate
	if err := f.db.First(&tmpl, "id = ?", f.template).Error; err != nil {
		t.Fatal(err)
	}
	var src models.AnsibleInventorySource
	if err := f.db.First(&src, "id = ?", f.source).Error; err != nil {
		t.Fatal(err)
	}
	if tmpl.TimeoutSeconds != 0 || src.TimeoutSeconds != 0 {
		t.Errorf("the refused writes stored a template timeout %d and a sync timeout %d", tmpl.TimeoutSeconds, src.TimeoutSeconds)
	}

	if code, body := f.call(t, http.MethodPatch, template, neighbourDocument(t, "ansible-job-templates", map[string]any{"timeout-seconds": settings.MaxRunTimeoutSeconds}, nil, nil)); code != http.StatusOK {
		t.Errorf("update a template to the bound = %d, want 200 (%s)", code, body)
	}
}
