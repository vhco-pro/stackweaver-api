// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A job template variable is addressed under its template, so a variable that belongs to another
// template is not found under this one: updating or deleting it answers exactly what an id that
// does not exist answers, and leaves the variable alone. A different answer would tell a caller
// which variable ids exist.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration

package ansible

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func TestJobTemplateVariable_AnotherTemplatesVariableIsNotFound(t *testing.T) {
	f := setupAnsibleSubResourceAuthz(t)
	db := f.db

	var first models.AnsibleJobTemplate
	if err := db.Where("id = ?", f.templateID).First(&first).Error; err != nil {
		t.Fatalf("load the fixture template: %v", err)
	}
	second := models.AnsibleJobTemplate{
		ID: uuid.New(), ProjectID: first.ProjectID, PlaybookID: first.PlaybookID, InventoryID: first.InventoryID,
		Name: first.Name + "-second",
	}
	if err := db.Create(&second).Error; err != nil {
		t.Fatalf("seed a second template: %v", err)
	}
	other := models.AnsibleJobTemplateVariable{
		ID: "var-" + uuid.NewString()[:8] + "11111111", JobTemplateID: second.ID, Key: "other", Value: "kept", Category: "env",
	}
	if err := db.Create(&other).Error; err != nil {
		t.Fatalf("seed the second template's variable: %v", err)
	}
	t.Cleanup(func() {
		// Registered after the fixture's cleanup, so it runs first.
		db.Where("id = ?", other.ID).Delete(&models.AnsibleJobTemplateVariable{})
		db.Where("id = ?", second.ID).Delete(&models.AnsibleJobTemplate{})
	})

	call := func(method, variableID string) (int, string) {
		path := "/ansible/job-templates/" + f.templateID + "/vars/" + variableID
		body := ""
		if method == http.MethodPatch {
			body = `{"data":{"type":"vars","attributes":{"value":"changed"}}}`
		}
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/vnd.api+json")
		req.Header.Set("X-Test-User", f.owner.ID.String())
		rec := httptest.NewRecorder()
		f.router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			missingCode, missingBody := call(method, "var-doesnotexist0000000")
			otherCode, otherBody := call(method, other.ID)
			if missingCode != http.StatusNotFound {
				t.Errorf("%s of a variable that does not exist = %d, want 404 (%s)", method, missingCode, missingBody)
			}
			if otherCode != missingCode || otherBody != missingBody {
				t.Errorf("%s of another template's variable must answer like a missing one:\n missing: %d %s\n other:   %d %s",
					method, missingCode, missingBody, otherCode, otherBody)
			}
		})
	}

	var kept models.AnsibleJobTemplateVariable
	if err := db.Where("id = ?", other.ID).First(&kept).Error; err != nil {
		t.Fatalf("the other template's variable is gone: %v", err)
	}
	if kept.Value != "kept" || kept.JobTemplateID != second.ID {
		t.Errorf("the other template's variable changed: %+v", kept)
	}
}
