// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the run-create wire contract (#844, AC3 and AC4): POST /api/v2/runs
// accepts exactly the document go-tfe marshals for RunCreateOptions, and resolves the run's
// intent from is-destroy, plan-only and auto-apply alone.
//
// They drive the real handler against real Postgres and read the stored row back, because the
// property that matters is on the row: `auto_apply_after_plan` is the marker the agent handler
// reads to tell an applyable run from a speculative one, so every plan-and-apply and destroy run
// this endpoint creates must carry it, whatever the caller did or did not send.
//
// Each case builds its own fixture (its own workspace). Run creation folds a second run with the
// same operation in the same workspace within ten seconds into the first, as retry protection,
// so cases sharing a workspace would read each other's rows.
//
// Gated behind `integration`; cleanup is row-scoped through setupRunCreateScope.

//go:build integration

package terraform

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// postRunBody posts a raw body as the fixture's JWT identity.
func (f *runCreateScopeFixture) postRunBody(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

// runDocument renders a run-create document for the fixture's workspace. attributes is a JSON
// object, or "" to omit the member the way go-tfe does when no option is set. The configuration
// version is always the explicit null go-tfe marshals for a nil relationship.
func (f *runCreateScopeFixture) runDocument(attributes string) string {
	attrs := ""
	if attributes != "" {
		attrs = `"attributes":` + attributes + `,`
	}
	return `{"data":{"type":"runs",` + attrs + `"relationships":{` +
		`"configuration-version":{"data":null},` +
		`"workspace":{"data":{"type":"workspaces","id":"` + f.workspace + `"}}}}}`
}

func (f *runCreateScopeFixture) runCount(t *testing.T) int64 {
	t.Helper()
	_, n, err := f.runRepo.ListByWorkspace(f.workspace, 100, 0)
	if err != nil {
		t.Fatalf("counting runs: %v", err)
	}
	return n
}

func TestRunCreate_ResolvesIntentFromGoTFEAttributes(t *testing.T) {
	tests := []struct {
		name          string
		attributes    string // "" omits the attributes member
		wantOp        models.RunOperation
		wantApplyable bool // AutoApplyAfterPlan: the not-plan-only marker
		wantAutoApply bool // AutoApply: apply without confirmation
	}{
		{
			name:          "go-tfe RunCreateOptions{Workspace}: no attributes member at all",
			wantOp:        models.RunOperationPlanAndApply,
			wantApplyable: true,
		},
		{
			name:          "go-tfe RunCreateOptions{Workspace, AutoApply: false}",
			attributes:    `{"auto-apply":false}`,
			wantOp:        models.RunOperationPlanAndApply,
			wantApplyable: true,
		},
		{
			name:          "auto-apply true applies without confirmation",
			attributes:    `{"auto-apply":true}`,
			wantOp:        models.RunOperationPlanAndApply,
			wantApplyable: true,
			wantAutoApply: true,
		},
		{
			name:       "plan-only is speculative and cannot be applied",
			attributes: `{"plan-only":true}`,
			wantOp:     models.RunOperationPlanOnly,
		},
		{
			name:          "is-destroy is an applyable destroy run",
			attributes:    `{"is-destroy":true,"auto-apply":false}`,
			wantOp:        models.RunOperationDestroy,
			wantApplyable: true,
		},
		{
			name:          "auto-apply-after-plan false changes nothing: still applyable",
			attributes:    `{"auto-apply-after-plan":false}`,
			wantOp:        models.RunOperationPlanAndApply,
			wantApplyable: true,
		},
		{
			name:          "auto-apply-after-plan true changes nothing: still waits for confirmation",
			attributes:    `{"auto-apply-after-plan":true}`,
			wantOp:        models.RunOperationPlanAndApply,
			wantApplyable: true,
		},
		{
			name:       "auto-apply-after-plan true changes nothing: plan-only stays speculative",
			attributes: `{"auto-apply-after-plan":true,"plan-only":true}`,
			wantOp:     models.RunOperationPlanOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := setupRunCreateScope(t)

			w := f.postRunBody(t, f.runDocument(tt.attributes))
			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201 (body %s)", w.Code, w.Body.String())
			}
			var resp struct {
				Data struct {
					ID         string `json:"id"`
					Type       string `json:"type"`
					Attributes struct {
						PlanOnly  bool `json:"plan-only"`
						IsDestroy bool `json:"is-destroy"`
					} `json:"attributes"`
				} `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("response is not JSON: %v (%s)", err, w.Body.String())
			}
			if resp.Data.Type != "runs" || resp.Data.ID == "" {
				t.Fatalf("resource = %s/%q, want a runs resource with an id", resp.Data.Type, resp.Data.ID)
			}
			if wantPlanOnly := tt.wantOp == models.RunOperationPlanOnly; resp.Data.Attributes.PlanOnly != wantPlanOnly {
				t.Errorf("response plan-only = %v, want %v", resp.Data.Attributes.PlanOnly, wantPlanOnly)
			}
			if wantDestroy := tt.wantOp == models.RunOperationDestroy; resp.Data.Attributes.IsDestroy != wantDestroy {
				t.Errorf("response is-destroy = %v, want %v", resp.Data.Attributes.IsDestroy, wantDestroy)
			}

			run, err := f.runRepo.GetByID(resp.Data.ID)
			if err != nil {
				t.Fatalf("loading created run: %v", err)
			}
			if run.Operation != tt.wantOp {
				t.Errorf("operation = %q, want %q", run.Operation, tt.wantOp)
			}
			if run.AutoApplyAfterPlan != tt.wantApplyable {
				t.Errorf("AutoApplyAfterPlan = %v, want %v (the applyable-run marker)", run.AutoApplyAfterPlan, tt.wantApplyable)
			}
			if run.AutoApply != tt.wantAutoApply {
				t.Errorf("AutoApply = %v, want %v", run.AutoApply, tt.wantAutoApply)
			}
			if run.ConfigurationVersionID != nil {
				t.Errorf("configuration version = %q, want none for a null relationship in a workspace without one", *run.ConfigurationVersionID)
			}
		})
	}
}

func TestRunCreate_RejectsBodiesThatAreNotTheDocument(t *testing.T) {
	const retiredDetail = "top-level fields are not accepted: workspace_id, configuration_version_id, " +
		"operation, auto_apply_after_plan; use data.attributes and data.relationships"
	const documentDetail = `request body must be a JSON:API document: {"data": {"type": "runs", "attributes": {...}}}`

	f := setupRunCreateScope(t)
	valid := f.runDocument(`{"auto-apply":false}`)
	// Splice a top-level member into the valid document, after its closing `data` object.
	hybrid := func(member string) string { return valid[:len(valid)-1] + `,` + member + `}` }

	tests := []struct {
		name       string
		body       string
		wantDetail string
	}{
		{"empty object", `{}`, documentDetail},
		{"flat workspace_id, the body the testing guide used to show", `{"workspace_id":"` + f.workspace + `"}`, retiredDetail},
		{"hybrid: valid data plus operation", hybrid(`"operation":"plan-and-apply"`), retiredDetail},
		{"hybrid: valid data plus workspace_id", hybrid(`"workspace_id":"` + f.workspace + `"`), retiredDetail},
		{"hybrid: valid data plus configuration_version_id", hybrid(`"configuration_version_id":null`), retiredDetail},
		{"hybrid: valid data plus auto_apply_after_plan", hybrid(`"auto_apply_after_plan":true`), retiredDetail},
		{
			"wrong data.type",
			strings.Replace(valid, `"type":"runs"`, `"type":"workspaces"`, 1),
			`data.type must be "runs" (got "workspaces")`,
		},
		{
			"no workspace relationship",
			`{"data":{"type":"runs","attributes":{"auto-apply":false},"relationships":{"configuration-version":{"data":null}}}}`,
			"a workspace relationship is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := f.postRunBody(t, tt.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
			}
			var doc struct {
				Errors []struct {
					Status string `json:"status"`
					Title  string `json:"title"`
					Detail string `json:"detail"`
				} `json:"errors"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || len(doc.Errors) != 1 {
				t.Fatalf("response is not a single-error JSON:API document: %v (%s)", err, w.Body.String())
			}
			if got := doc.Errors[0]; got.Status != "400" || got.Title != "Bad Request" || got.Detail != tt.wantDetail {
				t.Errorf("error = %+v, want status 400, title Bad Request, detail %q", got, tt.wantDetail)
			}
		})
	}

	// A 400 that still wrote a row would be no rejection at all.
	if n := f.runCount(t); n != 0 {
		t.Errorf("rejected bodies created %d run(s)", n)
	}
}

// --- allow-destroy-plan (#844, AC13) ---------------------------------------------------------
//
// A workspace's `allow-destroy-plan` setting says whether destroy plans can be queued on it.
// Run create enforces it: a destroy run on a workspace with the setting off is a 422 and creates
// nothing. The check sits AFTER the workspace lookup, the token's organization binding, the RBAC
// checks and the lock check, so a caller who may not create runs there learns nothing about the
// setting, and a locked workspace still answers 409. No primary source states the status or body
// Terraform Enterprise returns here; the wording is Stackweaver's own.

const destroyNotAllowedDetail = "Destroy plans are not allowed on this workspace: its allow-destroy-plan " +
	"setting is off. Turn the setting on to queue a destroy run."

// setAllowDestroyPlan writes the setting with an UPDATE and reads it back, so a case can flip it
// on the shared fixture without building a workspace of its own.
func (f *runCreateScopeFixture) setAllowDestroyPlan(t *testing.T, allow bool) {
	t.Helper()
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.workspace).
		Update("allow_destroy_plan", allow).Error; err != nil {
		t.Fatalf("setting allow_destroy_plan: %v", err)
	}
	var ws models.Workspace
	if err := f.db.Select("allow_destroy_plan").First(&ws, "id = ?", f.workspace).Error; err != nil {
		t.Fatalf("reading workspace back: %v", err)
	}
	if ws.AllowDestroyPlan != allow {
		t.Fatalf("allow_destroy_plan reads back %v, want %v", ws.AllowDestroyPlan, allow)
	}
}

// postRunAs posts a body with optional caller overrides: another user, or an API token bound to
// an organization.
func (f *runCreateScopeFixture) postRunAs(t *testing.T, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

// errorDetail decodes a single-error JSON:API document and returns its status member and detail.
func errorDetail(t *testing.T, w *httptest.ResponseRecorder) (status, title, detail string) {
	t.Helper()
	var doc struct {
		Errors []struct {
			Status string `json:"status"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || len(doc.Errors) != 1 {
		t.Fatalf("response is not a single-error JSON:API document: %v (%s)", err, w.Body.String())
	}
	return doc.Errors[0].Status, doc.Errors[0].Title, doc.Errors[0].Detail
}

// mentionsTheSetting reports whether an error body gives away the allow-destroy-plan setting.
func mentionsTheSetting(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "allow-destroy-plan") || strings.Contains(lower, "destroy plans")
}

func TestRunCreate_DestroyRequiresAllowDestroyPlan(t *testing.T) {
	const destroyAttrs = `{"is-destroy":true,"auto-apply":false}`

	t.Run("setting off: a destroy is 422 and creates no run", func(t *testing.T) {
		f := setupRunCreateScope(t)
		f.setAllowDestroyPlan(t, false)

		for _, attrs := range []string{destroyAttrs, `{"is-destroy":true}`, `{"is-destroy":true,"auto-apply":true}`} {
			w := f.postRunBody(t, f.runDocument(attrs))
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("attributes %s: status = %d, want 422 (body %s)", attrs, w.Code, w.Body.String())
			}
			status, title, detail := errorDetail(t, w)
			if status != "422" || title != "Unprocessable Entity" || detail != destroyNotAllowedDetail {
				t.Errorf("attributes %s: error = {%s %s %q}, want 422, Unprocessable Entity and the stated detail", attrs, status, title, detail)
			}
		}
		if n := f.runCount(t); n != 0 {
			t.Errorf("refused destroy requests created %d run(s)", n)
		}
	})

	t.Run("setting on: the destroy run is created", func(t *testing.T) {
		f := setupRunCreateScope(t)

		// The fixture sets it; the handler's default is pinned by TestWorkspaceCreate_BooleanDefaults.
		var ws models.Workspace
		if err := f.db.Select("allow_destroy_plan").First(&ws, "id = ?", f.workspace).Error; err != nil {
			t.Fatalf("reading workspace: %v", err)
		}
		if !ws.AllowDestroyPlan {
			t.Fatal("the fixture's workspace must have allow-destroy-plan on")
		}

		w := f.postRunBody(t, f.runDocument(destroyAttrs))
		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body %s)", w.Code, w.Body.String())
		}
		var resp struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("response is not JSON: %v", err)
		}
		run, err := f.runRepo.GetByID(resp.Data.ID)
		if err != nil {
			t.Fatalf("loading created run: %v", err)
		}
		if run.Operation != models.RunOperationDestroy {
			t.Errorf("operation = %q, want destroy", run.Operation)
		}
	})

	t.Run("setting off: plan-and-apply and plan-only runs are unaffected", func(t *testing.T) {
		f := setupRunCreateScope(t)
		f.setAllowDestroyPlan(t, false)

		for _, attrs := range []string{`{"auto-apply":false}`, `{"plan-only":true}`} {
			if w := f.postRunBody(t, f.runDocument(attrs)); w.Code != http.StatusCreated {
				t.Errorf("attributes %s: status = %d, want 201 (body %s)", attrs, w.Code, w.Body.String())
			}
		}
		if n := f.runCount(t); n != 2 {
			t.Errorf("run count = %d, want the plan-and-apply and the plan-only run", n)
		}
	})

	t.Run("setting off: a viewer still gets the 403, with no mention of the setting", func(t *testing.T) {
		f := setupRunCreateScope(t)
		f.setAllowDestroyPlan(t, false)

		// A member of the organization whose team can only read the project.
		sfx := uuid.NewString()[:8]
		viewer := &models.User{ID: uuid.New(), ZitadelSubject: "runguard-view-" + sfx, Email: "runguard-view-" + sfx + "@test.local"}
		team := &models.Team{ID: uuid.New(), OrganizationID: f.orgA, Name: "readers-" + sfx}
		readAccess := "read"
		rows := []any{
			viewer, team,
			&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.orgA, UserID: viewer.ID},
			&models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: viewer.ID},
			&models.TeamProjectAccess{ID: uuid.New(), TeamID: team.ID, ProjectID: f.projectA, Access: &readAccess},
		}
		// Registered before the fixture's own cleanup runs (cleanups run last-in, first-out), so
		// these rows are gone before the organization and project they point at.
		t.Cleanup(func() {
			f.db.Where("team_id = ?", team.ID).Delete(&models.TeamProjectAccess{})
			f.db.Where("team_id = ?", team.ID).Delete(&models.TeamMember{})
			f.db.Where("id = ?", team.ID).Delete(&models.Team{})
			f.db.Where("user_id = ?", viewer.ID).Delete(&models.OrganizationMember{})
			f.db.Where("id = ?", viewer.ID).Delete(&models.User{})
		})
		for _, row := range rows {
			if err := f.db.Create(row).Error; err != nil {
				t.Fatalf("seed %T: %v", row, err)
			}
		}

		w := f.postRunAs(t, f.runDocument(destroyAttrs), map[string]string{"X-Test-User": viewer.ID.String()})
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body %s)", w.Code, w.Body.String())
		}
		if mentionsTheSetting(w.Body.String()) {
			t.Errorf("the 403 tells a caller without run permission about the setting: %s", w.Body.String())
		}
		if n := f.runCount(t); n != 0 {
			t.Errorf("a forbidden request created %d run(s)", n)
		}
	})

	t.Run("setting off: a token bound to another organization is refused first", func(t *testing.T) {
		f := setupRunCreateScope(t)
		f.setAllowDestroyPlan(t, false)

		w := f.postRunAs(t, f.runDocument(destroyAttrs), map[string]string{
			"X-Test-Token-Kind": models.APIKeyKindOrg,
			"X-Test-Token-Org":  f.orgB.String(),
		})
		if w.Code != http.StatusForbidden && w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want the 403 or 404 the token gets today (body %s)", w.Code, w.Body.String())
		}
		if mentionsTheSetting(w.Body.String()) {
			t.Errorf("the refusal tells a token from another organization about the setting: %s", w.Body.String())
		}
	})

	t.Run("a workspace that does not exist is still a 404", func(t *testing.T) {
		f := setupRunCreateScope(t)

		body := strings.Replace(f.runDocument(destroyAttrs), f.workspace, "ws-doesnotexist0000", 1)
		w := f.postRunBody(t, body)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body %s)", w.Code, w.Body.String())
		}
		if mentionsTheSetting(w.Body.String()) {
			t.Errorf("the 404 mentions the setting: %s", w.Body.String())
		}
	})

	t.Run("setting off and locked: the lock answers first with 409", func(t *testing.T) {
		f := setupRunCreateScope(t)
		f.setAllowDestroyPlan(t, false)
		if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.workspace).Update("locked", true).Error; err != nil {
			t.Fatalf("locking workspace: %v", err)
		}

		w := f.postRunBody(t, f.runDocument(destroyAttrs))
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (body %s)", w.Code, w.Body.String())
		}
		if mentionsTheSetting(w.Body.String()) {
			t.Errorf("the 409 mentions the setting: %s", w.Body.String())
		}
	})
}
