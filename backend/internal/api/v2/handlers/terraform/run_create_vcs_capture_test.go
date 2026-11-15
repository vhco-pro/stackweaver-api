// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A run created on a VCS-backed workspace without a configuration version clones nothing in the
// API (#938, AC-19): it gets a configuration version in status fetching, which an executor fills
// with the branch head. The workspace's latest configuration version, which a run of a workspace
// without VCS falls back to, must not be planned instead, in remote or agent execution mode.

//go:build integration

package terraform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func TestRunCreate_VCSWorkspaceGetsAFetchingConfigurationVersion(t *testing.T) {
	for _, mode := range []string{"remote", "agent"} {
		t.Run(mode, func(t *testing.T) {
			f := setupRunConfigurationVersions(t)
			conn := &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgA, Provider: models.VCSProviderGitLab, AccessToken: "unused", AccountName: "runcap-" + uuid.NewString()[:8]}
			if err := f.db.Create(conn).Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.db.Where("id = ?", conn.ID).Delete(&models.VCSConnection{}) })
			if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.workspace).Updates(map[string]any{
				"vcs_connection_id": conn.ID, "vcs_repository": "acme/infra", "vcs_branch": "main", "execution_mode": mode,
			}).Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				f.db.Model(&models.Workspace{}).Where("id = ?", f.workspace).Updates(map[string]any{"vcs_connection_id": nil, "vcs_repository": "", "vcs_branch": ""})
				f.db.Where("workspace_id = ? AND status = ?", f.workspace, models.ConfigurationVersionStatusFetching).Delete(&models.Run{})
			})

			body, _ := json.Marshal(map[string]any{"data": map[string]any{
				"type":          "runs",
				"attributes":    map[string]any{"message": "capture", "plan-only": true},
				"relationships": map[string]any{"workspace": map[string]any{"data": map[string]any{"type": "workspaces", "id": f.workspace}}},
			}})
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runs", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/vnd.api+json")
			rec := httptest.NewRecorder()
			f.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusCreated {
				t.Fatalf("run create = %d, want 201.\nbody: %s", rec.Code, rec.Body.String())
			}
			var doc struct {
				Data struct {
					ID string `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			var run models.Run
			if err := f.db.First(&run, "id = ?", doc.Data.ID).Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				f.db.Where("id = ?", run.ID).Delete(&models.Run{})
				if run.ConfigurationVersionID != nil && *run.ConfigurationVersionID != f.own.ID {
					f.db.Where("id = ?", *run.ConfigurationVersionID).Delete(&models.ConfigurationVersion{})
				}
			})
			if run.ConfigurationVersionID == nil {
				t.Fatal("the run has no configuration version")
			}
			if *run.ConfigurationVersionID == f.own.ID {
				t.Fatalf("the run took the workspace's older uploaded configuration version %s instead of capturing the branch", f.own.ID)
			}
			var cv models.ConfigurationVersion
			f.db.First(&cv, "id = ?", *run.ConfigurationVersionID)
			if cv.Status != models.ConfigurationVersionStatusFetching || cv.CommitHash != "" || cv.Source != "tfe-vcs" || cv.WorkspaceID != f.workspace {
				t.Errorf("configuration version = status %s commit %q source %s workspace %s, want fetching at the branch head", cv.Status, cv.CommitHash, cv.Source, cv.WorkspaceID)
			}
		})
	}
}

// A refused run request creates no configuration version: the fetching version is created only
// with its run, so a request refused after the workspace was found to be VCS-backed (here, for an
// identity binding its pool does not offer) leaves nothing that no capture will ever fill.
func TestRunCreate_ARefusedRunLeavesNoFetchingVersion(t *testing.T) {
	f := setupRunCreateScope(t)
	if err := f.db.AutoMigrate(&models.AgentPool{}, &models.IdentityBinding{}); err != nil {
		t.Fatal(err)
	}
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA, Name: "orphan-pool-" + uuid.NewString()[:8], OrganizationScoped: true}
	other := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA, Name: "orphan-other-" + uuid.NewString()[:8], OrganizationScoped: true}
	foreign := &models.IdentityBinding{ID: uuid.New(), OrganizationID: f.orgA, AgentPoolID: other.ID, Name: "elsewhere", Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-elsewhere"}
	conn := &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgA, Provider: models.VCSProviderGitLab, AccessToken: "unused", AccountName: "orphan-" + uuid.NewString()[:8]}
	for _, o := range []any{pool, other, foreign, conn} {
		if err := f.db.Create(o).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.workspace).Updates(map[string]any{
		"execution_mode": "agent", "agent_pool_id": pool.ID, "identity_binding_id": foreign.ID,
		"vcs_connection_id": conn.ID, "vcs_repository": "acme/infra", "vcs_branch": "main",
	}).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Model(&models.Workspace{}).Where("id = ?", f.workspace).Updates(map[string]any{
			"identity_binding_id": nil, "agent_pool_id": nil, "vcs_connection_id": nil, "vcs_repository": "", "vcs_branch": "",
		})
		f.db.Where("workspace_id = ? AND status = ?", f.workspace, models.ConfigurationVersionStatusFetching).Delete(&models.ConfigurationVersion{})
		f.db.Where("id = ?", foreign.ID).Delete(&models.IdentityBinding{})
		f.db.Where("id IN ?", []uuid.UUID{pool.ID, other.ID}).Delete(&models.AgentPool{})
		f.db.Where("id = ?", conn.ID).Delete(&models.VCSConnection{})
	})
	if rec := f.postRun(t, "", nil); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a run with another pool's binding = %d %s, want 422", rec.Code, rec.Body.String())
	}
	var fetching int64
	f.db.Model(&models.ConfigurationVersion{}).Where("workspace_id = ? AND status = ?", f.workspace, models.ConfigurationVersionStatusFetching).Count(&fetching)
	if fetching != 0 {
		t.Errorf("a refused run left %d fetching configuration versions, want none", fetching)
	}
}

// The fetching version and its run are created in one transaction (R-16 F-07): a run insert that
// fails leaves no version behind, whatever ends the request between the two writes.
func TestRunCreate_AFailedRunInsertLeavesNoFetchingVersion(t *testing.T) {
	f := setupRunConfigurationVersions(t)
	conn := &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgA, Provider: models.VCSProviderGitLab, AccessToken: "unused", AccountName: "atomic-" + uuid.NewString()[:8]}
	if err := f.db.Create(conn).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", conn.ID).Delete(&models.VCSConnection{}) })
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.workspace).Updates(map[string]any{
		"vcs_connection_id": conn.ID, "vcs_repository": "acme/infra", "vcs_branch": "main", "execution_mode": "remote",
	}).Error; err != nil {
		t.Fatal(err)
	}
	fn := "test_fail_run_insert_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if err := f.db.Exec(`CREATE FUNCTION ` + fn + `() RETURNS trigger AS $$ BEGIN
		IF NEW.workspace_id = '` + f.workspace + `' THEN RAISE EXCEPTION 'injected run insert failure'; END IF;
		RETURN NEW; END $$ LANGUAGE plpgsql`).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Exec(`DROP TRIGGER IF EXISTS ` + fn + ` ON runs`)
		f.db.Exec(`DROP FUNCTION IF EXISTS ` + fn + `()`)
		f.db.Model(&models.Workspace{}).Where("id = ?", f.workspace).Updates(map[string]any{"vcs_connection_id": nil, "vcs_repository": "", "vcs_branch": ""})
		f.db.Where("workspace_id = ? AND status = ?", f.workspace, models.ConfigurationVersionStatusFetching).Delete(&models.ConfigurationVersion{})
	})
	if err := f.db.Exec(`CREATE TRIGGER ` + fn + ` BEFORE INSERT ON runs FOR EACH ROW EXECUTE FUNCTION ` + fn + `()`).Error; err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"data": map[string]any{
		"type":          "runs",
		"attributes":    map[string]any{"message": "atomic", "plan-only": true},
		"relationships": map[string]any{"workspace": map[string]any{"data": map[string]any{"type": "workspaces", "id": f.workspace}}},
	}})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/runs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	if rec.Code == http.StatusCreated {
		t.Fatalf("run create succeeded although its insert fails")
	}
	var fetching int64
	f.db.Model(&models.ConfigurationVersion{}).Where("workspace_id = ? AND status = ?", f.workspace, models.ConfigurationVersionStatusFetching).Count(&fetching)
	if fetching != 0 {
		t.Errorf("a failed run insert left %d fetching configuration versions, want none", fetching)
	}
}
