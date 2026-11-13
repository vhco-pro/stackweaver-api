// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The workspace's terraform-version under the installation default (#1069, D2): a workspace created
// without one stores nothing and reads the effective version, follows the installation default
// when nothing narrower is set, and keeps a version set on it.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestWorkspaceVersion

//go:build integration

package terraform

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/settings"
	"github.com/michielvha/stackweaver/core/tofu"
	"gorm.io/gorm"
)

// catalogueVersion adds an enabled catalogue version no release uses, so a workspace may be
// created with it, and removes it afterwards.
func catalogueVersion(t *testing.T, db *gorm.DB) string {
	t.Helper()
	v := &models.TofuVersion{Version: fmt.Sprintf("0.%d.0", 100000+rand.IntN(800000)), Enabled: true, Beta: true}
	if err := db.Create(v).Error; err != nil {
		t.Fatalf("create catalogue version: %v", err)
	}
	t.Cleanup(func() { db.Where("id = ?", v.ID).Delete(&models.TofuVersion{}) })
	return v.Version
}

// storedVersion is the workspace's tofu_version column.
func storedVersion(t *testing.T, db *gorm.DB, id string) string {
	t.Helper()
	var ws models.Workspace
	if err := db.First(&ws, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	return ws.TofuVersion
}

// readVersion is terraform-version as GET /api/v2/workspaces/:id and the by-name read answer it.
func (f *workspaceBooleansFixture) readVersion(t *testing.T, id, name string) string {
	t.Helper()
	code, _, byID := f.do(t, http.MethodGet, "/api/v2/workspaces/"+id, nil)
	if code != http.StatusOK {
		t.Fatalf("read by id = %d (%v)", code, byID)
	}
	code, _, byName := f.do(t, http.MethodGet, "/api/v2/organizations/"+f.orgName+"/workspaces/"+name, nil)
	if code != http.StatusOK {
		t.Fatalf("read by name = %d (%v)", code, byName)
	}
	if byID["terraform-version"] != byName["terraform-version"] {
		t.Errorf("the reads disagree: by id %v, by name %v", byID["terraform-version"], byName["terraform-version"])
	}
	v, _ := byID["terraform-version"].(string)
	return v
}

func (f *workspaceBooleansFixture) setOrgDefault(t *testing.T, version string) {
	t.Helper()
	if err := f.db.Model(&models.Organization{}).Where("name = ?", f.orgName).Update("default_tofu_version", version).Error; err != nil {
		t.Fatal(err)
	}
}

// A workspace created without terraform-version stores none and reads the effective version: the
// organization's default while it has one, then the installation default, which it follows. A
// version set through POST or PATCH is kept (AC9).
func TestWorkspaceVersion_CreateWithoutVersionReadsTheEffectiveOne(t *testing.T) {
	t.Setenv(settings.EnvTofuDefaultVersion, "")
	f := setupWorkspaceBooleans(t)
	orgDefault := catalogueVersion(t, f.db)
	f.setOrgDefault(t, orgDefault)

	id, name, created := f.create(t, nil)
	if got := storedVersion(t, f.db, id); got != "" {
		t.Errorf("a workspace created without terraform-version stored %q, want nothing (it inherits)", got)
	}
	if created["terraform-version"] != orgDefault {
		t.Errorf("the create response reads terraform-version %v, want the organization default %s", created["terraform-version"], orgDefault)
	}
	if got := f.readVersion(t, id, name); got != orgDefault {
		t.Errorf("terraform-version = %q, want the organization default %s", got, orgDefault)
	}

	f.setOrgDefault(t, "")
	if got := f.readVersion(t, id, name); got != tofu.BundledVersion {
		t.Errorf("with no organization default, terraform-version = %q, want the installation default %s", got, tofu.BundledVersion)
	}
	t.Setenv(settings.EnvTofuDefaultVersion, "1.12.0")
	if got := f.readVersion(t, id, name); got != "1.12.0" {
		t.Errorf("after the installation default changed, terraform-version = %q, want 1.12.0", got)
	}
	f.router.GET("/api/v2/organizations/:name/workspaces", f.h.ListByOrganization)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v2/organizations/"+f.orgName+"/workspaces", nil))
	var list struct {
		Data []struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("list = %d %v (%s)", rec.Code, err, rec.Body.String())
	}
	for _, ws := range list.Data {
		if ws.ID == id && ws.Attributes["terraform-version"] != "1.12.0" {
			t.Errorf("the list reads terraform-version %v, want 1.12.0", ws.Attributes["terraform-version"])
		}
	}

	// A version set on the workspace is kept and read back.
	pin := catalogueVersion(t, f.db)
	pinnedID, pinnedName, _ := f.create(t, map[string]any{"terraform-version": pin})
	if got := storedVersion(t, f.db, pinnedID); got != pin {
		t.Errorf("a workspace created with %s stored %q", pin, got)
	}
	if got := f.readVersion(t, pinnedID, pinnedName); got != pin {
		t.Errorf("a pinned workspace reads %q, want %s", got, pin)
	}
	repin := catalogueVersion(t, f.db)
	if code, _, attrs := f.do(t, http.MethodPatch, "/api/v2/workspaces/"+pinnedID, map[string]any{"terraform-version": repin}); code != http.StatusOK || attrs["terraform-version"] != repin {
		t.Fatalf("PATCH a version = %d, terraform-version %v; want 200 and %s", code, attrs["terraform-version"], repin)
	}
	if got := f.readVersion(t, pinnedID, pinnedName); got != repin {
		t.Errorf("a re-pinned workspace reads %q, want %s", got, repin)
	}
}
