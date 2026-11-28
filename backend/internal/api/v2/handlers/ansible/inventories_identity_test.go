// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A VCS inventory's identity binding (#1113, D1, AC-01): set and cleared through the inventory's
// create and update, refused for a binding of another organization and for an inventory of any
// other type, returned on the resource, and resolved with its level by the inventory's
// effective-settings read.
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestInventoryIdentityBinding

//go:build integration

package ansible

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/handlers"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/levelrefs"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/dbtest/testschema"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/gorm"
)

type inventoryIdentityFixture struct {
	*neighbourScopeFixture
	orgID         uuid.UUID
	vcs, static   uuid.UUID
	binding       *models.IdentityBinding
	foreign       *models.IdentityBinding
	projectSelect *models.IdentityBinding
}

func setupInventoryIdentity(t *testing.T) *inventoryIdentityFixture {
	t.Helper()
	f := setupNeighbourScope(t)
	if err := testschema.Ensure(f.db); err != nil {
		t.Fatal(err)
	}
	var project models.Project
	if err := f.db.First(&project, "id = ?", f.projectID).Error; err != nil {
		t.Fatal(err)
	}
	sfx := uuid.NewString()[:6]
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: project.OrganizationID, Name: "invid-" + sfx, OrganizationScoped: true}
	otherPool := &models.AgentPool{ID: uuid.New(), OrganizationID: f.otherOrgID, Name: "invid-" + sfx, OrganizationScoped: true}
	binding := &models.IdentityBinding{ID: uuid.New(), OrganizationID: project.OrganizationID, AgentPoolID: pool.ID, Name: "files-" + sfx, Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "sw-files"}
	projectSelect := &models.IdentityBinding{ID: uuid.New(), OrganizationID: project.OrganizationID, AgentPoolID: pool.ID, Name: "project-" + sfx, Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "sw-project"}
	foreign := &models.IdentityBinding{ID: uuid.New(), OrganizationID: f.otherOrgID, AgentPoolID: otherPool.ID, Name: "foreign-" + sfx, Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "sw-foreign"}
	vcsInv := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: project.OrganizationID, ProjectID: &project.ID, Name: "invid-vcs-" + sfx, Type: models.InventoryTypeVCS}
	staticInv := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: project.OrganizationID, ProjectID: &project.ID, Name: "invid-static-" + sfx, Type: models.InventoryTypeStatic}
	for _, row := range []any{pool, otherPool, binding, projectSelect, foreign, vcsInv, staticInv} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	// Registered after the fixture's own cleanup, so it runs first.
	t.Cleanup(func() {
		f.db.Model(&models.Project{}).Where("id = ?", project.ID).Update("identity_binding_id", nil)
		f.db.Model(&models.Organization{}).Where("id = ?", project.OrganizationID).Update("identity_binding_id", nil)
		f.db.Where("organization_id = ? AND name LIKE ?", project.OrganizationID, "invid-%").Delete(&models.AnsibleInventory{})
		f.db.Where("id IN ?", []uuid.UUID{binding.ID, projectSelect.ID, foreign.ID}).Delete(&models.IdentityBinding{})
		f.db.Where("id IN ?", []uuid.UUID{pool.ID, otherPool.ID}).Delete(&models.AgentPool{})
	})

	db := f.db
	inventoryRepo := repository.NewAnsibleInventoryRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), projectRepo)
	inventories := NewInventoryHandler(ansiblesvc.NewInventoryService(inventoryRepo, orgRepo), inventoryRepo, orgRepo, projectRepo, authService, rbacService, nil, nil, repository.NewVCSConnectionRepository(db))
	inventories.SetLevelRefs(levelrefs.New(db))
	effective := handlers.NewEffectiveSettingsHandlerV2(repository.NewWorkspaceRepository(db), repository.NewAnsibleJobTemplateRepository(db),
		repository.NewAnsibleInventorySourceRepository(db), inventoryRepo, projectRepo, orgRepo, authService, rbacService)
	f.router.POST("/api/v2/organizations/:name/ansible/inventories", inventories.Create)
	f.router.PATCH("/api/v2/ansible/inventories/:id", inventories.Update)
	f.router.GET("/api/v2/ansible/inventories/:id", inventories.Get)
	f.router.GET("/api/v2/ansible/inventories/:id/effective-settings", effective.GetInventory)
	return &inventoryIdentityFixture{neighbourScopeFixture: f, orgID: project.OrganizationID, vcs: vcsInv.ID, static: staticInv.ID, binding: binding, foreign: foreign, projectSelect: projectSelect}
}

func inventoryAttr(t *testing.T, body []byte, key string) any {
	t.Helper()
	var doc struct {
		Data struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	return doc.Data.Attributes[key]
}

func (f *inventoryIdentityFixture) patch(t *testing.T, id uuid.UUID, binding any) (int, []byte) {
	t.Helper()
	return f.call(t, http.MethodPatch, "/api/v2/ansible/inventories/"+id.String(),
		neighbourDocument(t, "ansible-inventories", map[string]any{"identity-binding-id": binding}, nil, nil))
}

func (f *inventoryIdentityFixture) stored(t *testing.T, id uuid.UUID) *uuid.UUID {
	t.Helper()
	var inv models.AnsibleInventory
	if err := f.db.First(&inv, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	return inv.IdentityBindingID
}

func TestInventoryIdentityBinding_Update(t *testing.T) {
	f := setupInventoryIdentity(t)

	code, body := f.patch(t, f.vcs, f.binding.ID.String())
	if code != http.StatusOK {
		t.Fatalf("set = %d, want 200 (%s)", code, body)
	}
	if got := inventoryAttr(t, body, "identity-binding-id"); got != f.binding.ID.String() {
		t.Errorf("resource identity-binding-id = %v, want %s", got, f.binding.ID)
	}
	if got := f.stored(t, f.vcs); got == nil || *got != f.binding.ID {
		t.Errorf("stored binding = %v, want %s", got, f.binding.ID)
	}
	_, body = f.call(t, http.MethodGet, "/api/v2/ansible/inventories/"+f.vcs.String(), "")
	if got := inventoryAttr(t, body, "identity-binding-id"); got != f.binding.ID.String() {
		t.Errorf("GET identity-binding-id = %v, want %s", got, f.binding.ID)
	}

	// Another attribute leaves the binding as it is; null inherits.
	if code, body := f.call(t, http.MethodPatch, "/api/v2/ansible/inventories/"+f.vcs.String(),
		neighbourDocument(t, "ansible-inventories", map[string]any{"description": "kept"}, nil, nil)); code != http.StatusOK {
		t.Fatalf("unrelated update = %d (%s)", code, body)
	}
	if got := f.stored(t, f.vcs); got == nil || *got != f.binding.ID {
		t.Errorf("an update without the attribute changed the binding to %v", got)
	}
	if code, body := f.patch(t, f.vcs, nil); code != http.StatusOK {
		t.Fatalf("inherit (null) = %d (%s)", code, body)
	}
	if got := f.stored(t, f.vcs); got != nil {
		t.Errorf("null left the binding %s, want it cleared", *got)
	}

	if code, body := f.patch(t, f.vcs, f.foreign.ID.String()); code != http.StatusUnprocessableEntity {
		t.Errorf("another organization's binding = %d, want 422 (%s)", code, body)
	}
	if code, body := f.patch(t, f.static, f.binding.ID.String()); code != http.StatusUnprocessableEntity {
		t.Errorf("binding on a static inventory = %d, want 422 (%s)", code, body)
	}
	if got := f.stored(t, f.static); got != nil {
		t.Errorf("the static inventory stored binding %s", *got)
	}
}

func TestInventoryIdentityBinding_Create(t *testing.T) {
	f := setupInventoryIdentity(t)
	create := func(typ string, binding string) (int, []byte) {
		return f.call(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/ansible/inventories",
			neighbourDocument(t, "ansible-inventories", map[string]any{"name": "invid-new-" + uuid.NewString()[:6], "inventory-type": typ, "identity-binding-id": binding},
				map[string]string{"project": f.projectID.String()}, nil))
	}
	code, body := create("vcs", f.binding.ID.String())
	if code != http.StatusCreated {
		t.Fatalf("create with a binding = %d, want 201 (%s)", code, body)
	}
	if got := inventoryAttr(t, body, "identity-binding-id"); got != f.binding.ID.String() {
		t.Errorf("created identity-binding-id = %v, want %s", got, f.binding.ID)
	}
	if code, body := create("vcs", f.foreign.ID.String()); code != http.StatusUnprocessableEntity {
		t.Errorf("create with another organization's binding = %d, want 422 (%s)", code, body)
	}
	if code, body := create("static", f.binding.ID.String()); code != http.StatusUnprocessableEntity {
		t.Errorf("create a static inventory with a binding = %d, want 422 (%s)", code, body)
	}
}

func TestInventoryIdentityBinding_EffectiveSettings(t *testing.T) {
	f := setupInventoryIdentity(t)
	effective := func() (any, any) {
		t.Helper()
		code, body := f.call(t, http.MethodGet, "/api/v2/ansible/inventories/"+f.vcs.String()+"/effective-settings", "")
		if code != http.StatusOK {
			t.Fatalf("effective settings = %d (%s)", code, body)
		}
		setting, _ := inventoryAttr(t, body, "identity-binding-id").(map[string]any)
		return setting["value"], setting["level"]
	}
	if v, l := effective(); v != nil || l != "deployment" {
		t.Errorf("nothing selected = %v at %v, want null at deployment", v, l)
	}
	if err := f.db.Model(&models.Organization{}).Where("id = ?", f.orgID).Update("identity_binding_id", f.projectSelect.ID).Error; err != nil {
		t.Fatal(err)
	}
	if v, l := effective(); v != f.projectSelect.ID.String() || l != "organization" {
		t.Errorf("organization selection = %v at %v, want %s at organization", v, l, f.projectSelect.ID)
	}
	if err := f.db.Model(&models.Project{}).Where("id = ?", f.projectID).Update("identity_binding_id", f.projectSelect.ID).Error; err != nil {
		t.Fatal(err)
	}
	if v, l := effective(); v != f.projectSelect.ID.String() || l != "project" {
		t.Errorf("project selection = %v at %v, want %s at project", v, l, f.projectSelect.ID)
	}
	if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", f.vcs).Update("identity_binding_id", f.binding.ID).Error; err != nil {
		t.Fatal(err)
	}
	if v, l := effective(); v != f.binding.ID.String() || l != "inventory" {
		t.Errorf("inventory selection = %v at %v, want %s at inventory", v, l, f.binding.ID)
	}
}

// An organization-scoped inventory's own selection wins over its organization's default (AC-01).
func TestInventoryIdentityBinding_OrganizationScopedOwnSelectionWins(t *testing.T) {
	f := setupInventoryIdentity(t)
	orgInv := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.orgID, Name: "invid-org-" + uuid.NewString()[:6], Type: models.InventoryTypeVCS, IdentityBindingID: &f.binding.ID}
	if err := f.db.Create(orgInv).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Model(&models.Organization{}).Where("id = ?", f.orgID).Update("identity_binding_id", f.projectSelect.ID).Error; err != nil {
		t.Fatal(err)
	}
	code, body := f.call(t, http.MethodGet, "/api/v2/ansible/inventories/"+orgInv.ID.String()+"/effective-settings", "")
	if code != http.StatusOK {
		t.Fatalf("effective settings = %d (%s)", code, body)
	}
	setting, _ := inventoryAttr(t, body, "identity-binding-id").(map[string]any)
	if setting["value"] != f.binding.ID.String() || setting["level"] != "inventory" {
		t.Errorf("organization-scoped inventory = %v at %v, want its own %s at inventory over the organization's %s",
			setting["value"], setting["level"], f.binding.ID, f.projectSelect.ID)
	}
}

// An update that neither sends the binding nor moves the inventory succeeds and keeps a retained
// binding that is no longer usable: the hosted binding renamed away, or a binding whose pool no
// longer lets the inventory's project use it (AC-01).
func TestInventoryIdentityBinding_DescriptionOnlyPatchKeepsARetiredBinding(t *testing.T) {
	f := setupInventoryIdentity(t)
	describe := func(t *testing.T, id uuid.UUID, text string) {
		t.Helper()
		code, body := f.call(t, http.MethodPatch, "/api/v2/ansible/inventories/"+id.String(),
			neighbourDocument(t, "ansible-inventories", map[string]any{"description": text}, nil, nil))
		if code != http.StatusOK {
			t.Fatalf("description-only PATCH = %d, want 200 (%s)", code, body)
		}
	}

	t.Run("hosted binding renamed", func(t *testing.T) {
		repository.SetHostedBinding(&repository.HostedBindingConfig{
			Name: "invid-hosted", Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "stackweaver-hosted-identity",
			Annotations: map[string]string{"azure.workload.identity/client-id": "11111111-2222-3333-4444-555555555555"},
		})
		t.Cleanup(func() { repository.SetHostedBinding(nil) })
		old := models.HostedIdentityBindingID("invid-hosted")
		if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", f.vcs).Update("identity_binding_id", old).Error; err != nil {
			t.Fatal(err)
		}
		repository.SetHostedBinding(&repository.HostedBindingConfig{
			Name: "invid-hosted-renamed", Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "stackweaver-hosted-identity",
			Annotations: map[string]string{"azure.workload.identity/client-id": "11111111-2222-3333-4444-555555555555"},
		})
		describe(t, f.vcs, "after the rename")
		if got := f.stored(t, f.vcs); got == nil || *got != old {
			t.Errorf("stored binding = %v, want the retained %s", got, old)
		}
	})

	t.Run("pool no longer allows the project", func(t *testing.T) {
		restricted := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgID, Name: "invid-restricted-" + uuid.NewString()[:6]}
		b := &models.IdentityBinding{ID: uuid.New(), OrganizationID: f.orgID, AgentPoolID: restricted.ID, Name: "invid-retired-" + uuid.NewString()[:6], Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "sw-retired"}
		for _, row := range []any{restricted, b} {
			if err := f.db.Create(row).Error; err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() {
			f.db.Model(&models.AnsibleInventory{}).Where("id = ?", f.vcs).Update("identity_binding_id", nil)
			f.db.Where("id = ?", b.ID).Delete(&models.IdentityBinding{})
			f.db.Where("id = ?", restricted.ID).Delete(&models.AgentPool{})
		})
		// The pool lets no project use it, so the inventory's project may not use the binding.
		if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", f.vcs).Update("identity_binding_id", b.ID).Error; err != nil {
			t.Fatal(err)
		}
		// Sending it is refused, which shows the retained binding is no longer usable.
		if code, body := f.patch(t, f.vcs, b.ID.String()); code != http.StatusUnprocessableEntity {
			t.Fatalf("sending the binding = %d, want 422 (%s)", code, body)
		}
		describe(t, f.vcs, "pool restricted")
		if got := f.stored(t, f.vcs); got == nil || *got != b.ID {
			t.Errorf("stored binding = %v, want the retained %s", got, b.ID)
		}
	})
}

// A PATCH that moves the inventory to a project whose pool may not be used is refused with 422,
// whether the binding is kept or sent in the same request, and the inventory keeps its project and
// its binding; the same move clearing the binding succeeds (AC-01, R-30 F-03).
func TestInventoryIdentityBinding_MoveToAProjectThePoolRefuses(t *testing.T) {
	f := setupInventoryIdentity(t)
	sfx := uuid.NewString()[:6]
	other := &models.Project{ID: uuid.New(), OrganizationID: f.orgID, Name: "invid-dest-" + sfx}
	restricted := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgID, Name: "invid-onlysrc-" + sfx}
	b := &models.IdentityBinding{ID: uuid.New(), OrganizationID: f.orgID, AgentPoolID: restricted.ID, Name: "invid-onlysrc-" + sfx, Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "sw-onlysrc"}
	for _, row := range []any{other, restricted, b} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	// The pool lets only the inventory's current project use it.
	if err := f.db.Exec("INSERT INTO agent_pool_allowed_projects (agent_pool_id, project_id) VALUES (?, ?)", restricted.ID, f.projectID).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Model(&models.AnsibleInventory{}).Where("id = ?", f.vcs).Updates(map[string]any{"identity_binding_id": nil, "project_id": f.projectID})
		f.db.Where("id = ?", b.ID).Delete(&models.IdentityBinding{})
		f.db.Exec("DELETE FROM agent_pool_allowed_projects WHERE agent_pool_id = ?", restricted.ID)
		f.db.Where("id = ?", restricted.ID).Delete(&models.AgentPool{})
		f.db.Where("id = ?", other.ID).Delete(&models.Project{})
	})
	if code, body := f.patch(t, f.vcs, b.ID.String()); code != http.StatusOK {
		t.Fatalf("selecting the binding in the source project = %d, want 200 (%s)", code, body)
	}

	move := func(t *testing.T, attrs map[string]any) (int, []byte) {
		t.Helper()
		return f.call(t, http.MethodPatch, "/api/v2/ansible/inventories/"+f.vcs.String(),
			neighbourDocument(t, "ansible-inventories", attrs, map[string]string{"project": other.ID.String()}, nil))
	}
	unchanged := func(t *testing.T) {
		t.Helper()
		var inv models.AnsibleInventory
		if err := f.db.First(&inv, "id = ?", f.vcs).Error; err != nil {
			t.Fatal(err)
		}
		if inv.ProjectID == nil || *inv.ProjectID != f.projectID {
			t.Errorf("a refused move changed the project to %v, want %s", inv.ProjectID, f.projectID)
		}
		if inv.IdentityBindingID == nil || *inv.IdentityBindingID != b.ID {
			t.Errorf("a refused move changed the binding to %v, want %s", inv.IdentityBindingID, b.ID)
		}
	}

	t.Run("binding kept", func(t *testing.T) {
		code, body := move(t, map[string]any{"description": "moved keeping the binding"})
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("move keeping the binding = %d, want 422 (%s)", code, body)
		}
		if !strings.Contains(string(body), restricted.Name) {
			t.Errorf("the refusal does not name the pool %s: %s", restricted.Name, body)
		}
		unchanged(t)
	})
	t.Run("binding sent", func(t *testing.T) {
		code, body := move(t, map[string]any{"identity-binding-id": b.ID.String()})
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("move sending the binding = %d, want 422 (%s)", code, body)
		}
		unchanged(t)
	})
	t.Run("binding cleared", func(t *testing.T) {
		if code, body := move(t, map[string]any{"identity-binding-id": nil}); code != http.StatusOK {
			t.Fatalf("move clearing the binding = %d, want 200 (%s)", code, body)
		}
		var inv models.AnsibleInventory
		if err := f.db.First(&inv, "id = ?", f.vcs).Error; err != nil {
			t.Fatal(err)
		}
		if inv.ProjectID == nil || *inv.ProjectID != other.ID || inv.IdentityBindingID != nil {
			t.Errorf("after the move: project %v, binding %v; want %s and none", inv.ProjectID, inv.IdentityBindingID, other.ID)
		}
	})
}

// failInventoryWrites makes every write of the given kind to ansible_inventories that match fail,
// until the returned function or the test's end removes the callback.
func failInventoryWrites(t *testing.T, db *gorm.DB, kind string, match func(*gorm.DB) bool) func() {
	t.Helper()
	name := "test:fail-inventory-" + kind + "-" + uuid.NewString()[:8]
	fail := func(tx *gorm.DB) {
		if tx.Statement.Table == "ansible_inventories" && match(tx) {
			_ = tx.AddError(errors.New("injected inventory write failure"))
		}
	}
	var err error
	remove := func() {}
	switch kind {
	case "create":
		err = db.Callback().Create().Before("gorm:create").Register(name, fail)
		remove = func() { _ = db.Callback().Create().Remove(name) }
	case "update":
		err = db.Callback().Update().Before("gorm:update").Register(name, fail)
		remove = func() { _ = db.Callback().Update().Remove(name) }
	default:
		t.Fatalf("unknown write kind %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	removeOnce := func() { once.Do(remove) }
	t.Cleanup(removeOnce)
	return removeOnce
}

// A failed inventory write leaves the stored row, binding included, as it was: a create stores no
// inventory, and an update that sends a binding and another attribute keeps both the binding and
// the attribute, also when only the binding's own column write fails (AC-01, R-30 F-03).
func TestInventoryIdentityBinding_FailedWriteLeavesTheInventory(t *testing.T) {
	f := setupInventoryIdentity(t)
	always := func(*gorm.DB) bool { return true }

	t.Run("create", func(t *testing.T) {
		name := "invid-failed-" + uuid.NewString()[:6]
		remove := failInventoryWrites(t, f.db, "create", always)
		code, body := f.call(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/ansible/inventories",
			neighbourDocument(t, "ansible-inventories", map[string]any{"name": name, "inventory-type": "vcs", "identity-binding-id": f.binding.ID.String()},
				map[string]string{"project": f.projectID.String()}, nil))
		remove()
		if code != http.StatusInternalServerError {
			t.Fatalf("create with a failing insert = %d, want 500 (%s)", code, body)
		}
		var n int64
		if err := f.db.Model(&models.AnsibleInventory{}).Where("organization_id = ? AND name = ?", f.orgID, name).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("a failed create stored %d inventories", n)
		}
	})

	update := func(t *testing.T, match func(*gorm.DB) bool) {
		t.Helper()
		if err := f.db.Model(&models.AnsibleInventory{}).Where("id = ?", f.vcs).
			Updates(map[string]any{"identity_binding_id": f.binding.ID, "description": "before"}).Error; err != nil {
			t.Fatal(err)
		}
		remove := failInventoryWrites(t, f.db, "update", match)
		code, body := f.call(t, http.MethodPatch, "/api/v2/ansible/inventories/"+f.vcs.String(),
			neighbourDocument(t, "ansible-inventories", map[string]any{"description": "after", "identity-binding-id": f.projectSelect.ID.String()}, nil, nil))
		remove()
		if code != http.StatusInternalServerError {
			t.Fatalf("update with a failing write = %d, want 500 (%s)", code, body)
		}
		var inv models.AnsibleInventory
		if err := f.db.First(&inv, "id = ?", f.vcs).Error; err != nil {
			t.Fatal(err)
		}
		if inv.IdentityBindingID == nil || *inv.IdentityBindingID != f.binding.ID || inv.Description != "before" {
			t.Errorf("after a failed update: binding %v, description %q; want %s and %q", inv.IdentityBindingID, inv.Description, f.binding.ID, "before")
		}
	}
	t.Run("update", func(t *testing.T) { update(t, always) })
	t.Run("update whose binding write fails", func(t *testing.T) {
		update(t, func(tx *gorm.DB) bool {
			cols, ok := tx.Statement.Dest.(map[string]any)
			if !ok {
				return false
			}
			_, binding := cols["identity_binding_id"]
			return binding
		})
	})
}
