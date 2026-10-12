// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a group may name as its parent (#916): a group of its own inventory. A group of another
// inventory is answered exactly like an identifier that names nothing, and a group row that
// already hangs under another inventory's group is not treated as that inventory's child.
//
// The defect these tests were written against: a create held the parent to the group's
// inventory, an update stored what it was sent. An inventory lists its groups' children by name
// when it is rendered, so a member of one organization could hang a group of their own under a
// group of another organization's inventory and have that inventory list it as a child.
//
// Every request is sent by a member of the first organization who has no part in the second.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run 'TestGroupParent'

//go:build integration

package ansible

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
)

// groupParentFixture is neighbourScopeFixture with inventory groups: two in the first
// organization's inventory, one in its second inventory, and one in the second organization's.
type groupParentFixture struct {
	*neighbourScopeFixture
	router      *gin.Engine
	inventories *ansiblesvc.InventoryService
	repo        *repository.AnsibleInventoryRepository

	own, ownParent, sibling, other *models.AnsibleInventoryGroup
	otherInventory                 uuid.UUID
}

func setupGroupParents(t *testing.T) *groupParentFixture {
	t.Helper()
	base := setupNeighbourScope(t)
	db := base.db
	if err := db.AutoMigrate(&models.AnsibleInventoryGroup{}); err != nil {
		t.Fatalf("migrating the tables: %v", err)
	}
	sfx := uuid.NewString()[:8]
	otherInventory := uuid.MustParse(base.otherInventory)
	group := func(inventory uuid.UUID, name string) *models.AnsibleInventoryGroup {
		return &models.AnsibleInventoryGroup{ID: uuid.New(), InventoryID: inventory, Name: name + sfx}
	}
	f := &groupParentFixture{
		neighbourScopeFixture: base, otherInventory: otherInventory,
		own:       group(base.inventory, "grpscope-own-"),
		ownParent: group(base.inventory, "grpscope-parent-"),
		sibling:   group(uuid.MustParse(base.inventory2), "grpscope-sibling-"),
		other:     group(otherInventory, "grpscope-other-"),
	}
	for _, row := range []*models.AnsibleInventoryGroup{f.own, f.ownParent, f.sibling, f.other} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seeding the group %s: %v", row.Name, err)
		}
	}
	// Registered after the shared fixture's cleanup, so it runs before it: every group of the
	// three inventories goes before its inventory, children before the groups they hang under.
	inventoryIDs := []uuid.UUID{base.inventory, uuid.MustParse(base.inventory2), otherInventory}
	t.Cleanup(func() {
		db.Model(&models.AnsibleInventoryGroup{}).Where("inventory_id IN ?", inventoryIDs).Update("parent_id", nil)
		db.Where("inventory_id IN ?", inventoryIDs).Delete(&models.AnsibleInventoryGroup{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	f.repo = repository.NewAnsibleInventoryRepository(db)
	f.inventories = ansiblesvc.NewInventoryService(f.repo, orgRepo)
	groups := NewGroupHandler(
		f.inventories, f.repo, auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db)),
	)
	f.router = storedAsSentRouter()
	f.router.POST("/api/v2/ansible/inventories/:id/groups", groups.Create)
	f.router.GET("/api/v2/ansible/groups/:id", groups.Get)
	f.router.PATCH("/api/v2/ansible/groups/:id", groups.Update)
	return f
}

func (f *groupParentFixture) send(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return storedAsSentCall(t, f.router, method, path, f.member, body)
}

// parentOf reads the parent a group names, empty when it names none.
func (f *groupParentFixture) parentOf(t *testing.T, group uuid.UUID) string {
	t.Helper()
	var parent *string
	if err := f.db.Raw("SELECT parent_id FROM ansible_inventory_groups WHERE id = ?", group).Scan(&parent).Error; err != nil {
		t.Fatalf("reading the parent of group %s: %v", group, err)
	}
	if parent == nil {
		return ""
	}
	return *parent
}

func (f *groupParentFixture) groupsOf(t *testing.T, inventory uuid.UUID) int64 {
	t.Helper()
	return f.rows(t, "SELECT count(*) FROM ansible_inventory_groups WHERE inventory_id = ?", inventory)
}

func TestGroupParent_AnotherInventoryReadsAsNotFound(t *testing.T) {
	f := setupGroupParents(t)
	writes := map[string]func(parent string) (int, []byte){
		"a create": func(parent string) (int, []byte) {
			return f.send(t, http.MethodPost, "/api/v2/ansible/inventories/"+f.inventoryID+"/groups",
				neighbourDocument(t, "ansible-groups", map[string]any{"name": "grpscope-" + uuid.NewString()[:8]}, map[string]string{"parent": parent}, nil))
		},
		"an update": func(parent string) (int, []byte) {
			return f.send(t, http.MethodPatch, "/api/v2/ansible/groups/"+f.own.ID.String(),
				neighbourDocument(t, "ansible-groups", map[string]any{}, map[string]string{"parent": parent}, nil))
		},
	}
	foreign := map[string]*models.AnsibleInventoryGroup{
		"another organization's inventory":           f.other,
		"another inventory of the same organization": f.sibling,
	}
	before := f.groupsOf(t, f.inventory)
	for name, send := range writes {
		missingCode, missingBody := send(uuid.NewString())
		assertBadRequest(t, missingCode, missingBody, "parent group not found")
		for whose, group := range foreign {
			t.Run(name+" naming a group of "+whose, func(t *testing.T) {
				code, body := send(group.ID.String())
				assertBadRequest(t, code, body, "parent group not found")
				if code != missingCode || !bytes.Equal(body, missingBody) {
					t.Errorf("a group of another inventory and one that does not exist are answered differently:\n  other inventory: %d %s\n  does not exist:  %d %s",
						code, body, missingCode, missingBody)
				}
			})
		}
	}
	if got := f.groupsOf(t, f.inventory) - before; got != 0 {
		t.Errorf("the refused creates left %d group(s) behind", got)
	}
	if got := f.parentOf(t, f.own.ID); got != "" {
		t.Errorf("after the refused updates the group hangs under %q, want no parent", got)
	}
}

func TestGroupParent_OwnInventoryIsAccepted(t *testing.T) {
	f := setupGroupParents(t)

	code, body := f.send(t, http.MethodPatch, "/api/v2/ansible/groups/"+f.own.ID.String(),
		neighbourDocument(t, "ansible-groups", map[string]any{}, map[string]string{"parent": f.ownParent.ID.String()}, nil))
	if code != http.StatusOK {
		t.Fatalf("hanging a group under a group of its own inventory: %d %s", code, body)
	}
	if got := f.parentOf(t, f.own.ID); got != f.ownParent.ID.String() {
		t.Errorf("the group hangs under %q, want %q", got, f.ownParent.ID)
	}

	code, body = f.send(t, http.MethodPost, "/api/v2/ansible/inventories/"+f.inventoryID+"/groups",
		neighbourDocument(t, "ansible-groups", map[string]any{"name": "grpscope-" + uuid.NewString()[:8]}, map[string]string{"parent": f.ownParent.ID.String()}, nil))
	if code != http.StatusCreated {
		t.Fatalf("creating a group under a group of its own inventory: %d %s", code, body)
	}
	var doc struct {
		Data storedAsSentResource `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decoding the created group: %v (%s)", err, body)
	}
	if got := f.parentOf(t, uuid.MustParse(doc.Data.ID)); got != f.ownParent.ID.String() {
		t.Errorf("the created group hangs under %q, want %q", got, f.ownParent.ID)
	}

	// The parent's inventory lists both as its children.
	rendered, err := f.inventories.GenerateInventoryJSON(f.inventory)
	if err != nil {
		t.Fatalf("rendering the inventory: %v", err)
	}
	if !strings.Contains(rendered, f.own.Name) {
		t.Errorf("the rendered inventory does not list %q under its parent", f.own.Name)
	}
}

// TestGroupParent_StoredRowIsNotTrusted hangs a group of the first organization under a group of
// the second organization's inventory directly, the way a row stored before an update checked
// would be, and uses the second organization's inventory.
func TestGroupParent_StoredRowIsNotTrusted(t *testing.T) {
	f := setupGroupParents(t)
	f.exec(t, "UPDATE ansible_inventory_groups SET parent_id = ? WHERE id = ?", f.other.ID, f.own.ID)

	t.Run("the rendered inventory does not list the group", func(t *testing.T) {
		asJSON, err := f.inventories.GenerateInventoryJSON(f.otherInventory)
		if err != nil {
			t.Fatalf("rendering the other organization's inventory as JSON: %v", err)
		}
		asINI, err := f.inventories.GenerateInventoryINI(f.otherInventory)
		if err != nil {
			t.Fatalf("rendering the other organization's inventory as INI: %v", err)
		}
		for format, rendered := range map[string]string{"JSON": asJSON, "INI": asINI} {
			if strings.Contains(rendered, f.own.Name) {
				t.Errorf("the other organization's inventory, rendered as %s, lists the first organization's group %q as a child", format, f.own.Name)
			}
		}
	})
	t.Run("the parent does not load the group as a child", func(t *testing.T) {
		parent, err := f.repo.GetGroupByID(f.other.ID)
		if err != nil {
			t.Fatalf("loading the other organization's group: %v", err)
		}
		if len(parent.Children) != 0 {
			t.Errorf("the other organization's group loads %d child(ren) of another inventory", len(parent.Children))
		}
	})
	t.Run("deleting the parent's inventory does not delete the group", func(t *testing.T) {
		// An inventory of the second organization of this test's own, so that the shared
		// fixture's rows are left alone.
		victim := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.otherOrgID, Name: "grpscope-victim-" + uuid.NewString()[:8], Type: models.InventoryTypeStatic}
		parent := &models.AnsibleInventoryGroup{ID: uuid.New(), InventoryID: victim.ID, Name: "grpscope-victim-" + uuid.NewString()[:8]}
		for _, row := range []any{victim, parent} {
			if err := f.db.Create(row).Error; err != nil {
				t.Fatalf("seeding %T: %v", row, err)
			}
		}
		t.Cleanup(func() {
			f.db.Model(&models.AnsibleInventoryGroup{}).Where("parent_id = ?", parent.ID).Update("parent_id", nil)
			f.db.Where("id = ?", parent.ID).Delete(&models.AnsibleInventoryGroup{})
			f.db.Where("id = ?", victim.ID).Delete(&models.AnsibleInventory{})
		})
		f.exec(t, "UPDATE ansible_inventory_groups SET parent_id = ? WHERE id = ?", parent.ID, f.own.ID)

		if err := f.repo.Delete(victim.ID); err != nil {
			t.Fatalf("deleting the other organization's inventory: %v", err)
		}
		if got := f.rows(t, "SELECT count(*) FROM ansible_inventory_groups WHERE id = ?", f.own.ID); got != 1 {
			t.Fatalf("deleting another organization's inventory deleted the first organization's group")
		}
		if got := f.parentOf(t, f.own.ID); got != "" {
			t.Errorf("the group still hangs under %q, a group that was deleted", got)
		}
	})
}
