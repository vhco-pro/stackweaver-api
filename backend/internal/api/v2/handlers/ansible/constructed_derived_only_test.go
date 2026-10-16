// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A constructed inventory is derived-only (#909, owner decision 2026-10-16): its hosts and groups
// come from its build alone, as in AWX. A build replaces the whole materialized set and nothing on
// a row tells a derived one from one a person added, so every route that would add a host or
// group to a constructed inventory by hand, or attach or move one inside it, answers 409 in the
// JSON:API error envelope and writes nothing. The refusal is InventoryService's
// (ansible.ErrConstructedInventory); these tests hold each route to it. Reads and deletes stay
// open, and a static inventory accepts every one of the same writes.
//
// Every request is sent by an owner of the organization. Gated behind `integration`; skips unless
// $TEST_DATABASE_URL is set. Cleanup is strictly row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run 'TestConstructedDerivedOnly'

//go:build integration

package ansible

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
)

// derivedOnlyInventory is an inventory with rows as a build leaves them: host is a member of
// group, group hangs under parent, and loose has no parent and no members.
type derivedOnlyInventory struct {
	id                   string
	host                 *models.AnsibleInventoryHost
	group, parent, loose *models.AnsibleInventoryGroup
}

type derivedOnlyRoutesFixture struct {
	*neighbourScopeFixture
	router              *gin.Engine
	constructed, static derivedOnlyInventory
}

func setupDerivedOnlyRoutes(t *testing.T) *derivedOnlyRoutesFixture {
	t.Helper()
	base := setupNeighbourScope(t)
	db := base.db
	if err := db.AutoMigrate(&models.AnsibleInventoryHost{}, &models.AnsibleInventoryGroup{}); err != nil {
		t.Fatalf("migrating the tables: %v", err)
	}
	sfx := uuid.NewString()[:8]
	var org models.Organization
	if err := db.First(&org, "name = ?", base.orgName).Error; err != nil {
		t.Fatalf("reading the organization: %v", err)
	}
	constructed := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: org.ID, Name: "derivedonly-c-" + sfx, Type: models.InventoryTypeConstructed}
	if err := db.Create(constructed).Error; err != nil {
		t.Fatalf("seeding the constructed inventory: %v", err)
	}
	// Registered after the shared fixture's cleanup, so it runs before it: the rows of both
	// inventories go first, then the constructed inventory itself.
	inventoryIDs := []uuid.UUID{constructed.ID, base.inventory}
	t.Cleanup(func() {
		hostIDs := db.Model(&models.AnsibleInventoryHost{}).Select("id").Where("inventory_id IN ?", inventoryIDs)
		db.Exec("DELETE FROM ansible_inventory_host_groups WHERE ansible_inventory_host_id IN (?)", hostIDs)
		db.Where("inventory_id IN ?", inventoryIDs).Delete(&models.AnsibleInventoryHost{})
		db.Model(&models.AnsibleInventoryGroup{}).Where("inventory_id IN ?", inventoryIDs).Update("parent_id", nil)
		db.Where("inventory_id IN ?", inventoryIDs).Delete(&models.AnsibleInventoryGroup{})
		db.Where("inventory_id = ?", constructed.ID).Delete(&models.AnsibleInventorySource{})
		db.Where("id = ?", constructed.ID).Delete(&models.AnsibleInventory{})
	})

	shape := func(inventory uuid.UUID) derivedOnlyInventory {
		s := derivedOnlyInventory{
			id:     inventory.String(),
			host:   &models.AnsibleInventoryHost{ID: uuid.New(), InventoryID: inventory, Name: "web1-" + sfx, Port: 22, Enabled: true},
			parent: &models.AnsibleInventoryGroup{ID: uuid.New(), InventoryID: inventory, Name: "all_web-" + sfx},
			loose:  &models.AnsibleInventoryGroup{ID: uuid.New(), InventoryID: inventory, Name: "loose-" + sfx},
		}
		s.group = &models.AnsibleInventoryGroup{ID: uuid.New(), InventoryID: inventory, Name: "web-" + sfx, ParentID: &s.parent.ID}
		for _, row := range []any{s.host, s.parent, s.group, s.loose} {
			if err := db.Create(row).Error; err != nil {
				t.Fatalf("seeding %T: %v", row, err)
			}
		}
		if err := db.Exec("INSERT INTO ansible_inventory_host_groups (ansible_inventory_host_id, ansible_inventory_group_id) VALUES (?, ?)", s.host.ID, s.group.ID).Error; err != nil {
			t.Fatalf("seeding the membership: %v", err)
		}
		return s
	}

	orgRepo := repository.NewOrganizationRepository(db)
	inventoryRepo := repository.NewAnsibleInventoryRepository(db)
	inventories := ansiblesvc.NewInventoryService(inventoryRepo, orgRepo)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	hosts := NewHostHandler(inventories, inventoryRepo, authService, rbacService)
	groups := NewGroupHandler(inventories, inventoryRepo, authService, rbacService)
	sources := NewInventorySourceHandler(
		ansiblesvc.NewInventorySourceService(repository.NewAnsibleInventorySourceRepository(db), inventoryRepo, repository.NewAnsibleCredentialRepository(db), nil),
		inventories, authService, rbacService, nil,
	)

	router := storedAsSentRouter()
	router.GET("/api/v2/ansible/inventories/:id/hosts", hosts.List)
	router.POST("/api/v2/ansible/inventories/:id/hosts", hosts.Create)
	router.GET("/api/v2/ansible/inventories/:id/groups", groups.List)
	router.POST("/api/v2/ansible/inventories/:id/groups", groups.Create)
	router.GET("/api/v2/ansible/hosts/:id", hosts.Get)
	router.PATCH("/api/v2/ansible/hosts/:id", hosts.Update)
	router.DELETE("/api/v2/ansible/hosts/:id", hosts.Delete)
	router.POST("/api/v2/ansible/hosts/:id/groups/:group_id", hosts.AddToGroup)
	router.DELETE("/api/v2/ansible/hosts/:id/groups/:group_id", hosts.RemoveFromGroup)
	router.GET("/api/v2/ansible/groups/:id", groups.Get)
	router.PATCH("/api/v2/ansible/groups/:id", groups.Update)
	router.DELETE("/api/v2/ansible/groups/:id", groups.Delete)
	router.POST("/api/v2/ansible/inventories/:id/sources", sources.Create)

	return &derivedOnlyRoutesFixture{
		neighbourScopeFixture: base, router: router,
		constructed: shape(constructed.ID), static: shape(base.inventory),
	}
}

func (f *derivedOnlyRoutesFixture) send(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return storedAsSentCall(t, f.router, method, path, f.member, body)
}

// rowsOf is every row a refused write could have added or changed in the inventory: hosts,
// groups, memberships, sources, and groups that hang under a parent.
func (f *derivedOnlyRoutesFixture) rowsOf(t *testing.T, inventory string) [5]int64 {
	t.Helper()
	return [5]int64{
		f.rows(t, "SELECT count(*) FROM ansible_inventory_hosts WHERE inventory_id = ?", inventory),
		f.rows(t, "SELECT count(*) FROM ansible_inventory_groups WHERE inventory_id = ?", inventory),
		f.rows(t, "SELECT count(*) FROM ansible_inventory_host_groups m JOIN ansible_inventory_hosts h ON h.id = m.ansible_inventory_host_id WHERE h.inventory_id = ?", inventory),
		f.rows(t, "SELECT count(*) FROM ansible_inventory_sources WHERE inventory_id = ?", inventory),
		f.rows(t, "SELECT count(*) FROM ansible_inventory_groups WHERE inventory_id = ? AND parent_id IS NOT NULL", inventory),
	}
}

// derivedOnlyWrite is one route that adds a host or group to an inventory, or attaches or moves
// one inside it, and the status it answers with on a static inventory.
type derivedOnlyWrite struct {
	name     string
	accepted int
	send     func(s derivedOnlyInventory) (int, []byte)
}

func (f *derivedOnlyRoutesFixture) handMadeWrites(t *testing.T) []derivedOnlyWrite {
	t.Helper()
	name := func() string { return "byhand-" + uuid.NewString()[:8] }
	return []derivedOnlyWrite{
		{"POST /ansible/inventories/:id/hosts", http.StatusCreated, func(s derivedOnlyInventory) (int, []byte) {
			return f.send(t, http.MethodPost, "/api/v2/ansible/inventories/"+s.id+"/hosts",
				neighbourDocument(t, "ansible-hosts", map[string]any{"name": name(), "hostname": "10.0.0.9"}, nil, nil))
		}},
		{"POST /ansible/inventories/:id/groups", http.StatusCreated, func(s derivedOnlyInventory) (int, []byte) {
			return f.send(t, http.MethodPost, "/api/v2/ansible/inventories/"+s.id+"/groups",
				neighbourDocument(t, "ansible-groups", map[string]any{"name": name()}, nil, nil))
		}},
		{"POST /ansible/inventories/:id/groups with a parent", http.StatusCreated, func(s derivedOnlyInventory) (int, []byte) {
			return f.send(t, http.MethodPost, "/api/v2/ansible/inventories/"+s.id+"/groups",
				neighbourDocument(t, "ansible-groups", map[string]any{"name": name()}, map[string]string{"parent": s.parent.ID.String()}, nil))
		}},
		{"PATCH /ansible/groups/:id moving a group", http.StatusOK, func(s derivedOnlyInventory) (int, []byte) {
			return f.send(t, http.MethodPatch, "/api/v2/ansible/groups/"+s.loose.ID.String(),
				neighbourDocument(t, "ansible-groups", map[string]any{}, map[string]string{"parent": s.parent.ID.String()}, nil))
		}},
		{"POST /ansible/hosts/:id/groups/:group_id", http.StatusNoContent, func(s derivedOnlyInventory) (int, []byte) {
			return f.send(t, http.MethodPost, "/api/v2/ansible/hosts/"+s.host.ID.String()+"/groups/"+s.loose.ID.String(), "")
		}},
		{"POST /ansible/inventories/:id/sources", http.StatusCreated, func(s derivedOnlyInventory) (int, []byte) {
			return f.send(t, http.MethodPost, "/api/v2/ansible/inventories/"+s.id+"/sources",
				neighbourDocument(t, "ansible-inventory-sources", map[string]any{"name": name(), "source-type": "custom"}, nil, nil))
		}},
	}
}

func assertConstructedRefusal(t *testing.T, code int, body []byte) {
	t.Helper()
	if code != http.StatusConflict {
		t.Errorf("status = %d, want 409 (%s)", code, body)
		return
	}
	var doc struct {
		Errors []struct {
			Status string `json:"status"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decoding the error document: %v\n%s", err, body)
	}
	if len(doc.Errors) != 1 {
		t.Fatalf("got %d errors, want 1: %s", len(doc.Errors), body)
	}
	got := doc.Errors[0]
	if got.Status != "409" || got.Title != "Conflict" || got.Detail != ansiblesvc.ErrConstructedInventory.Error() {
		t.Errorf("error = %+v, want status 409, title Conflict, detail %q", got, ansiblesvc.ErrConstructedInventory)
	}
}

func TestConstructedDerivedOnly_HandMadeWritesAreRefused(t *testing.T) {
	f := setupDerivedOnlyRoutes(t)
	before := f.rowsOf(t, f.constructed.id)
	for _, w := range f.handMadeWrites(t) {
		t.Run(w.name, func(t *testing.T) {
			code, body := w.send(f.constructed)
			assertConstructedRefusal(t, code, body)
		})
	}
	if after := f.rowsOf(t, f.constructed.id); after != before {
		t.Errorf("hosts, groups, memberships, sources, parented groups went from %v to %v", before, after)
	}
}

func TestConstructedDerivedOnly_StaticAcceptsTheSameWrites(t *testing.T) {
	f := setupDerivedOnlyRoutes(t)
	for _, w := range f.handMadeWrites(t) {
		t.Run(w.name, func(t *testing.T) {
			if code, body := w.send(f.static); code != w.accepted {
				t.Errorf("status = %d, want %d (%s)", code, w.accepted, body)
			}
		})
	}
}

// Reads and deletes stay open on a constructed inventory, and so does an edit that leaves a row
// where it is: disabling a host, describing a group without moving it.
func TestConstructedDerivedOnly_ReadsEditsAndDeletesStayOpen(t *testing.T) {
	f := setupDerivedOnlyRoutes(t)
	s := f.constructed
	steps := []struct {
		name         string
		method, path string
		body         string
		want         int
	}{
		{"list hosts", http.MethodGet, "/api/v2/ansible/inventories/" + s.id + "/hosts", "", http.StatusOK},
		{"list groups", http.MethodGet, "/api/v2/ansible/inventories/" + s.id + "/groups", "", http.StatusOK},
		{"read a host", http.MethodGet, "/api/v2/ansible/hosts/" + s.host.ID.String(), "", http.StatusOK},
		{"read a group", http.MethodGet, "/api/v2/ansible/groups/" + s.group.ID.String(), "", http.StatusOK},
		{
			"disable a host", http.MethodPatch, "/api/v2/ansible/hosts/" + s.host.ID.String(),
			neighbourDocument(t, "ansible-hosts", map[string]any{"enabled": false}, nil, nil), http.StatusOK,
		},
		{
			"describe a group, naming the parent it has", http.MethodPatch, "/api/v2/ansible/groups/" + s.group.ID.String(),
			neighbourDocument(t, "ansible-groups", map[string]any{"description": "noted"}, map[string]string{"parent": s.parent.ID.String()}, nil), http.StatusOK,
		},
		{"remove a host from a group", http.MethodDelete, "/api/v2/ansible/hosts/" + s.host.ID.String() + "/groups/" + s.group.ID.String(), "", http.StatusNoContent},
		{"delete a group", http.MethodDelete, "/api/v2/ansible/groups/" + s.group.ID.String(), "", http.StatusNoContent},
		{"delete a host", http.MethodDelete, "/api/v2/ansible/hosts/" + s.host.ID.String(), "", http.StatusNoContent},
	}
	for _, step := range steps {
		if code, body := f.send(t, step.method, step.path, step.body); code != step.want {
			t.Errorf("%s: status = %d, want %d (%s)", step.name, code, step.want, body)
		}
	}
	if got := f.rowsOf(t, s.id); got != [5]int64{0, 2, 0, 0, 0} {
		t.Errorf("hosts, groups, memberships, sources, parented groups = %v, want [0 2 0 0 0]", got)
	}
}
