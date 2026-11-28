// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The entry points of a VCS file sync (#1113, D2; AC-23, AC-26): the manual sync route checks the
// request before it marks the inventory syncing and answers 422 for a refusal and 500 for a database
// error; an inventory create still answers 201 and records the refusal or failure only when no file
// sync of the inventory exists yet; nothing the request writes after it queued can overwrite a fast
// completion.
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestInventorySyncEntry

//go:build integration

package ansible

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/levelrefs"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/wakeup"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type syncEntryFixture struct {
	*neighbourScopeFixture
	orgID, projectID     uuid.UUID
	gitlab               *models.VCSConnection
	restricted, open     *models.AgentPool
	onRestricted, onOpen *models.IdentityBinding
	items                *ansiblesvc.WorkItemService
	rdb                  *redis.Client
}

func setupSyncEntry(t *testing.T) *syncEntryFixture {
	t.Helper()
	f := &syncEntryFixture{neighbourScopeFixture: setupNeighbourScope(t)}
	var project models.Project
	if err := f.db.First(&project, "id = ?", f.neighbourScopeFixture.projectID).Error; err != nil {
		t.Fatal(err)
	}
	f.orgID, f.projectID = project.OrganizationID, project.ID
	sfx := uuid.NewString()[:6]
	f.gitlab = &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgID, Provider: models.VCSProviderGitLab, AccessToken: "glpat-unused", AccountName: "syncentry-" + sfx}
	f.restricted = &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgID, Name: "syncentry-restricted-" + sfx}
	f.open = &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgID, Name: "syncentry-open-" + sfx, OrganizationScoped: true}
	f.onRestricted = &models.IdentityBinding{ID: uuid.New(), OrganizationID: f.orgID, AgentPoolID: f.restricted.ID, Name: "syncentry-r-" + sfx, Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "sw-r"}
	f.onOpen = &models.IdentityBinding{ID: uuid.New(), OrganizationID: f.orgID, AgentPoolID: f.open.ID, Name: "syncentry-o-" + sfx, Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "sw-o"}
	for _, row := range []any{f.gitlab, f.restricted, f.open, f.onRestricted, f.onOpen} {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		var ids []uuid.UUID
		f.db.Model(&models.AnsibleInventory{}).Where("organization_id = ? AND name LIKE ?", f.orgID, "syncentry-%").Pluck("id", &ids)
		f.db.Where("inventory_id IN ?", ids).Delete(&models.WorkItem{})
		f.db.Where("id IN ?", ids).Delete(&models.AnsibleInventory{})
		f.db.Where("id IN ?", []uuid.UUID{f.onRestricted.ID, f.onOpen.ID}).Delete(&models.IdentityBinding{})
		f.db.Where("id IN ?", []uuid.UUID{f.restricted.ID, f.open.ID}).Delete(&models.AgentPool{})
		f.db.Where("id = ?", f.gitlab.ID).Delete(&models.VCSConnection{})
		f.db.Model(&models.Organization{}).Where("id = ?", f.orgID).Update("allow_stored_vcs_credentials_on_agent_pools", false)
	})
	mr := miniredis.RunT(t)
	f.rdb = redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = f.rdb.Close() })
	f.items = ansiblesvc.NewWorkItemService(f.db, f.rdb)

	db := f.db
	inventoryRepo := repository.NewAnsibleInventoryRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), projectRepo)
	h := NewInventoryHandler(ansiblesvc.NewInventoryService(inventoryRepo, orgRepo), inventoryRepo, orgRepo, projectRepo, authService, rbacService, f.items, nil, repository.NewVCSConnectionRepository(db))
	h.SetLevelRefs(levelrefs.New(db))
	f.router.POST("/api/v2/organizations/:name/ansible/inventories", h.Create)
	f.router.POST("/api/v2/ansible/inventories/:id/actions/sync", h.SyncInventory)
	return f
}

// inventory stores a VCS inventory of the project on conn, selecting binding, with a settled sync.
func (f *syncEntryFixture) inventory(t *testing.T, conn uuid.UUID, binding *uuid.UUID) *models.AnsibleInventory {
	t.Helper()
	inv := &models.AnsibleInventory{
		ID: uuid.New(), OrganizationID: f.orgID, ProjectID: &f.projectID, Name: "syncentry-" + uuid.NewString()[:8], Type: models.InventoryTypeVCS,
		VCSConnectionID: &conn, VCSRepository: "acme/inventory", VCSBranch: "main", InventoryPath: "hosts.yml",
		IdentityBindingID: binding, LastSyncStatus: "completed",
	}
	if err := f.db.Create(inv).Error; err != nil {
		t.Fatal(err)
	}
	return inv
}

func (f *syncEntryFixture) state(t *testing.T, id uuid.UUID) (status, syncErr string, items int64) {
	t.Helper()
	var inv models.AnsibleInventory
	if err := f.db.First(&inv, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	f.db.Model(&models.WorkItem{}).Where("inventory_id = ?", id).Count(&items)
	return inv.LastSyncStatus, inv.LastSyncError, items
}

func (f *syncEntryFixture) sync(t *testing.T, id uuid.UUID) (int, []byte) {
	t.Helper()
	return f.call(t, http.MethodPost, "/api/v2/ansible/inventories/"+id.String()+"/actions/sync", "")
}

func TestInventorySyncEntry_ManualSyncRefusals(t *testing.T) {
	f := setupSyncEntry(t)
	conn := f.gitlab.ID
	for name, tc := range map[string]struct {
		binding *uuid.UUID
		want    []string
	}{
		"pool does not allow the inventory": {&f.onRestricted.ID, []string{f.restricted.Name}},
		"stored credential":                 {&f.onOpen.ID, []string{"stored credential", "Allow stored VCS credentials on agent pools", f.gitlab.AccountName}},
	} {
		inv := f.inventory(t, conn, tc.binding)
		code, body := f.sync(t, inv.ID)
		if code != http.StatusUnprocessableEntity {
			t.Errorf("%s: manual sync = %d %s, want 422", name, code, body)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(string(body), w) {
				t.Errorf("%s: refusal %s does not say %q", name, body, w)
			}
		}
		if status, _, n := f.state(t, inv.ID); status != "completed" || n != 0 {
			t.Errorf("%s: status %q with %d work items, want the status unchanged and nothing queued", name, status, n)
		}
	}
}

func TestInventorySyncEntry_ManualSyncDatabaseError(t *testing.T) {
	f := setupSyncEntry(t)
	inv := f.inventory(t, f.gitlab.ID, &f.onOpen.ID)
	name := "syncentry-fail-" + uuid.NewString()[:6]
	if err := f.db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table == "identity_bindings" {
			_ = tx.AddError(errors.New("database read interrupted"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	code, body := f.sync(t, inv.ID)
	_ = f.db.Callback().Query().Remove(name)
	if code != http.StatusInternalServerError {
		t.Fatalf("manual sync during a read failure = %d %s, want 500", code, body)
	}
	if status, _, n := f.state(t, inv.ID); status != "completed" || n != 0 {
		t.Errorf("status %q with %d work items, want nothing changed", status, n)
	}
}

func TestInventorySyncEntry_CreateRecordsARefusedFirstSync(t *testing.T) {
	f := setupSyncEntry(t)
	body := neighbourDocument(t, "ansible-inventories", map[string]any{
		"name": "syncentry-create-" + uuid.NewString()[:6], "inventory-type": "vcs", "vcs_repository": "acme/inventory", "vcs_branch": "main",
		"inventory_path": "hosts.yml", "identity-binding-id": f.onOpen.ID.String(),
	}, map[string]string{"vcs_connection": f.gitlab.ID.String(), "project": f.projectID.String()}, nil)
	code, resp := f.call(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/ansible/inventories", body)
	if code != http.StatusCreated {
		t.Fatalf("create = %d %s, want 201", code, resp)
	}
	id := uuid.MustParse(inventoryID(t, resp))
	status, syncErr, n := f.state(t, id)
	if status != "failed" || !strings.Contains(syncErr, "stored credential") || n != 0 {
		t.Errorf("after a refused first sync: status %q error %q, %d work items; want failed with the reason and nothing queued", status, syncErr, n)
	}
}

func TestInventorySyncEntry_FailureRecordKeepsAnotherSyncsStatus(t *testing.T) {
	f := setupSyncEntry(t)
	inv := f.inventory(t, f.gitlab.ID, nil)
	// Another request queued a file sync meanwhile: neither a create's nor a webhook's failure
	// record may take the status from it.
	queued := time.Now()
	other := &models.WorkItem{OrganizationID: f.orgID, ProjectID: &f.projectID, Kind: models.WorkItemInventoryFileSync, InventoryID: &inv.ID, AgentPoolID: &f.open.ID, Status: models.WorkItemStatusPending, QueuedAt: &queued}
	if err := f.db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	for _, mode := range []ansiblesvc.FailureRecord{ansiblesvc.FirstSyncFailure, ansiblesvc.WebhookSyncFailure} {
		if err := f.items.RecordFileSyncFailure(context.Background(), inv.ID, "refused", mode); err != nil {
			t.Fatal(err)
		}
		if status, _, _ := f.state(t, inv.ID); status != "completed" {
			t.Errorf("mode %v recorded over a waiting sync: status %q", mode, status)
		}
	}
	// Once that sync has finished, a webhook's refusal is recorded; a create's is not, because a
	// file sync of the inventory exists.
	if err := f.db.Model(other).Update("status", models.WorkItemStatusCompleted).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.items.RecordFileSyncFailure(context.Background(), inv.ID, "refused by create", ansiblesvc.FirstSyncFailure); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := f.state(t, inv.ID); status != "completed" {
		t.Errorf("a create's failure record with a finished sync present: status %q", status)
	}
	if err := f.items.RecordFileSyncFailure(context.Background(), inv.ID, "refused by webhook", ansiblesvc.WebhookSyncFailure); err != nil {
		t.Fatal(err)
	}
	if status, syncErr, _ := f.state(t, inv.ID); status != "failed" || syncErr != "refused by webhook" {
		t.Errorf("a webhook's failure record with no active sync: status %q error %q", status, syncErr)
	}
}

func TestInventorySyncEntry_FastCompletionIsNeverOverwritten(t *testing.T) {
	f := setupSyncEntry(t)
	if err := f.db.Model(&models.Organization{}).Where("id = ?", f.orgID).Update("allow_stored_vcs_credentials_on_agent_pools", true).Error; err != nil {
		t.Fatal(err)
	}
	inv := f.inventory(t, f.gitlab.ID, &f.onOpen.ID)
	// As soon as the launchers are woken, the sync completes.
	sub := f.rdb.Subscribe(context.Background(), wakeup.Channel)
	t.Cleanup(func() { _ = sub.Close() })
	if _, err := sub.Receive(context.Background()); err != nil {
		t.Fatal(err)
	}
	completed := make(chan struct{})
	go func() {
		defer close(completed)
		if _, err := sub.ReceiveMessage(context.Background()); err != nil {
			return
		}
		f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("last_sync_status", "completed-fast")
	}()
	if code, body := f.sync(t, inv.ID); code != http.StatusAccepted {
		t.Fatalf("manual sync = %d %s", code, body)
	}
	select {
	case <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("no wakeup was published")
	}
	time.Sleep(100 * time.Millisecond)
	if status, _, _ := f.state(t, inv.ID); status != "completed-fast" {
		t.Errorf("status = %q, want the completion that landed after the wakeup", status)
	}
}

func inventoryID(t *testing.T, body []byte) string {
	t.Helper()
	var doc struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Data.ID == "" {
		t.Fatalf("no inventory id in %s (%v)", body, err)
	}
	return doc.Data.ID
}

// createVCS creates a VCS inventory of the project on conn through the create route, sending
// identity-binding-id only when binding is set.
func (f *syncEntryFixture) createVCS(t *testing.T, name string, conn uuid.UUID, binding *uuid.UUID) (int, []byte) {
	t.Helper()
	attrs := map[string]any{"name": name, "inventory-type": "vcs", "vcs_repository": "acme/inventory", "vcs_branch": "main", "inventory_path": "hosts.yml"}
	if binding != nil {
		attrs["identity-binding-id"] = binding.String()
	}
	body := neighbourDocument(t, "ansible-inventories", attrs, map[string]string{"vcs_connection": conn.String(), "project": f.projectID.String()}, nil)
	return f.call(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/ansible/inventories", body)
}

// selectOnProject makes the project select binding, which a create that sends no binding inherits.
func (f *syncEntryFixture) selectOnProject(t *testing.T, binding *uuid.UUID) {
	t.Helper()
	if err := f.db.Model(&models.Project{}).Where("id = ?", f.projectID).Update("identity_binding_id", binding).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Model(&models.Project{}).Where("id = ?", f.projectID).Update("identity_binding_id", nil) })
}

func (f *syncEntryFixture) allowStored(t *testing.T, allow bool) {
	t.Helper()
	if err := f.db.Model(&models.Organization{}).Where("id = ?", f.orgID).Update("allow_stored_vcs_credentials_on_agent_pools", allow).Error; err != nil {
		t.Fatal(err)
	}
}

// failFirstRead fails the next read of table, as an interrupted database read, and only that one.
func (f *syncEntryFixture) failFirstRead(t *testing.T, table string) {
	t.Helper()
	name := "syncentry-failread-" + uuid.NewString()[:6]
	var fired atomic.Bool
	if err := f.db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table == table && fired.CompareAndSwap(false, true) {
			_ = tx.AddError(errors.New("database read interrupted"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.db.Callback().Query().Remove(name) })
}

// atSecondSyncLock runs fn before the second statement that takes an inventory's sync advisory lock
// from now on. In a create whose first sync fails, the first is the failed request's own and the
// second is its failure record's.
func (f *syncEntryFixture) atSecondSyncLock(t *testing.T, fn func(tx *gorm.DB)) {
	t.Helper()
	name := "syncentry-lock-" + uuid.NewString()[:6]
	var n atomic.Int32
	if err := f.db.Callback().Raw().Before("gorm:raw").Register(name, func(tx *gorm.DB) {
		if strings.Contains(tx.Statement.SQL.String(), "pg_advisory_xact_lock") && n.Add(1) == 2 {
			fn(tx)
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.db.Callback().Raw().Remove(name) })
}

// responseSync reads the last sync status and error an inventory response carries.
func responseSync(t *testing.T, body []byte) (status, syncErr string) {
	t.Helper()
	var doc struct {
		Data struct {
			Attributes struct {
				Status string `json:"last-sync-status"`
				Error  string `json:"last-sync-error"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	return doc.Data.Attributes.Status, doc.Data.Attributes.Error
}

// A create whose first sync the pool rule refuses answers 201 with the failed status and the reason,
// in the response and on the inventory, and queues nothing (#1113, D2; AC-23).
func TestInventorySyncEntry_CreateRecordsAPoolRefusal(t *testing.T) {
	f := setupSyncEntry(t)
	// The project selects a binding whose pool does not let the project use it, so a create that
	// sends no binding inherits a selection the first sync's pool check refuses.
	f.selectOnProject(t, &f.onRestricted.ID)
	code, resp := f.createVCS(t, "syncentry-pool-"+uuid.NewString()[:6], f.gitlab.ID, nil)
	if code != http.StatusCreated {
		t.Fatalf("create = %d %s, want 201", code, resp)
	}
	if status, syncErr := responseSync(t, resp); status != "failed" || !strings.Contains(syncErr, f.restricted.Name) {
		t.Errorf("response sync = %q %q, want failed naming pool %s", status, syncErr, f.restricted.Name)
	}
	status, syncErr, n := f.state(t, uuid.MustParse(inventoryID(t, resp)))
	if status != "failed" || !strings.Contains(syncErr, f.restricted.Name) || !strings.Contains(syncErr, "does not let the inventory's project use it") || n != 0 {
		t.Errorf("stored: status %q error %q, %d work items; want failed with the pool reason and nothing queued", status, syncErr, n)
	}
}

// A create whose first sync fails on a binding read answers 201 with the failed status and the
// retry reason, and a manual sync then queues (#1113, D2; AC-23).
func TestInventorySyncEntry_FailedBindingReadAtCreate(t *testing.T) {
	f := setupSyncEntry(t)
	f.allowStored(t, true)
	f.selectOnProject(t, &f.onOpen.ID)
	f.failFirstRead(t, "identity_bindings")
	code, resp := f.createVCS(t, "syncentry-readfail-"+uuid.NewString()[:6], f.gitlab.ID, nil)
	if code != http.StatusCreated {
		t.Fatalf("create = %d %s, want 201", code, resp)
	}
	if status, syncErr := responseSync(t, resp); status != "failed" || syncErr != ansiblesvc.FirstSyncRetryReason {
		t.Errorf("response sync = %q %q, want failed with the retry reason", status, syncErr)
	}
	id := uuid.MustParse(inventoryID(t, resp))
	if status, syncErr, n := f.state(t, id); status != "failed" || syncErr != ansiblesvc.FirstSyncRetryReason || n != 0 {
		t.Fatalf("stored: status %q error %q, %d work items; want failed with the retry reason and nothing queued", status, syncErr, n)
	}
	if code, body := f.sync(t, id); code != http.StatusAccepted {
		t.Fatalf("manual retry = %d %s, want 202", code, body)
	}
	if status, _, n := f.state(t, id); status != "syncing" || n != 1 {
		t.Errorf("after the manual retry: status %q, %d work items; want syncing with one queued", status, n)
	}
}

// A create's failure record that runs after another request queued a file sync, and after that
// sync finished, keeps that sync's status: for a database error, a pool refusal and a stored
// credential refusal of the first sync (#1113, D2; AC-23). The other request runs between the
// failed request and the record's advisory lock.
func TestInventorySyncEntry_CreateFailureRecordKeepsANewerSyncsStatus(t *testing.T) {
	for _, cause := range []string{"database error", "pool refusal", "stored credential"} {
		for _, finished := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, other sync finished %v", cause, finished), func(t *testing.T) {
				f := setupSyncEntry(t)
				switch cause {
				case "database error":
					f.allowStored(t, true)
					f.selectOnProject(t, &f.onOpen.ID)
					f.failFirstRead(t, "identity_bindings")
				case "pool refusal":
					f.selectOnProject(t, &f.onRestricted.ID)
				case "stored credential":
					f.selectOnProject(t, &f.onOpen.ID)
				}
				name := "syncentry-race-" + uuid.NewString()[:6]
				var (
					ran     bool
					hookErr error
				)
				f.atSecondSyncLock(t, func(*gorm.DB) {
					ran = true
					var inv models.AnsibleInventory
					if hookErr = f.db.First(&inv, "organization_id = ? AND name = ?", f.orgID, name).Error; hookErr != nil {
						return
					}
					// Another request, after the cause was put right, queues a file sync.
					f.db.Model(&models.Project{}).Where("id = ?", f.projectID).Update("identity_binding_id", f.onOpen.ID)
					f.db.Model(&models.Organization{}).Where("id = ?", f.orgID).Update("allow_stored_vcs_credentials_on_agent_pools", true)
					item, err := f.items.RequestInventorySync(context.Background(), &inv, "manual")
					if err != nil {
						hookErr = err
						return
					}
					if finished {
						f.db.Model(&models.WorkItem{}).Where("id = ?", item.ID).Update("status", models.WorkItemStatusCompleted)
						f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("last_sync_status", "successful")
					}
				})
				code, resp := f.createVCS(t, name, f.gitlab.ID, nil)
				if code != http.StatusCreated {
					t.Fatalf("create = %d %s, want 201", code, resp)
				}
				if !ran || hookErr != nil {
					t.Fatalf("the other request did not run before the failure record (ran %v): %v", ran, hookErr)
				}
				want := "syncing"
				if finished {
					want = "successful"
				}
				if status, syncErr, n := f.state(t, uuid.MustParse(inventoryID(t, resp))); status != want || syncErr != "" || n != 1 {
					t.Errorf("stored: status %q error %q, %d work items; want %q from the other request's sync", status, syncErr, n, want)
				}
				if status, _ := responseSync(t, resp); status != want {
					t.Errorf("response sync status %q, want %q", status, want)
				}
			})
		}
	}
}

// A create whose failure record fails too still answers 201, and a manual sync retries (#1113, D2;
// AC-23).
func TestInventorySyncEntry_CreateWhoseFailureRecordFails(t *testing.T) {
	f := setupSyncEntry(t)
	f.allowStored(t, true)
	f.selectOnProject(t, &f.onOpen.ID)
	f.failFirstRead(t, "identity_bindings")
	f.atSecondSyncLock(t, func(tx *gorm.DB) { _ = tx.AddError(errors.New("database write interrupted")) })
	code, resp := f.createVCS(t, "syncentry-recfail-"+uuid.NewString()[:6], f.gitlab.ID, nil)
	if code != http.StatusCreated {
		t.Fatalf("create = %d %s, want 201", code, resp)
	}
	id := uuid.MustParse(inventoryID(t, resp))
	if status, _, n := f.state(t, id); status == "failed" || status == "syncing" || n != 0 {
		t.Fatalf("stored: status %q, %d work items; want neither a recorded failure nor a queued sync", status, n)
	}
	if code, body := f.sync(t, id); code != http.StatusAccepted {
		t.Fatalf("manual retry = %d %s, want 202", code, body)
	}
	if status, _, n := f.state(t, id); status != "syncing" || n != 1 {
		t.Errorf("after the manual retry: status %q, %d work items; want syncing with one queued", status, n)
	}
}

// The stored-credential refusal at the manual sync route (422 naming the connection and the setting,
// nothing queued, the status unchanged) and at create (201 with the failed status and that reason),
// for each stored-credential connection type: a GitHub token, GitLab, Bitbucket and Azure DevOps
// connection (#1113, D2; AC-26).
func TestInventorySyncEntry_StoredCredentialRefusalForEachConnectionType(t *testing.T) {
	f := setupSyncEntry(t)
	terms := []string{"stored credential", "Allow stored VCS credentials on agent pools"}
	for name, provider := range map[string]models.VCSProvider{
		"GitHub token": models.VCSProviderGitHub, "GitLab": models.VCSProviderGitLab,
		"Bitbucket": models.VCSProviderBitbucket, "Azure DevOps": models.VCSProviderAzureDevOps,
	} {
		conn := &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgID, Provider: provider, AccessToken: "stored-token", AccountName: "syncentry-stored-" + uuid.NewString()[:6]}
		if err := f.db.Create(conn).Error; err != nil {
			t.Fatal(err)
		}
		// Runs before the fixture's cleanup: the inventories on the connection go first.
		t.Cleanup(func() {
			var ids []uuid.UUID
			f.db.Model(&models.AnsibleInventory{}).Where("vcs_connection_id = ?", conn.ID).Pluck("id", &ids)
			f.db.Where("inventory_id IN ?", ids).Delete(&models.WorkItem{})
			f.db.Where("id IN ?", ids).Delete(&models.AnsibleInventory{})
			f.db.Where("id = ?", conn.ID).Delete(&models.VCSConnection{})
		})
		want := append([]string{conn.AccountName}, terms...)

		inv := f.inventory(t, conn.ID, &f.onOpen.ID)
		code, body := f.sync(t, inv.ID)
		if code != http.StatusUnprocessableEntity {
			t.Errorf("%s: manual sync = %d %s, want 422", name, code, body)
		}
		for _, w := range want {
			if !strings.Contains(string(body), w) {
				t.Errorf("%s: manual sync refusal %s does not say %q", name, body, w)
			}
		}
		if status, _, n := f.state(t, inv.ID); status != "completed" || n != 0 {
			t.Errorf("%s: after the manual refusal: status %q, %d work items; want it unchanged and nothing queued", name, status, n)
		}

		code, resp := f.createVCS(t, "syncentry-stored-"+uuid.NewString()[:6], conn.ID, &f.onOpen.ID)
		if code != http.StatusCreated {
			t.Errorf("%s: create = %d %s, want 201", name, code, resp)
			continue
		}
		respStatus, respErr := responseSync(t, resp)
		status, syncErr, n := f.state(t, uuid.MustParse(inventoryID(t, resp)))
		if respStatus != "failed" || status != "failed" || n != 0 {
			t.Errorf("%s: create: response status %q, stored %q, %d work items; want failed and nothing queued", name, respStatus, status, n)
		}
		for _, w := range want {
			if !strings.Contains(syncErr, w) || !strings.Contains(respErr, w) {
				t.Errorf("%s: create reason (stored %q, response %q) does not say %q", name, syncErr, respErr, w)
			}
		}
	}
}
