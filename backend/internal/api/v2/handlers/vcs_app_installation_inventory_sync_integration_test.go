// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A webhook-triggered VCS file sync (#1113, D2; AC-23, AC-26): a refusal or a failed binding read
// records the failed status and reason unless a file sync of the inventory is waiting or running,
// serialized with any sync request at the inventory's advisory lock, and the request runs under a
// bounded context, so a lock wait that is canceled writes nothing and the next request proceeds.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration

package handlers

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/gorm"
)

func (f *workItemRunnerFixture) webhookState(t *testing.T, id uuid.UUID) (string, string, int64) {
	t.Helper()
	var inv models.AnsibleInventory
	if err := f.db.First(&inv, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	var n int64
	f.db.Model(&models.WorkItem{}).Where("inventory_id = ? AND status IN ?", id, []string{models.WorkItemStatusPending, models.WorkItemStatusRunning}).Count(&n)
	return inv.LastSyncStatus, inv.LastSyncError, n
}

func TestWebhookInventorySync_RefusalIsRecordedUnlessASyncIsActive(t *testing.T) {
	f := setupWorkItemRunner(t)
	restricted := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA, Name: "webhook-restricted-" + uuid.NewString()[:6]}
	if err := f.db.Create(restricted).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", restricted.ID).Delete(&models.AgentPool{}) })
	b := f.binding(t, restricted.ID, "restricted")
	h := &VCSAppInstallationHandlerV2{workItems: f.items}

	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	if err := f.db.Model(inv).Updates(map[string]any{"identity_binding_id": b.ID, "last_sync_status": "completed"}).Error; err != nil {
		t.Fatal(err)
	}
	h.requestInventorySync(inv)
	if status, syncErr, n := f.webhookState(t, inv.ID); status != "failed" || !strings.Contains(syncErr, restricted.Name) || n != 0 {
		t.Errorf("refused webhook sync: status %q error %q, %d active; want failed naming the pool and nothing queued", status, syncErr, n)
	}

	// With a file sync waiting, the refusal leaves the status to it.
	busy := f.fileSyncInventory(t, models.InventoryTypeVCS)
	queued := time.Now()
	waiting := &models.WorkItem{OrganizationID: f.orgA, ProjectID: &f.projectA, Kind: models.WorkItemInventoryFileSync, InventoryID: &busy.ID, AgentPoolID: &f.poolA, Status: models.WorkItemStatusPending, QueuedAt: &queued}
	if err := f.db.Create(waiting).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Model(busy).Updates(map[string]any{"identity_binding_id": b.ID, "last_sync_status": "syncing"}).Error; err != nil {
		t.Fatal(err)
	}
	h.requestInventorySync(busy)
	if status, _, _ := f.webhookState(t, busy.ID); status != "syncing" {
		t.Errorf("refused webhook sync with a sync waiting: status %q, want it left to that sync", status)
	}
}

func TestWebhookInventorySync_TimedOutLockWaitWritesNothing(t *testing.T) {
	f := setupWorkItemRunner(t)
	prev := webhookSyncTimeout
	webhookSyncTimeout = 300 * time.Millisecond
	t.Cleanup(func() { webhookSyncTimeout = prev })
	h := &VCSAppInstallationHandlerV2{workItems: f.items}
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	if err := f.db.Model(inv).Update("last_sync_status", "completed").Error; err != nil {
		t.Fatal(err)
	}

	tx := f.db.Begin()
	if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", ansible.InventorySyncLockKey(inv.ID)).Error; err != nil {
		t.Fatal(err)
	}
	h.requestInventorySync(inv)
	status, _, n := f.webhookState(t, inv.ID)
	tx.Rollback()
	if status != "completed" || n != 0 {
		t.Fatalf("a webhook whose lock wait timed out: status %q, %d queued; want nothing written", status, n)
	}

	// The next request proceeds.
	h.requestInventorySync(inv)
	if status, _, n := f.webhookState(t, inv.ID); status != "syncing" || n != 1 {
		t.Errorf("the next webhook request: status %q, %d queued; want it queued and syncing", status, n)
	}
}

// failFirstReadOf fails the next read of table on the fixture's database, and only that one.
func (f *workItemRunnerFixture) failFirstReadOf(t *testing.T, table string) {
	t.Helper()
	name := "webhook-failread-" + uuid.NewString()[:6]
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

// syncRequestMark marks the context of a sync request a test runs beside a webhook, so a lock hook
// can tell the two apart: the webhook's own context never carries it.
type syncRequestMark struct{}

func markedRequest(tx *gorm.DB) bool {
	return tx.Statement.Context != nil && tx.Statement.Context.Value(syncRequestMark{}) != nil
}

// onSyncLock calls fn for every statement that takes an inventory's sync advisory lock, before the
// statement runs when before is true and after it returned (the lock held) otherwise.
func (f *workItemRunnerFixture) onSyncLock(t *testing.T, before bool, fn func(tx *gorm.DB)) {
	t.Helper()
	name := "webhook-lock-" + uuid.NewString()[:6]
	hook := func(tx *gorm.DB) {
		if strings.Contains(tx.Statement.SQL.String(), "pg_advisory_xact_lock") {
			fn(tx)
		}
	}
	var err error
	if before {
		err = f.db.Callback().Raw().Before("gorm:raw").Register(name, hook)
	} else {
		err = f.db.Callback().Raw().After("gorm:raw").Register(name, hook)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.db.Callback().Raw().Remove(name) })
}

// waitForSyncLockWaiter waits until a session waits for the inventory's sync advisory lock.
func (f *workItemRunnerFixture) waitForSyncLockWaiter(t *testing.T, inventoryID uuid.UUID) {
	t.Helper()
	key := ansible.InventorySyncLockKey(inventoryID)
	waitFor(t, "a request to wait on the inventory's sync lock", func() bool {
		var n int64
		f.db.Raw("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND objsubid = 1 AND ((classid::bigint << 32) | objid::bigint) = ?", key).Scan(&n)
		return n > 0
	})
}

// boundFileSyncInventory is a VCS inventory of project A on the fixture's GitLab connection,
// selecting a binding on pool A, with a settled sync.
func (f *workItemRunnerFixture) boundFileSyncInventory(t *testing.T) *models.AnsibleInventory {
	t.Helper()
	b := f.binding(t, f.poolA, "webhook")
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	if err := f.db.Model(inv).Updates(map[string]any{"identity_binding_id": b.ID, "last_sync_status": "completed"}).Error; err != nil {
		t.Fatal(err)
	}
	inv.IdentityBindingID = &b.ID
	return inv
}

func (f *workItemRunnerFixture) allowStoredOnOrgA(t *testing.T, allow bool) {
	t.Helper()
	if err := f.db.Model(&models.Organization{}).Where("id = ?", f.orgA).Update("allow_stored_vcs_credentials_on_agent_pools", allow).Error; err != nil {
		t.Fatal(err)
	}
}

// A webhook whose binding read fails records the failed status and the retry reason, and a manual
// sync then queues (#1113, D2; AC-23).
func TestWebhookInventorySync_FailedBindingReadRecordsTheRetryReason(t *testing.T) {
	f := setupWorkItemRunner(t)
	h := &VCSAppInstallationHandlerV2{workItems: f.items}
	inv := f.boundFileSyncInventory(t)
	f.failFirstReadOf(t, "identity_bindings")
	h.requestInventorySync(inv)
	if status, syncErr, n := f.webhookState(t, inv.ID); status != "failed" || syncErr != ansible.FirstSyncRetryReason || n != 0 {
		t.Fatalf("webhook during a read failure: status %q error %q, %d active; want failed with the retry reason and nothing queued", status, syncErr, n)
	}
	// The manual sync route's request.
	item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatalf("manual retry: %v", err)
	}
	if item.AgentPoolID == nil || *item.AgentPoolID != f.poolA {
		t.Errorf("manual retry queued on %v, want pool A", item.AgentPoolID)
	}
	if status, _, n := f.webhookState(t, inv.ID); status != "syncing" || n != 1 {
		t.Errorf("after the manual retry: status %q, %d active; want syncing with one queued", status, n)
	}
}

// A webhook whose failure record's lock wait is canceled writes nothing, and the next request
// queues (#1113, D2; AC-23). The request fails on a binding read; another session holds the
// inventory's sync lock when the record asks for it, until the webhook's bounded context cancels
// the wait. TestWebhookInventorySync_TimedOutLockWaitWritesNothing cancels the request's own wait.
func TestWebhookInventorySync_CanceledRecordWaitWritesNothing(t *testing.T) {
	f := setupWorkItemRunner(t)
	prev := webhookSyncTimeout
	webhookSyncTimeout = 300 * time.Millisecond
	t.Cleanup(func() { webhookSyncTimeout = prev })
	h := &VCSAppInstallationHandlerV2{workItems: f.items}
	inv := f.boundFileSyncInventory(t)
	f.failFirstReadOf(t, "identity_bindings")

	var (
		calls  atomic.Int32
		holder *gorm.DB
	)
	f.onSyncLock(t, true, func(*gorm.DB) {
		// The first is the failed request's lock, the second the failure record's.
		if calls.Add(1) == 2 {
			holder = f.db.Begin()
			holder.Exec("SELECT pg_advisory_xact_lock(?)", ansible.InventorySyncLockKey(inv.ID))
		}
	})
	start := time.Now()
	h.requestInventorySync(inv)
	waited := time.Since(start)
	if holder == nil {
		t.Fatal("the failure record never asked for the lock")
	}
	status, _, n := f.webhookState(t, inv.ID)
	holder.Rollback()
	if waited < webhookSyncTimeout {
		t.Errorf("the webhook returned after %v, before its bounded context ended", waited)
	}
	if status != "completed" || n != 0 {
		t.Fatalf("a webhook whose record wait was canceled: status %q, %d active; want nothing written", status, n)
	}

	h.requestInventorySync(inv)
	if status, _, n := f.webhookState(t, inv.ID); status != "syncing" || n != 1 {
		t.Errorf("the next webhook request: status %q, %d active; want it queued and syncing", status, n)
	}
}

type syncRequestResult struct {
	item *models.WorkItem
	err  error
	at   time.Time
}

// A refused webhook held at the inventory's advisory lock and a sync request for the same inventory
// run one after the other, in both orders (#1113, D2; AC-23). The webhook is refused for the stored
// credential; the setting is turned on before the sync request, which then queues. Whichever holds
// the lock first, the other waits for it, and the final status is the queued sync's.
func TestWebhookInventorySync_RefusalAndASyncRequestSerialize(t *testing.T) {
	marked := context.WithValue(context.Background(), syncRequestMark{}, true)
	request := func(f *workItemRunnerFixture, inv *models.AnsibleInventory, done chan<- syncRequestResult) {
		item, err := f.items.RequestInventorySync(marked, inv, "manual")
		done <- syncRequestResult{item: item, err: err, at: time.Now()}
	}
	settle := func(t *testing.T, f *workItemRunnerFixture, inv *models.AnsibleInventory, req syncRequestResult) {
		t.Helper()
		if req.err != nil {
			t.Fatalf("the sync request: %v", req.err)
		}
		if status, syncErr, n := f.webhookState(t, inv.ID); status != "syncing" || syncErr != "" || n != 1 {
			t.Errorf("final: status %q error %q, %d active; want the queued sync's status", status, syncErr, n)
		}
	}

	t.Run("webhook holds the lock first", func(t *testing.T) {
		f := setupWorkItemRunner(t)
		h := &VCSAppInstallationHandlerV2{workItems: f.items}
		inv := f.boundFileSyncInventory(t)
		f.allowStoredOnOrgA(t, false)
		holding, release := make(chan struct{}), make(chan struct{})
		var webhookLocks atomic.Int32
		f.onSyncLock(t, false, func(tx *gorm.DB) {
			// The webhook's second lock is its failure record's: hold it there.
			if !markedRequest(tx) && webhookLocks.Add(1) == 2 {
				close(holding)
				<-release
			}
		})
		// What the sync request finds once it holds the lock: the webhook's committed record.
		var seen atomic.Value
		f.onSyncLock(t, false, func(tx *gorm.DB) {
			if markedRequest(tx) {
				var stored models.AnsibleInventory
				f.db.Select("last_sync_status").First(&stored, "id = ?", inv.ID)
				seen.Store(stored.LastSyncStatus)
			}
		})
		webhookDone := make(chan time.Time, 1)
		go func() {
			h.requestInventorySync(inv)
			webhookDone <- time.Now()
		}()
		select {
		case <-holding:
		case <-time.After(20 * time.Second):
			t.Fatal("the refused webhook never took the lock for its failure record")
		}
		f.allowStoredOnOrgA(t, true)
		reqDone := make(chan syncRequestResult, 1)
		go request(f, inv, reqDone)
		f.waitForSyncLockWaiter(t, inv.ID)
		close(release)
		webhookAt := <-webhookDone
		req := <-reqDone
		if !req.at.After(webhookAt) {
			t.Errorf("the sync request returned at %v, before the webhook it waited for (%v)", req.at, webhookAt)
		}
		if got, _ := seen.Load().(string); got != "failed" {
			t.Errorf("the sync request took the lock with status %q, want the webhook's failure already recorded", got)
		}
		settle(t, f, inv, req)
	})

	t.Run("sync request holds the lock first", func(t *testing.T) {
		f := setupWorkItemRunner(t)
		h := &VCSAppInstallationHandlerV2{workItems: f.items}
		inv := f.boundFileSyncInventory(t)
		f.allowStoredOnOrgA(t, false)
		refused, proceed := make(chan struct{}), make(chan struct{})
		reqHolding, reqRelease := make(chan struct{}), make(chan struct{})
		var webhookLocks atomic.Int32
		f.onSyncLock(t, true, func(tx *gorm.DB) {
			// The webhook was refused and is about to ask for the lock for its failure record.
			if !markedRequest(tx) && webhookLocks.Add(1) == 2 {
				close(refused)
				<-proceed
			}
		})
		var once sync.Once
		f.onSyncLock(t, false, func(tx *gorm.DB) {
			if markedRequest(tx) {
				once.Do(func() {
					close(reqHolding)
					<-reqRelease
				})
			}
		})
		webhookDone := make(chan time.Time, 1)
		go func() {
			h.requestInventorySync(inv)
			webhookDone <- time.Now()
		}()
		select {
		case <-refused:
		case <-time.After(20 * time.Second):
			t.Fatal("the webhook was never refused")
		}
		f.allowStoredOnOrgA(t, true)
		reqDone := make(chan syncRequestResult, 1)
		go request(f, inv, reqDone)
		select {
		case <-reqHolding:
		case <-time.After(20 * time.Second):
			t.Fatal("the sync request never took the lock")
		}
		close(proceed)
		f.waitForSyncLockWaiter(t, inv.ID)
		close(reqRelease)
		req := <-reqDone
		webhookAt := <-webhookDone
		if !webhookAt.After(req.at) {
			t.Errorf("the webhook returned at %v, before the sync request it waited for (%v)", webhookAt, req.at)
		}
		settle(t, f, inv, req)
	})
}

// A webhook request for an inventory whose connection holds a stored credential, bound to a
// customer pool while the organization does not allow stored credentials there, records the failed
// status with a reason in the glossary terms, for each stored-credential connection type (#1113,
// D2; AC-26).
func TestWebhookInventorySync_StoredCredentialRefusalIsRecorded(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.allowStoredOnOrgA(t, false)
	h := &VCSAppInstallationHandlerV2{workItems: f.items}
	for name, provider := range map[string]models.VCSProvider{
		"GitHub token": models.VCSProviderGitHub, "GitLab": models.VCSProviderGitLab,
		"Bitbucket": models.VCSProviderBitbucket, "Azure DevOps": models.VCSProviderAzureDevOps,
	} {
		conn := &models.VCSConnection{ID: uuid.New(), OrganizationID: f.orgA, Provider: provider, AccessToken: "stored-token", AccountName: "webhook-stored-" + uuid.NewString()[:6]}
		if err := f.db.Create(conn).Error; err != nil {
			t.Fatal(err)
		}
		inv := f.boundFileSyncInventory(t)
		if err := f.db.Model(inv).Update("vcs_connection_id", conn.ID).Error; err != nil {
			t.Fatal(err)
		}
		inv.VCSConnectionID = &conn.ID
		// Runs before the inventory's own cleanup, so the inventory goes before its connection.
		t.Cleanup(func() {
			f.db.Where("inventory_id = ?", inv.ID).Delete(&models.WorkItem{})
			f.db.Where("id = ?", inv.ID).Delete(&models.AnsibleInventory{})
			f.db.Where("id = ?", conn.ID).Delete(&models.VCSConnection{})
		})
		h.requestInventorySync(inv)
		status, syncErr, n := f.webhookState(t, inv.ID)
		if status != "failed" || n != 0 {
			t.Errorf("%s: status %q, %d active; want failed and nothing queued", name, status, n)
		}
		for _, term := range []string{"stored credential", "Allow stored VCS credentials on agent pools", conn.AccountName} {
			if !strings.Contains(syncErr, term) {
				t.Errorf("%s: recorded reason %q does not say %q", name, syncErr, term)
			}
		}
	}
}
