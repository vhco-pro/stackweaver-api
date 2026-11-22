// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/storage/storagetest"
	"gorm.io/gorm"
)

type runnerReadRepositoryContextKey struct{}

func TestRunnerReadDelivery_RepositoriesKeepRequestContext(t *testing.T) {
	for _, mode := range []string{"job cache", "launcher cache", "snapshot"} {
		t.Run(mode, func(t *testing.T) {
			var fixture *runnerDeliveryFixture
			var table string
			if mode == "snapshot" {
				fixture = runnerDeliverySnapshot(t, []byte("context-bound snapshot"))
				table = "ansible_playbooks"
			} else {
				fixture = newRunnerDeliveryFixture(t, "blob", []byte("context-bound cache"))
				entry := runnerDeliveryCacheEntry(t, fixture, storagetest.NewMemory())
				table = "cache_entries"
				if mode == "launcher cache" {
					fixture.path = "/api/v2/runner/cache/provider/" + entry.SHA256 + "?organization=" + entry.OrganizationID.String()
				}
			}
			var observed atomic.Int32
			var missing atomic.Bool
			name := "selected-context-probe-" + fixture.id
			callback := func(tx *gorm.DB) {
				if tx.Statement.Table == table {
					observed.Add(1)
					if tx.Statement.Context.Value(runnerReadRepositoryContextKey{}) != fixture.id {
						missing.Store(true)
						_ = tx.AddError(errors.New("selected repository lost the request operation context"))
					}
				}
			}
			if err := fixture.claim.db.Callback().Query().Before("gorm:query").Register(name, callback); err != nil {
				t.Fatal(err)
			}
			if err := fixture.claim.db.Callback().Update().Before("gorm:update").Register(name, callback); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := fixture.claim.db.Callback().Query().Remove(name); err != nil {
					t.Error(err)
				}
				if err := fixture.claim.db.Callback().Update().Remove(name); err != nil {
					t.Error(err)
				}
			})
			router := runnerReadDeliveryRouter(fixture.claim, true)
			server := runnerReadDeliveryServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				ctx := context.WithValue(request.Context(), runnerReadRepositoryContextKey{}, fixture.id)
				router.ServeHTTP(w, request.WithContext(ctx))
			}))
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+fixture.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			bearer := fixture.token.Token
			if mode == "launcher cache" {
				bearer = fixture.claim.token
			}
			req.Header.Set("Authorization", "Bearer "+bearer)
			response, err := runnerReadSingleAttemptClient(t).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			closeErr := response.Body.Close()
			if missing.Load() || observed.Load() == 0 || response.StatusCode != http.StatusOK || readErr != nil || closeErr != nil {
				t.Fatalf("selected repository operation did not inherit request context: observed=%d missing=%v status=%d read=%v close=%v", observed.Load(), missing.Load(), response.StatusCode, readErr, closeErr)
			}
		})
	}
}

func TestRunnerReadDelivery_RepositoryReadsCancelWithRequest(t *testing.T) {
	for _, mode := range []string{"job cache", "launcher cache", "snapshot"} {
		t.Run(mode, func(t *testing.T) {
			var fixture *runnerDeliveryFixture
			var table string
			if mode == "snapshot" {
				fixture = runnerDeliverySnapshot(t, []byte("cancelable snapshot"))
				table = "ansible_playbooks"
			} else {
				fixture = newRunnerDeliveryFixture(t, "blob", []byte("cancelable cache"))
				entry := runnerDeliveryCacheEntry(t, fixture, storagetest.NewMemory())
				table = "cache_entries"
				if mode == "launcher cache" {
					fixture.path = "/api/v2/runner/cache/provider/" + entry.SHA256 + "?organization=" + entry.OrganizationID.String()
				}
			}
			started := make(chan context.Context, 1)
			release := make(chan struct{})
			defer close(release)
			var entered atomic.Bool
			name := "cancel-selected-repository-" + fixture.id
			if err := fixture.claim.db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
				if tx.Statement.Table != table || !entered.CompareAndSwap(false, true) {
					return
				}
				// Model a repository operation waiting on the driver's context. The release channel
				// is a test-owned backstop, so even broken context propagation cannot hang cleanup.
				started <- tx.Statement.Context
				select {
				case <-tx.Statement.Context.Done():
					_ = tx.AddError(tx.Statement.Context.Err())
				case <-release:
					_ = tx.AddError(errors.New("test released an unbound repository operation"))
				}
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := fixture.claim.db.Callback().Query().Remove(name); err != nil {
					t.Error(err)
				}
			})
			server := runnerReadDeliveryServer(t, runnerReadDeliveryRouter(fixture.claim, true))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+fixture.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			bearer := fixture.token.Token
			if mode == "launcher cache" {
				bearer = fixture.claim.token
			}
			request.Header.Set("Authorization", "Bearer "+bearer)
			done := make(chan error, 1)
			client := runnerReadSingleAttemptClient(t)
			go func() {
				response, err := client.Do(request)
				if response != nil {
					err = errors.Join(err, response.Body.Close())
				}
				done <- err
			}()
			ready := time.NewTimer(10 * time.Second)
			defer ready.Stop()
			var operation context.Context
			select {
			case operation = <-started:
			case <-ready.C:
				t.Fatal("fixture never entered its selected repository read")
			}
			canceledAt := time.Now()
			cancel()
			stopped := time.NewTimer(5 * time.Second)
			defer stopped.Stop()
			select {
			case <-operation.Done():
				if !errors.Is(operation.Err(), context.Canceled) {
					t.Fatalf("repository cancellation cause: %v", operation.Err())
				}
			case <-stopped.C:
				t.Fatal("selected SQL operation stayed alive after request cancellation")
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("client cancellation: %v", err)
				}
			case <-stopped.C:
				t.Fatal("HTTP request did not stop with its repository read")
			}
			if elapsed := time.Since(canceledAt); elapsed >= 5*time.Second {
				t.Fatalf("repository cancellation took %s", elapsed)
			}
		})
	}
}

func TestRunnerReadDelivery_ArtifactFamiliesKeepRequestContext(t *testing.T) {
	for _, kind := range []string{"tofu", "ansible", "work item"} {
		t.Run(kind, func(t *testing.T) {
			var fixture *runnerDeliveryFixture
			switch kind {
			case "tofu":
				fixture = newRunnerDeliveryFixture(t, "artifacts", []byte("bounded configuration"))
			case "ansible":
				fixture = runnerDeliverySnapshot(t, []byte("bounded playbook"))
				fixture.path = "/api/v2/runner/jobs/" + fixture.id + "/artifacts"
				fixture.claim.handler.inventoryService = ansible.NewInventoryService(repository.NewAnsibleInventoryRepository(fixture.claim.db), repository.NewOrganizationRepository(fixture.claim.db))
			case "work item":
				claim := setupClaimRouteFixture(t)
				input := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: claim.orgA, Name: "read-context-" + uuid.NewString(), Type: models.InventoryTypeStatic}
				if err := claim.db.Create(input).Error; err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := claim.db.Where("constructed_id = ? AND input_id = ?", claim.inventory, input.ID).Delete(&models.AnsibleConstructedInput{}).Error; err != nil {
						t.Error(err)
					}
					if err := claim.db.Where("id = ?", input.ID).Delete(&models.AnsibleInventory{}).Error; err != nil {
						t.Error(err)
					}
				})
				inventories := repository.NewAnsibleInventoryRepository(claim.db)
				if err := inventories.SetConstructedInputs(claim.inventory, []uuid.UUID{input.ID}); err != nil {
					t.Fatal(err)
				}
				claim.handler.SetWorkItems(ansible.NewWorkItemRuntime(claim.db, ansible.NewInventoryService(inventories, repository.NewOrganizationRepository(claim.db)), nil))
				id, _, token := claim.startCompletion(t, startRouteCases[1])
				fixture = &runnerDeliveryFixture{claim: claim, id: id, token: token, path: "/api/v2/runner/jobs/" + id + "/artifacts"}
			}
			var active atomic.Bool
			var missing atomic.Bool
			var observed atomic.Int32
			name := "artifact-context-" + fixture.id
			callback := func(tx *gorm.DB) {
				if !active.Load() || tx.Statement.Table == "api_keys" {
					return
				}
				observed.Add(1)
				if tx.Statement.Context.Value(runnerReadRepositoryContextKey{}) != fixture.id {
					missing.Store(true)
					_ = tx.AddError(errors.New("artifact read lost its operation context"))
				}
			}
			if err := fixture.claim.db.Callback().Query().Before("gorm:query").Register(name, callback); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := fixture.claim.db.Callback().Query().Remove(name); err != nil {
					t.Error(err)
				}
			})
			router := runnerReadDeliveryRouter(fixture.claim, true, func(c *gin.Context) {
				c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), runnerReadRepositoryContextKey{}, fixture.id))
				active.Store(true)
				defer active.Store(false)
				c.Next()
			})
			server := runnerReadDeliveryServer(t, router)
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+fixture.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+fixture.token.Token)
			request.Header.Set("X-Stackweaver-Artifact-Sequence", "1")
			response, err := runnerReadSingleAttemptClient(t).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			closeErr := response.Body.Close()
			if missing.Load() || observed.Load() == 0 || response.StatusCode != http.StatusOK || readErr != nil || closeErr != nil {
				t.Fatalf("artifact family repository context: missing=%v observed=%d status=%d read=%v close=%v", missing.Load(), observed.Load(), response.StatusCode, readErr, closeErr)
			}
		})
	}
}
